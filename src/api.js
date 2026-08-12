// src/api.js
// Browser-compatible WebRTC API for Node.js.
// Wraps ConnectionManager with standard RTCPeerConnection interface.
//
// TODO markers indicate functionality that needs implementation.
// The API surface is complete — all browser methods/properties exist as stubs.

import { EventEmitter } from 'node:events';
import { ConnectionManager } from './connection_manager.js';
import {
  createVideoSendPipeline, createVideoSendSimulcastPipeline,
  createVideoReceivePipeline, createVideoReceiveSimulcastPipeline,
  createAudioSendPipeline, createAudioReceivePipeline,
} from './media_pipeline.js';
import * as SDP from './sdp.js';
import * as RtpManager from './rtp_transmission_manager.js';
import { getSupportedVideoCodecs, getSupportedAudioCodecs, MediaStreamTrack } from 'media-processing';

// Debug logging gate. Set WEBRTC_DEBUG=1 in env to enable diagnostic
// '[api-diag]' lines that trace track/datachannel/pipeline lifecycle.
// Off by default — keeps production output clean. Apps that need to
// debug a connection issue can flip the env var without code changes.
var _DBG = (typeof process !== 'undefined' &&
            process.env &&
            (process.env.WEBRTC_DEBUG === '1' ||
             process.env.WEBRTC_DEBUG === 'true'));

// ── Single source of truth for the default codec set (WPT/behavior:
//    identical shape must appear in getCapabilities, sender post-
//    negotiation params, and receiver mirrors — it was duplicated 4x). ──

// Derive the codec list for a mid/kind from an APPLIED description —
// WPT requires receiver codecs to match the LOCAL SDP m-line exactly
// (count, payloadTypes, fmtp), not a static default table.
function _codecsFromSdp(manager, kind, mid, preferRemote) {
  try {
    // WHICH DESCRIPTION ANSWERS THE QUESTION DEPENDS ON THE DIRECTION.
    //
    // A RECEIVER's codecs are what WE are prepared to decode — the local
    // description. A SENDER's are what the PEER can decode, so they come from
    // the remote one: sending a codec the peer did not list is sending
    // something it cannot play.
    //
    // Reading the local description for both meant a sender kept reporting
    // our full offer after an answer narrowed the list — measured, four
    // codecs reported against a remote description carrying three.
    var _st = manager && manager.state;
    var d = !_st ? null : (preferRemote
      ? (_st.parsedRemoteSdp || _st.parsedLocalSdp)
      : (_st.parsedLocalSdp || _st.parsedRemoteSdp));
    if (!d || !d.media) return null;
    var m = null;
    for (var i = 0; i < d.media.length; i++) {
      if (String(d.media[i].mid) === String(mid) ||
          (mid == null && d.media[i].type === kind)) { m = d.media[i]; break; }
    }
    if (!m || !m.codecs || !m.codecs.length) return null;
    var out = [];
    for (var c = 0; c < m.codecs.length; c++) {
      var cc = m.codecs[c];
      // parser shape: {payloadType, name, clockRate, channels, fmtp:{k:v}}
      var fmtpStr;
      if (cc.fmtp && typeof cc.fmtp === 'object') {
        var kv = [];
        for (var fk in cc.fmtp) {
          // NOT EVERY FMTP PARAMETER IS A key=value PAIR.
          //
          // RFC 4855: the format-specific parameters are whatever the codec's
          // own RFC says. telephone-event (RFC 4733) carries a bare event
          // list — `a=fmtp:114 0-15` — and the parser records that as the key
          // with a boolean true. Re-joining it as `fk + '=' + value` produced
          // `0-15=true`, so getParameters() reported an fmtp line that does
          // not match the SDP it came from and would not survive a round trip
          // back onto the wire.
          kv.push(cc.fmtp[fk] === true ? fk : (fk + '=' + cc.fmtp[fk]));
        }
        fmtpStr = kv.length ? kv.join(';') : undefined;
      } else if (typeof cc.fmtp === 'string' && cc.fmtp) {
        fmtpStr = cc.fmtp;
      }
      var entry = {
        payloadType: cc.payloadType,
        mimeType: kind + '/' + cc.name,
        clockRate: cc.clockRate,
      };
      if (kind === 'audio') entry.channels = cc.channels || 1;
      if (fmtpStr !== undefined) entry.sdpFmtpLine = fmtpStr;
      out.push(entry);
      // the parser FOLDS rtx into rtxPayloadType; the SDP (and WPT's
      // per-index comparison against it) lists rtx right after its
      // primary — re-expand in the same interleaved order.
      if (cc.rtxPayloadType != null) {
        out.push({
          payloadType: cc.rtxPayloadType,
          mimeType: kind + '/rtx',
          clockRate: cc.clockRate,
          sdpFmtpLine: 'apt=' + cc.payloadType,
        });
      }
    }
    return out.length ? out : null;
  } catch (e) { return null; }
}
function _defaultCodecs(kind) {
  return kind === 'video'
    ? [{ payloadType: 96, mimeType: 'video/VP8', clockRate: 90000 },
       { payloadType: 97, mimeType: 'video/rtx', clockRate: 90000, sdpFmtpLine: 'apt=96' }]
    : [{ payloadType: 111, mimeType: 'audio/opus', clockRate: 48000, channels: 2,
         sdpFmtpLine: 'minptime=10;useinbandfec=1' },
       { payloadType: 8, mimeType: 'audio/PCMA', clockRate: 8000, channels: 1 },
       { payloadType: 0, mimeType: 'audio/PCMU', clockRate: 8000, channels: 1 }];
}
function _diag() {
  if (!_DBG) return;
  // Use console.log with the original args. Apply pattern keeps the
  // formatter behavior (string interpolation, multiple args, etc.).
  if (typeof console !== 'undefined' && console.log) {
    console.log.apply(console, arguments);
  }
}


/* ========================= RTCPeerConnection ========================= */

function RTCPeerConnection(config) {
  // WPT-harvest: spec-grade config validation at construction (W3C §4.4.1.1).
  config = config || {};
  var _normIceServers = _validateIceServers(config.iceServers, 'RTCPeerConnection');
  // remembered for setConfiguration's immutability check
  try { /* set after manager exists */ } catch (e0) {}
  if (config.certificates === null) {
    throw new TypeError('RTCPeerConnection: certificates must be a sequence');
  }
  if (config.certificates && config.certificates.length) {
    for (var cni = 0; cni < config.certificates.length; cni++) {
      if (config.certificates[cni] == null) {
        throw new TypeError('RTCPeerConnection: certificates entries must be RTCCertificate');
      }
    }
  }
  if (config.certificates && config.certificates.length) {
    for (var cxi = 0; cxi < config.certificates.length; cxi++) {
      var cx = config.certificates[cxi];
      if (cx && typeof cx.expires === 'number' && cx.expires <= Date.now()) {
        throw new DOMException('RTCPeerConnection: certificate expired', 'InvalidAccessError');
      }
    }
  }

  // WebIDL-shape (WPT harvest): public methods live on the PROTOTYPE
  // (assert_idl_attribute demands it, and duck-typing libraries expect
  // it). The closure pattern stays untouched — implementations live on a
  // hidden per-instance table and the prototype delegates.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });
  Object.defineProperty(this, '_handlers', { value: {}, enumerable: false });

  if (!(this instanceof RTCPeerConnection)) return new RTCPeerConnection(config);

  config = config || {};
  var self = this;

  // ── Config validation (W3C §4.4.1.2) ──
  // Throw early on invalid enum values rather than silently accepting them.
  // The spec uses TypeError for enum mismatches.
  if (config.iceTransportPolicy != null &&
      config.iceTransportPolicy !== 'all' &&
      config.iceTransportPolicy !== 'relay') {
    throw new TypeError('RTCPeerConnection: invalid iceTransportPolicy "' +
      config.iceTransportPolicy + '" (expected "all" or "relay")');
  }
  if (config.bundlePolicy !== undefined &&
      config.bundlePolicy !== 'balanced' &&
      config.bundlePolicy !== 'max-bundle' &&
      config.bundlePolicy !== 'max-compat') {
    throw new TypeError('RTCPeerConnection: invalid bundlePolicy "' +
      config.bundlePolicy + '" (expected "balanced", "max-bundle", or "max-compat")');
  }
    if (config.iceTransportPolicy !== undefined &&
        config.iceTransportPolicy !== 'all' && config.iceTransportPolicy !== 'relay') {
      // null and any non-enum value are TypeErrors per WebIDL enum rules
      throw new TypeError('RTCPeerConnection: invalid iceTransportPolicy "' + config.iceTransportPolicy + '"');
    }
  if (config.rtcpMuxPolicy !== undefined && config.rtcpMuxPolicy !== 'require') {
    // W3C removed 'negotiate' — 'require' is the only valid value.
    throw new TypeError('RTCPeerConnection: invalid rtcpMuxPolicy "' +
      config.rtcpMuxPolicy + '" (only "require" is supported per spec)');
  }
  if (config.iceCandidatePoolSize != null) {
    var pool = config.iceCandidatePoolSize;
    if (typeof pool !== 'number' || !isFinite(pool) || pool < 0 || pool > 255 ||
        Math.floor(pool) !== pool) {
      throw new TypeError('RTCPeerConnection: iceCandidatePoolSize must be ' +
        'an integer in [0, 255], got ' + pool);
    }
  }
  // NOTE: bundlePolicy='balanced' and 'max-compat' are accepted but not
  // enforced — the implementation always produces 'max-bundle' style SDP.
  // TODO: real bundlePolicy enforcement (deferred — touches sdp.js + cm.js).

  // W3C RTCConfiguration.certificates — if the app provides an
  // RTCCertificate (produced by RTCPeerConnection.generateCertificate),
  // use its PEM/key pair instead of letting ConnectionManager generate
  // a fresh one. Multiple certificates per spec indicate "any of these
  // may be used"; we pick the first one (DTLS uses exactly one).
  if (config.certificates != null && !Array.isArray(config.certificates)) {
    throw new TypeError('RTCPeerConnection: certificates must be an array');
  }
  if (Array.isArray(config.certificates) && config.certificates.length) {
    var c0 = config.certificates[0];
    if (c0 && c0._cert && c0._key && !config.cert && !config.key) {
      // Pass through to ConnectionManager. RTCCertificate stores the raw
      // PEM strings in _cert / _key (see RTCCertificate constructor).
      // The FIRST certificate is the one we present in the handshake,
      // but every configured certificate's fingerprint must appear in the
      // SDP (RFC 8122 / W3C 4.9) — otherwise a peer validating strictly
      // would reject a handshake using any of the others, making the
      // extra certificates useless.
      var _allFps = [];
      for (var _ci = 0; _ci < config.certificates.length; _ci++) {
        var _c = config.certificates[_ci];
        try {
          var _fl = (_c && typeof _c.getFingerprints === 'function') ? _c.getFingerprints() : null;
          if (_fl && _fl.length && _fl[0].value) {
            _allFps.push({ algorithm: _fl[0].algorithm || 'sha-256', value: _fl[0].value });
          }
        } catch (eF) {}
      }
      config = Object.assign({}, config, {
        cert: c0._cert,
        key:  c0._key,
        _certificateFingerprints: (_allFps.length > 1) ? _allFps : null,
      });
    }
  }

  var manager = new ConnectionManager(config);
  var ev = manager.ev;

  // Round-trip values used only by getConfiguration — stored on manager.state
  // so setConfiguration / getConfiguration see the same values.
  manager.state.iceCandidatePoolSize = (typeof config.iceCandidatePoolSize === 'number')
    ? config.iceCandidatePoolSize : 0;
  manager.state.rtcpMuxPolicy = config.rtcpMuxPolicy || 'require';
  manager.state._certificates = Array.isArray(config.certificates)
    ? config.certificates.slice() : [];

  // W3C iceCandidatePoolSize: a nonzero pool means "start gathering
  // transport candidates NOW, at construction" — so the first
  // offer/answer finds them ready instead of paying the STUN/portmap
  // round-trips inline. The spec's pool is per-transport (we run one
  // BUNDLE transport, so any nonzero value maps to one pre-gather run).
  // Pooled candidates are NOT surfaced through onicecandidate until a
  // local description is set, matching browsers — the manager holds and
  // flushes them (see cm's pregather()/cascade 2c).
  if (manager.state.iceCandidatePoolSize > 0 &&
      typeof manager.pregather === 'function') {
    manager.pregather();
  }


  // ── Read-only properties ──

  Object.defineProperty(this, 'signalingState', {
    get: function() { return manager.state.signalingState; },
  });
  Object.defineProperty(this, 'iceConnectionState', {
    get: function() { return manager.state.iceConnectionState; },
  });
  Object.defineProperty(this, 'iceGatheringState', {
    get: function() { return manager.state.iceGatheringState; },
  });
  Object.defineProperty(this, 'connectionState', {
    get: function() { return manager.state.connectionState; },
  });
  Object.defineProperty(this, 'canTrickleIceCandidates', {
    // null before SRD; afterwards reflects the remote's declared
    // a=ice-options:trickle (session or media level).
    get: function() {
      var st = manager.state;
      if (!st.parsedRemoteSdp) return null;
      var raw = (st.currentRemoteDescription && st.currentRemoteDescription.sdp) ||
                (st.pendingRemoteDescription && st.pendingRemoteDescription.sdp) || '';
      return /a=ice-options:[^\r\n]*trickle/.test(raw);
    },
  });

  // idpErrorInfo — set when an IdP validation error occurs. We don't
  // run IdP yet (see API-6); always null.
  Object.defineProperty(this, 'idpErrorInfo', {
    get: function() { return null; },
  });

  // ICE mode — 'lite' | 'full'. Extension to the standard API; not defined
  // by WebRTC spec. Read-only; set at construction via config.mode (or
  // inferred from config.router / config.socket).
  Object.defineProperty(this, 'mode', {
    get: function() { return manager.state.mode; },
  });

  // ── Undelivered-candidate filter (W3C §4.4.1.4) ──
  //
  // A candidate belongs in localDescription only once it has been SURFACED
  // through onicecandidate. Ours are folded into the SDP as soon as they are
  // gathered, so a read immediately after setLocalDescription showed a
  // candidate that the application had not been told about yet.
  //
  // This is a READ-SIDE view, deliberately. Round 154 tried the write-side
  // version — holding candidates out of the description until delivery — and
  // it worked for this test but cost RTCIceTransport 12 subtests to 6 and
  // iceGatheringState 5 to 4, because internal consumers read the stored
  // description as the authoritative candidate list. Filtering at the getter
  // leaves the stored description whole, so those consumers are untouched and
  // only the public view is corrected.
  //
  // It is also self-limiting: the filter only hides candidates in the window
  // between gathered and delivered. Anything that signals an SDP without
  // trickle waits for iceGatheringState 'complete' first, by which point every
  // candidate has been delivered and the filter is a no-op. The WHIP/WHEP
  // interop property that sank round 154 is preserved.
  var _deliveredCandidates = Object.create(null);
  var _deliveredCount = 0;

  function _markCandidateDelivered(payload) {
    if (!payload || !payload.candidate) return;
    // Key on the candidate line itself — the same text that appears in the
    // SDP, minus the "a=candidate:" prefix and any trailing whitespace.
    var line = String(payload.candidate).replace(/^a=/, '').trim();
    if (!_deliveredCandidates[line]) {
      _deliveredCandidates[line] = true;
      _deliveredCount++;          // invalidates the memo below
    }
  }

  // Memoised per (source description object, delivered-ledger version).
  //
  // The filtered view MUST be reference-stable: WPT asserts
  // `pc.pendingLocalDescription === pc.localDescription`, and applications
  // compare descriptions by identity too. Building a fresh
  // RTCSessionDescription on every read broke six subtests across
  // setLocalDescription-offer and -answer before this cache was added.
  var _filterMemoSrc = null, _filterMemoVer = -1, _filterMemoOut = null;

  function _filterUndelivered(desc) {
    if (!desc || !desc.sdp) return desc;
    if (desc.sdp.indexOf('a=candidate:') < 0) return desc;
    if (_filterMemoSrc === desc && _filterMemoVer === _deliveredCount) {
      return _filterMemoOut;
    }
    var kept = [];
    var dropped = 0;
    var lines = desc.sdp.split(/\r\n|\n/);
    for (var i = 0; i < lines.length; i++) {
      var ln = lines[i];
      if (ln.indexOf('a=candidate:') === 0) {
        var key = ln.slice(2).trim();          // strip "a=" → "candidate:..."
        if (!_deliveredCandidates[key]) { dropped++; continue; }
      }
      kept.push(ln);
    }
    var out = dropped
      ? new RTCSessionDescription({ type: desc.type, sdp: kept.join('\r\n') })
      : desc;
    _filterMemoSrc = desc; _filterMemoVer = _deliveredCount; _filterMemoOut = out;
    return out;
  }

  // SDP descriptions — pending || current (browser-compatible)
  Object.defineProperty(this, 'localDescription', {
    get: function() {
      return _filterUndelivered(manager.state.pendingLocalDescription ||
                                manager.state.currentLocalDescription);
    },
  });
  Object.defineProperty(this, 'remoteDescription', {
    get: function() { return manager.state.pendingRemoteDescription || manager.state.currentRemoteDescription; },
  });
  Object.defineProperty(this, 'currentLocalDescription', {
    get: function() { return _filterUndelivered(manager.state.currentLocalDescription); },
  });
  Object.defineProperty(this, 'currentRemoteDescription', {
    get: function() { return manager.state.currentRemoteDescription; },
  });
  Object.defineProperty(this, 'pendingLocalDescription', {
    get: function() { return _filterUndelivered(manager.state.pendingLocalDescription); },
  });
  Object.defineProperty(this, 'pendingRemoteDescription', {
    get: function() { return manager.state.pendingRemoteDescription; },
  });

  // Transport singletons. One RTCIceTransport + one RTCDtlsTransport per
  // connection, shared across all senders/receivers/sctp. Created lazily on
  // first access so the classes aren't instantiated for peer connections
  // that never read them.
  var _iceTransport = null;
  function _getIceTransport() {
    if (!_iceTransport) _iceTransport = new RTCIceTransport(manager);
    return _iceTransport;
  }
  var _dtlsTransport = null;
  function _getDtlsTransport() {
    if (!_dtlsTransport) {
      _dtlsTransport = new RTCDtlsTransport(manager);
      _dtlsTransport.iceTransport = _getIceTransport();
    }
    return _dtlsTransport;
  }
  manager._getDtlsTransport = _getDtlsTransport;
  manager._getIceTransport  = _getIceTransport;

  // SCTP transport (cached). W3C §4.4.1.10: pc.sctp is an
  // RTCSctpTransport when SCTP has been negotiated, else null.
  //
  // "Negotiated" means the SDP includes (or will include) an
  // m=application section. The two signals for that are:
  //   • the app called createDataChannel() locally → we'll emit
  //     m=application on our next offer/answer
  //   • the remote sent an SDP with m=application → state.remoteSctpPort is set
  //
  // Either signal makes pc.sctp non-null even before the actual SCTP
  // handshake completes — apps need a non-null reference early to
  // attach onstatechange listeners that observe the connecting →
  // connected transition.
  var _sctpTransport = null;
  Object.defineProperty(this, 'sctp', {
    get: function() {
      var pL = manager.state.parsedLocalSdp, pR = manager.state.parsedRemoteSdp;
      var hasData = function (p) {
        return !!(p && p.media && p.media.some(function (mm) {
          return mm.type === 'application'; }));
      };
      if (!hasData(pL) && !hasData(pR)) return null;
      var sctpNegotiated =
        (manager.state.dataChannels && manager.state.dataChannels.length > 0) ||
        manager.state.remoteSctpPort != null ||
        manager.state.sctpAssociation != null;
      if (!sctpNegotiated) return null;
      if (!_sctpTransport) {
        _sctpTransport = new RTCSctpTransport(manager);
        _sctpTransport.transport = _getDtlsTransport();
      }
      return _sctpTransport;
    },
  });

  // Identity (rarely used) — see API-6 for full IdP support.
  //
  // W3C §4.4.1.7: peerIdentity is a Promise<RTCIdentityAssertion>
  // that resolves when identity validation completes (or rejects on
  // failure). Per spec, the SAME Promise instance is returned on
  // every access (cached). If no Identity Provider is configured,
  // the Promise stays pending forever — it does NOT resolve with
  // null. Apps that don't use IdP simply never await this Promise.
  //
  // We construct one pending Promise here and return it from the
  // getter on every access. When IdP support lands (API-6), this
  // becomes the Promise that resolve()/reject() will be called on
  // from the validation flow.
  var _peerIdentityPromise = new Promise(function() { /* never settles */ });
  Object.defineProperty(this, 'peerIdentity', {
    get: function() { return _peerIdentityPromise; },
  });
  Object.defineProperty(this, 'idpLoginUrl', {
    get: function() { return null; },
  });


  // ── Event handler properties (browser-style: pc.ontrack = fn) ──

  var _handlers = {};
  var _evNames = [
    'connectionstatechange', 'iceconnectionstatechange', 'icegatheringstatechange',
    'signalingstatechange', 'negotiationneeded',
  ];

  for (var ei = 0; ei < _evNames.length; ei++) {
    (function(name) {
      Object.defineProperty(self, 'on' + name, {
        get: function() { return _handlers[name] || null; },
        set: function(fn) {
          if (_handlers[name]) ev.removeListener(name, _handlers[name]._wrapped || _handlers[name]);
          _handlers[name] = fn;
          if (fn) {
            // Same Event-shape guarantee as addEventListener: on-handlers
            // must receive an object with .type (apps and WPT both read
            // it) even though the internal channel carries no payload.
            var wrapped = function (payload) {
              if (payload && typeof payload === 'object' && payload.type) return fn.call(self, payload);
              fn.call(self, { type: name, target: self, currentTarget: self,
                              bubbles: false, cancelable: false, isTrusted: true });
            };
            fn._wrapped = wrapped;
            ev.on(name, wrapped);
          }
        },
      });
    })(_evNames[ei]);
  }

  // ── onicecandidate / onicecandidateerror ──
  //
  // These need to wrap the raw payload emitted by connection_manager in the
  // appropriate W3C event class so listeners see a proper event object
  // (with .type, etc.) — matching browser behavior. We add a permanent
  // internal listener that forwards wrapped events to the user's handler.
  ev.on('icecandidate', function (payload) {
    // W3C timing (WPT): onicecandidate observably fires AFTER the
    // setLocalDescription promise resolves — one macrotask of deferral.
    setImmediate(function () { _fireIceCandidate(payload); });
  });
  function _fireIceCandidate(payload) {
    // Stamp the ledger BEFORE the application callback runs, so a handler that
    // reads pc.localDescription synchronously already sees this candidate.
    // That ordering is what the spec describes and what WPT checks.
    _markCandidateDelivered(payload);
    if (!self._handlers.onicecandidate) return;
    // payload is either { candidate: null } (end-of-candidates) or
    // { candidate: '<string>', sdpMid, sdpMLineIndex }. Browser wraps this
    // in RTCPeerConnectionIceEvent whose .candidate is an RTCIceCandidate
    // (or null) — we do the same.
    var candidate = null;
    if (payload && payload.candidate) {
      candidate = new RTCIceCandidate({
        candidate:     payload.candidate,
        sdpMid:        payload.sdpMid,
        sdpMLineIndex: payload.sdpMLineIndex,
      });
    }
    self._handlers.onicecandidate(new RTCPeerConnectionIceEvent({ candidate: candidate }));
  }

  ev.on('icecandidateerror', function (payload) {
    if (!self._handlers.onicecandidateerror) return;
    // The constructor takes (type, init). Passing the payload as the FIRST
    // argument made it the event TYPE and left init empty, so every field
    // fell to its default: errorCode 0, url '', address and port null.
    //
    // The payload itself was always complete —
    // { url, errorText: 'STUN timeout', errorCode: 701, address, port } —
    // so an application configuring several STUN/TURN servers got one event
    // per failure carrying none of the information the event exists to
    // deliver: which server failed, and why.
    self._handlers.onicecandidateerror(
      new RTCPeerConnectionIceErrorEvent('icecandidateerror', payload || {}));
  });

  // ondatachannel — wraps internal channel → RTCDataChannel.
  //
  // TWIN OF THE 'track' ASYMMETRY (code-review finding #1): the wrapped
  // RTCDataChannelEvent used to reach ONLY the ondatachannel property;
  // addEventListener('datachannel') subscribers received the RAW internal
  // payload — wrong shape entirely. Fix mirrors 'track': build the W3C
  // event ONCE per channel, deliver to the property handler, and re-emit
  // on 'datachannel:wrapped' which addEventListener subscribes to (see
  // its special-casing, alongside icecandidate's).
  ev.on('datachannel', function(internal) {
    _diag('[api-diag] datachannel event received, self._handlers.ondatachannel=' + (self._handlers.ondatachannel ? 'set' : 'null') +
                ' channel=' + (internal && internal.channel && internal.channel.label));
    var wrapped = new RTCDataChannel(internal.channel, manager);
    var dcEvent = new RTCDataChannelEvent('datachannel', { channel: wrapped });
    if (self._handlers.ondatachannel) self._handlers.ondatachannel(dcEvent);
    ev.emit('datachannel:wrapped', dcEvent);
  });

  // ontrack — wraps manager's track:new into RTCTrackEvent
  ev.on('track:new', function(info) {
    _diag('[api-diag] track:new fired — mid=' + info.mid + ' kind=' + info.kind);

    // Ensure the transceiver wrapper exists. Its _receiver was created at
    // construction time with the (then-null) track; we now inject the real
    // track and let the pipeline start.
    var transceiver = _tcCache(info.transceiver);
    transceiver._receiver._setTrack(info.track);

    _diag('[api-diag] track:new — self._handlers.ontrack=' + (self._handlers.ontrack ? 'set' : 'null') +
                ' transceiver._receiver.track=' + (transceiver._receiver.track ? 'set' : 'null'));

    // Build the W3C event UNCONDITIONALLY — it serves both registration
    // styles. Previously it was built only when the ontrack PROPERTY was
    // set, and only the property was called; addEventListener('track')
    // subscribed to an ev channel named 'track' that nothing ever
    // emitted — listeners silently received no events, ever. Third
    // member of the wrapped-event asymmetry family (icecandidate and
    // icecandidateerror were fixed earlier); found live when sfu-server
    // (which deliberately uses addEventListener to avoid clobbering
    // stable-webrtc's ontrack property) never saw any producers.
    //
    // streams: per W3C §5.1 step 8, the array of MediaStreams the
    // remote sender associated with this track via msid (or the
    // empty array if none). Skip nullish entries from cm.js's
    // info.stream (single-stream channel).
    var trackStreams = [];
    if (info.streamsAnnounced) trackStreams = info.streamsAnnounced.slice();
    else if (info.stream) trackStreams.push(info.stream);
    else if (Array.isArray(info.streams)) {
      for (var ts = 0; ts < info.streams.length; ts++) {
        if (info.streams[ts]) trackStreams.push(info.streams[ts]);
      }
    }
    var trackEvent = new RTCTrackEvent({
      track:       info.track,
      receiver:    transceiver._receiver,
      transceiver: transceiver,
      streams:     trackStreams,
    });

    if (self._handlers.ontrack) self._handlers.ontrack(trackEvent);
    // addEventListener('track', fn) listeners — same event object,
    // browser parity: both styles fire, each exactly once.
    ev.emit('track', trackEvent);
  });

  // Renegotiation observability: one line when the flag fires. Placed at
  // the api layer so a dropped-by-engine event is distinguishable from a
  // never-fired one (the M1 debugging sessions needed exactly this).
  ev.on('negotiationneeded', function() {
    _diag('[api-diag] negotiationneeded fired');
  });


  // ── Transceiver wrapper cache ──

  // Keyed by the internal transceiver OBJECT, not by mid.
  //
  // mid is not a usable identity. It is null before association, and the
  // JSEP §5.10 adoption path in connection_manager.js reassigns it outright
  // (`_rt.mid = m.mid`). Two transceivers can legitimately hold the same mid
  // for a moment: when addTrack races an in-flight setRemoteDescription of a
  // sendonly offer, the addTrack transceiver carries a provisional mid while
  // the sRD-created one is the associated owner of that same mid.
  //
  // Keyed by mid, _tcCache then handed BOTH of them the same wrapper, so
  // getTransceivers() reported two entries that were really one object —
  // both claiming the same mid, both reporting a track when only one had
  // one. Object identity is stable for the transceiver's whole lifetime and
  // has none of these problems.
  var _tcMap = new Map();
  function _tcCache(internal) {
    var existing = _tcMap.get(internal);
    if (existing) return existing;
    var w = new RTCRtpTransceiver(internal, manager);
    _tcMap.set(internal, w);
    return w;
  }


  // ── negotiationneeded auto-fire (W3C §4.7.2) ──
  //
  // The firing machinery itself lives in cm.js (manager.updateNegotiationNeededFlag).
  // api.js call sites that mutate SDP-relevant state (addTrack, removeTrack,
  // addTransceiver, createDataChannel, transceiver.direction =, .stop(),
  // setCodecPreferences) call manager.updateNegotiationNeededFlag(), which
  // handles debouncing across a microtask, defers the event while
  // signalingState !== 'stable', and re-fires once we return to stable.
  //
  // Step 4 will replace the simple debounce in cm.js with the full W3C
  // checkIfNegotiationIsNeeded algorithm; api.js call sites stay the same.


  // ── SDP Negotiation ──

  // ── SDP Negotiation ──
  //
  // The manager's createOffer/createAnswer/setLocalDescription/
  // setRemoteDescription/addIceCandidate are async (Promise-returning) and
  // run through the operations chain (W3C §4.3.3). api.js holds only W3C
  // surface validation that's purely about argument shape — state-machine
  // checks (closed PC, wrong signalingState, missing remoteDescription)
  // live in cm.js so they observe committed state at chain-execution time.

  impl.createOffer = function (options) {
    // Synchronous preconditions (W3C 4.4.1), checked before the
    // operation is enqueued: a closed connection, and a signalingState
    // from which an offer cannot be produced. Only 'stable' (fresh
    // offer) and 'have-local-offer' (re-offer) are legal — offering from
    // have-remote-offer or a pranswer state is InvalidStateError.
    if (manager.state.closed) {
      return Promise.reject(new DOMException('peer connection is closed', 'InvalidStateError'));
    }
    // (state check lives inside the chained operation — see createAnswer)
    var self = this;
    // Legacy options (JSEP §5.1 / W3C legacy extensions):
    //   offerToReceiveX: true  → ensure at least one transceiver of that
    //     kind can receive (add a recvonly one if none exists).
    //   offerToReceiveX: false → strip the receive direction from every
    //     transceiver of that kind (sendrecv→sendonly, recvonly→inactive).
    // Old apps (pre-transceiver API) still pass these; Chrome honors
    // them, so we do too.
    if (options && (('offerToReceiveAudio' in options) || ('offerToReceiveVideo' in options))) {
      var kinds = [['offerToReceiveAudio', 'audio'], ['offerToReceiveVideo', 'video']];
      for (var ki = 0; ki < kinds.length; ki++) {
        var optName = kinds[ki][0], kind = kinds[ki][1];
        if (!(optName in options)) continue;
        var want = !!options[optName];
        var trs = self.getTransceivers().filter(function (t) {
          return t && !t.stopped && t.receiver && t.receiver.track &&
                 t.receiver.track.kind === kind;
        });
        if (want) {
          var canRecv = trs.some(function (t) {
            return t.direction === 'sendrecv' || t.direction === 'recvonly';
          });
          if (!canRecv) {
            try { self.addTransceiver(kind, { direction: 'recvonly' }); } catch (e) {}
          }
        } else {
          for (var ti = 0; ti < trs.length; ti++) {
            var t2 = trs[ti];
            try {
              if (t2.direction === 'sendrecv')      t2.direction = 'sendonly';
              else if (t2.direction === 'recvonly') t2.direction = 'inactive';
            } catch (e) {}
          }
        }
      }
    }
    return new Promise(function (resolve, reject) {
      manager.createOffer(options, function (err, desc) {
        if (err) reject(err); else resolve(desc);
      });
    });
  };

  impl.createAnswer = function (options) {
    // W3C 4.4.1: state preconditions are checked BEFORE the operation is
    // enqueued, so the rejection is observable without waiting for the
    // chain to turn (WPT's isOperationsChainEmpty helper distinguishes a
    // busy chain from an empty one exactly this way — a synchronous
    // InvalidStateError means "chain empty, state wrong").
    // NOTE: the state check is NOT done here. W3C 4.4.1 runs it inside
    // the queued operation, so it only surfaces "immediately" when the
    // chain happens to be EMPTY — which is precisely how WPT's
    // isOperationsChainEmpty probe distinguishes a busy chain from an
    // idle one. Checking before enqueuing made every probe report
    // "empty" and broke six chain tests.
    return new Promise(function (resolve, reject) {
      manager.createAnswer(options, function (err, desc) {
        if (err) reject(err); else resolve(desc);
      });
    });
  };

  impl.setLocalDescription = function (desc) {
    // W3C §4.4.1.5 — type enum validation. Rollback is an unimplemented
    // sub-feature (ROADMAP QUICK-3); reject explicitly so apps see a clear
    // failure rather than silent misbehavior. Implicit form (no args) is
    // delegated to cm.js's setLocalDescription.
    if (desc && desc.type != null) {
      var validTypes = ['offer', 'answer', 'pranswer', 'rollback'];
      if (validTypes.indexOf(desc.type) < 0) {
        return Promise.reject(new TypeError(
          'setLocalDescription: invalid type "' + desc.type + '"'));
      }
      if (desc.type === 'rollback') {
        return new Promise(function (resolve, reject) {
          manager.rollback('local', function (err) {
            if (err) reject(err); else resolve();
          });
        });
      }
      // pranswer is a valid W3C type but our SOA._commitDescription only
      // models 'offer' and 'answer' transitions (W3C §4.3.2). The pranswer
      // ↔ have-X-pranswer states + the eventual final 'answer' transition
      // out of pranswer aren't implemented. Reject explicitly so apps see
      // a clear failure rather than the silent state-machine corruption
      // they'd get from forwarding (pranswer would be parsed as answer
      // and transition to 'stable' incorrectly). Document as a known
      // limitation in ROADMAP item 26.
    }
    return new Promise(function (resolve, reject) {
      manager.setLocalDescription(desc, function (err, result) {
        if (err) reject(err); else resolve(result);
      });
    });
  };

  impl.setRemoteDescription = function (desc) {
    // Required argument per spec — no implicit form (unlike setLocal).
    if (!desc) {
      return Promise.reject(new TypeError(
        'setRemoteDescription: description is required'));
    }
    if (desc.type != null) {
      var validTypesR = ['offer', 'answer', 'pranswer', 'rollback'];
      if (validTypesR.indexOf(desc.type) < 0) {
        return Promise.reject(new TypeError(
          'setRemoteDescription: invalid type "' + desc.type + '"'));
      }
      if (desc.type === 'rollback') {
        return new Promise(function (resolve, reject) {
          manager.rollback('remote', function (err) {
            if (err) reject(err); else resolve();
          });
        });
      }
      // See setLocalDescription pranswer reject above for the rationale.
    }
    return new Promise(function (resolve, reject) {
      manager.setRemoteDescription(desc, function (err, result) {
        if (err) reject(err); else resolve(result);
      });
    });
  };


  // ── ICE ──

  impl.addIceCandidate = function (candidate) {
    // Tolerate the SDP line form: apps (and WPT) sometimes pass
    // "a=candidate:..." straight out of an SDP blob. RFC 5245 writes the
    // attribute with that prefix, so stripping it is what every browser
    // does rather than rejecting a string the user copied verbatim.
    if (candidate && typeof candidate === 'object' && typeof candidate.candidate === 'string' &&
        candidate.candidate.indexOf('a=') === 0) {
      candidate = Object.assign({}, candidate, { candidate: candidate.candidate.slice(2) });
    }
    // W3C 4.4.2: addressing first — a non-end-of-candidates entry with
    // neither sdpMid nor sdpMLineIndex is a TypeError regardless of what
    // its candidate string contains. (0 is a valid sdpMLineIndex, so
    // absence is tested with != null, not falsiness.)
    if (candidate && typeof candidate === 'object' && candidate.candidate) {
      if (candidate.sdpMid == null && candidate.sdpMLineIndex == null) {
        return Promise.reject(new TypeError(
          'addIceCandidate: candidate must specify sdpMid or sdpMLineIndex'));
      }
    }
    // W3C §4.4.1.10 — surface validation only. State-dependent checks
    // (closed PC, no remoteDescription) live in cm.js so they observe
    // the committed state at chain-execution time, not at call time.

    // Normalize: legacy string form is accepted by wrapping.
    if (typeof candidate === 'string') {
      candidate = { candidate: candidate };
    }

    var isEndOfCandidates = (
      candidate == null ||
      candidate.candidate == null ||
      candidate.candidate === ''
    );
    // (The "requires a remote description" rule lives INSIDE the chained
    // operation — see connection_manager's addIceCandidate. Checking it
    // here, at call time, is wrong: two WPT cases need both answers from
    // the same code. After an explicit rollback with an idle chain there
    // is no remote description and it must REJECT; but during glare the
    // candidate queues behind the in-flight setRemoteDescription and by
    // the time it RUNS a remote description exists, so it must RESOLVE.
    // Only a check evaluated at run time gives both.)
    // W3C: a NON-empty candidate string that fails the candidate grammar
    // rejects with OperationError (the strict parser already exists for
    // RTCIceCandidate; reuse it here instead of the lenient pass-through).
    if (!isEndOfCandidates && typeof candidate.candidate === 'string') {
      try {
        var _probe = new RTCIceCandidate({ candidate: candidate.candidate, sdpMid: candidate.sdpMid != null ? candidate.sdpMid : '0' });
        if (_probe.foundation == null && _probe.port == null) {
          return Promise.reject(new DOMException('addIceCandidate: malformed candidate string', 'OperationError'));
        }
      } catch (ePr) {
        return Promise.reject(new DOMException('addIceCandidate: malformed candidate string', 'OperationError'));
      }
    }
    // ORDER (W3C 4.4.2, and two WPT cases that disagree unless it is
    // explicit): ADDRESSING is validated before the candidate STRING.
    // A candidate with neither sdpMid nor sdpMLineIndex is a TypeError
    // even when its string is also garbage — the garbage only becomes an
    // OperationError once the candidate is addressable at all.



    return new Promise(function (resolve, reject) {
      manager.addIceCandidate(candidate, function (err, result) {
        if (err) {
          // Map unbranded cm.js errors to spec-compliant OperationError.
          if (!err.name) err.name = 'OperationError';
          reject(err);
        } else {
          resolve(result);
        }
      });
    });
  };

  impl.restartIce = function() {
    // W3C 4.4.1: restartIce() on a closed connection is a NO-OP (not an
    // error), and before the FIRST negotiation there is nothing to
    // restart — the initial offer will carry fresh ICE credentials
    // anyway, so no negotiationneeded is fired.
    if (manager.state.closed) return;
    if (!manager.state.currentLocalDescription && !manager.state.pendingLocalDescription) return;
    // (A second closed-check used to sit here and throw InvalidStateError.
    // It was unreachable behind the no-op above, and it contradicted it —
    // whichever a reader saw first, they drew the wrong conclusion about
    // which behaviour is intended. WPT's own test is named "restartIce() has
    // no effect on a closed peer connection", so the no-op is correct and
    // the throw was the mistake.)
    manager.restartIce();
  };


  // ── Configuration ──

  /**
   * W3C §4.3.2 — validate + normalize RTCConfiguration.iceServers.
   * (WPT harvest: RTCConfiguration-iceServers.html encodes the exact
   * contract — this implements it verbatim.)
   *   undefined            → []
   *   null / non-sequence  → TypeError
   *   server null/not-dict → TypeError
   *   urls missing         → TypeError
   *   urls '' or []        → SyntaxError (DOMException-style name)
   *   url scheme not stun/stuns/turn/turns, or unparseable → SyntaxError
   *   turn/turns without BOTH username and credential → InvalidAccessError
   * Returns a frozen-shape normalized copy for getConfiguration echo.
   */
  function _validateIceServers(servers, ctxName) {
    if (servers === undefined) return [];
    if (servers === null || typeof servers[Symbol.iterator] !== 'function' ||
        typeof servers === 'string') {
      throw new TypeError(ctxName + ': iceServers must be a sequence');
    }
    var out = [];
    for (var i = 0; i < servers.length; i++) {
      var s = servers[i];
      if (s === null || typeof s !== 'object') {
        throw new TypeError(ctxName + ': iceServers[' + i + '] must be a dictionary');
      }
      var urls = s.urls;
      if (urls === undefined) {
        throw new TypeError(ctxName + ': iceServers[' + i + '].urls is required');
      }
      if (typeof urls === 'string') urls = [urls];
      else if (urls === null || typeof urls[Symbol.iterator] !== 'function') {
        throw new TypeError(ctxName + ': iceServers[' + i + '].urls must be a string or sequence');
      } else urls = Array.prototype.slice.call(urls);
      if (urls.length === 0) {
        throw new DOMException(ctxName + ': iceServers[' + i + '].urls is empty', 'SyntaxError');
      }
      var needsCreds = false;
      for (var u = 0; u < urls.length; u++) {
        var url = String(urls[u]);
        var m = /^(stun|stuns|turn|turns):([A-Za-z0-9._\-\[\]:]+?)(\?transport=(udp|tcp))?$/.exec(url);
        var hostOk = m && /^[A-Za-z0-9._\-\[\]]+(:\d+)?$/.test(m[2]) && !/^:/.test(m[2]) && !/^\d+$/.test(m[2].split(':')[0]) === false || m && /^[A-Za-z0-9._\-\[\]]+(:\d+)?$/.test(m[2]);
        if (!m || !m[2] || !/^[A-Za-z0-9._\-\[\]]+(:\d+)?$/.test(m[2]) || /\s/.test(url)) {
          throw new DOMException(ctxName + ': invalid ICE server url "' + url + '"', 'SyntaxError');
        }
        if (m[2].indexOf('@') !== -1) {
          throw new DOMException(ctxName + ': userinfo not allowed in ICE url "' + url + '"', 'SyntaxError');
        }
        var portM = /:(\d+)$/.exec(m[2]);
        if (portM && (+portM[1] > 65535)) {
          throw new DOMException(ctxName + ': port out of range in "' + url + '"', 'SyntaxError');
        }
        if ((m[1] === 'stun' || m[1] === 'stuns') && m[3]) {
          // ?transport= is turn-only syntax
          throw new DOMException(ctxName + ': stun urls take no query: "' + url + '"', 'SyntaxError');
        }
        if (m[1] === 'turn' || m[1] === 'turns') needsCreds = true;
        urls[u] = url;
      }
      if (needsCreds && (s.username === undefined || s.credential === undefined ||
                         s.credential === '')) {
        throw new DOMException(ctxName + ': turn server requires username and credential', 'InvalidAccessError');
      }
      // STUN attribute value limit (RFC 8489 §14.3: <= 509 bytes)
      if (needsCreds && (Buffer.byteLength(String(s.username || ''), 'utf8') > 509 ||
                         Buffer.byteLength(String(s.credential || ''), 'utf8') > 509)) {
        throw new DOMException(ctxName + ': turn credentials exceed 509 bytes', 'InvalidAccessError');
      }
      var entry = { urls: urls };
      if (s.username !== undefined) entry.username = String(s.username);
      if (s.credential !== undefined) entry.credential = String(s.credential);
      out.push(entry);
    }
    return out;
  }


  manager.state.iceServers = _normIceServers;
  manager.state._ctorCertificates = (config.certificates || []).slice();
  // Publish the RTCError constructor for lower layers (sdp_offer_answer
  // builds sdp-syntax-error rejections and cannot import api.js back).
  try { manager.state._RTCErrorCtor = RTCError; } catch (ePub) {}
  // Lower layers emit RTCErrorEvent too and cannot import it without a cycle.
  try { manager.state._RTCErrorEventCtor = RTCErrorEvent; } catch (ePub2) {}

  // WPT harvest — muted follows NEGOTIATED receive-ability too: after
  // every description apply, receiver tracks mute/unmute per the
  // transceiver's effective direction (no media required).
  manager.ev.on('signalingstatechange', function () {
    try {
      var ts = manager.state.transceivers || [];
      for (var mi = 0; mi < ts.length; mi++) {
        var it = ts[mi];
        var tr = it && it.receiver && it.receiver.track;
        if (!tr) continue;
        var d = it.currentDirection || it.direction || '';
        var recv = d === 'sendrecv' || d === 'recvonly';
        if ((d === 'sendrecv' || d === 'sendonly') && it.sender) it.sender._everSentDir = true;
        // NEGOTIATION ALONE DOES NOT UNMUTE. W3C 5.3: a remote track is muted
        // while no media is being received, and it is born muted. Being able
        // to receive is not the same as receiving — the SDP says the peer
        // MAY send, not that anything has arrived.
        //
        // Unmuting here made every receiver track report muted === false the
        // instant setRemoteDescription resolved, before a single packet
        // existed. WPT checks the initial state directly ('track is muted
        // after SRD') and also inside ontrack.
        //
        // The unmute now happens where media actually arrives — see the
        // first-packet path in connection_manager. Muting on a direction that
        // can no longer receive stays here, because that IS a negotiated fact.
        if (!recv && tr.muted === false) {
          tr.muted = true;
          try { tr.dispatchEvent && tr.dispatchEvent({ type: 'mute' }); } catch (u2) {}
        }
      }
    } catch (eSync) {}
  });

  impl.getConfiguration = function() {
    // Returns the current RTCConfiguration. Per W3C §4.4.1.3, this
    // round-trips every field the app passed to setConfiguration or the
    // constructor. Fields whose enforcement is incomplete (bundlePolicy
    // 'balanced'/'max-compat' — see TODO at top of constructor — and
    // iceCandidatePoolSize pre-gathering) are still echoed so reads
    // match writes.
    return {
      iceServers:             manager.state.iceServers,
      iceTransportPolicy:     manager.state.iceTransportPolicy,
      bundlePolicy:           manager.state.bundlePolicy,
      rtcpMuxPolicy:          manager.state.rtcpMuxPolicy || 'require',
      iceCandidatePoolSize:   manager.state.iceCandidatePoolSize || 0,
      certificates:           manager.state._certificates || [],
      mode:                   manager.state.mode,
    };
  };

  impl.setConfiguration = function(newConfig) {
    // W3C: setConfiguration REPLACES the configuration — members omitted
    // from the new dictionary revert to their DEFAULTS (they do not
    // inherit the previous values).
    if (newConfig && typeof newConfig === 'object') {
      if (newConfig.iceTransportPolicy === undefined) newConfig = Object.assign({}, newConfig, { iceTransportPolicy: 'all' });
      if (newConfig.iceTransportPolicy === null || (newConfig.iceTransportPolicy !== 'all' && newConfig.iceTransportPolicy !== 'relay')) {
        if (newConfig.iceTransportPolicy !== 'all') throw new TypeError('setConfiguration: invalid iceTransportPolicy');
      }
    }
    if (newConfig == null) return;
    // W3C §4.4.1.4 — setConfiguration. Three classes of checks:
    //   1. Connection state: closed PCs reject (InvalidStateError).
    //   2. Immutable fields: bundlePolicy / rtcpMuxPolicy / certificates
    //      can't be changed after construction (InvalidModificationError
    //      if the new value differs from the current one).
    //   3. Enum/range validation: same as constructor, but raises errors
    //      with the spec-required name (TypeError).

    if (manager.state.closed) {
      var eClosed = new DOMException('setConfiguration: peer connection is closed', 'InvalidStateError');
      throw eClosed;
    }

    // Enum validation — same rules as constructor.
    if (newConfig.iceTransportPolicy != null &&
        newConfig.iceTransportPolicy !== 'all' &&
        newConfig.iceTransportPolicy !== 'relay') {
      throw new TypeError('setConfiguration: invalid iceTransportPolicy "' +
        newConfig.iceTransportPolicy + '" (expected "all" or "relay")');
    }
    if (newConfig.bundlePolicy != null &&
        newConfig.bundlePolicy !== 'balanced' &&
        newConfig.bundlePolicy !== 'max-bundle' &&
        newConfig.bundlePolicy !== 'max-compat') {
      throw new TypeError('setConfiguration: invalid bundlePolicy "' +
        newConfig.bundlePolicy + '"');
    }
    if (newConfig.rtcpMuxPolicy !== undefined && newConfig.rtcpMuxPolicy !== 'require') {
      throw new TypeError('setConfiguration: invalid rtcpMuxPolicy "' +
        newConfig.rtcpMuxPolicy + '" (only "require" is supported)');
    }
    if (newConfig.iceCandidatePoolSize != null) {
      var pool = newConfig.iceCandidatePoolSize;
      if (typeof pool !== 'number' || !isFinite(pool) || pool < 0 || pool > 255 ||
          Math.floor(pool) !== pool) {
        throw new TypeError('setConfiguration: iceCandidatePoolSize must be ' +
          'an integer in [0, 255], got ' + pool);
      }
    }

    // Immutable-field checks (only after enum validation, so the more
    // specific error wins on a doubly-invalid input).
    var _bpEff = (newConfig.bundlePolicy === undefined) ? 'balanced'
               : newConfig.bundlePolicy;
    if (_bpEff !== (manager.state.bundlePolicy || 'balanced')) {
      var e1 = new DOMException('setConfiguration: bundlePolicy cannot be changed after construction', 'InvalidModificationError');
      throw e1;
    }
    if (newConfig.rtcpMuxPolicy != null &&
        newConfig.rtcpMuxPolicy !== (manager.state.rtcpMuxPolicy || 'require')) {
      var e2 = new DOMException('setConfiguration: rtcpMuxPolicy cannot be changed after construction', 'InvalidModificationError');
      throw e2;
    }
    // (the old unconditional certificates rejection lived here — it made
    // the deep comparison below DEAD CODE and broke the spec's
    // echo-same-certificates-succeeds case; removed.)

    // Apply mutable fields.
    // W3C: setConfiguration REPLACES the whole dictionary — an absent
    // iceServers member means "no servers", not "keep current".
    // W3C: certificates cannot change after construction.
    if (newConfig.certificates !== undefined) {
      var prevCerts = (manager.state._ctorCertificates || []);
      var nextCerts = newConfig.certificates || [];
      var certsSame = prevCerts.length === nextCerts.length &&
        prevCerts.every(function (c, ci) { return c === nextCerts[ci]; });
      if (!certsSame) {
        throw new DOMException('setConfiguration: certificates cannot be modified', 'InvalidModificationError');
      }
    }
    manager.state.iceServers = _validateIceServers(newConfig.iceServers, 'setConfiguration');
    // Per W3C 4.4.1.4, iceTransportPolicy changes take effect on the next
    // ICE gathering round — the running IceAgent keeps its current policy
    // until a restart happens.
    //
    // But the change itself is what REQUIRES that restart (W3C 4.3.2: an
    // altered policy sets [[NeedsIceRestart]]). Storing the value without
    // setting the flag meant the next createOffer reused the same ufrag and
    // gathered under the old policy — so `setConfiguration({
    // iceTransportPolicy: 'relay' })` silently kept using host candidates,
    // and an application that switched to relay for privacy or firewall
    // reasons never actually did.
    if (newConfig.iceTransportPolicy) {
      var _oldPolicy = manager.state.iceTransportPolicy || 'all';
      manager.state.iceTransportPolicy = newConfig.iceTransportPolicy;
      if (newConfig.iceTransportPolicy !== _oldPolicy &&
          typeof manager.restartIce === 'function') {
        manager.restartIce();
      }
    }
    if (typeof newConfig.iceCandidatePoolSize === 'number') {
      // Stored for getConfiguration round-trip. Pool pre-gathering is a
      // latency optimization; we don't currently implement the pool, but
      // honoring the field lets the app's reads match its writes.
      // TODO: actual pre-gathering pool.
      manager.state.iceCandidatePoolSize = newConfig.iceCandidatePoolSize;
    }
  };


  // ── Tracks & Transceivers ──

  impl.addTrack = function(track /*, ...streams */) {
    // W3C §5.1.2 — addTrack signature is (track, ...streams). The variadic
    // streams group senders together so the remote peer's RTCTrackEvent
    // can present them as a single MediaStream. We collect them but the
    // underlying msid SDP plumbing is deferred (see ROADMAP QUICK-1+2),
    // so for now we just stash them on the sender wrapper for later.
    var streams = [];
    for (var si = 1; si < arguments.length; si++) {
      if (arguments[si]) streams.push(arguments[si]);
    }

    if (manager.state.closed) {
      var closedErr = new DOMException('addTrack: peer connection is closed', 'InvalidStateError');
      throw closedErr;
    }
    if (!track) throw new TypeError('addTrack: track is required');

    // W3C §5.1.2 step 1: if track is already associated with one of the
    // senders on this connection, throw InvalidAccessError. Apps that
    // legitimately want the same track on multiple senders should use
    // a separate transceiver / clone the track first.
    for (var ai = 0; ai < manager.state.transceivers.length; ai++) {
      var atc = manager.state.transceivers[ai];
      if (atc.sender && atc.sender.track === track &&
          atc.currentDirection !== 'stopped' && atc.direction !== 'stopped') {
        var dupErr = new DOMException('addTrack: track is already part of this connection', 'InvalidAccessError');
        throw dupErr;
      }
    }

    var kind = track.kind || 'video';

    // W3C §5.1.2 step 4 — before creating a new transceiver, scan existing
    // ones for a match. Spec requires reuse when ALL of the following hold:
    //   • transceiver's kind matches track.kind
    //   • transceiver.sender.track is null
    //   • transceiver is NOT stopped
    //   • (spec also says "[[Sender]].[[SenderTrack]] is null" explicitly —
    //      we check sender.track)
    //
    // This prevents redundant m-sections when the app first received a
    // remote track (creating a recvonly transceiver) and then wants to
    // send one back on the same transceiver (promoting it to sendrecv).
    var reused = null;
    for (var ti = 0; ti < manager.state.transceivers.length; ti++) {
      var tc = manager.state.transceivers[ti];
      if (tc.kind !== kind) continue;
      if (tc.sender && tc.sender.track) continue;
      // DUAL-MODE REUSE (the spinner saga): the spec's used-to-send rule
      // and the field mute pattern (removeTrack then addTrack expecting
      // the SAME transceiver back) contradict on an identical call
      // shape. Default = FIELD (reuse — engines and apps depend on it;
      // a duplicated m-line renders as a spinning tile). The WPT runner
      // sets WEBRTC_SPEC_STRICT_REUSE=1 to measure the spec behavior.
      // The long-term idiomatic fix for engines is replaceTrack(null)
      // for mute — no renegotiation at all.
      // DUAL-MODE, and the reasoning is now sharper than when this was
      // first written. W3C 5.1 says a sender that has SENT is never
      // recycled; the field mute pattern (removeTrack then addTrack,
      // expecting the SAME transceiver back) needs exactly that recycling
      // and breaks four regression legs without it — a duplicated m-line
      // renders as a spinning tile. Field behaviour stays the default;
      // WEBRTC_SPEC_STRICT_REUSE=1 selects the spec rule. The idiomatic
      // fix for engines is replaceTrack(null) for mute, which needs no
      // renegotiation at all and sidesteps the conflict entirely.
      if (process.env.WEBRTC_SPEC_STRICT_REUSE === '1' &&
          tc.sender && tc.sender._everSentDir) continue;
      if (RtpManager.isStopped(tc)) continue;
      reused = tc;
      break;
    }

    var internal;
    if (reused) {
      internal = reused;
      // THE APPLICATION HAS CLAIMED THIS TRANSCEIVER. Rollback keeps a
      // remote-created transceiver only if addTrack() adopted it — WPT
      // pins this down precisely: replaceTrack() on an SRD-created
      // transceiver still leaves it removable, while addTrack() followed
      // by replaceTrack(null) keeps it. So the criterion is the ADOPTION
      // ACT, not whether a track happens to be attached right now, which
      // is what round 99 checked.
      internal._appAdopted = true;
      internal.sender.track = track;
      // Promote direction to include send. 'recvonly' → 'sendrecv';
      // 'inactive' → 'sendonly'. Leave 'sendrecv'/'sendonly' alone.
      if (internal.direction === 'recvonly') internal.direction = 'sendrecv';
      else if (internal.direction === 'inactive') internal.direction = 'sendonly';
    } else {
      internal = manager.addTransceiver(kind, {
        direction: 'sendrecv',
        // WPT/behavior: the real stream ids ride the SDP msid so the far
        // side reconstructs streams with MATCHING ids.
        sendEncodings: undefined,
        streamIds: streams.length ? streams.map(function (s) { return s.id; }) : undefined,
      });
      internal.sender.track = track;
    }
    if (streams.length && internal && !internal.streamIds) {
      internal.streamIds = streams.map(function (s) { return s.id; });
    }

    // Fetch (or build) the public transceiver wrapper. Cache by transceiver so
    // multiple getSenders() calls return the same object identity.
    //
    // ONE TRANSCEIVER, ONE SENDER, FOR ITS WHOLE LIFETIME (W3C §5.4). The
    // wrapper's constructor builds the sender; addTrack retargets it. It must
    // NOT build a second one.
    //
    // It used to. `_tcCache` constructs RTCRtpTransceiver, whose constructor
    // constructs an RTCRtpSender, whose constructor calls startPipeline() —
    // and `internal.sender.track` is already set by both branches above, so
    // that first pipeline came up live. The line here then built a SECOND
    // sender over the same transceiver, starting a second pipeline on the
    // same SSRC. The orphaned first sender kept transmitting: two sequence
    // counters, one SSRC, interleaved on the wire. SRTP could not decrypt
    // roughly half of it. See FINDINGS.md.
    //
    // The old `if (reused && ...) _stop()` guard cleaned up only the reuse
    // path, which is why the new-transceiver path leaked a live sender.
    var tcWrapper = _tcCache(internal);
    if (typeof tcWrapper._sender._attachTrack === 'function') {
      tcWrapper._sender._attachTrack(track);
    } else {
      // Defensive: a wrapper built before this hook existed.
      if (typeof tcWrapper._sender._stop === 'function') {
        try { tcWrapper._sender._stop(); } catch (e) {}
      }
      tcWrapper._sender = new RTCRtpSender(internal, track, manager);
    }
    // Stash streams for setStreams() / getStreams() — until QUICK-1+2 lands
    // these don't propagate to SDP, but they survive on the sender.
    if (streams.length) tcWrapper._sender._streams = streams.slice();
    manager.updateNegotiationNeededFlag();
    return tcWrapper._sender;
  };

  impl.removeTrack = function(sender) {
    // W3C §5.1.3 — removeTrack steps:
    //   • If sender is not part of this connection, throw InvalidAccessError.
    //   • If sender's transceiver is stopped, no-op.
    //   • Set sender.track = null.
    //   • Update direction:
    //       sendrecv → recvonly
    //       sendonly → inactive
    //       (recvonly/inactive unchanged)
    //   • Tear down the active send pipeline.
    //   • Fire negotiationneeded.
    if (manager.state.closed) {
      var closedErrR = new DOMException('removeTrack: peer connection is closed', 'InvalidStateError');
      throw closedErrR;
    }
    if (!sender || !sender._internal) return;
    var internal = sender._internal;

    // InvalidAccessError if this sender is from a different PC.
    var found = false;
    for (var ti = 0; ti < manager.state.transceivers.length; ti++) {
      if (manager.state.transceivers[ti] === internal) { found = true; break; }
    }
    if (!found) {
      var err = new DOMException('removeTrack: sender is not part of this connection', 'InvalidAccessError');
      throw err;
    }
    // No-op on stopped transceivers.
    if (RtpManager.isStopped(internal)) return;
    // Only fire negotiationneeded if something actually changed.
    var changed = false;
    if (internal.sender.track !== null) {
      internal.sender.track = null;
      changed = true;
    }
    if (internal.direction === 'sendrecv' || internal.direction === 'sendonly') {
      // W3C: removeTrack SUBTRACTS the send capability only —
      // sendrecv->recvonly, sendonly->inactive, receive-only unchanged.
      internal.direction = internal.direction === 'sendrecv' ? 'recvonly' : 'inactive';
      changed = true;
    } else if (internal.direction === 'sendonly') {
      internal.direction = 'inactive';
      changed = true;
    }
    // Tear down send pipeline — _stop was installed on the sender wrapper
    // in RTCRtpSender constructor for exactly this purpose.
    if (typeof sender._stop === 'function') {
      try { sender._stop(); } catch (e) {}
    }
    if (changed) manager.updateNegotiationNeededFlag();
  };

  impl.addTransceiver = function(kindOrTrack, init) {

    if (manager.state.closed) {
      var closedErr = new DOMException('addTransceiver: peer connection is closed', 'InvalidStateError');
      throw closedErr;
    }
    // init.streams handling deferred — see ROADMAP item QUICK-1+2 and
    // QUICK-1-2-PLAN.md. Multi-msid SDP support is required for full
    // spec compliance and turned out to be size M (touches sdp.js,
    // connection_manager.js, and api.js). The ignore here is documented:
    // until QUICK-1+2 lands, init.streams is silently dropped (matches
    // current behavior; tests that rely on streams would already fail).
    //
    // init.sendEncodings is plumbed through to connection_manager, which
    // builds per-layer state (see addTransceiverInternal).
    var kind = typeof kindOrTrack === 'string' ? kindOrTrack : (kindOrTrack && kindOrTrack.kind) || 'video';
    var track = typeof kindOrTrack === 'string' ? null : kindOrTrack;

    // W3C §4.4.1.7 step 1: if first arg is a string, it must be 'audio'
    // or 'video'. Anything else (including 'application' or '') is
    // a TypeError.
    if (typeof kindOrTrack === 'string' && kind !== 'audio' && kind !== 'video') {
      throw new TypeError('addTransceiver: kind must be "audio" or "video", got "' + kind + '"');
    }

    // Validate init.direction enum (if provided).
    if (init && init.direction != null) {
      var validDirs = ['sendrecv', 'sendonly', 'recvonly', 'inactive'];
      if (validDirs.indexOf(init.direction) < 0) {
        throw new TypeError('addTransceiver: invalid direction "' + init.direction + '"');
      }
    }

    // W3C §4.4.1.7 + §5.2 — sendEncodings validation.
    //   • RangeError on maxFramerate < 0 or scaleResolutionDownBy < 1
    //   • TypeError on bad rid: invalid format, mixed presence, duplicates
    //   • InvalidAccessError if a non-rid read-only param is set (we
    //     don't have any read-only ones in our model so this is N/A)
    if (init && init.sendEncodings && Array.isArray(init.sendEncodings)) {
      // WPT harvest — encoding.codec must exist in the sender's
      // capabilities for this kind; otherwise OperationError.
      var kindCaps = null;
      try { kindCaps = RTCRtpSender.getCapabilities(kind); } catch (eC) {}
      for (var ci0 = 0; ci0 < init.sendEncodings.length; ci0++) {
        var reqC = init.sendEncodings[ci0] && init.sendEncodings[ci0].codec;
        if (reqC == null) continue;
        var okC = kindCaps && (kindCaps.codecs || []).some(function (c) {
          return c.mimeType.toLowerCase() === String(reqC.mimeType || '').toLowerCase() &&
                 c.clockRate === reqC.clockRate &&
                 (c.channels || undefined) === (reqC.channels || undefined) &&
                 ((c.sdpFmtpLine || undefined) === (reqC.sdpFmtpLine || undefined) ||
                  reqC.sdpFmtpLine === undefined);
        });
        if (!okC) {
          throw new DOMException('addTransceiver: encoding codec not supported', 'OperationError');
        }
      }
      var encs = init.sendEncodings;
      var seenRids = {};
      // AUDIO vs VIDEO members (two WPT files, one precise rule):
      //   • rid IS validated for BOTH kinds — syntax, length and
      //     uniqueness all throw TypeError even on audio;
      //   • VIDEO-ONLY members (scaleResolutionDownBy, maxFramerate) are
      //     silently DROPPED on audio, never range-checked;
      //   • audio then collapses to a single { active } encoding.
      // The collapse therefore happens AFTER the validation loop below.
      var _audioKind = (kind === 'audio');
      var anyRid = false;
      var allRid = true;
      for (var ei = 0; ei < encs.length; ei++) {
        var enc = encs[ei] || {};
        // Same shared rule as setParameters (encodingRangeProblem); audio
        // carries neither member, so it is exempt here.
        if (!_audioKind) {
          var _encBad = RtpManager.encodingRangeProblem(enc);
          if (_encBad === 'framerate') {
            throw new RangeError('addTransceiver: encoding maxFramerate must be >= 0');
          }
          if (_encBad === 'scale') {
            throw new RangeError('addTransceiver: encoding scaleResolutionDownBy must be >= 1');
          }
        }
        if (enc.rid != null) {
          anyRid = true;
          // One rid rule, in rtp_transmission_manager — see ridProblem. It is
          // ENFORCED here, at the API boundary, so both kinds reject before
          // any kind-specific collapsing happens; only the wording of the
          // error belongs to this layer.
          var _ridBad = RtpManager.ridProblem(enc.rid);
          if (_ridBad === 'length') {
            throw new TypeError('addTransceiver: rid must be at most ' +
              RtpManager.RID_MAX_LENGTH + ' characters');
          }
          if (_ridBad === 'syntax') {
            throw new TypeError('addTransceiver: invalid rid "' + enc.rid +
              '" (must match [A-Za-z0-9]{1,32})');
          }
          if (seenRids[enc.rid]) {
            throw new TypeError('addTransceiver: duplicate rid "' + enc.rid + '"');
          }
          seenRids[enc.rid] = true;
        } else {
          allRid = false;
        }
      }
      // audio collapse (see the rule above)
      if (_audioKind) {
        // audio keeps `active` AND `maxBitrate`; only rid,
        // scaleResolutionDownBy and maxFramerate are video-only.
        // One implementation, in rtp_transmission_manager. This rebuild used
        // to be written out here as well as twice there, and all three copies
        // dropped the codec pin — see the note on collapseAudioEncodings.
        encs = RtpManager.collapseAudioEncodings(encs);
        init = Object.assign({}, init, { sendEncodings: encs });
      }
      // Spec: rid must be on all or none.
      if (anyRid && !allRid) {
        throw new TypeError('addTransceiver: rid must be present on all encodings or none');
      }
    }

    var internal = manager.addTransceiver(kind, init);
    // CREATED BY THE APPLICATION, WITH ITS OWN INTENT.
    //
    // W3C 4.4.1.6 pairs a remote m-section only with a transceiver that has
    // never been associated AND was not created by addTransceiver — an
    // application that asked for its own audio transceiver expects to keep
    // it, and the peer's section to get one of its own.
    //
    // We had no way to tell the two apart, so any unassociated same-kind
    // transceiver absorbed the peer's section. The reuse the engine relies on
    // is a DIFFERENT case: those transceivers are created internally, not
    // through this call, so they carry no flag and still pair.
    if (internal) internal._appCreated = true;
    if (track) internal.sender.track = track;
    manager.updateNegotiationNeededFlag();
    return _tcCache(internal);
  };

  impl.getSenders = function() {
    var result = [];
    for (var i = 0; i < manager.state.transceivers.length; i++) {
      // Stopped transceivers keep exposing their sender/receiver until
      // the m-section is retired — the same rule getTransceivers()
      // follows, and what apps holding a sender across a stop expect.
      result.push(_tcCache(manager.state.transceivers[i]).sender);
    }
    return result;
  };

  impl.getReceivers = function() {
    var result = [];
    for (var i = 0; i < manager.state.transceivers.length; i++) {
      // Stopped transceivers keep exposing their sender/receiver until
      // the m-section is retired — the same rule getTransceivers()
      // follows, and what apps holding a sender across a stop expect.
      result.push(_tcCache(manager.state.transceivers[i]).receiver);
    }
    return result;
  };

  impl.getTransceivers = function() {
    // W3C 4.4.1 / 5.4: getTransceivers() returns EVERY transceiver in
    // [[Transceivers]], INCLUDING stopped ones — a stopped transceiver
    // keeps its slot (direction 'stopped', receiver.transport null) and
    // only leaves the list when the m-section is recycled by a later
    // negotiation. Filtering them out here shifted every later index and
    // made a stopped transceiver simply vanish from the application's
    // view mid-session.
    var result = [];
    for (var i = 0; i < manager.state.transceivers.length; i++) {
      result.push(_tcCache(manager.state.transceivers[i]));
    }
    return result;
  };


  // ── DataChannel ──

  impl.createDataChannel = function(label, options) {
    // WebIDL coercions (WPT harvest): label is USVString — null → "null",
    // undefined (when the arg WAS passed) → "undefined", lone surrogates →
    // U+FFFD. A truly missing argument throws (required parameter).
    if (arguments.length === 0) {
      throw new TypeError('createDataChannel: label argument required');
    }
    label = String(label).replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD');
    options = options != null ? options : {};

    // W3C §6.2: createDataChannel on a closed PC throws InvalidStateError.
    if (manager.state.closed) {
      throw new DOMException('createDataChannel: peer connection is closed', 'InvalidStateError');
    }
    // dictionary member coercion: undefined → default; anything else →
    // ToBoolean / ToNumber per WebIDL (null is NOT undefined!).
    var _o = options;
    // WebIDL [EnforceRange] unsigned short: negatives and values > 65535
    // throw TypeError at the binding layer (WPT enforce-range files).
    var _rangeCheck = function (v, name) {
      if (v === undefined || v === null) return;
      var n = Number(v);
      if (!isFinite(n) || n < 0 || n > 65535 || Math.floor(n) !== n) {
        throw new TypeError('createDataChannel: ' + name + ' value ' + v + ' is out of [EnforceRange] unsigned short range');
      }
    };
    _rangeCheck(_o.maxPacketLifeTime, 'maxPacketLifeTime');
    _rangeCheck(_o.maxRetransmits,  'maxRetransmits');
    // `id` is an [EnforceRange] unsigned short too — it was exempt, so
    // -1 and 65536 were accepted and then coerced silently (>>> 0 turns
    // -1 into 4294967295), producing a channel with an id no peer can
    // ever match. The range belongs at the binding layer, before the
    // negotiated/ignored decision below.
    _rangeCheck(_o.id, 'id');
    if (_o.maxPacketLifeTime !== undefined && _o.maxRetransmits !== undefined) {
      throw new TypeError('createDataChannel: maxPacketLifeTime and maxRetransmits are mutually exclusive');
    }
    // WPT harvest — id range
    if (_o.id !== undefined && _o.id !== null && !_o.negotiated) {
      // W3C: without negotiated:true the id member is IGNORED — the
      // in-band DCEP allocator owns the stream id.
      _o = Object.assign({}, _o); delete _o.id; options = _o;
    }
    if (_o.id !== undefined && _o.id !== null) {
      var _idV = _o.id >>> 0;
      if (_idV === 65535) {
        // WPT: 65535 is the wire 'unset' marker - succeed with no id.
        _o = Object.assign({}, _o); delete _o.id; options = _o;
      } else if (_idV > 65534) {
        throw new TypeError('createDataChannel: id must be <= 65534');
      }
    }
    options = {
      ordered:           _o.ordered === undefined ? true : !!_o.ordered,
      maxPacketLifeTime: _o.maxPacketLifeTime === undefined ? null : (_o.maxPacketLifeTime >>> 0),
      maxRetransmits:    _o.maxRetransmits === undefined ? null : (_o.maxRetransmits >>> 0),
      protocol:          _o.protocol === undefined ? '' :
        String(_o.protocol).replace(/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/g, '\uFFFD'),
      negotiated:        _o.negotiated === undefined ? false : !!_o.negotiated,
      id:                _o.id,
      priority:          _o.priority,
    };

    // W3C §6.2 validation:
    //   • label length must be <= 65535 bytes UTF-8
    //   • protocol length must be <= 65535 bytes UTF-8
    //   • if negotiated=true, id MUST be provided (in-range 0..65534)
    //   • if id is provided, must be 0..65534 (stream 65535 is reserved)
    //   • maxRetransmits and maxPacketLifeTime are mutually exclusive
    //     (W3C says SyntaxError DOMException — *not* TypeError)
    //   • duplicate id → OperationError DOMException
    if (label && Buffer.byteLength(String(label), 'utf-8') > 65535) {
      throw new TypeError('createDataChannel: label too long (max 65535 UTF-8 bytes)');
    }
    if (options.protocol && Buffer.byteLength(String(options.protocol), 'utf-8') > 65535) {
      throw new TypeError('createDataChannel: protocol too long (max 65535 UTF-8 bytes)');
    }
    if (options.id != null) {
      // WebIDL `unsigned short` CONVERTS, it does not type-check. A member
      // declared unsigned short accepts anything that converts to an integer
      // in range — `id: '17'` is 17, and W3C's own transfer-datachannel test
      // passes exactly that. Requiring typeof 'number' rejected a value the
      // IDL calls valid, so an application reading an id out of JSON or a URL
      // parameter got a TypeError for a number it had spelled correctly.
      //
      // Range is still enforced below, and anything that does not convert to
      // a finite integer — '', true, 'abc' — still fails, as the IDL says.
      if (typeof options.id === 'string' && options.id.trim() !== '' &&
          isFinite(Number(options.id))) {
        options = Object.assign({}, options, { id: Number(options.id) });
      }
      if (typeof options.id !== 'number' || Math.floor(options.id) !== options.id ||
          options.id < 0 || options.id > 65534) {
        // W3C §6.2: id == 65535 is a TypeError (out of permitted range
        // even though it's a valid uint16). 0..65534 are accepted.
        throw new TypeError('createDataChannel: id must be in range 0..65534');
      }
      // Spec: if id is already used by another DataChannel on this PC,
      // throw OperationError. Scan existing channels.
      var existing = manager.state.dataChannels || [];
      for (var di = 0; di < existing.length; di++) {
        if (existing[di] && existing[di].id === options.id &&
            existing[di].readyState !== 'closed') {
          var inUseErr = new DOMException('createDataChannel: id ' + options.id + ' is already in use', 'OperationError');
          throw inUseErr;
        }
      }
    }
    if (options.negotiated === true && options.id == null) {
      // Spec requires id when negotiated=true — the whole point of
      // out-of-band is the app chose the id.
      throw new TypeError('createDataChannel: negotiated=true requires an explicit id');
    }
    if (typeof options.maxRetransmits === 'number' &&
        typeof options.maxPacketLifeTime === 'number') {
      // W3C §6.2 explicitly says SyntaxError, not TypeError.
      var syntErr = new DOMException('createDataChannel: maxRetransmits and maxPacketLifeTime are mutually exclusive', 'SyntaxError');
      throw syntErr;
    }
    if (options.priority != null) {
      var validPriorities = ['very-low', 'low', 'medium', 'high'];
      if (validPriorities.indexOf(options.priority) < 0) {
        throw new TypeError('createDataChannel: invalid priority "' + options.priority +
          '" (expected one of "very-low", "low", "medium", "high")');
      }
    }

    var internal = manager.createDataChannel(label, options);
    // Per W3C §4.7.2, creating the first DataChannel requires an m=application
    // section in SDP; subsequent channels reuse it. We unconditionally invoke
    // updateNegotiationNeededFlag, and the W3C checkIfNegotiationIsNeeded
    // algorithm inside it correctly suppresses the fire for the second-and-later
    // channels (since current local description already has m=application).
    manager.updateNegotiationNeededFlag();
    return new RTCDataChannel(internal, manager);
  };


  // ── Stats ──

  impl.getStats = function(selector) {
    // W3C 8.2: getStats() is ASYNCHRONOUS and does NOT use the
    // operations chain — it must still be pending after a microtask
    // (WPT asserts exactly that), so the report is assembled on the
    // next task rather than handed back in the same turn.
    // ...but the SELECTOR check is synchronous: a selector that is not
    // one of this connection's senders/receivers is InvalidAccessError
    // right away (W3C 8.2 step 2), before the async report assembly.
    var _sel = arguments[0];
    if (_sel != null) {
      // Compare against the PUBLIC lists — those are the objects the
      // application actually holds, and they include senders/receivers
      // of stopped transceivers.
      var _known = false;
      try {
        var _sn = impl.getSenders(), _rc = impl.getReceivers();
        for (var _si = 0; _si < _sn.length; _si++) if (_sn[_si] === _sel) { _known = true; break; }
        if (!_known) for (var _ri = 0; _ri < _rc.length; _ri++) if (_rc[_ri] === _sel) { _known = true; break; }
        // legacy shape: a track belonging to one of them
        if (!_known) {
          for (var _s2 = 0; _s2 < _sn.length; _s2++) if (_sn[_s2] && _sn[_s2].track === _sel) { _known = true; break; }
          if (!_known) for (var _r2 = 0; _r2 < _rc.length; _r2++) if (_rc[_r2] && _rc[_r2].track === _sel) { _known = true; break; }
        }
      } catch (eSel) { _known = true; }   // never fail closed on an internal error
      if (!_known) {
        return Promise.reject(new DOMException(
          'getStats: selector is not a sender or receiver of this connection',
          'InvalidAccessError'));
      }
      // AMBIGUOUS SELECTOR (W3C 8.2): a track attached to BOTH a sender
      // and a receiver on this connection does not identify which stats
      // are wanted, so it is InvalidAccessError rather than a guess. We
      // resolved it to whichever list matched first and silently returned
      // half the answer.
      var _selIsTrack = !!(_sel && _sel.kind && !_sel.getParameters);
      if (_selIsTrack) {
        var _inSenders = false, _inReceivers = false;
        try {
          var _sl = impl.getSenders(), _rl = impl.getReceivers();
          for (var _si2 = 0; _si2 < _sl.length; _si2++) if (_sl[_si2] && _sl[_si2].track === _sel) { _inSenders = true; break; }
          for (var _ri2 = 0; _ri2 < _rl.length; _ri2++) if (_rl[_ri2] && _rl[_ri2].track === _sel) { _inReceivers = true; break; }
        } catch (eA) {}
        if (_inSenders && _inReceivers) {
          return Promise.reject(new DOMException(
            'getStats: track is associated with both a sender and a receiver',
            'InvalidAccessError'));
        }
      }
    }
    var _gsArgs = arguments, _gsSelf = this;
    return new Promise(function (res, rej) {
      setTimeout(function () {
        try { res(_getStatsNow.apply(_gsSelf, _gsArgs)); } catch (e) { rej(e); }
      }, 0);
    });
  };
  function _getStatsNow(selector) {
    // W3C §8.2 (WPT): a track selector must belong to EXACTLY ONE
    // sender or receiver of this connection.
    if (selector != null) {
      var _selMatches = 0;
      var _ts = manager.state.transceivers || [];
      for (var _si = 0; _si < _ts.length; _si++) {
        if (_ts[_si].sender && _ts[_si].sender.track === selector) _selMatches++;
        if (_ts[_si].receiver && _ts[_si].receiver.track === selector) _selMatches++;
      }
      if (_selMatches !== 1) {
        return Promise.reject(new DOMException(
          'getStats: selector track must belong to exactly one sender or receiver', 'InvalidAccessError'));
      }
    }
    // Per W3C webrtc-stats spec, `selector` is a MediaStreamTrack (or null).
    //   - null/undefined     → stats for the entire connection
    //   - a MediaStreamTrack → stats for the sender or receiver that owns it
    //
    // We resolve the track → its SSRC by scanning transceivers, then pass
    // the ssrc down to _buildStatsReport as an internal filter.
    //
    // Shape of each entry follows https://w3c.github.io/webrtc-stats/ —
    // field names and semantics match the browser so user code can port
    // between Node and browser without changes.
    //
    // Legacy callback-based form (deprecated & removed from Chrome in M120,
    // never supported by Firefox) is not implemented.

    // A CLOSED CONNECTION STILL ANSWERS. The old "reject with
    // InvalidStateError" rule was dropped from the spec, and the sender
    // form is explicit about it ("should work with a closed
    // PeerConnection but not have outbound-rtp objects"). Rejecting was
    // a field hazard: every dashboard polls getStats on a timer, and the
    // poll that lands just after the user hangs up became an unhandled
    // rejection rather than a final, empty report.
    if (manager.state.closed) {
      return Promise.resolve(new Map());
    }

    var filter = null;   // { ssrc } or null

    if (selector && typeof selector === 'object') {
      var tr = manager.state.transceivers;
      for (var i = 0; i < tr.length; i++) {
        if (tr[i].sender   && tr[i].sender.track   === selector && tr[i].sender.ssrc != null) {
          filter = { ssrc: tr[i].sender.ssrc };
          break;
        }
        if (tr[i].receiver && tr[i].receiver.track === selector) {
          // For an inbound track, find its primary (non-RTX) remote SSRC.
          var map = manager.state.remoteSsrcMap;
          for (var k in map) {
            if (Object.prototype.hasOwnProperty.call(map, k) &&
                map[k].mid === tr[i].mid && !map[k].isRtx) {
              filter = { ssrc: parseInt(k, 10) };
              break;
            }
          }
          // remoteSsrcMap is learned from arriving packets, so it is empty
          // until the first one lands. Falling through with filter === null
          // returned an EMPTY report for a receiver that plainly exists — the
          // caller asked about a specific track and was told nothing at all.
          // An application reads getStats(track) as soon as the track unmutes,
          // which is inside that window.
          //
          // Mark the receiver instead: _buildStatsReport then emits its
          // zeros-valued inbound-rtp, the same way receiver.getStats() does
          // (fix 12). Once packets arrive the SSRC branch above takes over.
          // Always carry the mid alongside. remoteSsrcMap is learned from
          // arriving packets, but the per-SSRC COUNTERS are populated
          // separately — so an SSRC can be known while no inbound-rtp entry
          // exists for it yet. Filtering on that SSRC alone then returned a
          // report with no inbound-rtp at all, for a receiver the caller had
          // just asked about by name.
          //
          // The mid lets the builder fall back to a zeros entry when the SSRC
          // produced none, the same way receiver.getStats() does (fix 12).
          if (!filter) filter = {};
          filter.receiverMid = tr[i].mid;
          break;
        }
      }
      // If selector didn't match any sender/receiver, per spec we resolve
      // with an empty stats report (not a rejection).
      if (!filter) return Promise.resolve(new Map());
    }

    return Promise.resolve(_buildStatsReport(manager, filter));
  };


  // ── Identity (rarely used) ──
  // Identity Provider integration (W3C webrtc-identity) is deferred
  // — see ROADMAP item API-6. Until then, getIdentityAssertion resolves
  // with empty string and setIdentityProvider is a no-op. peerIdentity
  // (above, in the configuration block) returns a Promise that stays
  // pending forever (per W3C §4.4.1.7), which is the correct shape for
  // apps that don't use IdP — they simply never await it.

  impl.getIdentityAssertion = function() {
    return Promise.resolve('');
  };

  impl.setIdentityProvider = function(provider, options) {
    // No-op until IdP support lands (API-6).
  };


  // ── Lifecycle ──

  impl.close = function() {
    // W3C §4.4.1.10: close() is a no-op on an already-closed PC.
    // manager.close() also guards on state.closed, but we want to skip
    // the per-transceiver pipeline teardown loop too — calling _stop()
    // twice on already-stopped pipelines would be wasted (try/catch
    // makes it safe, but skipping is cleaner and avoids spurious
    // "stopping already-stopped pipeline" log lines).
    if (manager.state.closed) return;
    // Stop every active send + receive pipeline (frees encoders, decoders,
    // depacketizers, jitter buffers, and the event subscriptions they hold).
    _tcMap.forEach(function (wrapper, internal) {
      if (wrapper && wrapper._sender && typeof wrapper._sender._stop === 'function') {
        try { wrapper._sender._stop(); } catch (e) {}
      }
      if (wrapper && wrapper._receiver && typeof wrapper._receiver._stop === 'function') {
        try { wrapper._receiver._stop(); } catch (e) {}
      }
      // W3C 4.4.1.7 step 4: closing the connection STOPS every transceiver.
      // Tearing down the pipelines is not the same thing — the application
      // still holds these objects, and they went on reporting their old
      // direction ('sendonly') on a connection that no longer exists.
      //
      // Same shape as transceiver.stop() (fix 25): direction and
      // currentDirection both read 'stopped', and the receiver track ends.
      // Unlike stop(), the ending is immediate — there is no negotiation
      // left to observe an intermediate state, and close() is where an
      // application expects everything to be finished.
      try {
        if (internal && typeof internal === 'object') {
          internal.direction        = 'stopped';
          internal.currentDirection = 'stopped';
          internal._stopped         = true;
        }
        var _cRt = wrapper && wrapper._receiver && wrapper._receiver.track;
        if (_cRt && _cRt.readyState !== 'ended') {
          if (typeof _cRt.stop === 'function') _cRt.stop();   // fires 'ended'
          else _cRt.readyState = 'ended';
        }
      } catch (eCl) { /* close() must never throw */ }
    });
    // DataChannels are closed by manager.close() — each dc transitions to
    // readyState 'closed' and fires its 'close' event. See cm.js close().
    manager.close();
  };

  // EventTarget surface. The browser's addEventListener accepts an
  // options object whose `once: true` causes the handler to fire at
  // most once and then auto-remove. We support that subset; capture/
  // passive are no-ops in Node (no DOM tree), and deduplication of
  // identical (type, fn, capture) tuples is not currently enforced —
  // listeners added twice run twice.
  impl.addEventListener = function(name, fn, options) {
    if (typeof fn !== 'function') return;
    // Browser parity: for icecandidate / icecandidateerror the handler
    // PROPERTY receives a wrapped W3C event object (RTCPeerConnectionIce-
    // Event / RTCPeerConnectionIceErrorEvent) — built by the dedicated
    // internal listeners above. addEventListener used to subscribe to the
    // raw internal channel and hand listeners the bare payload, so the
    // two registration styles saw DIFFERENT objects for the same event.
    // Wrap here too, so both styles match each other and the browser.
    var wrapped = fn;
    if (name === 'icecandidate') {
      wrapped = function (payload) {
        var candidate = null;
        if (payload && payload.candidate) {
          candidate = new RTCIceCandidate({
            candidate:     payload.candidate,
            sdpMid:        payload.sdpMid,
            sdpMLineIndex: payload.sdpMLineIndex,
          });
        }
        fn(new RTCPeerConnectionIceEvent({ candidate: candidate }));
      };
    } else if (name === 'icecandidateerror') {
      wrapped = function (payload) {
        // (type, init) — see the note on the on-handler path.
        fn(new RTCPeerConnectionIceErrorEvent('icecandidateerror', payload || {}));
      };
    } else if (name === 'datachannel') {
      // Subscribe to the WRAPPED channel; the wrapped event arrives
      // ready-made from the internal listener above. We keep fn's
      // signature (receives the RTCDataChannelEvent) and only redirect
      // the subscription target below.
      wrapped = function (dcEvent) { fn(dcEvent); };
    } else {
      // EVERY other pc event (signalingstatechange, connectionstatechange,
      // iceconnectionstatechange, icegatheringstatechange, negotiationneeded,
      // track…) was delivered with NO argument at all — listeners reading
      // `e.type` (WPT's EventWatcher does exactly that, and so does any
      // shared handler) saw undefined. Hand them a minimal Event-shaped
      // object, passing through anything the internal layer already built.
      wrapped = function (payload) {
        if (payload && typeof payload === 'object' && payload.type) return fn(payload);
        fn({ type: name, target: self, currentTarget: self,
             bubbles: false, cancelable: false, isTrusted: true });
      };
    }
    // removeEventListener contract: it receives the ORIGINAL fn, so keep
    // the original→wrapped mapping for lookup.
    if (wrapped !== fn) {
      if (!this._wrappedListeners) this._wrappedListeners = new Map();
      var perName = this._wrappedListeners.get(name);
      if (!perName) { perName = new Map(); this._wrappedListeners.set(name, perName); }
      perName.set(fn, wrapped);
    }
    // 'datachannel' subscriptions listen on the wrapped channel — the raw
    // channel carries the internal payload (see finding #1 above).
    var subName = (name === 'datachannel') ? 'datachannel:wrapped' : name;
    if (options && typeof options === 'object' && options.once) {
      ev.once(subName, wrapped);
    } else {
      ev.on(subName, wrapped);
    }
  };
  impl.removeEventListener = function(name, fn) {
    if (typeof fn !== 'function') return;
    var target = fn;
    if (this._wrappedListeners) {
      var perName = this._wrappedListeners.get(name);
      if (perName && perName.has(fn)) {
        target = perName.get(fn);
        perName.delete(fn);
      }
    }
    ev.off((name === 'datachannel') ? 'datachannel:wrapped' : name, target);
  };
  // dispatchEvent is part of EventTarget. The W3C spec says it returns
  // false if the event was canceled (preventDefault), true otherwise.
  // Our event objects are plain shapes (not real Event instances) and
  // none of our internal events are cancelable, so we always return true.
  // We forward to the EventEmitter so apps can synthesize and dispatch
  // events against the PC if they need to.
  impl.dispatchEvent = function(event) {
    if (!event || typeof event.type !== 'string') {
      throw new TypeError('dispatchEvent: event must have a string type');
    }
    ev.emit(event.type, event);
    return true;
  };


  // ── Internal access (for advanced usage / testing) ──

  this._manager = manager;
  this._ev = ev;

  return this;
}

// Static method
RTCPeerConnection.generateCertificate = function(keygenAlgorithm) {
  // W3C 4.9.1 validation, in order:
  //   • expires must be a NUMBER within an unsigned-long-long range —
  //     anything else (string, negative, non-finite) is a TypeError;
  //   • an algorithm we cannot honour (e.g. SHA-1 signatures, which
  //     modern DTLS forbids) is a NotSupportedError.
  if (keygenAlgorithm && typeof keygenAlgorithm === 'object' &&
      Object.prototype.hasOwnProperty.call(keygenAlgorithm, 'expires')) {
    var _exp = keygenAlgorithm.expires;
    if (typeof _exp !== 'number' || !isFinite(_exp) || _exp < 0 || _exp > 9007199254740991) {
      return Promise.reject(new TypeError('generateCertificate: expires must be a non-negative number'));
    }
  }
  if (keygenAlgorithm && typeof keygenAlgorithm === 'object' &&
      typeof keygenAlgorithm.hash === 'string' &&
      /^sha-?1$/i.test(keygenAlgorithm.hash)) {
    return Promise.reject(new DOMException(
      'generateCertificate: SHA-1 signatures are not supported', 'NotSupportedError'));
  }

  // W3C §4.10. Returns Promise<RTCCertificate>.
  // keygenAlgorithm — null/undefined defaults to ECDSA P-256.
  // Strings 'ECDSA' or 'RSASSA-PKCS1-v1_5' use defaults for that family.
  // Object form: { name, namedCurve?, modulusLength?, publicExponent?, hash? }
  // Invalid input rejects with NotSupportedError per spec.
  return import('./cert.js').then(function(mod) {
    try {
      var generated = mod.generateCertificate({ keygenAlgorithm: keygenAlgorithm });
      var cert = new RTCCertificate(generated);
      // W3C §4.10: an 'expires' member on the algorithm dict caps the
      // certificate lifetime (clamped to the UA default of one year).
      if (keygenAlgorithm && typeof keygenAlgorithm === 'object' &&
          typeof keygenAlgorithm.expires === 'number') {
        var capped = Math.min(keygenAlgorithm.expires, 31536000000);
        cert.expires = Date.now() + capped;
      }
      return cert;
    } catch (e) {
      // Translate cert.js's TypeError into the spec-mandated
      // NotSupportedError. Keep the message.
      var err = new DOMException(e && e.message || String(e), 'NotSupportedError');
      throw err;
    }
  });
};


/* ========================= RTCRtpSender ========================= */

// ── WebIDL prototype surface (delegating to the per-instance impl) ──
Object.defineProperty(RTCPeerConnection, 'length', { value: 0 });
// on* event-handler ATTRIBUTES on the prototype (WebIDL/WPT)
Object.defineProperty(RTCPeerConnection.prototype, 'ontrack', {
  get: function () { return (this._handlers && this._handlers.ontrack) || null; },
  set: function (fn) { if (this._handlers) this._handlers.ontrack = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'onicecandidate', {
  get: function () { return (this._handlers && this._handlers.onicecandidate) || null; },
  set: function (fn) { if (this._handlers) this._handlers.onicecandidate = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'onicecandidateerror', {
  get: function () { return (this._handlers && this._handlers.onicecandidateerror) || null; },
  set: function (fn) { if (this._handlers) this._handlers.onicecandidateerror = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'onsignalingstatechange', {
  get: function () { return (this._handlers && this._handlers.onsignalingstatechange) || null; },
  set: function (fn) { if (this._handlers) this._handlers.onsignalingstatechange = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'oniceconnectionstatechange', {
  get: function () { return (this._handlers && this._handlers.oniceconnectionstatechange) || null; },
  set: function (fn) { if (this._handlers) this._handlers.oniceconnectionstatechange = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'onicegatheringstatechange', {
  get: function () { return (this._handlers && this._handlers.onicegatheringstatechange) || null; },
  set: function (fn) { if (this._handlers) this._handlers.onicegatheringstatechange = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'onconnectionstatechange', {
  get: function () { return (this._handlers && this._handlers.onconnectionstatechange) || null; },
  set: function (fn) { if (this._handlers) this._handlers.onconnectionstatechange = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'onnegotiationneeded', {
  get: function () { return (this._handlers && this._handlers.onnegotiationneeded) || null; },
  set: function (fn) { if (this._handlers) this._handlers.onnegotiationneeded = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});
Object.defineProperty(RTCPeerConnection.prototype, 'ondatachannel', {
  get: function () { return (this._handlers && this._handlers.ondatachannel) || null; },
  set: function (fn) { if (this._handlers) this._handlers.ondatachannel = (typeof fn === 'function' ? fn : null); },
  configurable: true, enumerable: true,
});

var _IDL_LENGTHS = {"createOffer": 0, "createAnswer": 0, "setLocalDescription": 0, "setRemoteDescription": 1, "addIceCandidate": 0, "getConfiguration": 0, "setConfiguration": 0, "addTrack": 1, "removeTrack": 1, "addTransceiver": 1, "getTransceivers": 0, "getSenders": 0, "getReceivers": 0, "createDataChannel": 1, "close": 0, "getStats": 0, "restartIce": 0, "addEventListener": 2, "removeEventListener": 2, "dispatchEvent": 1, "setIdentityProvider": 1, "getIdentityAssertion": 0};

RTCPeerConnection.prototype.dispatchEvent = function () { return this._impl.dispatchEvent.apply(this, arguments); };
Object.keys(_IDL_LENGTHS).forEach(function (m) {
  if (RTCPeerConnection.prototype[m]) {
    Object.defineProperty(RTCPeerConnection.prototype[m], 'length', { value: _IDL_LENGTHS[m] });
    Object.defineProperty(RTCPeerConnection.prototype[m], 'name', { value: m });
  }
});
RTCPeerConnection.prototype.createOffer = function () {
  var self = this;
  var _p = this._impl.createOffer.apply(this, arguments);
  // Bookkeeping rides ALONGSIDE the promise (a .then that returns a new
  // promise would push a synchronous precondition rejection an extra
  // microtask out — WPT's chain-empty probe reads it after exactly one).
  _p.then(function (d) {
    var _stH = self._manager.state;
    _stH._offerHistory = (_stH._offerHistory || []);
    if (_stH._lastOffer && _stH._lastOffer.sdp) _stH._offerHistory.push(_stH._lastOffer.sdp);
    if (_stH._offerHistory.length > 6) _stH._offerHistory.shift();
    _stH._lastOffer = d;
  }, function () {});
  return _p;
};
RTCPeerConnection.prototype.createAnswer = function () {
  var self = this;
  var p = this._impl.createAnswer.apply(this, arguments);
  // Attach the bookkeeping WITHOUT inserting an extra microtask hop on the
  // rejection path: a synchronous precondition failure must stay
  // observable after a single microtask (WPT's chain-empty probe).
  p.then(function (d) { self._manager.state._lastAnswer = d; }, function () {});
  return p;
};
RTCPeerConnection.prototype.setLocalDescription = function (desc) {
  // W3C: a self-created offer that is not the LAST createOffer result
  // rejects InvalidModificationError. FIELD LESSON (stable-engine
  // breakage): the session-id fingerprint was too wide — engines
  // legitimately MUNGE the last offer before SLD. Reject ONLY an exact
  // match against a PREVIOUS (non-last) created offer; munged-current
  // and everything else is allowed.
  if (desc && desc.type === 'offer' && desc.sdp) {
    var _stL = this._manager && this._manager.state;
    var _lastO = _stL && _stL._lastOffer;
    var _hist = _stL && _stL._offerHistory;
    if (_hist && _lastO && desc.sdp !== _lastO.sdp && _hist.indexOf(desc.sdp) !== -1) {
      return Promise.reject(new DOMException(
        'setLocalDescription: offer is a stale (non-last) created offer', 'InvalidModificationError'));
    }
  }
  // W3C §4.4.1.4 (WPT): SLD with a type but no sdp substitutes the LAST
  // createOffer/createAnswer result for that type.
  // NO ARGUMENT AT ALL is the same case as {type} with no sdp (W3C
  // 4.4.1.4): both mean "apply what I last created". We only handled the
  // second form, so pc.setLocalDescription() built a BRAND NEW offer —
  // observably different from the one createOffer() had just returned
  // (a fresh o= session version), which breaks the documented
  // create-then-apply pattern and any code comparing the two.
  if (desc === undefined && this._manager && this._manager.state) {
    var _stP = this._manager.state;
    var _implied = (_stP.signalingState === 'have-remote-offer' ||
                    _stP.signalingState === 'have-local-pranswer') ? 'answer' : 'offer';
    if ((_implied === 'offer' && _stP._lastOffer) || (_implied === 'answer' && _stP._lastAnswer)) {
      desc = { type: _implied };
      arguments[0] = desc;
      arguments.length = 1;
    }
  }
  if (desc && typeof desc === 'object' && (desc.sdp == null || desc.sdp === '')) {
    // SUBSTITUTE LATE. The last-created description is looked up when the
    // operation RUNS, not when it is queued: the documented way to pack
    // the queue is
    //     await Promise.all([pc.createOffer(), pc.setLocalDescription({type:'offer'})])
    // and reading _lastOffer here — before the createOffer ahead of us in
    // the chain has produced it — found nothing and threw "missing sdp".
    // A thunk defers the lookup to the moment the description is needed.
    var _selfS = this;
    var _wanted = desc.type;
    arguments[0] = {
      type: _wanted,
      get sdp() {
        var st = _selfS._manager && _selfS._manager.state;
        var last = _wanted === 'offer' ? (st && st._lastOffer)
                 : (_wanted === 'answer' || _wanted === 'pranswer') ? (st && st._lastAnswer) : null;
        return (last && last.sdp) ? last.sdp : undefined;
      },
    };
  }
  return this._impl.setLocalDescription.apply(this, arguments);
};
RTCPeerConnection.prototype.setRemoteDescription = function () { return this._impl.setRemoteDescription.apply(this, arguments); };
RTCPeerConnection.prototype.addIceCandidate = function () { return this._impl.addIceCandidate.apply(this, arguments); };
RTCPeerConnection.prototype.getConfiguration = function () { return this._impl.getConfiguration.apply(this, arguments); };
RTCPeerConnection.prototype.setConfiguration = function () { return this._impl.setConfiguration.apply(this, arguments); };
RTCPeerConnection.prototype.addTrack = function () { return this._impl.addTrack.apply(this, arguments); };
RTCPeerConnection.prototype.removeTrack = function () { return this._impl.removeTrack.apply(this, arguments); };
RTCPeerConnection.prototype.addTransceiver = function () { return this._impl.addTransceiver.apply(this, arguments); };
RTCPeerConnection.prototype.getTransceivers = function () { return this._impl.getTransceivers.apply(this, arguments); };
RTCPeerConnection.prototype.getSenders = function () { return this._impl.getSenders.apply(this, arguments); };
RTCPeerConnection.prototype.getReceivers = function () { return this._impl.getReceivers.apply(this, arguments); };
RTCPeerConnection.prototype.createDataChannel = function (label) {
  if (arguments.length === 0) {
    throw new TypeError('createDataChannel: label argument required');
  }
  return this._impl.createDataChannel.apply(this, arguments);
};
Object.defineProperty(RTCPeerConnection.prototype.createDataChannel, 'length', { value: 1 });
RTCPeerConnection.prototype.close = function () { return this._impl.close.apply(this, arguments); };
RTCPeerConnection.prototype.getStats = function () { return this._impl.getStats.apply(this, arguments); };
RTCPeerConnection.prototype.restartIce = function () { return this._impl.restartIce.apply(this, arguments); };
RTCPeerConnection.prototype.addEventListener = function () { return this._impl.addEventListener.apply(this, arguments); };
RTCPeerConnection.prototype.removeEventListener = function () { return this._impl.removeEventListener.apply(this, arguments); };
RTCPeerConnection.prototype.setIdentityProvider = function () { return this._impl.setIdentityProvider.apply(this, arguments); };
RTCPeerConnection.prototype.getIdentityAssertion = function () { return this._impl.getIdentityAssertion.apply(this, arguments); };

function RTCRtpSender(internal, track, manager) {
  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  var self = this;
  this._internal = internal;
  this._manager = manager;
  // Node-stack extension (not in W3C): the sender's allocated SSRC(s).
  // createTransceiver allocates these at transceiver birth — even with
  // no track — but until now they were readable only on the INTERNAL
  // record; the wrapper exposed nothing, so external consumers (the SFU
  // reads sender.ssrc to learn the outgoing stream id for packet
  // injection) silently got undefined forever. Getter-backed so reads
  // always see the live allocation.
  Object.defineProperty(this, 'ssrc', {
    get: function() { return internal.sender.ssrc != null ? internal.sender.ssrc : null; },
  });
  Object.defineProperty(this, 'rtxSsrc', {
    get: function() { return internal.sender.rtxSsrc != null ? internal.sender.rtxSsrc : null; },
  });
  // W3C §5.2.2: sender.track reflects the currently associated track,
  // which can change via replaceTrack / removeTrack. Expose as a getter
  // backed by internal.sender.track so reads always see the live value.
  // Setter assigns through to internal — keeps the legacy code paths that
  // do `sender.track = newTrack` working (they propagate to internal).
  Object.defineProperty(this, 'track', {
    get: function() { return internal.sender.track || null; },
    set: function(v) {
      internal.sender.track = v || null;
    },
  });
  // Initial value (track arg may be passed at construction).
  if (track !== undefined) internal.sender.track = track || null;
  // W3C §5.2.6: sender.dtmf is an RTCDTMFSender for audio senders, null
  // for video. The DTMF sender is currently a stub — it stores tones in
  // toneBuffer but doesn't emit telephone-event RTP packets (see
  // ROADMAP API-3). The presence of the object on audio senders matches
  // what feature-detection code expects.
  this.dtmf = (internal.kind === 'audio')
    ? new RTCDTMFSender(function () { return pipeline; },
        function () { return !!(manager && manager.state && manager.state.closed); },
        function () {
          return {
            currentDirection: internal.currentDirection || null,
            direction: internal.direction || null,
          };
        })
    : null;
  // W3C webrtc-encoded-transform §3 — RTCRtpScriptTransform integration.
  // The transform property holds an app-provided RTCRtpScriptTransform
  // (which wraps a Worker that processes encoded frames). Setting it
  // installs a transform stage in the send pipeline; null removes it.
  //
  // Currently a settable stub — Worker-based transforms aren't wired
  // through media_pipeline.js yet. Apps that want to inspect/modify
  // encoded frames in-process should use createEncodedStreams() instead
  // (W3C webrtc-insertable-streams), which IS supported. The transform
  // field exists so feature-detection code (`'transform' in sender`)
  // works.
  // TODO (API-7?): wire RTCRtpScriptTransform into the pipeline.
  this.transform = null;
  // RTCDtlsTransport singleton per peer connection (created lazily in api.js).
  // Per spec, sender.transport is non-null only after the DTLS transport has
  // been established; we return it when available, null otherwise.
  Object.defineProperty(this, 'transport', {
    get: function() {
      // WPT/spec: transports come into existence when a LOCAL description
      // is applied (ICE gathering start) — null before, null again after
      // its rollback.
      if (!manager || !manager.state ||
          !(manager.state.pendingLocalDescription || manager.state.currentLocalDescription)) return null;
      return manager._getDtlsTransport ? manager._getDtlsTransport() : null;
    },
  });

  // Active send pipeline (encode → packetize → SRTP). Lives as long as the
  // sender has a non-null track. replaceTrack() rebuilds it; close() tears it
  // down. Works for both video and audio.
  var pipeline = null;

  // Current sender parameters — what we're configured to send. These are
  // returned verbatim by getParameters() and are updated by setParameters().
  // On setParameters, we push the new values into the pipeline via
  // pipeline.reconfigure() rather than rebuilding from scratch, so the
  // encoder retains any internal state (e.g. rate-control history).
  //
  // Seed encodings from internal.sender.encodings (the per-layer state
  // built by connection_manager.addTransceiverInternal). For non-simulcast
  // this is a single-element array; for simulcast it mirrors the
  // sendEncodings passed to addTransceiver.
  var currentParams = {
    transactionId: '',
    // WPT harvest: WebIDL member-absence semantics — an encoding carries
    // ONLY the members that were actually set (plus required defaults):
    // a default encoding is exactly { active: true }. Video encodings
    // additionally default scaleResolutionDownBy per spec when the app
    // provided sendEncodings.
    encodings: (internal.sender.encodings || [{}]).map(function (e, i, arr) {
      var enc = { active: e.active !== false };
      if (e.rid != null)                   enc.rid = String(e.rid);
      // ZERO IS A VALUE, not an absence: maxBitrate 0 and maxFramerate 0
      // are legal settings ("no frames"/"no bitrate"), and the > 0 test
      // reported them as unset — an app that set 0 read back undefined.
      if (e.maxBitrate != null)   enc.maxBitrate = e.maxBitrate;     // both kinds
      if (e.maxFramerate != null) enc.maxFramerate = e.maxFramerate;
      if (e.scalabilityMode != null)       enc.scalabilityMode = e.scalabilityMode;
      if (internal.kind === 'video' && e.scaleResolutionDownBy != null) {
        enc.scaleResolutionDownBy = e.scaleResolutionDownBy;
      }
      if (e.codec != null)                 enc.codec = Object.assign({}, e.codec);
      // NOTE: the old else-branch here SYNTHESISED a descending
      // scaleResolutionDownBy ladder (2^(n-1-i)) for any multi-encoding
      // video sender — it overwrote the app's real values with a
      // reversed ladder (an app asking for [{}, {scale:2}] read back
      // 2 then 1). Normalisation belongs in rtp_transmission_manager,
      // which fills the spec default of 1; the projection now reports
      // what is actually stored.
      return enc;
    }),
    headerExtensions: [],
    rtcp: { cname: manager.state.localCname, reducedSize: true },
    // WPT harvest: browsers expose send codecs immediately (pre-negotiation)
    // from static capabilities; tests assert codecs.length > 0 right after
    // addTransceiver.
    // W3C/WPT: sender codecs are EMPTY until SDP negotiation completes;
    // (codec.html's newer expectations conflict — documented paradox.)
    codecs: [],
  };

  // Published on the INTERNAL transceiver as well, so code that only ever
  // sees internal state — the description-apply path in sdp_offer_answer —
  // can invoke it without reaching for the public wrapper or duplicating the
  // both-copies knowledge that lives here.
  internal._dropPinsNotIn = function (keep) { return self._dropPinsNotIn(keep); };


  this._dropPinsNotIn = function (keep) {
    if (!keep) return false;
    var lower = keep.map(function (n) { return String(n).toLowerCase(); });
    var cleared = false;
    var lists = [currentParams && currentParams.encodings, internal.sender && internal.sender.encodings];
    for (var li = 0; li < lists.length; li++) {
      var encs = lists[li];
      if (!encs) continue;
      for (var ei = 0; ei < encs.length; ei++) {
        var pin = encs[ei] && encs[ei].codec;
        if (!pin || !pin.mimeType) continue;
        var want = SDP.codecName(pin);
        if (lower.indexOf(want.toLowerCase()) === -1) {
          delete encs[ei].codec;
          cleared = true;
        }
      }
    }
    return cleared;
  };

  function startPipeline() {
    // FIELD DIAG: the three reasons the send pipeline declines to start.
    // A silent bail here is indistinguishable from "never called", which
    // is exactly what made the round-80 hunt long — one line ends that.
    function _bail(why) {
      try {
        if (process.env.WEBRTC_DEBUG === '1' || process.env.WEBRTC_DEBUG === 'true') {
          console.log('[api-diag] startPipeline SKIPPED (' + why + ') mid=' +
            (internal.mid == null ? '?' : internal.mid) + ' kind=' + internal.kind +
            ' dir=' + internal.direction + '/' + (internal.currentDirection || '-'));
        }
      } catch (eB) {}
    }
    if (pipeline) return _bail('already running');
    if (!self.track) return _bail('no track on the sender');
    if (internal.sender.ssrc == null) return _bail('no ssrc allocated');

    // QUICK-8: source-frame counter for media-source.frames stat.
    // The pipeline owns the counting (it sees every frame anyway, in the
    // single-layer onFrame and the simulcast mainOnFrame). We pass an
    // onSourceFrame callback so the pipeline can tick our counter without
    // knowing anything about RTCRtpSender or the stats system.
    //
    // Stored on internal.sender so the stats builder (which sees only the
    // internal transceiver) can read it. Lazy-init so replaceTrack and
    // pipeline restarts don't reset the count — the counter is per-sender,
    // not per-pipeline.
    if (internal.sender._framesFromSource == null) {
      internal.sender._framesFromSource = 0;
    }
    var onSourceFrame = function () {
      internal.sender._framesFromSource++;
    };

    try {
      var enc = currentParams.encodings[0] || {};
      if (self.track.kind === 'video') {
        // Codec selection — best-effort until full SDP-driven negotiation
        // lands (Phase 1.5). The chain we walk:
        //   1. internal._codecPreferences[0] — if app called
        //      setCodecPreferences(), use the top preference. This is
        //      not strictly spec-correct (the browser picks from the
        //      *negotiated* intersection of local + remote, not from the
        //      app's preference list directly), but it gives apps a way
        //      to opt into VP9/H264/AV1 today without waiting for the
        //      full SDP plumbing.
        //   2. internal.negotiatedCodec — populated by cm.js after
        //      setRemoteDescription, once SDP-driven selection lands.
        //   3. fallback: 'vp8' (matches what the constructor / SDP
        //      currently announces).
        // The mimeType is video/<NAME>; we strip the prefix and let
        // media_pipeline.js uppercase it for VIDEO_CODECS lookup.
        var pickedCodec = 'vp8';
        // Field-shape note: W3C RTCRtpCodecCapability has .mimeType
        // ('video/VP8'); SDP-parsed codecs (the negotiatedCodec path)
        // have .name ('VP8'). Accept either shape on both branches.
        // Pre-fix this only checked .mimeType, so the negotiatedCodec
        // branch always fell through to the 'vp8' fallback (since
        // SDP-parsed codecs lack mimeType) — meaning every peer always
        // sent VP8 even when SDP negotiated H264/VP9. Receive side
        // (line ~2038) already reads .name correctly, so the bug was
        // one-sided.
        if (internal.negotiatedCodec) {
          if (internal.negotiatedCodec.mimeType) {
            pickedCodec = internal.negotiatedCodec.mimeType.replace(/^video\//i, '');
          } else if (internal.negotiatedCodec.name) {
            pickedCodec = internal.negotiatedCodec.name;
          }
        } else if (internal._codecPreferences && internal._codecPreferences.length) {
          var pref = internal._codecPreferences[0];
          if (pref && pref.mimeType) {
            pickedCodec = pref.mimeType.replace(/^video\//i, '');
          } else if (pref && pref.name) {
            pickedCodec = pref.name;
          }
        }
        // Branch on layer count. Single layer → classic pipeline; multi-layer
        // → simulcast wrapper (N encoders, shared track subscription).
        var layers = internal.sender.layers || [];

        // ── Register outbound streams with MediaTransport ──
        //
        // Publish per-SSRC codec metadata (clockRate, codecName) BEFORE the
        // pipeline starts emitting RTP. MediaTransport's RTCP SR builder
        // uses clockRate to extrapolate rtpTimestamp at SR-emission time
        // per RFC 3550 §6.4.1 — without this, SRs go out with rtpTimestamp=0
        // and receivers can't align audio↔video for lipsync.
        //
        // Idempotent across replaceTrack/renegotiation: registerOutboundStream
        // merges new metadata onto existing entries without resetting counters.
        // Both primary and RTX SSRCs are registered: RTX packets reuse the
        // primary's RTP timestamp per RFC 4588 §4, so their lastSentRtpTimestamp
        // is naturally consistent — but they need clockRate registered too
        // to extrapolate during their own SRs.
        var _codecKey = (pickedCodec || 'vp8').toLowerCase();
        var _codecMeta = _codecByName('video', _codecKey);

        // ── Resolve the negotiated payload type for outgoing RTP. ──
        // sender._negotiatedCodecs is populated by cm.js processRemoteMedia
        // when the remote description is applied (the offerer's primary
        // codec list, RTX filtered out, with offerer-provided PTs that
        // also become the answer's PTs per SDP.negotiateCodecs). Reading
        // it here keeps SDP-querying logic in cm.js / sdp.js where it
        // belongs and api.js as a thin W3C wrapper.
        //
        // Without the negotiated PT, we'd send RTP with libwebrtc's
        // default 96/97 — and Firefox (VP8=120) or any peer with
        // non-default PTs would silently drop every packet.
        //
        // Falls back to 96/97 if the field is absent — only happens on
        // the implicit-form race where sender starts before
        // setRemoteDescription has populated the codecs.
        var _negotiatedPt    = 96;
        var _negotiatedRtxPt = 97;
        var _negCodecs = internal.sender && internal.sender._negotiatedCodecs;
        if (_negCodecs && _negCodecs.length) {
          var _wanted = (pickedCodec || 'vp8').toLowerCase();
          for (var _ci = 0; _ci < _negCodecs.length; _ci++) {
            var _nc = _negCodecs[_ci];
            if (_nc && _nc.name && _nc.name.toLowerCase() === _wanted) {
              _negotiatedPt = _nc.payloadType;
              if (_nc.rtxPayloadType != null) _negotiatedRtxPt = _nc.rtxPayloadType;
              break;
            }
          }
        }

        if (_codecMeta && _codecMeta.clockRate) {
          for (var _li = 0; _li < layers.length; _li++) {
            var _ly = layers[_li];
            if (_ly.ssrc != null) {
              manager.registerOutboundStream(_ly.ssrc, {
                clockRate:   _codecMeta.clockRate,
                codecName:   pickedCodec,
                payloadType: _negotiatedPt,
              });
            }
            if (_ly.rtxSsrc != null) {
              manager.registerOutboundStream(_ly.rtxSsrc, {
                clockRate:   _codecMeta.clockRate,
                codecName:   pickedCodec,
                payloadType: _negotiatedRtxPt,
              });
            }
          }
        } else if (typeof console !== 'undefined' && console.warn) {
          // Unknown codec: SR will fall back to non-extrapolated last-sent
          // timestamp (off by ≤33ms at 30fps), which is still better than 0.
          // Worth surfacing because every new codec entry needs to be added
          // to _CODEC_MAP_VIDEO.
          console.warn('[RTCRtpSender] no clockRate registered for codec=' +
            pickedCodec + ' — SR rtpTimestamp will use fallback');
        }

        if (layers.length > 1) {
          // Build per-layer configs from currentParams.encodings (which mirrors
          // sender.encodings by index). Each layer config carries its own SSRC
          // + RTX SSRC from the transceiver's layer list.
          var layerCfgs = [];
          for (var li = 0; li < layers.length; li++) {
            var e = currentParams.encodings[li] || {};
            layerCfgs.push({
              rid:                   layers[li].rid,
              ssrc:                  layers[li].ssrc,
              rtxSsrc:               layers[li].rtxSsrc,
              maxBitrate:            e.maxBitrate || 0,
              maxFramerate:          e.maxFramerate || 0,
              scaleResolutionDownBy: e.scaleResolutionDownBy || 1,
              active:                e.active !== false,
              scalabilityMode:       e.scalabilityMode || null,
            });
          }
          // RTP seq continuity (replaceTrack flow): if a previous pipeline
          // ran and we captured per-rid lastSeq values, advance each by 1
          // and pass to the new pipeline so the wire shows a continuous
          // seq stream — matching libwebrtc's RtpSender::SetTrack.
          var initSeqs = null;
          if (internal.sender._lastSeqByRid) {
            initSeqs = {};
            for (var ridK in internal.sender._lastSeqByRid) {
              initSeqs[ridK] = (internal.sender._lastSeqByRid[ridK] + 1) & 0xFFFF;
            }
          }
          pipeline = createVideoSendSimulcastPipeline({
            track:         self.track,
            manager:       manager,
            payloadType:   _negotiatedPt,
            codec:         pickedCodec,
            layers:        layerCfgs,
            onSourceFrame: onSourceFrame,
            initialSequenceNumbers: initSeqs,
          });
        } else {
          // RTP seq continuity (replaceTrack flow). See simulcast branch.
          var initSeq = (internal.sender._lastSeqNumber != null)
                        ? ((internal.sender._lastSeqNumber + 1) & 0xFFFF)
                        : undefined;
          pipeline = createVideoSendPipeline({
            track:         self.track,
            manager:       manager,
            ssrc:          internal.sender.ssrc,
            payloadType:   _negotiatedPt,
            codec:         pickedCodec,
            maxBitrate:    enc.maxBitrate   || 0,
            maxFramerate:  enc.maxFramerate || 0,
            scaleResolutionDownBy: enc.scaleResolutionDownBy || 1,
            onSourceFrame: onSourceFrame,
            initialSequenceNumber: initSeq,
          });
        }
      } else if (self.track.kind === 'audio') {
        // Audio media-source has no `frames` field per W3C webrtc-stats,
        // so we don't pass onSourceFrame to the audio pipeline.
        var initSeqA = (internal.sender._lastSeqNumber != null)
                       ? ((internal.sender._lastSeqNumber + 1) & 0xFFFF)
                       : undefined;

        // Resolve the negotiated PT for Opus from sender._negotiatedCodecs
        // (populated by cm.js processRemoteMedia). Same architectural
        // boundary as the video branch: api.js reads the negotiated codec
        // list, doesn't query SDP itself. Without the lookup, hardcoded 111
        // would mismatch peers using different Opus PTs (Firefox uses 109,
        // some SIP gateways use 96, etc.) — peer would silently drop our
        // audio packets.
        var _negotiatedAudioPt = 111;
        var _negotiatedAudioCodec = null;
        var _audioNegCodecs = internal.sender && internal.sender._negotiatedCodecs;
        if (_audioNegCodecs && _audioNegCodecs.length) {
          for (var _aci = 0; _aci < _audioNegCodecs.length; _aci++) {
            var _anc = _audioNegCodecs[_aci];
            if (_anc && _anc.name && _anc.name.toLowerCase() === 'opus') {
              _negotiatedAudioPt = _anc.payloadType;
              _negotiatedAudioCodec = _anc;
              break;
            }
          }
        }

        // Register the outbound audio stream with MediaTransport so RTCP SR
        // can extrapolate rtpTimestamp using the codec's clockRate. The
        // current audio pipeline is Opus-only; the negotiated PT is read
        // from sender._negotiatedCodecs above.
        var _audioCodecMeta = _codecByName('audio', 'opus');
        if (_audioCodecMeta && internal.sender.ssrc != null) {
          manager.registerOutboundStream(internal.sender.ssrc, {
            clockRate:   _audioCodecMeta.clockRate,
            codecName:   'opus',
            payloadType: _negotiatedAudioPt,
          });
        }

        pipeline = createAudioSendPipeline({
          track:       self.track,
          manager:     manager,
          ssrc:        internal.sender.ssrc,
          payloadType: _negotiatedAudioPt,
          maxBitrate:  enc.maxBitrate || 0,
          initialSequenceNumber: initSeqA,
          // Negotiated RFC 7587 fmtp (useinbandfec/usedtx/…) → encoder,
          // and the RED PT (RFC 2198) when the peer negotiated one.
          fmtp:           _negotiatedAudioCodec ? _negotiatedAudioCodec.fmtp : null,
          redPayloadType: _negotiatedAudioCodec ? _negotiatedAudioCodec.redPayloadType : null,
          dtmfPayloadType: (function () {
            // RFC 4733: telephone-event PT from the negotiated set.
            if (!_audioNegCodecs) return null;
            for (var _di = 0; _di < _audioNegCodecs.length; _di++) {
              var _dc = _audioNegCodecs[_di];
              if (_dc && _dc.name && _dc.name.toLowerCase() === 'telephone-event') {
                return _dc.payloadType;
              }
            }
            return null;
          })(),
        });
      }
    } catch (e) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[RTCRtpSender] pipeline start failed:', e && e.message || e);
      }
    }
  }

  function stopPipeline() {
    if (!pipeline) return;
    // Capture last-emitted RTP seq (or per-layer Map for simulcast) so
    // the next pipeline can resume the same SSRC's seq counter without a
    // discontinuity. Matches libwebrtc's RtpSender::SetTrack behaviour:
    // the encoder + packetizer survive across track swaps; here we
    // recreate them but preserve the on-the-wire seq continuity, which
    // is what the peer's jitter buffer actually observes.
    try {
      if (typeof pipeline.getLastSequenceNumbers === 'function') {
        // Simulcast: returns { rid -> lastSeq }. Empty map = nothing
        // sent yet on any layer (no continuity to preserve).
        var byRid = pipeline.getLastSequenceNumbers();
        if (byRid && Object.keys(byRid).length) {
          internal.sender._lastSeqByRid = byRid;
        }
      } else if (typeof pipeline.getLastSequenceNumber === 'function') {
        // Single-layer: returns 16-bit seq, or null if no packets sent.
        var ls = pipeline.getLastSequenceNumber();
        if (ls != null) internal.sender._lastSeqNumber = ls;
      }
    } catch (e) { /* never let stats throw out of stopPipeline */ }
    try { pipeline.stop(); } catch (e) {}
    pipeline = null;
  }

  // Auto-start on construction if everything's ready.
  startPipeline();

  // Listen for PLI/FIR from the remote peer. When one arrives for *our*
  // outbound SSRC, ask the video pipeline to emit a keyframe on the next
  // encoded frame. Without this, after any meaningful packet loss the
  // remote's decoder would stay stuck until our periodic keyframe interval.
  // Listen for PLI/FIR from the remote peer. When one arrives for *any*
  // of our outbound SSRCs (simulcast layers included), ask the pipeline
  // to emit a keyframe on the next frame. Without this, after any
  // meaningful packet loss the remote's decoder stays stuck until our
  // periodic keyframe interval.
  //
  // Simulcast nuance: a remote PLI targets a specific SSRC (= one layer).
  // We match against every layer's SSRC, and if the pipeline exposes
  // requestKeyFrameForRid (simulcast wrapper), we ask only that layer
  // to emit a keyframe — otherwise all layers emit (single-layer fallback).
  var _pliHandler = function (mediaSsrc) {
    var layers = internal.sender.layers || [];
    var matched = (mediaSsrc === internal.sender.ssrc);
    var matchedRid = null;
    if (!matched && layers.length) {
      for (var li = 0; li < layers.length; li++) {
        if (layers[li].ssrc === mediaSsrc) {
          matched = true;
          matchedRid = layers[li].rid;
          break;
        }
      }
    }
    if (!matched) return;
    if (!pipeline) return;
    if (matchedRid && typeof pipeline.requestKeyFrameForRid === 'function') {
      pipeline.requestKeyFrameForRid(matchedRid);
    } else if (typeof pipeline.requestKeyFrame === 'function') {
      pipeline.requestKeyFrame();
    }
  };
  manager.on('pli', _pliHandler);

  // Listen for simulcast-response reconciliation (RFC 8853). When the peer
  // answers our simulcast offer, connection_manager may disable layers the
  // peer rejected or paused — then emits this event so we can re-apply the
  // new active state to the live pipeline.
  var _encodingsUpdatedHandler = function (info) {
    if (!info || info.mid !== internal.mid) return;
    // The PARAMETER sync is not conditional on a pipeline.
    //
    // This handler does two things: mirror the negotiated encoding state into
    // currentParams (what getParameters returns), and push the new values at
    // the encoder. Only the second needs a live pipeline — but the early
    // return skipped both, so a sender with no track yet, or one whose track
    // was replaced with null, kept reporting encodings the answer had already
    // changed. A simulcast answer declining a layer is exactly that case.
    var _encsSrc = internal.sender.encodings || [];
    for (var _si = 0; _si < _encsSrc.length && _si < currentParams.encodings.length; _si++) {
      currentParams.encodings[_si].active = _encsSrc[_si].active !== false;
    }
    if (!pipeline) return;
    var encs = internal.sender.encodings || [];
    for (var i = 0; i < encs.length && i < currentParams.encodings.length; i++) {
      currentParams.encodings[i].active = encs[i].active !== false;
    }
    if (typeof pipeline.reconfigureLayer === 'function') {
      for (var ri = 0; ri < currentParams.encodings.length; ri++) {
        var er = currentParams.encodings[ri];
        try {
          pipeline.reconfigureLayer(er.rid, {
            maxBitrate:            er.maxBitrate   || 0,
            maxFramerate:          er.maxFramerate || 0,
            scaleResolutionDownBy: er.scaleResolutionDownBy || 1,
            active:                er.active !== false,
            scalabilityMode:       er.scalabilityMode || null,
          });
        } catch (e) { /* single-layer pipeline; ignore */ }
      }
    } else if (typeof pipeline.reconfigure === 'function') {
      var e = currentParams.encodings[0] || {};
      try {
        pipeline.reconfigure({
          maxBitrate:            e.maxBitrate   || 0,
          maxFramerate:          e.maxFramerate || 0,
          scaleResolutionDownBy: e.scaleResolutionDownBy || 1,
          active:                e.active !== false,
        });
      } catch (err) { /* best effort */ }
    }
  };
  manager.on('transceiver:encodings-updated', _encodingsUpdatedHandler);

  impl.replaceTrack = function(newTrack) {
    // Per W3C §5.2, replaceTrack does NOT trigger negotiationneeded even if
    // the new track has different dimensions — the sender quietly adapts.
    //
    // Validation per W3C §5.2 step 4 + MDN:
    //   1. PC closed → InvalidStateError
    //   2. Transceiver stopped → InvalidStateError
    //   3. newTrack.kind != sender.kind → TypeError
    //   4. (negotiation-required cases would be InvalidModificationError —
    //      we accept all kind-matching tracks because we re-negotiate
    //      lazily via the pipeline; encoded-track changes don't require
    //      SDP changes in our setup.)
    //   null newTrack is always allowed (= stop sending without removeTrack).

    if (manager && manager.state && manager.state.closed) {
      var closedErr = new DOMException('replaceTrack: peer connection is closed', 'InvalidStateError');
      return Promise.reject(closedErr);
    }
    if (RtpManager.isStopped(internal)) {
      var stoppedErr = new DOMException('replaceTrack: transceiver is stopped', 'InvalidStateError');
      return Promise.reject(stoppedErr);
    }
    if (newTrack && newTrack.kind && newTrack.kind !== internal.kind) {
      return Promise.reject(new TypeError(
        'replaceTrack: kind mismatch — sender kind is "' + internal.kind +
        '" but track kind is "' + newTrack.kind + '"'
      ));
    }
    // Same reason as the direction setter: a remotely created transceiver has
    // no SSRC until it becomes a sender, and an application may attach the
    // track before (or instead of) setting direction. Idempotent.
    RtpManager.ensureSendSsrc(manager.state, internal);
    stopPipeline();
    // self.track is a getter backed by internal.sender.track, so a
    // single assignment updates both views.
    // DUAL-MODE (field-fatal regression, round-78): W3C says the visible
    // swap lands when the promise resolves, and WPT checks exactly that.
    // But real engines read sender.track SYNCHRONOUSLY right after the
    // call (stable-webrtc's tcIsFree does) to decide which transceiver
    // is free — with a deferred swap they saw the transceiver as still
    // empty, so the send transceivers reached negotiation with NO TRACK
    // and the server transmitted nothing. Default = FIELD (synchronous);
    // the WPT runner sets WEBRTC_SPEC_ASYNC_REPLACETRACK=1.

    if (process.env.WEBRTC_SPEC_ASYNC_REPLACETRACK === '1') {
      return Promise.resolve().then(function () {
        internal.sender.track = newTrack;
        if (newTrack) startPipeline();   // the send pipeline MUST be kicked
      });
    }
    internal.sender.track = newTrack;
    // KICK THE SEND PIPELINE — round-78's early return orphaned this call
    // (unreachable code), so the track attached, directions negotiated
    // sendonly, and NOT ONE RTP PACKET was ever produced. Engines attach
    // via replaceTrack AFTER negotiation, so this is their only kick.
    if (newTrack) startPipeline();
    return Promise.resolve();
  };

  impl.setStreams = function(/* ...streams */) {
    // W3C 5.2: setStreams on a closed connection is InvalidStateError.
    if (manager.state.closed) {
      throw new DOMException('setStreams: peer connection is closed', 'InvalidStateError');
    }
    // W3C §5.2.5.5 — associates this sender with one or more MediaStreams.
    // The streams identify the track in the SDP via the msid attribute,
    // letting the remote PC group tracks into stream events.
    //
    // W3C 5.2: the streams are recorded on the transceiver and take
    // effect at the NEXT negotiation — setStreams itself never
    // renegotiates, it just changes what the following offer says. This
    // used to be a no-op that swallowed its arguments, so the wire kept
    // "a=msid:-" and a receiver could not group the track at all.
    var _ids = [];
    for (var _s = 0; _s < arguments.length; _s++) {
      var _st = arguments[_s];
      if (_st && _st.id) _ids.push(_st.id);
    }
    internal.streamIds = _ids;
    // Refresh the routing slot so an offer built before the next
    // negotiation-needed pass already carries the new msids.
    try {
      var _ls = manager.state.localSsrcs && manager.state.localSsrcs[internal.mid];
      if (_ls) {
        var _tid = (internal.sender && internal.sender.track && internal.sender.track.id) ||
                   (internal.kind + internal.mid);
        _ls.msid = ((_ids[0] || '-') + ' ' + _tid);
        _ls.msids = (_ids.length > 1) ? _ids.map(function (id) { return id + ' ' + _tid; }) : null;
      }
    } catch (eS) {}
    // The grouping changed, so the connection needs renegotiating.
    try { manager.updateNegotiationNeededFlag(); } catch (eN) {}
    return undefined;
  };

  // Internal hook: called by RTCPeerConnection.close(), removeTrack, or
  // track-swap (addTrack with transceiver reuse). Besides stopping the
  // pipeline, we unregister our manager-event listeners — otherwise every
  // addTrack→removeTrack cycle leaks two listeners (pli, encodings-updated)
  // and old/stopped senders keep reacting to events meant for the live one.
  this._stop = function () {
    stopPipeline();
    if (manager.ev && typeof manager.ev.off === 'function') {
      manager.ev.off('pli', _pliHandler);
      manager.ev.off('transceiver:encodings-updated', _encodingsUpdatedHandler);
    }
  };

  // Internal hook: point this sender at a different track, restarting the
  // send pipeline. Used by addTrack().
  //
  // W3C §5.4: a transceiver's sender is fixed for the transceiver's lifetime.
  // addTrack therefore either reuses an existing transceiver — and must
  // retarget ITS sender — or creates a new transceiver, which brings its own
  // sender with it. It must never construct a second sender for a transceiver
  // that already has one.
  //
  // It did, and both senders started a pipeline on the SAME SSRC with
  // independent sequence counters. The two streams interleaved on the wire,
  // SRTP's per-SSRC rollover estimate went wrong, and the receiver failed to
  // decrypt about half of all packets on every connection — rising to ~98%
  // whenever the two counters happened to start more than 32768 apart. See
  // FINDINGS.md.
  //
  // Same stop/start pair replaceTrack uses, for the same reason: the pipeline
  // captures the track at construction, so it has to be rebuilt to follow a
  // new one.
  this._attachTrack = function (newTrack) {
    if (internal.sender.track === newTrack && pipeline) return;
    stopPipeline();
    internal.sender.track = newTrack;
    if (newTrack) startPipeline();
  };

  impl.getParameters = function() {
    // negotiated -> expose the codec set; before that, spec says [].
    if ((!currentParams.codecs || !currentParams.codecs.length) &&
        manager && manager.state && manager.state.currentRemoteDescription) {
      // isSender is the sender-side getParameters path — see the note in
      // _codecsFromSdp on why the direction picks the description.
      // This is inside RTCRtpSender, so the remote description is the right
      // source — see the note in _codecsFromSdp.
      currentParams.codecs = (_codecsFromSdp(manager, internal.kind, internal.mid, true) ||
                              _defaultCodecs(internal.kind));
    }
    // HEADER EXTENSIONS FOLLOW THE SAME RULE as codecs: empty until the
    // negotiation settles, then the set the SDP actually agreed on. We
    // filled the codecs and left this at [] forever, so an application
    // reading getParameters() after negotiation could see which codecs
    // were chosen but never which extensions — and header extensions are
    // exactly what an app inspects to know whether, say, transport-cc or
    // the mid extension survived.
    if ((!currentParams.headerExtensions || !currentParams.headerExtensions.length) &&
        manager && manager.state && manager.state.currentLocalDescription) {
      try {
        var _p = manager.state.parsedCurrentLocalSdp;
        var _sec = null;
        if (_p && _p.media) {
          for (var _hi = 0; _hi < _p.media.length; _hi++) {
            if (String(_p.media[_hi].mid) === String(internal.mid)) { _sec = _p.media[_hi]; break; }
          }
        }
        // the parsed section calls them `extensions`
        var _ext = (_sec && (_sec.extensions || _sec.headerExtensions)) || [];
        currentParams.headerExtensions = _ext.map(function (e) {
          return {
            uri: e.uri || e.value || '',
            id: (e.id != null) ? e.id : e.value,
            encrypted: !!e.encrypted,
          };
        }).filter(function (e) { return !!e.uri; });
      } catch (eH) {}
    }
    // W3C 5.2: the transaction id is issued PER TASK, not per call —
    // back-to-back getParameters() within one turn of the event loop
    // must return the SAME id (WPT asserts this directly), while a new
    // task gets a fresh one. Regenerating on every call also made the
    // natural pattern `const p = getParameters(); ...; setParameters(p)`
    // fail whenever anything else read parameters in between.
    if (!internal.sender._txIdTask || !internal.sender._txId) {
      internal.sender._txId =
        Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
      internal.sender._txIdTask = true;
      // Cleared at the end of THIS task (a macrotask boundary), so
      // microtasks — `await undefined` in the tests — keep the same id
      // while a real event-loop turn issues a fresh one.
      setTimeout(function () { internal.sender._txIdTask = false; }, 0);
    }
    currentParams.transactionId = internal.sender._txId;
    // Return a shallow clone so caller mutations don't corrupt our state.
    // WPT harvest: WebIDL dictionaries OMIT unset members — rid:null or
    // maxBitrate:null poison every dictionary-shape assert (typeof null
    // is 'object'). Scrub on the way out; a default encoding is exactly
    // { active: true } and nothing else.
    function scrub(o) {
      var c = Object.assign({}, o);
      Object.keys(c).forEach(function(k) { if (c[k] === null || c[k] === undefined) delete c[k]; });
      return c;
    }
    var out = {
      transactionId:    currentParams.transactionId,
      encodings:        currentParams.encodings.map(scrub),
      headerExtensions: currentParams.headerExtensions.map(scrub),
      rtcp:             scrub(currentParams.rtcp),
      codecs:           currentParams.codecs.map(scrub),
    };
    if (currentParams.degradationPreference != null) {
      out.degradationPreference = currentParams.degradationPreference;
    }
    out.encodings.forEach(function(e) { if (e.active === undefined) e.active = true; });
    return out;
  };

  impl.setParameters = function(params, setParameterOptions) {
    return _setParametersInner.apply(this, arguments);
  };
  var _setParametersInner = function (params, setParameterOptions) {
    // W3C §5.2.4 validation order:
    //   1. transactionId match (InvalidStateError)
    //   2. transceiver stopped → InvalidStateError
    //   3. encodings.length / order / read-only changes → InvalidModificationError
    //   4. scaleResolutionDownBy < 1 or maxFramerate < 0 → RangeError
    //   5. priority enum mismatch → TypeError

    // WPT harvest — encoding.codec selection (W3C §5.2): the requested
    // codec must match one the sender knows (mimeType case-insensitive +
    // clockRate + channels); anything else rejects.
    if (params && Array.isArray(params.encodings)) {
      for (var eci = 0; eci < params.encodings.length; eci++) {
        var reqCodec = params.encodings[eci] && params.encodings[eci].codec;
        if (reqCodec == null) continue;
        // The list a per-encoding codec must come from, in priority
        // order (W3C 5.2): the NEGOTIATED codecs if negotiation has
        // happened, else the transceiver's PREFERRED list if the app set
        // one, else the platform capabilities. Falling straight through
        // to capabilities let an app pick a codec it had explicitly
        // de-preferred — or one the peer never agreed to — and the call
        // succeeded, so the encoding named a codec that could never be
        // used on the wire.
        var _srcList = (currentParams.codecs && currentParams.codecs.length)
          ? currentParams.codecs
          : (internal._codecPreferences && internal._codecPreferences.length)
            ? internal._codecPreferences
            : (function () { try { return (RTCRtpSender.getCapabilities(internal.kind) || {}).codecs || []; }
                             catch (eCv) { return []; } })();
        var known = _srcList.some(function (c) {
          if (!c || !c.mimeType) return false;
          return c.mimeType.toLowerCase() === String(reqCodec.mimeType || '').toLowerCase() &&
                 c.clockRate === reqCodec.clockRate &&
                 (c.channels || undefined) === (reqCodec.channels || undefined);
        });
        if (!known) {
          return Promise.reject(new DOMException(
            'setParameters: encoding codec not in sender codecs', 'InvalidModificationError'));
        }
      }
    }

    // WPT harvest — encodings structural immutability: same length,
    // same rid per index; anything else is InvalidModificationError.
    if (params && Array.isArray(params.encodings)) {
      if (params.encodings.length !== currentParams.encodings.length) {
        return Promise.reject(new DOMException(
          'setParameters: encodings length is read-only', 'InvalidModificationError'));
      }
      for (var ri0 = 0; ri0 < params.encodings.length; ri0++) {
        var pr = params.encodings[ri0] || {};
        var cr = currentParams.encodings[ri0] || {};
        var pRid = pr.rid === undefined ? (cr.rid === undefined ? undefined : cr.rid) : pr.rid;
        if ((cr.rid || undefined) !== (pRid || undefined)) {
          return Promise.reject(new DOMException(
            'setParameters: encoding rid is read-only', 'InvalidModificationError'));
        }
      }
    }

    // Success-path member merge (WPT: requested values must ECHO from the
    // next getParameters — previously only 'active' survived the commit).
    var _mergeRequested = function () {
      if (!params || !Array.isArray(params.encodings)) return;
      for (var mi = 0; mi < params.encodings.length && mi < currentParams.encodings.length; mi++) {
        var pe = params.encodings[mi], ce = currentParams.encodings[mi];
        // NOTE (WPT): encoding.codec deliberately does NOT echo back from
        // setParameters — it applies and clears; only addTransceiver-time
        // codec persists in getParameters.
        ['active','maxBitrate','maxFramerate','scaleResolutionDownBy',
         'scalabilityMode','priority','networkPriority'].forEach(function (k) {
          if (pe[k] !== undefined) ce[k] = pe[k];
        });
      }
    };

    // WPT harvest: codecs are read-only through setParameters — any
    // omission, reorder, insertion, or field change rejects.
    // W3C 5.2 setParameters: `encodings` is REQUIRED — a parameters
    // object without it is a TypeError (it is how the spec prevents
    // callers from silently dropping layer configuration).
    if (!params || params.encodings === undefined) {
      return Promise.reject(new TypeError('setParameters: encodings is required'));
    }
    // Audio senders carry no video-only members: strip rather than
    // reject, matching addTransceiver's audio handling.
    if (internal.kind === 'audio' && Array.isArray(params.encodings)) {
      // The FOURTH copy of the audio collapse — fix 61 unified three in the
      // creation path (two in rtp_transmission_manager, one in api.js) and
      // this one, on the UPDATE path, kept its own field list and its own
      // omission: it dropped `codec`, so a pin set through setParameters was
      // discarded before any validation or copying saw it.
      //
      // rid survives here where the creation collapse drops it, because
      // setParameters must reject a rid CHANGE rather than silently ignore
      // one; the shared helper handles active, maxBitrate and codec, and rid
      // is re-attached after.
      params = Object.assign({}, params, {
        encodings: params.encodings.map(function (e) {
          var one = RtpManager.collapseAudioEncodings([e || {}])[0];
          if ((e || {}).rid !== undefined) one.rid = e.rid;
          return one;
        }),
      });
    }
    // W3C 5.2: rtcp is READ-ONLY through setParameters, exactly like
    // codecs and headerExtensions below — cname identifies the source
    // for the whole session and reducedSize is negotiated, so neither
    // is the sender's to change after the fact. We silently accepted
    // both, so an app could believe it had switched its CNAME
    // mid-session while the wire kept the original.
    if (params && params.rtcp !== undefined) {
      var curR = currentParams.rtcp || {};
      var newR = params.rtcp || {};
      var rtcpSame = (newR.cname === curR.cname) &&
                     ((newR.reducedSize || false) === (curR.reducedSize || false));
      if (!rtcpSame) {
        return Promise.reject(new DOMException(
          'setParameters: rtcp cannot be modified', 'InvalidModificationError'));
      }
    }
    // W3C 5.2: headerExtensions are READ-ONLY through setParameters —
    // any omission, reorder, insertion or field change rejects with
    // InvalidModificationError (identical rule to codecs below).
    if (params && params.headerExtensions !== undefined) {
      var curH = currentParams.headerExtensions || [];
      var newH = params.headerExtensions;
      var hSame = Array.isArray(newH) && newH.length === curH.length &&
        newH.every(function (h, i) {
          return h && h.uri === curH[i].uri && h.id === curH[i].id &&
                 (h.encrypted || false) === (curH[i].encrypted || false);
        });
      if (!hSame) {
        return Promise.reject(new DOMException(
          'setParameters: headerExtensions cannot be modified', 'InvalidModificationError'));
      }
    }
    if (params && params.codecs !== undefined) {
      var curC = currentParams.codecs || [];
      var newC = params.codecs;
      var codecsSame = Array.isArray(newC) && newC.length === curC.length &&
        newC.every(function(c, i) {
          return c && c.payloadType === curC[i].payloadType &&
                 c.mimeType === curC[i].mimeType &&
                 c.clockRate === curC[i].clockRate &&
                 (c.channels || undefined) === (curC[i].channels || undefined) &&
                 (c.sdpFmtpLine || undefined) === (curC[i].sdpFmtpLine || undefined);
        });
      if (!codecsSame) {
        return Promise.reject(new DOMException(
          'setParameters: codecs are read-only', 'InvalidModificationError'));
      }
    } else if (params && (currentParams.codecs || []).length) {
      return Promise.reject(new DOMException(
        'setParameters: codecs member is required', 'InvalidModificationError'));
    }

    // W3C 5.2: an absent transactionId is a TypeError (the member is
    // required), distinct from a WRONG id (InvalidModificationError) and
    // from a STALE-but-correct id (InvalidStateError).
    if (!params || typeof params.transactionId !== 'string' || !params.transactionId) {
      return Promise.reject(new TypeError('setParameters: transactionId is required'));
    }
    // (An earlier attempt also rejected a correct-but-EXPIRED id — i.e.
    // the event loop turned between getParameters and setParameters. It
    // is spec-true, but real callers legitimately await in between and
    // eight neighbouring subtests regressed on it, so the id is accepted
    // for as long as it is the most recent one and unconsumed. The
    // single-use rule below still catches genuine double-application.)
    // Spec: the id must match the most recent getParameters() AND each id
    // is single-use — a second setParameters() with the same id rejects.
    // RANGE VALIDATION FIRST (WebIDL): a scaleResolutionDownBy below 1
    // or a negative maxFramerate is a RangeError regardless of how old
    // the parameters are — the value is impossible, not merely stale.
    // Running the expiry check first reported InvalidStateError for a
    // plainly invalid number, which hides the real mistake from the app.
    if (params && Array.isArray(params.encodings)) {
      for (var _rv = 0; _rv < params.encodings.length; _rv++) {
        var _re = params.encodings[_rv] || {};
        // One range rule, in rtp_transmission_manager — see
        // encodingRangeProblem. This layer owns only the message.
        var _reBad = RtpManager.encodingRangeProblem(_re);
        if (_reBad === 'scale') {
          return Promise.reject(new RangeError(
            'setParameters: encodings[' + _rv + '].scaleResolutionDownBy must be >= 1.0'));
        }
        if (_reBad === 'framerate') {
          return Promise.reject(new RangeError(
            'setParameters: encodings[' + _rv + '].maxFramerate must be >= 0'));
        }
      }
    }

    // EXPIRED ID (W3C 5.2): parameters read in an EARLIER task are
    // stale — the sender may have renegotiated since — so applying them
    // is an InvalidStateError. _txIdTask is true only for the task that
    // issued the current id, which makes "was this read in this turn?"
    // a single boolean. (Round 85 tried this before the per-task model
    // was right and it cost eight neighbouring subtests; with the id no
    // longer reset on consume, it is exact.)
    if (params.transactionId === internal.sender._txId && !internal.sender._txIdTask) {
      return Promise.reject(new DOMException(
        'setParameters: parameters are stale, call getParameters() again', 'InvalidStateError'));
    }
    // NO REPLAY GUARD. WPT is explicit: "setParameters() with already
    // used parameters SHOULD WORK if the event loop has not been
    // relinquished". Within a task the same parameters may be applied
    // more than once — what makes them invalid is the TASK ending, which
    // the expiry check above already covers. A single-use rule on top of
    // that rejected legitimate calls.
    if (currentParams.transactionId &&
        params && params.transactionId !== currentParams.transactionId) {
      // W3C 5.2 step 5: a transactionId that does not match the last
      // getParameters() is an InvalidModificationError (the parameters
      // were modified out from under us) — InvalidStateError is for a
      // sender that cannot accept parameters at all.
      var txErr = new DOMException(
        'setParameters: transactionId mismatch (must call getParameters() first)', 'InvalidModificationError');
      return Promise.reject(txErr);
    }

    // The id is PER TASK, full stop: WPT asserts that getParameters()
    // before and after an intervening setParameters() — in the same turn
    // — returns the SAME id. Resetting the cache on consume (an earlier
    // reading of "setParameters clears [[LastReturnedParameters]]") broke
    // that. Single-use is enforced by the replay guard on _txIdConsumed
    // instead, which is the property that actually matters: an id may be
    // handed out repeatedly within its task but APPLIED only once.
    internal.sender._txIdConsumed = currentParams.transactionId;
    // Per spec, stopped transceiver → InvalidStateError ("not running").
    if (RtpManager.isStopped(internal)) {
      var stoppedErr = new DOMException('setParameters: transceiver is stopped', 'InvalidStateError');
      return Promise.reject(stoppedErr);
    }

    // W3C §5.2: encodings.length in setParameters must equal the current
    // count; the app can't add or remove layers via setParameters (that
    // would require renegotiation via addTransceiver). RIDs also must
    // match — they're identifiers, not mutable fields.
    if (params.encodings) {
      if (params.encodings.length !== currentParams.encodings.length) {
        var lenErr = new DOMException(
          'setParameters: encodings.length changed (' + currentParams.encodings.length +
          ' → ' + params.encodings.length + '); renegotiate via addTransceiver instead', 'InvalidModificationError');
        return Promise.reject(lenErr);
      }
      var validPrios = ['very-low', 'low', 'medium', 'high'];
      for (var vi = 0; vi < params.encodings.length; vi++) {
        var srcEnc = params.encodings[vi];
        if (!srcEnc) continue;
        var srid = srcEnc.rid;
        var crid = currentParams.encodings[vi].rid;
        if (srid != null && crid != null && srid !== crid) {
          var ridErr = new DOMException(
            'setParameters: rid at index ' + vi + ' changed ("' + crid + '" → "' + srid + '")', 'InvalidModificationError');
          return Promise.reject(ridErr);
        }
        // RangeError checks (spec §5.2.4): scaleResolutionDownBy must be
        // >= 1.0 and maxFramerate must be >= 0.0.
        var _srcBad = RtpManager.encodingRangeProblem(srcEnc);
        if (_srcBad === 'scale') {
          return Promise.reject(new RangeError(
            'setParameters: encodings[' + vi + '].scaleResolutionDownBy must be >= 1.0'));
        }
        if (_srcBad === 'framerate') {
          return Promise.reject(new RangeError(
            'setParameters: encodings[' + vi + '].maxFramerate must be >= 0.0'));
        }
        // priority enum (RTCPriorityType): very-low | low | medium | high.
        if (srcEnc.priority != null && validPrios.indexOf(srcEnc.priority) < 0) {
          return Promise.reject(new TypeError(
            'setParameters: encodings[' + vi + '].priority must be one of ' +
            validPrios.join(', ')));
        }
        if (srcEnc.networkPriority != null && validPrios.indexOf(srcEnc.networkPriority) < 0) {
          return Promise.reject(new TypeError(
            'setParameters: encodings[' + vi + '].networkPriority must be one of ' +
            validPrios.join(', ')));
        }
      }
    }
    // degradationPreference enum check.
    if (params.degradationPreference != null) {
      var validDP = ['balanced', 'maintain-framerate', 'maintain-resolution',
                     'maintain-framerate-and-resolution'];
      if (validDP.indexOf(params.degradationPreference) < 0) {
        return Promise.reject(new TypeError(
          'setParameters: invalid degradationPreference "' +
          params.degradationPreference + '"'));
      }
    }

    // Apply each encoding to the stored state. We accept partial updates —
    // only fields present in the input are copied. Everything else keeps
    // its prior value.
    //
    // Two stores need to stay in sync:
    //   • currentParams.encodings  — this sender's live state
    //   • internal.sender.encodings — transceiver-level state, read by
    //     a freshly-constructed RTCRtpSender (e.g. after removeTrack →
    //     addTrack with transceiver reuse). Without mirroring here,
    //     app-applied parameter changes would be silently lost across
    //     track swaps.
    if (params.encodings && params.encodings.length > 0) {
      for (var i = 0; i < params.encodings.length; i++) {
        var src = params.encodings[i];
        var dst = currentParams.encodings[i];
        var tdst = (internal.sender.encodings || [])[i];
        if (typeof src.active === 'boolean') {
          dst.active = src.active;
          if (tdst) tdst.active = src.active;
        }
        // REPLACE, not merge (W3C 5.2): setParameters applies the
        // dictionary as given, so an ABSENT member UNSETS the value —
        // "read parameters, delete maxFramerate, write back" is the
        // documented way to clear a cap. Merging kept the old value
        // forever and made every cap one-way.
        // The codec pin travels the same way (W3C 5.2): present means set,
        // absent means unset. It is not numeric, so it sits outside the loop
        // below — and being in no copy list at all is exactly why a pin set
        // through setParameters was silently ignored while one set at
        // addTransceiver worked.
        if (src.codec) {
          dst.codec = src.codec;
          if (tdst) tdst.codec = src.codec;
        } else if (Object.prototype.hasOwnProperty.call(src, 'codec')) {
          delete dst.codec;
          if (tdst) delete tdst.codec;
        }

        var _numMembers = ['maxBitrate', 'maxFramerate', 'scaleResolutionDownBy'];
        for (var _nm = 0; _nm < _numMembers.length; _nm++) {
          var _k = _numMembers[_nm];
          if (typeof src[_k] === 'number') {
            dst[_k] = src[_k];
            if (tdst) tdst[_k] = src[_k];
          } else if (Object.prototype.hasOwnProperty.call(src, _k)) {
            // Present-but-not-a-number (e.g. explicitly undefined) clears
            // it; a member the caller never touched is left alone, so the
            // spec's scaleResolutionDownBy defaults survive a round-trip
            // that only meant to change one field.
            delete dst[_k];
            if (tdst) delete tdst[_k];
          } else if (_k === 'scaleResolutionDownBy' && internal.kind === 'video') {
            // absence resets a VIDEO layer to full resolution (1), it
            // does not unset the member — video always reports it.
            dst[_k] = 1;
            if (tdst) tdst[_k] = 1;
          } else if (_k === 'maxFramerate' || _k === 'maxBitrate') {
            // getParameters() reports these only when set, so their
            // absence in the echoed dictionary genuinely means "unset".
            delete dst[_k];
            if (tdst) delete tdst[_k];
          }
        }
        if (typeof src.scalabilityMode === 'string') {
          dst.scalabilityMode = src.scalabilityMode;
          if (tdst) tdst.scalabilityMode = src.scalabilityMode;
        }
        // priority / networkPriority are sender-layer only; not in the
        // transceiver store (not tracked across wrapper lifecycles).
        if (src.priority)         dst.priority = src.priority;
        if (src.networkPriority)  dst.networkPriority = src.networkPriority;
      }
    }
    if (params.degradationPreference) {
      currentParams.degradationPreference = params.degradationPreference;
    }

    // Apply to the live pipeline. The pipeline exposes either:
    //   - reconfigure(params)             — single-layer (legacy)
    //   - reconfigureLayer(rid, params)   — simulcast, per-layer
    // We call whichever is available. A pipeline with reconfigureLayer
    // gets one call per encoding; a pipeline with only reconfigure gets
    // the first encoding only (legacy fallback).
    if (pipeline) {
      try {
        if (typeof pipeline.reconfigureLayer === 'function') {
          for (var ri = 0; ri < currentParams.encodings.length; ri++) {
            var er = currentParams.encodings[ri];
            pipeline.reconfigureLayer(er.rid, {
              maxBitrate:            er.maxBitrate   || 0,
              maxFramerate:          er.maxFramerate || 0,
              scaleResolutionDownBy: er.scaleResolutionDownBy || 1,
              active:                er.active !== false,
              scalabilityMode:       er.scalabilityMode || null,
            });
          }
        } else if (typeof pipeline.reconfigure === 'function') {
          var e = currentParams.encodings[0] || {};
          pipeline.reconfigure({
            maxBitrate:            e.maxBitrate   || 0,
            maxFramerate:          e.maxFramerate || 0,
            scaleResolutionDownBy: e.scaleResolutionDownBy || 1,
            active:                e.active !== false,
          });
        }
      } catch (err) {
        return Promise.reject(err);
      }
    }

    _mergeRequested();
    // Per spec, a new transactionId is generated after successful apply.
    currentParams.transactionId = '';

    // W3C 5.2 setParameterOptions — the SECOND argument can ask for a key
    // frame:
    //
    //   sender.setParameters(p, { encodings: [{ requestKeyFrame: true }] })
    //
    // This is how an application refreshes a decoder without waiting for the
    // receiver to send a PLI. The pipeline already serves exactly this
    // request for PLI/FIR; only the entry point was missing.
    try {
      var _kfEncs = setParameterOptions && setParameterOptions.encodings;
      if (_kfEncs && _kfEncs.length && pipeline &&
          typeof pipeline.requestKeyFrame === 'function') {
        for (var _ki = 0; _ki < _kfEncs.length; _ki++) {
          if (_kfEncs[_ki] && _kfEncs[_ki].requestKeyFrame === true) {
            pipeline.requestKeyFrame();
            break;
          }
        }
      }
    } catch (eKf) { /* a key-frame request must never fail setParameters */ }
    // W3C 5.2: setParameters is ASYNCHRONOUS — it must not settle in the
    // same turn (WPT checks the promise is still pending after a
    // microtask). It does NOT use the operations chain; it simply
    // resolves on the next task.
    return new Promise(function (res) { setTimeout(res, 0); });
  };

impl.getStats = function() {
    // W3C 8.2: getStats() is ASYNCHRONOUS and does not use the
    // operations chain — the report must still be pending after a
    // microtask (WPT checks exactly that on senders and receivers, the
    // same rule pc.getStats already follows). Assemble on the next task.
    var _gsSelf = this, _gsArgs = arguments;
    return new Promise(function (res, rej) {
      setTimeout(function () {
        try { res(_getStatsNow1.apply(_gsSelf, _gsArgs)); } catch (e) { rej(e); }
      }, 0);
    });
  };
  function _getStatsNow1() {
    // A DEAD SENDER HAS NO OUTBOUND STREAM (W3C 8.2): a stopped
    // transceiver or a closed connection still answers getStats() — the
    // report is not an error — but it must not claim an outbound-rtp
    // stream that is no longer sending. We reported one for both cases,
    // so an app polling stats after a stop or a close saw a phantom
    // outbound stream with frozen counters.
    if (manager.state.closed || RtpManager.isStopped(internal)) {
      return new Map();
    }
    // Spec: returns stats for this sender's outbound stream(s) + matching
    // remote-inbound-rtp entries. For simulcast senders we pass all
    // layer SSRCs so every layer's outbound-rtp entry appears in the
    // report (each with its own rid field, per W3C spec).
    var ssrcs = [];
    if (internal && internal.sender) {
      if (internal.sender.layers && internal.sender.layers.length) {
        for (var li = 0; li < internal.sender.layers.length; li++) {
          if (internal.sender.layers[li].ssrc != null) {
            ssrcs.push(internal.sender.layers[li].ssrc);
          }
        }
      } else if (internal.sender.ssrc != null) {
        ssrcs.push(internal.sender.ssrc);
      }
    }
    if (!ssrcs.length) return Promise.resolve(new Map());
    return Promise.resolve(_buildStatsReport(manager, { ssrcs: ssrcs }));
  };

  /**
   * Handoff encoded-frame streams for the app to inspect or transform
   * outgoing chunks before they hit the packetizer + SRTP layer.
   *
   * Returns { readable, writable } where:
   *   - `readable` emits RTCEncodedVideoFrame-shaped objects produced by
   *     the internal encoder (one per encoded frame, pre-packetize)
   *   - `writable` accepts the same shape and drives the packetizer; the
   *     chunk's synchronizationSource is IGNORED — the packetizer always
   *     stamps the sender's SSRC and monotonic sequence numbers, so the
   *     output is a valid RTP stream regardless of origin
   *
   * Typical patterns:
   *
   *   // SFU pass-through (forward a received stream as our own):
   *   var { readable } = peerA.getReceivers()[0].createEncodedStreams();
   *   var { writable } = peerB.getSenders()[0].createEncodedStreams();
   *   readable.pipeTo(writable);
   *
   *   // Transform (e.g. E2EE encrypt before send):
   *   var { readable, writable } = sender.createEncodedStreams();
   *   readable.pipeThrough(encryptTransform).pipeTo(writable);
   *
   *   // Local encoder pass-through (no-op, but breaks the default pipe):
   *   var { readable, writable } = sender.createEncodedStreams();
   *   readable.pipeTo(writable);
   *
   * Per spec, this method can only be called once per sender. After the
   * call, the encoder's default direct path to the wire is disabled — the
   * app must wire readable to writable (possibly through a transform) or
   * nothing will be sent.
   */
  this.createEncodedStreams = function() {
    if (!pipeline || typeof pipeline.takeStreams !== 'function') {
      var pErr = new DOMException('createEncodedStreams: pipeline not ready (no track yet?)', 'InvalidStateError');
      throw pErr;
    }
    return pipeline.takeStreams();
  };
}

/**
 * Look a codec up in the registry by NAME (case-insensitive), for the
 * send pipeline's clockRate/PT metadata. This is the only lookup helper
 * — it reads sdp.js's CODEC_REGISTRY, so it cannot drift from what we
 * offer the way the deleted _CODEC_MAP tables did.
 */
function _codecByName(kind, name) {
  var list = (SDP.CODEC_REGISTRY && SDP.CODEC_REGISTRY[kind]) || [];
  var want = String(name || '').toLowerCase();
  for (var i = 0; i < list.length; i++) {
    if (String(list[i].name).toLowerCase() === want) return list[i];
  }
  return null;
}

// (The former _CODEC_MAP_VIDEO/_CODEC_MAP_AUDIO tables lived here. They
// were a THIRD codec list, independent of both the SDP wire tables and
// media-processing, and that is exactly how getCapabilities() came to
// advertise codecs no offer contained. The single registry in sdp.js
// replaces them; this file only presents it.)

RTCRtpSender.prototype.getParameters = function () { return this._impl.getParameters.apply(this, arguments); };
Object.defineProperty(RTCRtpSender.prototype.getParameters, 'length', { value: 0 });
Object.defineProperty(RTCRtpSender.prototype.getParameters, 'name', { value: 'getParameters' });
RTCRtpSender.prototype.setParameters = function () { return this._impl.setParameters.apply(this, arguments); };
Object.defineProperty(RTCRtpSender.prototype.setParameters, 'length', { value: 1 });
Object.defineProperty(RTCRtpSender.prototype.setParameters, 'name', { value: 'setParameters' });
RTCRtpSender.prototype.replaceTrack = function () { return this._impl.replaceTrack.apply(this, arguments); };
Object.defineProperty(RTCRtpSender.prototype.replaceTrack, 'length', { value: 1 });
Object.defineProperty(RTCRtpSender.prototype.replaceTrack, 'name', { value: 'replaceTrack' });
RTCRtpSender.prototype.getStats = function () { return this._impl.getStats.apply(this, arguments); };
Object.defineProperty(RTCRtpSender.prototype.getStats, 'length', { value: 0 });
Object.defineProperty(RTCRtpSender.prototype.getStats, 'name', { value: 'getStats' });
RTCRtpSender.prototype.setStreams = function () { return this._impl.setStreams.apply(this, arguments); };
Object.defineProperty(RTCRtpSender.prototype.setStreams, 'length', { value: 0 });
Object.defineProperty(RTCRtpSender.prototype.setStreams, 'name', { value: 'setStreams' });

function _capabilityKey(c) {
  return c.mimeType + '|' + c.clockRate + '|' + (c.channels || 0);
}

RTCRtpSender.getCapabilities = function(kind) {
  // W3C 5.2/5.3: an unrecognised kind returns NULL — only 'audio' and
  // 'video' have capabilities. We were falling through to a default
  // table and reporting codecs for kinds that do not exist.
  if (kind !== 'audio' && kind !== 'video') return null;
  // W3C §5.2.7: returns RTCRtpCapabilities = { codecs, headerExtensions }
  // for the platform's capabilities (NOT for any particular sender).
  //
  // codecs: derived from media-processing's actual encoder/decoder
  // registry, filtered to WebRTC-relevant entries and deduplicated.
  //
  // headerExtensions: pulled from sdp.js's DEFAULT_*_EXTENSIONS so the
  // list matches what we actually advertise in our offers/answers.
  // Each entry is { uri } per spec.

  if (kind !== 'video' && kind !== 'audio') {
    return { codecs: [], headerExtensions: [] };
  }

  // DERIVED FROM THE REGISTRY (sdp.js), intersected with what
  // media-processing reports it can actually encode. Two rules make the
  // three-way disagreement that used to exist impossible:
  //   • nothing is ADVERTISED that the wire tables don't offer — both
  //     come from the same registry entries;
  //   • nothing is advertised that media-processing can't ENCODE, except
  //     entries with no encoder by design (telephone-event is produced
  //     by the DTMF sender).
  var registry = SDP.CODEC_REGISTRY[kind] || [];
  var available = {};
  try {
    var names = (kind === 'video') ? getSupportedVideoCodecs() : getSupportedAudioCodecs();
    for (var ni = 0; ni < names.length; ni++) available[String(names[ni]).toLowerCase()] = true;
  } catch (eSup) { available = null; }   // no encoder info: advertise the registry as-is

  var seen = {};
  var codecs = [];
  for (var i = 0; i < registry.length; i++) {
    var entry = registry[i];
    if (entry.mpName && available && !available[String(entry.mpName).toLowerCase()]) continue;
    var key = _capabilityKey(entry);
    if (seen[key]) continue;
    seen[key] = true;
    var out = { mimeType: entry.mimeType, clockRate: entry.clockRate };
    if (entry.channels !== undefined) out.channels = entry.channels;
    if (entry.fmtp && SDP.buildFmtpConfig) {
      var line = SDP.buildFmtpConfig(entry.fmtp);
      if (line) out.sdpFmtpLine = line;
    }
    codecs.push(out);
  }

  // Header extensions — read from sdp.js so the list stays in lockstep
  // with what we negotiate. SDP.DEFAULT_*_EXTENSIONS is the authoritative
  // table; we expose its URIs.
  var defaults = (kind === 'video')
    ? (SDP.DEFAULT_VIDEO_EXTENSIONS || [])
    : (SDP.DEFAULT_AUDIO_EXTENSIONS || []);

  var headerExtensions = [];
  for (var j = 0; j < defaults.length; j++) {
    var ext = defaults[j];
    // Each default may be { uri } or { uri, id, ... } — we expose only
    // the uri per spec (capabilities ≠ negotiated extmap).
    var uri = (typeof ext === 'string') ? ext : ext.uri;
    if (uri) headerExtensions.push({ uri: uri });
  }

  return { codecs: codecs, headerExtensions: headerExtensions };
};


/* ========================= RTCRtpReceiver ========================= */

function RTCRtpReceiver(track, kind, manager, internalTransceiver) {
  // W3C §5.3 (WPT harvest): the receiver's track exists from CONSTRUCTION —
  // muted, live, correct kind — long before any media (or even
  // negotiation). Media arrival later reuses this same object.
  if (!track) {
    try {
      track = new MediaStreamTrack({ kind: kind });   // options-object ctor
      track.muted = true;                             // plain data property
    } catch (e) { track = null; }
  }

  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  var self = this;
  this.track = track || null;
  // W3C webrtc-encoded-transform §3 — RTCRtpScriptTransform integration
  // for incoming frames (see RTCRtpSender.transform for the send-side
  // mirror). Settable stub today — Worker-based transforms aren't
  // wired through the pipeline. Apps wanting in-process inspection
  // of incoming encoded frames should use createEncodedStreams().
  // TODO (API-7?): wire RTCRtpScriptTransform into the receive pipeline.
  this.transform = null;
  // RTCDtlsTransport singleton per peer connection (see sender.transport).
  Object.defineProperty(this, 'transport', {
    get: function() {
      // WPT/spec: transports come into existence when a LOCAL description
      // is applied (ICE gathering start) — null before, null again after
      // its rollback.
      if (!manager || !manager.state ||
          !(manager.state.pendingLocalDescription || manager.state.currentLocalDescription)) return null;
      return manager._getDtlsTransport ? manager._getDtlsTransport() : null;
    },
  });

  // jitterBufferTarget (W3C extension, Chrome 114+). Target latency in
  // milliseconds the jitter buffer should aim for. null means "auto" — the
  // implementation decides. Pushed through to the active pipeline's
  // JitterBuffer when set; new pipelines read this value on startup.
  //
  // Range per spec: 0 to 4000 ms. Values outside range raise RangeError.
  var _jitterBufferTarget = null;
  Object.defineProperty(this, 'jitterBufferTarget', {
    get: function() { return _jitterBufferTarget; },
    set: function(ms) {
      if (ms != null) {
        var n = Number(ms);
        if (!isFinite(n) || n < 0 || n > 4000) {
          throw new RangeError('jitterBufferTarget must be between 0 and 4000 ms');
        }
        _jitterBufferTarget = n;
      } else {
        _jitterBufferTarget = null;
      }
      // Live-push to pipeline if running.
      if (pipeline && typeof pipeline.setJitterBufferTarget === 'function') {
        pipeline.setJitterBufferTarget(_jitterBufferTarget);
      }
    },
  });

  // playoutDelayHint (W3C extension). Target playout delay in SECONDS.
  // Applies to audio and video; null = auto. Not a hard guarantee — the
  // implementation balances against rebuffering risk.
  var _playoutDelayHint = null;
  Object.defineProperty(this, 'playoutDelayHint', {
    get: function() { return _playoutDelayHint; },
    set: function(s) {
      if (s != null) {
        var n = Number(s);
        if (!isFinite(n) || n < 0) {
          throw new RangeError('playoutDelayHint must be a non-negative number (seconds)');
        }
        _playoutDelayHint = n;
      } else {
        _playoutDelayHint = null;
      }
      if (pipeline && typeof pipeline.setPlayoutDelayHint === 'function') {
        pipeline.setPlayoutDelayHint(_playoutDelayHint);
      }
    },
  });

  // Receive pipeline (RTP → jitter buffer → depacketize → decode → track._push).
  // Only built for video in Phase 2. Audio is Phase 3.
  var pipeline = null;

  // Find the PRIMARY remote SSRC for this transceiver's mid. May return null
  // if the remote hasn't declared any SSRCs yet (happens when receiver is
  // built before setRemoteDescription has run). The pipeline is started later
  // via _tryStartPipeline() when the SSRC becomes available.
  //
  // An FID ssrc-group declares two SSRCs — the primary (video) and the RTX
  // retransmission stream. We skip RTX; RTX packets arrive on the second SSRC
  // with a different payload type and are currently dropped.
  function findRemoteSsrc() {
    if (!internalTransceiver) return null;
    var mid = internalTransceiver.mid;
    if (mid == null) return null;
    var map = manager.state.remoteSsrcMap;
    for (var k in map) {
      if (!Object.prototype.hasOwnProperty.call(map, k)) continue;
      var entry = map[k];
      if (entry.mid !== mid) continue;
      if (entry.isRtx) continue;
      return parseInt(k, 10);
    }
    return null;
  }

  // Find ALL remote primary (non-RTX) SSRCs for this transceiver's mid.
  // For single-layer senders returns one entry; for simulcast senders
  // returns one entry per layer, annotated with rid when parsed from SDP.
  function findRemoteSsrcs() {
    if (!internalTransceiver) return [];
    var mid = internalTransceiver.mid;
    if (mid == null) return [];
    var map = manager.state.remoteSsrcMap;
    var out = [];
    for (var k in map) {
      if (!Object.prototype.hasOwnProperty.call(map, k)) continue;
      var entry = map[k];
      if (entry.mid !== mid) continue;
      if (entry.isRtx) continue;
      out.push({ ssrc: parseInt(k, 10), rid: entry.rid || null });
    }
    // Sort by rid if present (stable ordering across renegotiations);
    // otherwise by SSRC for determinism.
    out.sort(function (a, b) {
      if (a.rid && b.rid) return a.rid < b.rid ? -1 : (a.rid > b.rid ? 1 : 0);
      return a.ssrc - b.ssrc;
    });
    return out;
  }

  function findRemoteSsrc() {
    var all = findRemoteSsrcs();
    return all.length ? all[0].ssrc : null;
  }

  // Detect whether the remote m-section bound to this transceiver's mid
  // declares simulcast (a=simulcast:send or >1 a=rid:X send). Used to
  // decide whether to construct a simulcast-capable pipeline that can
  // accept layers dynamically as they're learned from runtime RID
  // extensions — critical for Chrome-style offers that don't declare
  // any a=ssrc lines up front.
  // Whether the peer's offer declared simulcast in the send direction
  // (i.e., they want to send multiple layers, we receive). Decided by
  // cm.js's processRemoteMedia at SDP-apply time and stored on the
  // transceiver — we just read the field. Without populating, walking
  // parsedRemoteSdp here would put SDP-traversal logic in api.js, which
  // is meant to be a thin W3C surface wrapper.
  function isRemoteSimulcast() {
    return !!(internalTransceiver && internalTransceiver.remoteSimulcast);
  }

  function startPipelineIfReady() {
    if (pipeline) return;
    if (!self.track) return;
    var ssrcs = findRemoteSsrcs();
    var simulcast = isRemoteSimulcast();

    // For non-simulcast m-sections, we need at least one SSRC to begin.
    // For simulcast m-sections, we proceed even with zero SSRCs known —
    // the pipeline starts empty and grows via addLayer as RID-tagged
    // packets arrive (see manager 'ssrc:rid-learned' event wiring below).
    if (!ssrcs.length && !simulcast) {
      _diag('[api-diag] RTCRtpReceiver: no SSRC yet for mid=' +
                  (internalTransceiver && internalTransceiver.mid));
      return;
    }

    if (kind === 'video') {
      // Pull the negotiated codec from the transceiver (set by connection_manager
      // in processRemoteMedia). Defaults to 'vp8' if unknown.
      var codecName = 'vp8';
      if (internalTransceiver && internalTransceiver.negotiatedCodec) {
        codecName = (internalTransceiver.negotiatedCodec.name || 'VP8').toLowerCase();
      }

      // Simulcast path: use the simulcast wrapper whenever the offer
      // declared simulcast for this m-section. The wrapper supports 0-N
      // layers at construction and gains layers via addLayer at runtime.
      //
      // Non-simulcast path: the single-SSRC pipeline as before.
      try {
        if (simulcast) {
          _diag('[api-diag] RTCRtpReceiver: starting SIMULCAST video pipeline ' +
                      'initial-layers=' + ssrcs.length +
                      ' mid=' + (internalTransceiver && internalTransceiver.mid));
          pipeline = createVideoReceiveSimulcastPipeline({
            track:           self.track,
            manager:         manager,
            codec:           codecName,
            jitterLatencyMs: _jitterBufferTarget,
            layers:          ssrcs,   // may be empty — pipeline handles it
          });
        } else {
          _diag('[api-diag] RTCRtpReceiver: starting video pipeline ssrc=' + ssrcs[0].ssrc +
                      ' mid=' + (internalTransceiver && internalTransceiver.mid) +
                      ' codec=' + codecName);
          pipeline = createVideoReceivePipeline({
            track:   self.track,
            manager: manager,
            ssrc:    ssrcs[0].ssrc,
            codec:   codecName,
            jitterLatencyMs: _jitterBufferTarget,
          });
        }
        if (_playoutDelayHint != null && typeof pipeline.setPlayoutDelayHint === 'function') {
          pipeline.setPlayoutDelayHint(_playoutDelayHint);
        }
        _diag('[api-diag] RTCRtpReceiver: pipeline started ✓');
      } catch (e) {
        console.error('[RTCRtpReceiver] video pipeline start failed:', e && e.message || e);
      }
    } else if (kind === 'audio') {
      var ssrc = ssrcs[0].ssrc;
      _diag('[api-diag] RTCRtpReceiver: starting audio pipeline ssrc=' + ssrc +
                  ' mid=' + (internalTransceiver && internalTransceiver.mid));
      try {
        // RED PT from the negotiated codec set (offer/answer both attach
        // redPayloadType to the opus entry — sdp.js extractCodecs pass 2b).
        var _rxAudioRedPt = null;
        var _rxNegCodecs = (internalTransceiver && internalTransceiver._negotiatedCodecs) ||
                           (internalTransceiver && internalTransceiver.sender &&
                            internalTransceiver.sender._negotiatedCodecs);
        if (_rxNegCodecs) {
          for (var _rci = 0; _rci < _rxNegCodecs.length; _rci++) {
            var _rnc = _rxNegCodecs[_rci];
            if (_rnc && _rnc.redPayloadType != null &&
                _rnc.name && _rnc.name.toLowerCase() === 'opus') {
              _rxAudioRedPt = _rnc.redPayloadType;
              break;
            }
          }
        }
        pipeline = createAudioReceivePipeline({
          track:   self.track,
          manager: manager,
          ssrc:    ssrc,
          redPayloadType: _rxAudioRedPt,
        });
        _diag('[api-diag] RTCRtpReceiver: audio pipeline started ✓');
      } catch (e) {
        console.error('[RTCRtpReceiver] audio pipeline start failed:', e && e.message || e);
      }
    }
  }

  // Try now (covers the case where SSRC is already known — the normal path
  // through track:new after setRemoteDescription).
  startPipelineIfReady();

  // Runtime SSRC→RID learning (RFC 8852). For simulcast senders that don't
  // declare a=ssrc lines in the offer (Chrome) or declare them without a
  // SIM group (Firefox), we learn each layer's rid from the first RTP
  // packet's sdes:rtp-stream-id extension. connection_manager handles the
  // packet parsing + state update; here we plug the learned layer into
  // our pipeline, starting the pipeline if this is the first layer seen.
  var _ridLearnedHandler = function (info) {
    if (!internalTransceiver) return;
    if (info.mid !== internalTransceiver.mid) return;

    if (!pipeline) {
      // First learned SSRC for this mid — now we can start the pipeline.
      startPipelineIfReady();
    }
    if (pipeline && typeof pipeline.addLayer === 'function') {
      pipeline.addLayer({
        ssrc:  info.ssrc,
        rid:   info.rid,
        isRtx: info.isRtx,
      });
    }
  };
  manager.ev.on('ssrc:rid-learned', _ridLearnedHandler);

  // Internal hooks used by the PC to update the track after initial
  // construction (e.g. track:new event) and to tear down on close.
  this._setTrack = function(newTrack) {
    self.track = newTrack;
    startPipelineIfReady();
  };
  this._tryStartPipeline = startPipelineIfReady;

  /**
   * Drop any codec pin whose codec is no longer in `keep` (W3C 5.2).
   *
   * encoding.codec means "send this encoding with exactly this codec". A
   * negotiation that drops the codec makes that unhonourable, and reporting
   * it anyway tells the application a constraint is in force that is not.
   *
   * THE SENDER OWNS BOTH COPIES, so it owns the sweep. `currentParams` is
   * what getParameters() returns verbatim, and internal.sender.encodings is
   * the transceiver-level state — writing only the second from outside looks
   * like it works and changes nothing observable, which is exactly what an
   * earlier attempt at this did. setParameters already writes the pair
   * together (dst / tdst); this is the same discipline for the one case where
   * the change originates in a description rather than in a caller.
   *
   * @param {string[]} keep  codec names present in the applied m-section
   * @returns {boolean}      true if anything was cleared
   */

  this._stop = function() {
    if (pipeline) { try { pipeline.stop(); } catch (e) {} pipeline = null; }
    try { manager.ev.off('ssrc:rid-learned', _ridLearnedHandler); } catch (e) {}
  };

  /**
   * WebRTC Insertable Streams / Encoded Transforms API.
   *
   * Returns { readable, writable } where:
   *   - `readable` is a ReadableStream of RTCEncodedVideoFrame-shaped objects
   *     (one per encoded frame, before decoding)
   *   - `writable` is a WritableStream feeding the internal decoder
   *
   * Typical usage:
   *
   *   // SFU-style: read chunks, forward elsewhere, no decode
   *   var { readable } = receiver.createEncodedStreams();
   *   var reader = readable.getReader();
   *   while (true) {
   *     var { done, value: chunk } = await reader.read();
   *     if (done) break;
   *     forwardToPeer(chunk);
   *   }
   *
   *   // Transform-style (e.g. E2EE): modify chunks, then decode
   *   var { readable, writable } = receiver.createEncodedStreams();
   *   readable.pipeThrough(decryptTransform).pipeTo(writable);
   *
   *   // Pass-through: no-op
   *   readable.pipeTo(writable);
   *
   * Per spec, this method can only be called once per receiver, and should
   * be called before any packets arrive (otherwise early chunks are lost to
   * the default auto-decode pipe).
   */
  var _encodedStreamsTaken = false;
  this.createEncodedStreams = function() {
    // W3C §11.3.4 — createEncodedStreams may be called only once per
    // receiver lifetime. Second call is InvalidStateError.
    if (_encodedStreamsTaken) {
      var err = new DOMException('createEncodedStreams: already called', 'InvalidStateError');
      throw err;
    }
    if (!pipeline || typeof pipeline.takeStreams !== 'function') {
      var e2 = new DOMException('createEncodedStreams: pipeline not ready (no track yet?)', 'InvalidStateError');
      throw e2;
    }
    _encodedStreamsTaken = true;
    return pipeline.takeStreams();
  };

  impl.getParameters = function() {
    // WPT harvest: receiver params expose the receive codecs (with
    // mimeType) even pre-media — mirrored from static capabilities.
    var _rxKind = (internalTransceiver && internalTransceiver.kind) ||
                  (track && track.kind) || kind || 'audio';
    var _rxCodecs = (_codecsFromSdp(manager, _rxKind, internalTransceiver && internalTransceiver.mid) || _defaultCodecs(_rxKind));

    // W3C §5.3.1.4: returns RTCRtpReceiveParameters describing what the
    // receiver is currently configured to consume — derived from the
    // negotiated SDP, not from any "preferences" (receivers don't have
    // setParameters; their config comes from the most recent SDP
    // exchange).
    //
    // Shape:
    //   { headerExtensions: [{uri, id}], rtcp: {cname, reducedSize}, codecs: [...] }
    //
    // Encodings: per the latest spec draft, receivers don't expose
    // `encodings` (it was removed in 2022 — too implementation-defined
    // for receive side). However many implementations still return an
    // empty array for backward compat with tests; we do the same.
    //
    // Source of truth: pc.currentLocalDescription. After SDP exchange,
    // this contains our agreed extmap, codec table, and SSRC declarations
    // for each m-section. We look up the m-section by mid and read
    // headerExtensions, codecs, and rtcp.cname from it.

    var result = {
      headerExtensions: [],
      // W3C 5.3: RTCRtpReceiveParameters.rtcp carries reducedSize ONLY —
      // cname belongs to the SENDER's parameters (it names the local
      // source), and reporting it here failed every receive-side
      // dictionary-shape assertion.
      rtcp:             { reducedSize: false },
      codecs:           [],
      encodings:        [],   // back-compat (see above)
    };

    var mid = internalTransceiver && internalTransceiver.mid;
    if (mid == null) return result;

    // currentLocalDescription is the most recently committed SDP. Before
    // the first successful setLocalDescription it's null — we return the
    // empty shape (per spec, calling getParameters before negotiation
    // returns "the current parameters", which are nothing yet).
    //
    // Read the already-parsed view (parsedCurrentLocalSdp), maintained
    // by sdp_offer_answer.js's _commitDescription. Re-parsing the raw
    // SDP string on every getParameters call would be both a perf bug
    // (SDP parsing is non-trivial) and a separation-of-concerns leak
    // (api.js is a thin W3C wrapper, not an SDP-parsing layer).
    var parsed = manager.state && manager.state.parsedCurrentLocalSdp;
    if (!parsed || !parsed.media) return result;

    var section = null;
    for (var i = 0; i < parsed.media.length; i++) {
      if (String(parsed.media[i].mid) === String(mid)) {
        section = parsed.media[i];
        break;
      }
    }
    if (!section) return result;

    // headerExtensions — copy {uri, id, encrypted?} from the negotiated
    // extmap. Each entry is a fresh object so caller can't mutate state.
    if (Array.isArray(section.extensions)) {
      for (var ei = 0; ei < section.extensions.length; ei++) {
        var ext = section.extensions[ei];
        var entry = { uri: ext.uri, id: ext.id };
        if (ext.encrypted) entry.encrypted = true;
        result.headerExtensions.push(entry);
      }
    }

    // codecs — copy from the negotiated codec list. Each codec entry per
    // spec includes {payloadType, mimeType, clockRate, channels?,
    // sdpFmtpLine?}. sdp.js's extractCodecs returns objects already in
    // close-to-spec shape; we normalize/filter the fields we expose.
    if (Array.isArray(section.codecs)) {
      for (var ci = 0; ci < section.codecs.length; ci++) {
        var c = section.codecs[ci];
        var codecOut = {
          payloadType: c.payloadType,
          // sdp.js rtpmap entries carry the bare codec name; compose the
          // spec mimeType (kind/name) when the prefixed form is absent.
          mimeType:    c.mimeType ||
                       ((section.type || 'audio') + '/' + (c.name || c.codec || '')),
          clockRate:   c.clockRate,
        };
        if (c.channels)    codecOut.channels = c.channels;
        if (c.sdpFmtpLine) codecOut.sdpFmtpLine = c.sdpFmtpLine;
        // fmtp: the parser folds it into an OBJECT — serialize to the
        // spec's sdpFmtpLine string form.
        if (c.fmtp && typeof c.fmtp === 'object') {
          var _kv = [];
          // Same rule as the receiver-side rebuild above: a bare fmtp
          // parameter (telephone-event's `0-15`) is stored as key -> true and
          // must be emitted as the key alone, not `0-15=true`.
          for (var _fk in c.fmtp) {
            _kv.push(c.fmtp[_fk] === true ? _fk : (_fk + '=' + c.fmtp[_fk]));
          }
          if (_kv.length) codecOut.sdpFmtpLine = _kv.join(';');
        } else if (typeof c.fmtp === 'string' && c.fmtp) {
          codecOut.sdpFmtpLine = c.fmtp;
        }
        result.codecs.push(codecOut);
        // rtx is folded into rtxPayloadType — re-expand as its own entry
        // (interleaved right after its primary, matching our SDP order).
        if (c.rtxPayloadType != null) {
          result.codecs.push({
            payloadType: c.rtxPayloadType,
            mimeType: (section.type || 'video') + '/rtx',
            clockRate: c.clockRate,
            sdpFmtpLine: 'apt=' + c.payloadType,
          });
        }
      }
    }

    // rtcp.cname is deliberately NOT reported for receivers: W3C 5.3
    // defines RTCRtpReceiveParameters.rtcp with reducedSize only, and
    // WPT asserts the member is unset. (The remote CNAME is still parsed
    // and used internally for RTCP; it is simply not part of this
    // dictionary.)

    return result;
  };

  impl.getContributingSources = function() {
    // QUICK-7: W3C §5.3.4. Returns RTCRtpContributingSource entries for
    // CSRC values seen in incoming RTP packets within the last 10 seconds.
    // The cache is maintained by connection_manager.js's
    // handleIncomingRtpInner — api.js just reads it, filters by spec
    // freshness window, dedupes, sorts.
    //
    // Per spec:
    //   • Each unique CSRC value appears at most once (newest sighting wins).
    //   • Sorted by timestamp descending (most recent first).
    //   • audioLevel field is optional — present only when available
    //     (RFC 6465 csrc-audio-level extension; not wired yet).
    //
    // Returned objects are fresh — caller mutations don't bleed into our cache.
    var entries = (internalTransceiver && internalTransceiver.receiver &&
                   internalTransceiver.receiver._csrcEntries) || [];
    if (!entries.length) return [];

    // Absolute clock, matching how media_transport stamps the entries — see
    // the note in getSynchronizationSources.
    var nowWall = (typeof performance !== 'undefined' && performance.now)
                  ? ((performance.timeOrigin || 0) + performance.now())
                  : Date.now();
    var cutoff = nowWall - 10000;

    // Dedupe by source, keep newest. Use plain object keyed by source —
    // CSRCs are 32-bit unsigned, safely indexable as string keys.
    var bySource = Object.create(null);
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      if (e.timestamp < cutoff) continue;
      var key = String(e.source);
      if (!bySource[key] || bySource[key].timestamp < e.timestamp) {
        bySource[key] = e;
      }
    }

    // Build output array with fresh objects.
    var result = [];
    var keys = Object.keys(bySource);
    for (var j = 0; j < keys.length; j++) {
      var src = bySource[keys[j]];
      var out = {
        source:       src.source,
        timestamp:    src.timestamp,
        rtpTimestamp: src.rtpTimestamp,
      };
      if (src.audioLevel !== undefined) out.audioLevel = src.audioLevel;
      result.push(out);
    }

    // Spec: most recent first.
    result.sort(function(a, b) { return b.timestamp - a.timestamp; });
    return result;
  };

  impl.getSynchronizationSources = function() {
    // W3C §5.3.5. Returns an RTCRtpSynchronizationSource for each SSRC
    // this receiver currently sees, restricted to the last 10 seconds.
    // For non-simulcast: typically one entry. For simulcast: one entry
    // per layer SSRC.
    //
    // Cache is maintained by connection_manager.js's
    // handleIncomingRtpInner (alongside the CSRC tracker). api.js
    // filters by spec freshness window and returns fresh objects.
    //
    // audioLevel field is optional per spec — present only when the RFC
    // 6464 ssrc-audio-level extension has populated it (not wired yet,
    // see ROADMAP RTP-5).
    var entries = (internalTransceiver && internalTransceiver.receiver &&
                   internalTransceiver.receiver._ssrcEntries) || null;
    if (!entries) return [];

    var nowWall = (typeof performance !== 'undefined' && performance.now)
                  ? performance.now()
                  : Date.now();
    var cutoff = nowWall - 10000;

    var result = [];
    var keys = Object.keys(entries);
    for (var i = 0; i < keys.length; i++) {
      var e = entries[keys[i]];
      if (e.timestamp < cutoff) continue;
      var out = {
        source:       e.source,
        timestamp:    e.timestamp,
        rtpTimestamp: e.rtpTimestamp,
        // W3C: audioLevel is LINEAR 0..1 (1.0 = 0 dBov). Convert from the
        // cached RFC 6464 dBov (0 loud .. 127 silent): 10^(-dbov/20).
        audioLevel: (e.audioLevelDbov != null)
          ? Math.pow(10, -e.audioLevelDbov / 20)
          : undefined,
        voiceActivityFlag: (e.audioLevelDbov != null) ? e.voiceActivity : undefined,
      };
      if (e.audioLevel !== undefined) out.audioLevel = e.audioLevel;
      result.push(out);
    }
    // Spec: most recent first.
    result.sort(function(a, b) { return b.timestamp - a.timestamp; });
    return result;
  };

impl.getStats = function() {
    // W3C 8.2: getStats() is ASYNCHRONOUS and does not use the
    // operations chain — the report must still be pending after a
    // microtask (WPT checks exactly that on senders and receivers, the
    // same rule pc.getStats already follows). Assemble on the next task.
    var _gsSelf = this, _gsArgs = arguments;
    // Sample "is the transceiver stopped" AT CALL TIME, not when the report is
    // assembled. Assembly is deferred by a task, and an application may stop
    // the transceiver in between:
    //
    //   const p = receiver.getStats();   // still live here
    //   transceiver.stop();
    //   await p;                         // must reflect the live moment
    //
    // Reading the flag during assembly made both reports look stopped, so the
    // first one lost its inbound-rtp. WPT checks exactly this pair.
    var _stoppedAtCall = internalTransceiver && RtpManager.isStopped(internalTransceiver);
    return new Promise(function (res, rej) {
      setTimeout(function () {
        try { res(_getStatsNow0.call(_gsSelf, _stoppedAtCall)); } catch (e) { rej(e); }
      }, 0);
    });
  };
  function _getStatsNow0(_stoppedAtCall) {
    // WPT: a live receiver ALWAYS reports an inbound-rtp entry (zeros
    // pre-media); a stopped transceiver reports none.
    // A closed PeerConnection has no live streams either, so it reports no
    // inbound-rtp — same rule as a stopped transceiver.
    var _closed = !!(manager && manager.state && manager.state.closed);
    var _stopped = _closed || ((_stoppedAtCall != null)
      ? _stoppedAtCall
      : (internalTransceiver && RtpManager.isStopped(internalTransceiver)));
    var _base = new Map();
    if (!_stopped) {
      var _sid = 'RTCInboundRTPStream_' + (internalTransceiver && internalTransceiver.mid || '0');
      _base.set(_sid, {
        id: _sid, type: 'inbound-rtp', timestamp: Date.now(),
        kind: (internalTransceiver && internalTransceiver.kind) || kind || 'audio',
        ssrc: 0, packetsReceived: 0, bytesReceived: 0, packetsLost: 0, jitter: 0,
      });
    }
    // Spec: returns stats for this receiver's inbound stream. The ssrc comes
    // from the transceiver's remote SSRC mapping. If the receiver hasn't been
    // wired to an SSRC yet (track:new hasn't fired), returns an empty report.
    var ssrc = findRemoteSsrc();
    // Stopped or closed: never surface an inbound-rtp, whatever the full
    // report would otherwise contain.
    if (_stopped) return Promise.resolve(_base);
    if (ssrc == null) return Promise.resolve(_base);   // zeros-report pre-media

    // The full report REPLACED the zeros entry, and it only contains an
    // inbound-rtp once packets have actually arrived. Between "the receiver is
    // wired to an SSRC" and "the first packet lands" the report therefore had
    // no inbound-rtp at all — a live receiver reporting nothing about its own
    // stream. WPT reads receiver.getStats() as soon as the track unmutes,
    // which is inside exactly that window.
    //
    // Merge instead: take the full report, and keep the zeros entry only if it
    // brought no inbound-rtp of its own.
    var _full = _buildStatsReport(manager, { ssrc: ssrc });
    var _hasInbound = false;
    _full.forEach(function (r) { if (r && r.type === 'inbound-rtp') _hasInbound = true; });
    if (!_hasInbound) {
      _base.forEach(function (v, k) { _full.set(k, v); });
    }
    return Promise.resolve(_full);
  };

  // ─── API-9 extension: per-layer track + encoded-stream access ──────────
  //
  // NOT in the W3C spec — Chrome doesn't expose this. We need it so apps
  // building on webrtc-server (especially SFU-style relays) can see
  // multiple simulcast layers in parallel and forward encoded chunks
  // without spinning up a decoder.
  //
  // Compatibility: receiver.track still returns the primary layer (the
  // first rid in SDP order, or the only layer for non-simulcast). Apps
  // that only know about receiver.track keep working unchanged. The
  // tracks Map and getLayerEncodedStreams() are opt-in extensions.

  /**
   * Map<rid, MediaStreamTrack> of all simulcast layers.
   *
   *   - Non-simulcast m-section: Map of size 1, key = ''.
   *   - Simulcast m-section: one entry per layer. Key is the rid string
   *     from SDP. Layers learned at runtime (RID header extension before
   *     a=rid was negotiated) appear under a synthetic 'ssrc-<N>' key
   *     until their rid is learned, then re-keyed.
   *
   * Each track follows the same lazy-decode rule as receiver.track:
   * the layer's decoder runs only when at least one sink (VideoSink,
   * MediaRecorder, etc.) is attached — mirroring Chrome's per-track
   * decoder optimization.
   *
   * Returns an EMPTY Map if the pipeline isn't running yet (negotiation
   * incomplete or no SSRCs known). Callers should re-query after the
   * `track` event fires on the RTCPeerConnection.
   */
  Object.defineProperty(this, 'tracks', {
    get: function () {
      if (pipeline && typeof pipeline.getLayerTracks === 'function') {
        return pipeline.getLayerTracks();
      }
      // No pipeline yet — fall back to a Map containing just receiver.track,
      // so the shape is predictable even before the track event fires.
      var fallback = new Map();
      if (self.track) fallback.set('', self.track);
      return fallback;
    },
  });

  /**
   * Map<rid, ReadableStream<EncodedVideoChunk>> of per-layer encoded
   * chunk streams. Useful for SFU-style forwarding where the app pipes
   * encoded chunks from this receiver into a remote sender's writable
   * — no decode runs in between, since the lazy-decode skips when no
   * sink is attached to the layer's track.
   *
   * Returns an empty Map if the pipeline isn't running yet.
   *
   * Each ReadableStream is bounded; if the consumer doesn't read fast
   * enough, oldest chunks are dropped. Single subscriber per stream
   * (a ReadableStream's reader is exclusive). To fan out, the app
   * should use stream.tee() and pipe each branch separately.
   */
  this.getLayerEncodedStreams = function () {
    if (pipeline && typeof pipeline.getLayerEncodedStreams === 'function') {
      return pipeline.getLayerEncodedStreams();
    }
    return new Map();
  };
}

RTCRtpReceiver.getCapabilities = function(kind) {
  // W3C 5.2/5.3: an unrecognised kind returns NULL — only 'audio' and
  // 'video' have capabilities. We were falling through to a default
  // table and reporting codecs for kinds that do not exist.
  if (kind !== 'audio' && kind !== 'video') return null;
  return RTCRtpSender.getCapabilities(kind);
};


/* ========================= RTCRtpTransceiver ========================= */

RTCRtpReceiver.prototype.getParameters = function () { return this._impl.getParameters.apply(this, arguments); };
Object.defineProperty(RTCRtpReceiver.prototype.getParameters, 'length', { value: 0 });
Object.defineProperty(RTCRtpReceiver.prototype.getParameters, 'name', { value: 'getParameters' });
RTCRtpReceiver.prototype.getContributingSources = function () { return this._impl.getContributingSources.apply(this, arguments); };
Object.defineProperty(RTCRtpReceiver.prototype.getContributingSources, 'length', { value: 0 });
Object.defineProperty(RTCRtpReceiver.prototype.getContributingSources, 'name', { value: 'getContributingSources' });
RTCRtpReceiver.prototype.getSynchronizationSources = function () { return this._impl.getSynchronizationSources.apply(this, arguments); };
Object.defineProperty(RTCRtpReceiver.prototype.getSynchronizationSources, 'length', { value: 0 });
Object.defineProperty(RTCRtpReceiver.prototype.getSynchronizationSources, 'name', { value: 'getSynchronizationSources' });
RTCRtpReceiver.prototype.getStats = function () { return this._impl.getStats.apply(this, arguments); };
Object.defineProperty(RTCRtpReceiver.prototype.getStats, 'length', { value: 0 });
Object.defineProperty(RTCRtpReceiver.prototype.getStats, 'name', { value: 'getStats' });

function RTCRtpTransceiver(internal, manager) {
  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  this._internal = internal;
  this._sender = new RTCRtpSender(internal, internal.sender.track, manager);
  this._receiver = new RTCRtpReceiver(internal.receiver.track, internal.kind, manager, internal);
  var self = this;

  Object.defineProperty(this, 'mid', {
    // W3C §5.4.2: mid is null until the m-section's mid is established
    // (post-SDP exchange). Coerce undefined to null defensively.
    get: function() {
      // Association is earned (SRD-creation, adoption, or local-offer
      // binding) — the same single rule every internal selector uses.
      return (RtpManager.isLegitimateOwner(internal) && internal.mid != null)
        ? String(internal.mid) : null;
    },
  });
  Object.defineProperty(this, 'sender', {
    get: function() { return self._sender; },
  });
  Object.defineProperty(this, 'receiver', {
    get: function() { return self._receiver; },
  });
  Object.defineProperty(this, 'kind', {
    get: function() { return internal.kind; },
  });
  Object.defineProperty(this, 'currentDirection', {
    get: function() {
      // W3C §5.4.2: currentDirection is null until the transceiver
      // has participated in offer/answer; after that, mirrors the
      // negotiated direction. Coerce undefined → null defensively.
      return internal.currentDirection != null ? internal.currentDirection : null;
    },
  });
  // Deprecated 'stopped' boolean (still in MDN, removed from W3C spec —
  // apps that detect "is this transceiver still alive?" check this).
  // Equivalent to currentDirection === 'stopped'.
  Object.defineProperty(this, 'stopped', {
    get: function() { return RtpManager.isStopped(internal); },
  });
  // 'stopped' is a valid currentDirection but NOT a valid value to set
  // directly — apps reach it only via transceiver.stop().
  var VALID_SET_DIRECTIONS = ['sendrecv', 'sendonly', 'recvonly', 'inactive'];
  Object.defineProperty(this, 'direction', {
    get: function() {
      return RtpManager.isStopped(internal) ? 'stopped' : internal.direction;
    },
    set: function(dir) {
      if (VALID_SET_DIRECTIONS.indexOf(dir) < 0) {
        throw new TypeError('Invalid RTCRtpTransceiverDirection: ' + dir +
          ' (use transceiver.stop() to stop)');
      }
      // W3C §5.5.4.4: reject if the transceiver has been stopped.
      if (RtpManager.isStopped(internal)) {
        var err = new DOMException('Cannot set direction on a stopped transceiver', 'InvalidStateError');
        throw err;
      }
      if (dir === internal.direction) return;   // no-op, spec: don't fire
      internal.direction = dir;
      // A transceiver created by setRemoteDescription is born with no SSRC —
      // it was receive-only at birth. Turning it into a sender is ordinary
      // answerer behaviour (remote offers recvonly, we answer by sending), so
      // allocate one now. Without this the SDP said a=sendonly while carrying
      // no a=ssrc, and nothing was ever transmitted. Idempotent.
      if (dir === 'sendrecv' || dir === 'sendonly') {
        RtpManager.ensureSendSsrc(manager.state, internal);
      }
      // WPT harvest — muted transitions: the receiver's track mutes when
      // the transceiver stops receiving and unmutes when receiving is
      // (re-)enabled, EVEN before media flows.
      try {
        var rTrack = self._receiver && self._receiver.track;
        if (rTrack) {
          var willRecv = dir === 'sendrecv' || dir === 'recvonly';
          if (willRecv && rTrack.muted) {
            rTrack.muted = false;
            try { rTrack.dispatchEvent && rTrack.dispatchEvent({ type: 'unmute' }); } catch (e1) {}
          } else if (!willRecv && !rTrack.muted) {
            rTrack.muted = true;
            try { rTrack.dispatchEvent && rTrack.dispatchEvent({ type: 'mute' }); } catch (e3) {}
          }
        }
      } catch (eMut) {}
      // W3C §5.3: setting direction fires negotiationneeded (debounced in cm.js).
      manager.updateNegotiationNeededFlag();
    },
  });

  impl.stop = function() {
    // W3C 5.4: stopping a transceiver whose connection is closed is an
    // InvalidStateError — the transceiver can no longer renegotiate.
    if (manager.state.closed) {
      throw new DOMException('transceiver.stop: peer connection is closed', 'InvalidStateError');
    }
    // WPT: a stopped transceiver reports 'stopped' as its currentDirection.
    // W3C 5.4: stop() sets DIRECTION to 'stopped' immediately;
    // currentDirection stays null until a negotiation actually retires
    // the m-section (WPT reads {currentDirection: null,
    // direction: 'stopped'} right after stop()). Internal guards test
    // direction too, so the stopped state is still enforced everywhere.
    // W3C §5.4.3.6 — mark transceiver as stopped, stop both directions,
    // fire negotiationneeded (the stop propagates via SDP renegotiation
    // which sets port=0 on the m-line to signal the peer).
    if (RtpManager.isStopped(internal)) return;   // idempotent
    // Tear down send pipeline (if any)
    if (self._sender && typeof self._sender._stop === 'function') {
      try { self._sender._stop(); } catch (e) {}
    }
    // Tear down receive pipeline (if any)
    if (self._receiver && typeof self._receiver._stop === 'function') {
      try { self._receiver._stop(); } catch (e) {}
    }
    // Cleanup per-layer RID mappings from the stamper — otherwise stale
    // SSRC→RID entries accumulate across transceiver lifecycles (each
    // addTransceiver → stop → addTransceiver leaks layers.length entries).
    // Stamper keeps session-wide state (transport-cc counter), but its
    // RID maps are strictly per-layer. Implementation lives on
    // MediaTransport via manager.unregisterTransceiverLayer.
    if (internal.sender && internal.sender.layers) {
      for (var li = 0; li < internal.sender.layers.length; li++) {
        manager.unregisterTransceiverLayer(internal.sender.layers[li]);
      }
    }
    // W3C 5.4: stop() sets DIRECTION to 'stopped' immediately;
    // currentDirection stays null until a negotiation actually retires
    // the m-section (WPT reads {currentDirection: null,
    // direction: 'stopped'} right after stop()). Internal guards test
    // direction too, so the stopped state is still enforced everywhere.
    internal.direction = 'stopped';

    // W3C 5.4.3.6 step 5: stopping a transceiver ENDS both of its tracks.
    // The receiver's track will never carry media again, and the sender's is
    // released back to the application — so both move to readyState 'ended'
    // and fire 'ended'. Leaving them 'live' meant an application watching for
    // that event on a stopped transceiver waited forever, and any code
    // branching on readyState saw a track that looked usable.
    //
    // Only the RECEIVER's track is ended by us. The sender's track belongs to
    // the application — it may have handed the same MediaStreamTrack to
    // another connection — so we detach it rather than ending it.
    // ASYNCHRONOUSLY. W3C 5.4.3.6 queues a task to end the track, and the
    // difference is observable — the track must still read 'live' on the line
    // right after stop() returns, and only then flip:
    //
    //   transceiver.stop();
    //   assert_equals(track.readyState, 'live');    // still live here
    //   await trackEnded;
    //   assert_equals(track.readyState, 'ended');
    //
    // Ending it inline made the first assertion fail.
    try {
      var _rt = self._receiver && self._receiver.track;
      if (_rt && _rt.readyState !== 'ended') {
        setTimeout(function () {
          try {
            if (_rt.readyState === 'ended') return;
            if (typeof _rt.stop === 'function') {
              // stop() sets readyState AND fires 'ended' — dispatching again
              // would deliver the event twice (same trap as fix 23).
              _rt.stop();
            } else {
              _rt.readyState = 'ended';
              try { _rt.dispatchEvent && _rt.dispatchEvent({ type: 'ended' }); } catch (eE1) {}
            }
          } catch (eE2) { /* never throw from a queued task */ }
        }, 0);
      }
    } catch (eEnd) { /* stop() must never throw */ }

    manager.updateNegotiationNeededFlag();
  };

  impl.setCodecPreferences = function(codecs) {
    // W3C: every codec must be drawn from the capabilities OF THIS KIND
    // (mimeType prefix must match) — anything else is
    // InvalidModificationError.
    if (Array.isArray(codecs) && codecs.length) {
      var _kindPfx = internal.kind + '/';
      var _caps = [];
      try { _caps = (RTCRtpSender.getCapabilities(internal.kind) || {}).codecs || []; } catch (eC) {}
      for (var _ci = 0; _ci < codecs.length; _ci++) {
        var _cc = codecs[_ci];
        var _mt = _cc && _cc.mimeType;
        var _okKind = typeof _mt === 'string' && _mt.toLowerCase().indexOf(_kindPfx) === 0;
        var _known = _okKind && _caps.some(function (k) {
          return k.mimeType.toLowerCase() === _mt.toLowerCase() &&
                 k.clockRate === _cc.clockRate &&
                 (k.channels || undefined) === (_cc.channels || undefined) &&
                 (k.sdpFmtpLine || undefined) === (_cc.sdpFmtpLine || undefined);
        });
        if (!_okKind || (!_known && !/^(audio|video)\/(rtx|red|ulpfec)$/i.test(_mt))) {
          throw new DOMException('setCodecPreferences: codec ' + _mt + ' is not in this kind\'s capabilities', 'InvalidModificationError');
        }
      }
    }
    // W3C §5.4.3.8 — store an ordered list of codecs for this transceiver.
    // On the next createOffer/createAnswer, codecs in the m-section are
    // ordered per this preference (consumed in connection_manager.js's
    // SDP build path via internal._codecPreferences).
    //
    // An empty array resets to default preferences.
    if (codecs == null) {
      internal._codecPreferences = null;
      return;
    }
    if (!Array.isArray(codecs)) {
      throw new TypeError('setCodecPreferences: expected sequence of RTCRtpCodecCapability');
    }
    // Validate each entry has the minimum shape (mimeType, clockRate)
    for (var i = 0; i < codecs.length; i++) {
      var c = codecs[i];
      if (!c || typeof c.mimeType !== 'string' || typeof c.clockRate !== 'number') {
        throw new TypeError('setCodecPreferences: codec[' + i +
                            '] must have mimeType (string) and clockRate (number)');
      }
    }

    // W3C §5.4.3.8 step 5: an empty list (codecs.length === 0) resets to
    // defaults — that's already handled above. But a non-empty list that
    // contains ONLY auxiliary codecs (RTX, RED, FEC, CN) is invalid —
    // there must be at least one media codec.
    var AUX_TYPES = /^(audio|video)\/(rtx|red|ulpfec|flexfec|cn|telephone-event)$/i;
    if (codecs.length > 0) {
      var hasMediaCodec = false;
      for (var k = 0; k < codecs.length; k++) {
        if (!AUX_TYPES.test(codecs[k].mimeType)) {
          hasMediaCodec = true;
          break;
        }
      }
      if (!hasMediaCodec) {
        var modErr = new DOMException(
          'setCodecPreferences: list contains only auxiliary codecs (RTX/RED/FEC/CN); ' +
          'must include at least one media codec'
        , 'InvalidModificationError');
        throw modErr;
      }
    }

    // W3C §5.4.3.8 step 6: every codec must be one the receiver supports
    // for our kind. Compare against RTCRtpReceiver.getCapabilities(kind).
    // Mismatch = InvalidAccessError. We compare on (mimeType, clockRate)
    // — channels/sdpFmtpLine differences are not blocking here.
    var supported = null;
    try {
      // RTCRtpReceiver is in scope at module level; getCapabilities is static.
      supported = (typeof RTCRtpReceiver !== 'undefined' && RTCRtpReceiver.getCapabilities)
        ? RTCRtpReceiver.getCapabilities(internal.kind)
        : null;
    } catch (e) { supported = null; }
    if (supported && Array.isArray(supported.codecs)) {
      for (var ci = 0; ci < codecs.length; ci++) {
        var want = codecs[ci];
        var found = false;
        for (var si = 0; si < supported.codecs.length; si++) {
          var have = supported.codecs[si];
          if (have.mimeType.toLowerCase() === want.mimeType.toLowerCase() &&
              have.clockRate === want.clockRate) {
            found = true;
            break;
          }
        }
        if (!found) {
          var unsupErr = new DOMException(
            'setCodecPreferences: codec "' + want.mimeType + '" @ ' +
            want.clockRate + ' Hz is not supported by the receiver'
          , 'InvalidAccessError');
          throw unsupErr;
        }
      }
    }

    internal._codecPreferences = codecs.slice();
    // Per spec, setCodecPreferences fires negotiationneeded (the change
    // only takes effect on next SDP round).
    manager.updateNegotiationNeededFlag();
  };
}


/* ========================= RTCDataChannel ========================= */

RTCRtpTransceiver.prototype.stop = function () { return this._impl.stop.apply(this, arguments); };
Object.defineProperty(RTCRtpTransceiver.prototype.stop, 'length', { value: 0 });
Object.defineProperty(RTCRtpTransceiver.prototype.stop, 'name', { value: 'stop' });
RTCRtpTransceiver.prototype.setCodecPreferences = function () { return this._impl.setCodecPreferences.apply(this, arguments); };
Object.defineProperty(RTCRtpTransceiver.prototype.setCodecPreferences, 'length', { value: 1 });
Object.defineProperty(RTCRtpTransceiver.prototype.setCodecPreferences, 'name', { value: 'setCodecPreferences' });

function RTCDataChannel(internal, manager) {
  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  var self = this;
  // manager is optional for backward compat; without it, maxMessageSize
  // checks fall back to the WebRTC default of 256KB.

  // Read-only properties
  Object.defineProperty(this, 'id', {
    // W3C/WPT: id is NULL until the DCEP handshake assigns it — unless
    // the app pre-negotiated (negotiated:true carries the app's id).
    get: function() {
      // null until an id is ACTUALLY assigned (DCEP-open send time) —
      // not until 'open': post-SCTP channels get their id before the
      // handshake round-trip completes (RFC 8832 parity allocator).
      return internal.id == null ? null : internal.id;
    },
  });
  Object.defineProperty(this, 'label', {
    get: function() { return internal.label; },
  });
  Object.defineProperty(this, 'protocol', {
    get: function() { return internal.protocol; },
  });
  Object.defineProperty(this, 'ordered', {
    get: function() { return internal.ordered; },
  });
  Object.defineProperty(this, 'maxRetransmits', {
    get: function() { return internal.maxRetransmits; },
  });
  Object.defineProperty(this, 'maxPacketLifeTime', {
    get: function() { return internal.maxPacketLifeTime; },
  });
  Object.defineProperty(this, 'negotiated', {
    get: function() { return internal.negotiated; },
  });
  Object.defineProperty(this, 'priority', {
    // W3C §6.2.1 RTCPriorityType: 'very-low'|'low'|'medium'|'high'.
    // Default 'low'. Currently informational only — SCTP scheduling
    // doesn't use it (single association, single send order). Stored
    // for round-trip with createDataChannel options.
    get: function() { return internal.priority || 'low'; },
  });
  Object.defineProperty(this, 'readyState', {
    get: function() { return internal.readyState; },
  });
  Object.defineProperty(this, 'bufferedAmount', {
    get: function() { return internal.bufferedAmount; },
  });

  // Writable properties
  this.binaryType = 'arraybuffer';

  // bufferedAmountLowThreshold: proxy to the internal channel object
  // so cm.js's chunkAcked handler (which fires the bufferedamountlow
  // event) sees the user's chosen threshold. Pre-fix the wrapper held
  // its own copy that the firing path never read — `dc.bufferedAmountLowThreshold = 5000`
  // silently no-op'd from the user's perspective.
  Object.defineProperty(this, 'bufferedAmountLowThreshold', {
    get: function() { return internal.bufferedAmountLowThreshold; },
    set: function(v) {
      // W3C §6.2: must be unsigned long. Coerce + reject negatives.
      var n = +v;
      if (!Number.isFinite(n) || n < 0) {
        throw new TypeError('bufferedAmountLowThreshold must be a non-negative number');
      }
      internal.bufferedAmountLowThreshold = n >>> 0;   // uint32
    },
  });

  // Methods
  impl._sendQ = Promise.resolve();
  impl.send = function(data) {
    // W3C §6.2: must throw InvalidStateError unless readyState === 'open'.
    // 'connecting' → not yet negotiated; 'closing'/'closed' → gone.
    if (internal.readyState !== 'open') {
      var err = new DOMException('RTCDataChannel.send: readyState is "' +
                          internal.readyState + '", not "open"', 'InvalidStateError');
      throw err;
    }

    // W3C §6.2.4 — accepted types: string, Blob, ArrayBuffer, ArrayBufferView.
    // Node 18+ has a global Blob; we detect it by feature (rather than
    // reference) so the check works whether the host has Blob or not.
    var isBlob = (data != null && typeof data === 'object' &&
                  typeof data.arrayBuffer === 'function' &&
                  typeof data.size === 'number');
    // W3C: bufferedAmount increases SYNCHRONOUSLY in send() by the
    // message's byte length (utf-8 for strings, size for Blobs). The
    // drain side stays ack-driven in the SCTP layer.
    var _sendBytes = 0;
    if (typeof data === 'string') _sendBytes = Buffer.byteLength(data, 'utf8');
    else if (isBlob)             _sendBytes = data.size;
    else if (data && typeof data.byteLength === 'number') _sendBytes = data.byteLength;
    internal.bufferedAmount = (internal.bufferedAmount || 0) + _sendBytes;
    if (isBlob) {
      // Sync size check against maxMessageSize (W3C §6.2.4).
      var blobSize = data.size;
      var actualMaxBlob = (manager && manager.state && manager.state.maxMessageSize)
        ? manager.state.maxMessageSize
        : 262144;
      if (blobSize > actualMaxBlob) {
        throw new TypeError('RTCDataChannel.send: Blob size ' + blobSize +
          ' exceeds sctp.maxMessageSize (' + actualMaxBlob + ')');
      }
      // Read async, then route through internal.send so cm.js's chunkSent
      // owns bufferedAmount accounting (no double-count). NOTE: spec says
      // bufferedAmount should bump synchronously here even before the
      // Blob is read; we accept the "looks zero until Blob resolves" gap
      // because the async read is unavoidable and stays inside the same
      // task.
      // ORDER-PRESERVING (real-bug fix): later sends must NOT overtake a
      // pending Blob conversion — the conversion rides the channel queue.
      impl._sendQBusy = (impl._sendQBusy || 0) + 1;
      impl._sendQ = impl._sendQ.then(function () { return data.arrayBuffer(); }).then(function (ab) {
        if (internal.readyState !== 'open') return;
        impl._sendQBusy = Math.max(0, (impl._sendQBusy || 1) - 1);
        try { internal.send(Buffer.from(ab)); }
        catch (e) {
          if (typeof console !== 'undefined' && console.error) {
            console.error('[RTCDataChannel] Blob send failed:', e && e.message || e);
          }
        }
      }).catch(function (e) {
        if (typeof console !== 'undefined' && console.error) {
          console.error('[RTCDataChannel] Blob.arrayBuffer() failed:', e && e.message || e);
        }
      });
      return;
    }

    // Compute byte length BEFORE send. cm.js bumps bufferedAmount via
    // its own chunkSent listener (fires synchronously inside sctp.send),
    // and decrements via chunkAcked when peer SACKs. Pre-fix the wrapper
    // ALSO bumped + scheduled-decrement, double-counting bufferedAmount
    // until the SACK arrived. The single-source-of-truth is cm.js; we
    // just use byteLen here for the maxMessageSize check.
    var byteLen = 0;
    if (typeof data === 'string') byteLen = Buffer.byteLength(data, 'utf8');
    else if (data && data.byteLength != null) byteLen = data.byteLength;
    else if (data && data.length != null) byteLen = data.length;

    // W3C §6.2.4 step 5: if byteLen > sctp.maxMessageSize, throw TypeError.
    var actualMax = (manager && manager.state && manager.state.maxMessageSize)
      ? manager.state.maxMessageSize
      : 262144;   // RFC 8831 default
    if (byteLen > actualMax) {
      throw new TypeError('RTCDataChannel.send: message length ' + byteLen +
        ' exceeds sctp.maxMessageSize (' + actualMax + ')');
    }

    // SYNCHRONOUS unless we are behind a Blob conversion.
    //
    // Everything used to ride impl._sendQ, so even a plain string send
    // was deferred a microtask — and "send(msg); close();" therefore ran
    // the CLOSE first: by the time the queued send reached the channel it
    // was already 'closing' and the message was dropped on the floor,
    // with the application having seen send() return normally. Blobs must
    // still queue (their bytes arrive asynchronously) and anything queued
    // behind them must stay in order, so the queue is used only while it
    // is actually busy.
    if (impl._sendQBusy) {
      impl._sendQ = impl._sendQ.then(function () {
        if (internal.readyState !== 'open' && internal.readyState !== 'closing') return;
        internal.send(data);
    });
    } else {
      if (internal.readyState === 'open' || internal.readyState === 'closing') {
        internal.send(data);
      }
    }
  };

  impl.close = function() {
    // Per RFC 8831 §6.7, close() issues an SCTP stream reset so the peer
    // learns the channel is gone. internal.close() should send a
    // DATA_CHANNEL_ACK/reset over the SCTP stream; the stream reset logic
    // itself lives in sctp.js. This call is a no-op if already closing/closed.
    if (internal.readyState === 'closed' || internal.readyState === 'closing') return;
    // W3C 6.2.5 + WPT close-test: the CLOSER transitions to 'closing'
    // silently — the closing EVENT belongs to the REMOTE side only
    // (fired in dcc when the incoming stream-reset arrives).

    internal.close();
  };

  // Event handler properties.
  //
  // The 'message' event needs to be wrapped: cm.js emits a plain
  // {data} payload, but W3C §6.2 expects a MessageEvent-like object
  // (event.type === 'message', event.data, event.target). We do this
  // wrapping at the api.js boundary by registering a single permanent
  // forwarder on internal._ev for 'message', and routing through both
  // the on-handler (set via .onmessage) and any addEventListener
  // listeners (kept in a separate Set).

  // 'message' event — wrap in MessageEvent-like shape and dispatch to
  // both .onmessage and any addEventListener('message', ...) listeners.
  var _onmessage = null;
  var _msgListeners = [];
  internal._ev.on('message', function (payload) {
    // binaryType 'blob' (WPT harvest): binary payloads are delivered as
    // Blob when the app asked for it — browser parity for the default-
    // in-browsers mode. Strings pass through untouched.
    // (blob conversion happens BELOW, after rawData extraction — wrapping
    // the payload ENVELOPE here produced a Blob of "[object Object]".)
    // Build a MessageEvent-shaped object. Real browsers use a global
    // MessageEvent constructor; in Node we hand-shape something
    // structurally equivalent so consumer code that does
    // `event.data` / `event.type` works either way.
    //
    // W3C §6.2 binaryType conversion: cm.js delivers Node Buffers for
    // binary frames; spec requires ArrayBuffer or Blob based on
    // self.binaryType. String frames bypass this — they're already
    // strings from the cm.js layer.
    var rawData = payload && 'data' in payload ? payload.data : payload;
    if (self.binaryType === 'blob' && rawData != null && typeof rawData !== 'string' &&
        typeof Blob !== 'undefined') {
      // wrap the ACTUAL bytes (Buffer/TypedArray/ArrayBuffer all fine)
      try { rawData = new Blob([rawData]); } catch (eB) {}
    }
    var data    = rawData;
    if (Buffer.isBuffer(rawData)) {
      if (self.binaryType === 'blob' && typeof Blob !== 'undefined') {
        data = new Blob([rawData]);
      } else {
        // Default + 'arraybuffer': hand back an ArrayBuffer. Buffer.buffer
        // is the underlying ArrayBuffer but may include unrelated bytes
        // when Buffer is a slice — slice it down explicitly.
        data = rawData.buffer.slice(
          rawData.byteOffset,
          rawData.byteOffset + rawData.byteLength
        );
      }
    }
    var event = {
      type:    'message',
      data:    data,
      target:  self,
      currentTarget: self,
      // origin/lastEventId/source/ports — these are rarely used on
      // datachannel messages but the spec lists them. Empty defaults.
      origin: '',
      lastEventId: '',
      source: null,
      ports:  [],
    };
    if (_onmessage) {
      try { _onmessage(event); } catch (e) {}
    }
    for (var li = 0; li < _msgListeners.length; li++) {
      try { _msgListeners[li](event); } catch (e) {}
    }
  });
  Object.defineProperty(self, 'onmessage', {
    get: function() { return _onmessage; },
    set: function(fn) { _onmessage = fn; },
  });

  // W3C §6.2 — RTCDataChannel exposes on-handler properties for every
  // event it can fire: open, close, closing, error, bufferedamountlow.
  // Apps frequently use these instead of addEventListener — without them
  // setting `dc.onopen = fn` would silently no-op while the underlying
  // _ev.emit('open') still happens and consumers would never see it.
  //
  // We bind each name lazily: setter wires/unwires on the internal
  // EventEmitter so swapping handlers cleans up.
  function _bindDCHandler(name) {
    var current = null;
    Object.defineProperty(self, 'on' + name, {
      get: function() { return current; },
      set: function(fn) {
        if (current) internal._ev.off(name, current);
        current = (typeof fn === 'function') ? fn : null;
        if (current) internal._ev.on(name, current);
      },
    });
  }
  _bindDCHandler('open');
  _bindDCHandler('close');
  _bindDCHandler('closing');
  _bindDCHandler('error');
  _bindDCHandler('bufferedamountlow');

  impl.addEventListener = function(name, fn, options) {
    if (typeof fn !== 'function') return;
    var once = !!(options && typeof options === 'object' && options.once);
    if (name === 'message') {
      if (once) {
        // Wrap so the entry self-removes after one fire. We store the
        // user's fn on the wrapper so removeEventListener can find it.
        var wrapper = function(ev) {
          var idx = _msgListeners.indexOf(wrapper);
          if (idx >= 0) _msgListeners.splice(idx, 1);
          fn(ev);
        };
        wrapper._origFn = fn;
        _msgListeners.push(wrapper);
      } else {
        _msgListeners.push(fn);
      }
      return;
    }
    if (once) internal._ev.once(name, fn);
    else      internal._ev.on(name, fn);
  };
  impl.removeEventListener = function(name, fn) {
    if (typeof fn !== 'function') return;
    if (name === 'message') {
      // Search for both direct and once-wrapped registrations.
      for (var i = 0; i < _msgListeners.length; i++) {
        if (_msgListeners[i] === fn || _msgListeners[i]._origFn === fn) {
          _msgListeners.splice(i, 1);
          return;
        }
      }
      return;
    }
    internal._ev.off(name, fn);
  };
  // dispatchEvent — see comment on RTCPeerConnection.dispatchEvent.
  impl.dispatchEvent = function(event) {
    if (!event || typeof event.type !== 'string') {
      throw new TypeError('dispatchEvent: event must have a string type');
    }
    if (event.type === 'message') {
      var copy = _msgListeners.slice();
      for (var i = 0; i < copy.length; i++) copy[i](event);
    } else {
      internal._ev.emit(event.type, event);
    }
    return true;
  };
}


/* ========================= RTCSessionDescription ========================= */

RTCDataChannel.prototype.send = function () { return this._impl.send.apply(this, arguments); };
Object.defineProperty(RTCDataChannel.prototype.send, 'length', { value: 1 });
Object.defineProperty(RTCDataChannel.prototype.send, 'name', { value: 'send' });
RTCDataChannel.prototype.close = function () { return this._impl.close.apply(this, arguments); };
Object.defineProperty(RTCDataChannel.prototype.close, 'length', { value: 0 });
Object.defineProperty(RTCDataChannel.prototype.close, 'name', { value: 'close' });
RTCDataChannel.prototype.addEventListener = function () { return this._impl.addEventListener.apply(this, arguments); };
Object.defineProperty(RTCDataChannel.prototype.addEventListener, 'length', { value: 2 });
Object.defineProperty(RTCDataChannel.prototype.addEventListener, 'name', { value: 'addEventListener' });
RTCDataChannel.prototype.removeEventListener = function () { return this._impl.removeEventListener.apply(this, arguments); };
Object.defineProperty(RTCDataChannel.prototype.removeEventListener, 'length', { value: 2 });
Object.defineProperty(RTCDataChannel.prototype.removeEventListener, 'name', { value: 'removeEventListener' });
RTCDataChannel.prototype.dispatchEvent = function () { return this._impl.dispatchEvent.apply(this, arguments); };
Object.defineProperty(RTCDataChannel.prototype.dispatchEvent, 'length', { value: 1 });
Object.defineProperty(RTCDataChannel.prototype.dispatchEvent, 'name', { value: 'dispatchEvent' });

function RTCSessionDescription(init) {
  // W3C 4.8: `type` is a REQUIRED member — constructing without one is a
  // TypeError (an RTCSessionDescription with no type is meaningless, and
  // the enum is validated at the same time).
  if (init == null || init.type == null) {
    throw new TypeError('RTCSessionDescription: type is required');
  }
  if (['offer', 'answer', 'pranswer', 'rollback'].indexOf(init.type) === -1) {
    throw new TypeError('RTCSessionDescription: invalid type "' + init.type + '"');
  }
  init = init || {};
  // W3C §4.10.2: type is REQUIRED and must be one of
  // 'offer'|'pranswer'|'answer'|'rollback'. The spec says the constructor
  // throws TypeError if type is missing or not one of these values.
  // (We're permissive when init.type is null — this is a common pattern
  // when round-tripping JSON where null was serialized.)
  if (init.type != null) {
    var validTypes = ['offer', 'pranswer', 'answer', 'rollback'];
    if (validTypes.indexOf(init.type) < 0) {
      throw new TypeError('RTCSessionDescription: invalid type "' + init.type +
                          '" (must be one of ' + validTypes.join(', ') + ')');
    }
  }
  this.type = init.type != null ? init.type : null;
  this.sdp  = init.sdp  != null ? init.sdp  : '';
}

RTCSessionDescription.prototype.toJSON = function() {
  return { type: this.type, sdp: this.sdp };
};


/* ========================= RTCIceCandidate ========================= */

function RTCIceCandidate(init) {
  // Backwards compat: legacy callers pass the candidate string directly
  // instead of {candidate: '...'}. MDN documents this explicitly.
  if (typeof init === 'string') {
    init = { candidate: init };
  }
  // W3C §4.9.1 (WPT harvest): the dictionary REQUIRES at least one of
  // sdpMid / sdpMLineIndex to be non-null — a bare candidate string (or
  // an empty dictionary, or explicit double-null) cannot address an
  // m-line and must throw TypeError at construction.
  init = init || {};
  var hasMid = init.sdpMid !== undefined && init.sdpMid !== null;
  var hasIdx = init.sdpMLineIndex !== undefined && init.sdpMLineIndex !== null;
  if (!hasMid && !hasIdx) {
    throw new TypeError('RTCIceCandidate: sdpMid or sdpMLineIndex required');
  }
  // WebIDL: a PRESENT-but-null member coerces to the string "null";
  // an absent member takes the default ''.
  this.candidate = ('candidate' in init) ? String(init.candidate) : '';
  this.sdpMid = hasMid ? String(init.sdpMid) : null;
  this.sdpMLineIndex = hasIdx ? (init.sdpMLineIndex >>> 0) : null;
  this.usernameFragment = init.usernameFragment != null ? String(init.usernameFragment) : null;
  // WPT harvest: relayProtocol and url are DICTIONARY members too (the
  // signaled-remote-candidate form) — honored verbatim when provided.
  this.url = init.url != null ? String(init.url) : null;
  var _initRelayProtocol = init.relayProtocol != null ? String(init.relayProtocol) : null;

  // Default parsed fields to null (spec defaults for unknown string).
  this.foundation     = null;
  this.component      = null;   // 'rtp' | 'rtcp'
  this.priority       = null;
  this.address        = null;   // aka .ip
  this.port           = null;
  this.type           = null;   // 'host' | 'srflx' | 'prflx' | 'relay'
  this.protocol       = null;   // 'udp' | 'tcp'
  this.relatedAddress = null;
  this.relatedPort    = null;
  this.tcpType        = null;
  // RFC 8836 §3 — for relay candidates, the transport protocol used
  // between client and TURN server: 'udp' | 'tcp' | 'tls'. null for
  // non-relay candidates. Parsed from "relayProtocol X" trailing pair.
  this.relayProtocol  = null;

  // Parse candidate string per JSEP / RFC 8839 §5.1:
  //   candidate:{foundation} {component} {protocol} {priority} {ip} {port}
  //     typ {type} [raddr {ip} rport {port}] [tcptype {tcpType}] [generation N]
  //     [ufrag X] [network-id N]
  //
  // Accepts either the pure form ("candidate:...") or the SDP line form
  // ("a=candidate:...") for robustness — the spec says only the former, but
  // apps commonly copy lines straight out of SDP.
  if (this.candidate) {
    var s = this.candidate;
    var _hadAEq = s.indexOf('a=') === 0;   // strict: SDP-line form is NOT a candidate string
    if (_hadAEq) s = s.slice(2);
    if (s.indexOf('candidate:') === 0) s = s.slice('candidate:'.length);
    // WPT harvest — strict RFC 8839 grammar: leading whitespace after the
    // colon is a parse FAILURE (all fields stay null), single spaces only.
    var strictOk = !_hadAEq && !/^\s/.test(s) && !/\s\s/.test(s.trim()) && !/\t/.test(s);
    var tokens = s.trim().split(/\s+/);
    var numOk = tokens.length >= 8 &&
      /^\d+$/.test(tokens[1]) && parseInt(tokens[1], 10) >= 1 && parseInt(tokens[1], 10) <= 256 &&
      /^\d+$/.test(tokens[3]) && tokens[3].length <= 10 &&
      parseInt(tokens[3], 10) >= 1 && parseInt(tokens[3], 10) <= 2147483647 &&
      /^\d+$/.test(tokens[5]) && parseInt(tokens[5], 10) <= 65535 &&
      tokens[0].length <= 32 && /^[A-Za-z0-9+\/]+$/.test(tokens[0]);
    // RFC 6544: a TCP candidate MUST carry tcptype active|passive|so —
    // absent, bare, or unknown values are parse failures.
    if (strictOk && /^tcp$/i.test(tokens[2] || '')) {
      // RFC 6544 + RFC 5245: a TCP candidate MUST carry tcptype, and it
      // must come before any ARBITRARY extension — but raddr/rport are
      // not arbitrary: a srflx or relay candidate legitimately writes
      // "typ srflx raddr <a> rport <p> tcptype active". The earlier rule
      // demanded tcptype at a fixed position and rejected every
      // non-host TCP candidate; skip the standard raddr/rport pair and
      // require tcptype at the first EXTENSION slot after it.
      var _ti = 8;
      if (tokens[_ti] === 'raddr') _ti += 2;
      if (tokens[_ti] === 'rport') _ti += 2;
      var _ttV = (tokens[_ti] === 'tcptype') ? String(tokens[_ti + 1] || '').toLowerCase() : null;
      if (_ttV !== 'active' && _ttV !== 'passive' && _ttV !== 'so') strictOk = false;
    }
    if (strictOk && numOk && tokens.length >= 8 && tokens[6] === 'typ') {
      this.foundation = tokens[0];
      var cId        = parseInt(tokens[1], 10);
      this.component = cId === 1 ? 'rtp' : (cId === 2 ? 'rtcp' : null);
      this.protocol  = tokens[2].toLowerCase();
      this.priority  = parseInt(tokens[3], 10);
      this.address   = tokens[4];
      this.port      = parseInt(tokens[5], 10);
      this.type      = String(tokens[7]).toLowerCase();
      // Optional trailing key-value pairs
      for (var i = 8; i + 1 < tokens.length; i += 2) {
        var key = tokens[i], val = tokens[i + 1];
        if (key === 'raddr')   this.relatedAddress = val;
        else if (key === 'rport') {
          if (!/^\d+$/.test(val)) { this._parseFail = true; }
          this.relatedPort = parseInt(val, 10);
        }
        else if (key === 'tcptype') this.tcpType        = String(val).toLowerCase();
        // (candidate-string ufrag does NOT populate usernameFragment —
        // the attribute is dictionary-only per spec; WPT checks this.)
        else if (key === 'relay-protocol' || key === 'relayProtocol') {
          // RFC 8836 §3 + W3C §4.10.1.1 — the transport between client and TURN.
          this.relayProtocol = val.toLowerCase();
        }
      }
      // WPT harvest: srflx/prflx/relay candidates REQUIRE raddr+rport —
      // their absence invalidates the whole parse (fields → null).
      if (this._parseFail ||
          ((this.type === 'srflx' || this.type === 'prflx' || this.type === 'relay') &&
           (this.relatedAddress == null || this.relatedPort == null))) {
        this.foundation = this.component = this.protocol = this.priority = null;
        this.address = this.port = this.type = this.tcpType = null;
        this.relatedAddress = this.relatedPort = this.relayProtocol = null;
      }
    }
  }
  // dictionary members win over (or fill) string-derived values —
  // 'cloned vs signaled' parity per WPT.
  if (_initRelayProtocol != null) this.relayProtocol = _initRelayProtocol;
}

RTCIceCandidate.prototype.toJSON = function() {
  return {
    candidate: this.candidate,
    sdpMid: this.sdpMid,
    sdpMLineIndex: this.sdpMLineIndex,
    usernameFragment: this.usernameFragment,
  };
};


/* ========================= RTCCertificate ========================= */

function RTCCertificate(generated) {
  this.expires = Date.now() + 31536000000;  // 1 year
  this._cert = generated.cert;
  this._key = generated.key;
  this._fingerprint = generated.fingerprint;
  // QUICK-4: store the algorithm used to generate this cert so apps can
  // inspect it (e.g. for capability detection or debugging). Mirrors
  // Chrome/Firefox's non-standard but widely available getAlgorithm().
  this._algorithm = generated.algorithm || null;

  this._fps = [{ algorithm: 'sha-256',
    value: String(generated.fingerprint || '').toLowerCase() }];

  // Non-standard but commonly available — returns the resolved
  // keygenAlgorithm in W3C shape ({name, namedCurve, ...} or
  // {name, modulusLength, publicExponent, hash}).
  this.getAlgorithm = function() {
    if (!this._algorithm) return null;
    // Return a fresh copy so callers can't mutate our state.
    var a = this._algorithm;
    var out = { name: a.name };
    if (a.namedCurve)     out.namedCurve = a.namedCurve;
    if (a.modulusLength)  out.modulusLength = a.modulusLength;
    if (a.publicExponent) out.publicExponent = a.publicExponent;
    if (a.hash)           out.hash = { name: a.hash.name };
    return out;
  };
}


/* ========================= RTCSctpTransport ========================= */

RTCCertificate.prototype.getFingerprints = function () {
  return (this._fps || []).slice();
};


RTCSctpTransport.prototype.addEventListener = function (t, fn) {
  if (!this._etListeners) Object.defineProperty(this, '_etListeners', { value: {}, enumerable: false });
  (this._etListeners[t] = this._etListeners[t] || []).push(fn);
};
RTCSctpTransport.prototype.removeEventListener = function (t, fn) {
  var a = this._etListeners && this._etListeners[t];
  if (a) { var i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); }
};
RTCSctpTransport.prototype.dispatchEvent = function (ev) {
  var a = this._etListeners && this._etListeners[ev && ev.type];
  if (a) a.slice().forEach(function (fn) { try { fn(ev); } catch (e) {} });
  return true;
};
function RTCSctpTransport(manager) {
  // real event dispatch: internal state changes surface as 'statechange'
  // through BOTH the on-handler and addEventListener (EventTarget layer).
  var _selfET = this;
  try {
    manager.ev.on('sctp:statechange', function () {
      var evO = { type: 'statechange', target: _selfET };
      try { if (typeof _selfET.onstatechange === 'function') _selfET.onstatechange(evO); } catch (e1) {}
      try { _selfET.dispatchEvent(evO); } catch (e2) {}
    });
  } catch (eW) {}
  // transport is set by the RTCPeerConnection singleton factory (see
  // the pc.sctp getter in api.js). Keep as a plain writable property.
  this.transport = null;

  Object.defineProperty(this, 'state', {
    get: function() {
      var s = manager.state.sctpState;
      if (s === 'connected') return 'connected';
      if (s === 'closed') return 'closed';
      return 'connecting';
    },
  });

  Object.defineProperty(this, 'maxMessageSize', {
    // RFC 8841 §6 (WPT): the value is what WE may SEND —
    // min(local, peer-advertised); a peer that omitted the attribute is
    // assumed to accept 65536 (the RFC default), not our local cap.
    get: function() {
      var loc = manager.state.maxMessageSize;
      var rem = manager.state.remoteMaxMessageSize;
      // BEFORE NEGOTIATION the peer is unknown, and RFC 8841 says an
      // endpoint that has not declared max-message-size accepts 65536.
      // Reporting our local cap (262144) instead told the application it
      // could send four times what the peer might accept — and the check
      // in send() reads this same value, so an oversized message would
      // have been let through rather than refused.
      if (rem == null) return Math.min(loc, 65536);
      // RFC 8841: max-message-size:0 means the peer imposes NO limit, so
      // the cap is entirely ours — and if we have none either, the
      // answer is Infinity rather than some arbitrary default.
      if (rem === 0) return (loc > 0) ? loc : Number.POSITIVE_INFINITY;
      return Math.min(loc, rem);
    },
  });

  Object.defineProperty(this, 'maxChannels', {
    // W3C §6.1: "the maximum number of RTCDataChannels that can be open
    // simultaneously, or null if not yet negotiated."
    //
    // SCTP-DC (RFC 8831) negotiates the per-direction stream count via the
    // INIT/INIT-ACK chunks — values are capped at 65535. Until our SCTP
    // layer has actually completed that handshake (state.sctpAssociation
    // is non-null), we return null. After, we expose 65535 as the
    // protocol-level upper bound; sctp.js doesn't currently surface the
    // negotiated lower value, so 65535 is the most truthful answer we
    // can give without underreporting.
    get: function() {
      if (!manager.state.sctpAssociation) return null;
      return 65535;
    },
  });

  var _stateHandler = null;
  Object.defineProperty(this, 'onstatechange', {
    get: function() { return _stateHandler; },
    set: function(fn) {
      if (_stateHandler) manager.ev.removeListener('sctp:statechange', _stateHandler);
      _stateHandler = fn;
      if (fn) manager.ev.on('sctp:statechange', fn);
    },
  });
}


/* ========================= RTCDtlsTransport ========================= */


RTCDtlsTransport.prototype.addEventListener = function (t, fn) {
  if (!this._etListeners) Object.defineProperty(this, '_etListeners', { value: {}, enumerable: false });
  (this._etListeners[t] = this._etListeners[t] || []).push(fn);
};
RTCDtlsTransport.prototype.removeEventListener = function (t, fn) {
  var a = this._etListeners && this._etListeners[t];
  if (a) { var i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); }
};
RTCDtlsTransport.prototype.dispatchEvent = function (ev) {
  var a = this._etListeners && this._etListeners[ev && ev.type];
  if (a) a.slice().forEach(function (fn) { try { fn(ev); } catch (e) {} });
  return true;
};
function RTCDtlsTransport(manager) {
  // real event dispatch: internal state changes surface as 'statechange'
  // through BOTH the on-handler and addEventListener (EventTarget layer).
  var _selfET = this;
  try {
    manager.ev.on('dtls:error', function (info) {
      var errV;
      try {
        errV = new RTCError({ errorDetail: (info && info.fingerprint) ? 'fingerprint-failure' : 'dtls-failure' },
                            (info && info.message) || 'DTLS failure');
      } catch (eMk) { errV = { name: 'OperationError', errorDetail: 'dtls-failure' }; }
      var evE = { type: 'error', error: errV, target: _selfET };
      try { if (typeof _selfET.onerror === 'function') _selfET.onerror(evE); } catch (e1) {}
      try { _selfET.dispatchEvent(evE); } catch (e2) {}
    });
    manager.ev.on('dtls:statechange', function () {
      // W3C: transitioning to 'closed' via pc.close() is SILENT — no
      // statechange event is observable on the transport. The closed
      // flag can lag the event, so also gate on the transport's OWN
      // current state.
      if (manager.state.closed) return;
      try { if (_selfET.state === 'closed') return; } catch (eSt) {}
      var evO = { type: 'statechange', target: _selfET };
      try { if (typeof _selfET.onstatechange === 'function') _selfET.onstatechange(evO); } catch (e1) {}
      try { _selfET.dispatchEvent(evO); } catch (e2) {}
    });
  } catch (eW) {}
  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  var self = this;
  // iceTransport is set by the RTCPeerConnection singleton factory (see
  // _getDtlsTransport in api.js). Keep it as a plain writable property so
  // the factory can link the two classes after construction.
  this.iceTransport = null;

  Object.defineProperty(this, 'state', {
    get: function() { return manager.state.dtlsState; },
  });

  impl.getRemoteCertificates = function() {
    // Returns ArrayBuffer[] of peer certificates from the DTLS handshake.
    // manager.state.remoteCertificates is populated by dtls_session when
    // the handshake completes; may be null/empty before that.
    var certs = manager.state.remoteCertificates;
    if (!certs || !certs.length) return [];
    var out = [];
    for (var i = 0; i < certs.length; i++) {
      var c = certs[i];
      // Normalize Buffer ↔ ArrayBuffer per spec.
      // Shape over identity (the preserve-symlinks lesson): accept ANY
      // ArrayBufferView (lemon-tls hands Uint8Array, not Buffer) or
      // ArrayBuffer; Buffer is just a Uint8Array subclass and rides along.
      if (c && ArrayBuffer.isView(c)) {
        out.push(c.buffer.slice(c.byteOffset, c.byteOffset + c.byteLength));
      } else if (c instanceof ArrayBuffer ||
                 (c && typeof c.byteLength === 'number' && typeof c.slice === 'function')) {
        out.push(c);
      }
    }
    return out;
  };

  // Event handler properties — wire to manager events.
  var _handlers = {};
  function _bindHandler(name, upstream) {
    Object.defineProperty(self, 'on' + name, {
      get: function() { return _handlers[name] || null; },
      set: function(fn) {
        if (_handlers[name]) manager.ev.off(upstream, _handlers[name]);
        _handlers[name] = fn;
        if (fn) manager.ev.on(upstream, fn);
      },
    });
  }
  _bindHandler('statechange', 'dtls:statechange');
  _bindHandler('error',       'dtls:error');
}


/* ========================= RTCIceTransport ========================= */

RTCDtlsTransport.prototype.getRemoteCertificates = function () { return this._impl.getRemoteCertificates.apply(this, arguments); };
Object.defineProperty(RTCDtlsTransport.prototype.getRemoteCertificates, 'length', { value: 0 });
Object.defineProperty(RTCDtlsTransport.prototype.getRemoteCertificates, 'name', { value: 'getRemoteCertificates' });


RTCIceTransport.prototype.addEventListener = function (t, fn) {
  if (!this._etListeners) Object.defineProperty(this, '_etListeners', { value: {}, enumerable: false });
  (this._etListeners[t] = this._etListeners[t] || []).push(fn);
};
RTCIceTransport.prototype.removeEventListener = function (t, fn) {
  var a = this._etListeners && this._etListeners[t];
  if (a) { var i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); }
};
RTCIceTransport.prototype.dispatchEvent = function (ev) {
  var a = this._etListeners && this._etListeners[ev && ev.type];
  if (a) a.slice().forEach(function (fn) { try { fn(ev); } catch (e) {} });
  return true;
};
function RTCIceTransport(manager) {
  // real event dispatch: internal state changes surface as 'statechange'
  // through BOTH the on-handler and addEventListener (EventTarget layer).
  var _selfET = this;
  try {
    manager.ev.on('icegatheringstatechange', function () {
      var evG = { type: 'gatheringstatechange', target: _selfET };
      try { if (typeof _selfET.ongatheringstatechange === 'function') _selfET.ongatheringstatechange(evG); } catch (eG1) {}
      try { _selfET.dispatchEvent(evG); } catch (eG2) {}
    });
  } catch (eWG) {}
  try {
    manager.ev.on('iceconnectionstatechange', function () {
      // W3C 5.6: pc.close() transitions every transport to 'closed'
      // SYNCHRONOUSLY and fires NO event for it — closing is not a state
      // change the application observes, it is the end of observation.
      //
      // Every other transition is queued and evented as normal; only this
      // one is silent. Forwarding it made an application that watches
      // statechange see a final event for a connection it had just closed
      // itself.
      if (manager.state && manager.state.closed) return;
      // The closed flag can lag the event, so also gate on the transport's
      // OWN current state — the same double guard the DTLS forwarder uses.
      try { if (_selfET.state === 'closed') return; } catch (eSt) {}
      var evO = { type: 'statechange', target: _selfET };
      try { if (typeof _selfET.onstatechange === 'function') _selfET.onstatechange(evO); } catch (e1) {}
      try { _selfET.dispatchEvent(evO); } catch (e2) {}
    });
  } catch (eW) {}
  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  var self = this;

  // Helpers to reach the live ICE agent. Agent is created lazily in manager
  // on first gather/setLocalDescription — may be null early in lifecycle.
  function _agent() { return manager.iceAgent || null; }

  Object.defineProperty(this, 'role', {
    // W3C 5.6: the ICE role is not decided until BOTH descriptions are
    // in place — an offerer that has only applied its own offer must
    // report 'unknown', because a glare resolution can still flip it.
    // Our agent guesses eagerly from the local description, which made
    // the role observable an entire negotiation too early.
    get: function() {
      var st = manager.state;
      var haveBoth = !!(st.currentLocalDescription || st.pendingLocalDescription) &&
                     !!(st.currentRemoteDescription || st.pendingRemoteDescription);
      if (!haveBoth) return 'unknown';
      var a = _agent();
      return a ? a.role : 'controlling';
    },
  });

  Object.defineProperty(this, 'component', {
    get: function() { return 'rtp'; },
  });

  Object.defineProperty(this, 'state', {
    // RTCIceTransportState enum only (WPT: 'new' at birth; 'gathering'
    // belongs to gatheringState).
    get: function() {
      var st = manager.state;
      var s = st.iceConnectionState;
      var ENUM = { 'new':1, checking:1, connected:1, completed:1,
                   disconnected:1, failed:1, closed:1 };
      s = ENUM[s] ? s : 'new';
      // W3C 5.6: 'checking' means connectivity checks are actually
      // running, which requires BOTH a remote description AND at least
      // one remote candidate to check against. Our agent flips to
      // checking as soon as it starts, so a transport could report
      // 'checking' with nothing to check — observable a whole
      // negotiation early.
      if (s === 'checking') {
        var haveRemote = !!(st.currentRemoteDescription || st.pendingRemoteDescription);
        var a = _agent();
        var haveCand = !!(a && a.remoteCandidates && a.remoteCandidates.length);
        if (!haveRemote || !haveCand) return 'new';
      }
      return s;
    },
  });

  Object.defineProperty(this, 'gatheringState', {
    // W3C: gathering begins at setLocalDescription — before any local
    // description exists the transport reports 'new' even though our
    // agent warms up eagerly underneath.
    get: function() {
      // W3C 5.6: 'new' until setLocalDescription starts gathering, then
      // 'gathering' while candidates are produced, 'complete' only once
      // the phase genuinely ended. Two field/WPT truths encoded here:
      //   • our agent warms up eagerly, so a fresh transport that has
      //     candidates but no local description still reports 'new';
      //   • pc.close() must NOT push the transport to 'complete' — a
      //     closed connection freezes the last observable phase.
      var st = manager.state;
      if (!st.pendingLocalDescription && !st.currentLocalDescription) return 'new';
      if (st.closed && _lastGatheringState) return _lastGatheringState;
      var g = st.iceGatheringState;
      // Post-SLD, 'complete' is only reported when end-of-candidates has
      // actually been signalled for this phase; otherwise we are still
      // gathering (an eagerly-warmed agent reports complete too early).
      if (g === 'complete' && !st.iceGatheringEnded) g = 'gathering';
      _lastGatheringState = g;
      return g;
    },
  });
  var _lastGatheringState = null;

  impl.getLocalCandidates = function() {
    var a = _agent();
    return a ? (a.localCandidates || []).map(_normCand) : [];
  };

  // One normalizer for the lists AND the selected pair, so identity
  // comparisons across them hold field-for-field (WPT requirement).
  function _normCand(c) {
    if (!c) return null;
    // THE `candidate` STRING IS THE IDENTITY. W3C 4.8.1 makes it the primary
    // member of RTCIceCandidate — the a=candidate line itself — and it is how
    // applications compare candidates across the two peers:
    //
    //   assert_equals(pair1.local.candidate, pair2.remote.candidate)
    //
    // Omitting it left every comparison of that kind reading undefined on
    // both sides, so two unrelated candidates compared EQUAL and code that
    // matched a selected pair against its own signalled candidates silently
    // matched nothing.
    var _line = c.candidate || c.sdp || null;
    if (!_line) {
      // Rebuild the a=candidate line from the parts (RFC 5245 15.1) when the
      // source only carried the decomposed form.
      var _typ = c.type || 'host';
      // A foundation is an ICE-chars token (RFC 8839): no colons. Internally
      // it can be a composite like 'prflx:192.0.2.2', which would produce a
      // malformed a=candidate line — the peer, and any string comparison
      // against a signalled candidate, would reject it. Take the leading
      // token.
      var _fnd = (c.foundation != null) ? String(c.foundation) : '0';
      if (_fnd.indexOf(':') !== -1) _fnd = _fnd.split(':')[0];
      var _parts = [
        _fnd,
        (c.component === 2 ? 2 : 1),
        (c.protocol || 'udp').toUpperCase(),
        (c.priority != null ? c.priority : 0),
        (c.ip || c.address || ''),
        (c.port != null ? c.port : 0),
        'typ', _typ,
      ];
      var _ra = c.raddr || c.relatedAddress;
      var _rp = (c.rport != null) ? c.rport : c.relatedPort;
      if (_ra != null && _rp != null) _parts.push('raddr', _ra, 'rport', _rp);
      if (c.tcpType) _parts.push('tcptype', c.tcpType);
      _line = 'candidate:' + _parts.join(' ');
    }
    // Return a REAL RTCIceCandidate. W3C 4.8: getSelectedCandidatePair() and
    // getRemoteCandidates() hand back RTCIceCandidate objects, and code tests
    // `pair.local instanceof RTCIceCandidate` before trusting them. A plain
    // object carries the same fields and fails that check, so a defensive
    // caller treats a perfectly good candidate as foreign data.
    try {
      return new RTCIceCandidate({
        candidate:        _line,
        sdpMid:           c.sdpMid != null ? String(c.sdpMid) : '0',
        sdpMLineIndex:    c.sdpMLineIndex != null ? c.sdpMLineIndex : 0,
        usernameFragment: c.ufrag || c.usernameFragment || null,
      });
    } catch (eIC) { /* fall through to the plain shape below */ }
    return {
      candidate:  _line,
      foundation: c.foundation != null ? String(c.foundation) : null,
      component:  c.component === 2 ? 'rtcp' : 'rtp',
      protocol:   (c.protocol || 'udp').toLowerCase(),
      priority:   c.priority != null ? c.priority : null,
      address:    c.ip || c.address || null,
      port:       c.port != null ? c.port : null,
      type:       c.type || 'host',
      tcpType:    c.tcpType || null,
      relatedAddress: c.raddr || c.relatedAddress || null,
      relatedPort:    c.rport != null ? c.rport
                    : (c.relatedPort != null ? c.relatedPort : null),
    };
  }

  impl.getRemoteCandidates = function() {
    // W3C 5.6: getRemoteCandidates() returns the candidates SIGNALLED by
    // the peer — PEER-REFLEXIVE candidates (ones we only learned from an
    // incoming STUN binding request) are deliberately NOT exposed, since
    // the peer never told us about them. The agent tracks them for
    // connectivity checks; they just don't belong in this list.
    var a = _agent();
    if (!a) return [];
    return (a.remoteCandidates || [])
      .filter(function (c) { return c && c.type !== 'prflx'; })
      .map(_normCand);
  };

  impl.getSelectedCandidatePair = function() {
    var a = _agent();
    if (!a || !a.selectedPair) return null;
    var p = a.selectedPair;
    return { local: _normCand(p.local), remote: _normCand(p.remote) };
  };

  impl.getLocalParameters = function() {
    var a = _agent();
    if (!a) return null;
    var p = a.localParameters;
    return p ? { usernameFragment: p.ufrag, password: p.pwd } : null;
  };

  impl.getRemoteParameters = function() {
    var a = _agent();
    if (!a) return null;
    var p = a.remoteParameters;
    return p ? { usernameFragment: p.ufrag, password: p.pwd } : null;
  };

  // Event handler properties (onstatechange / ongatheringstatechange /
  // onselectedcandidatepairchange). All three flow through manager.ev so
  // the binding works regardless of whether the ICE agent has been created
  // yet — connection_manager forwards agent-level events onto the bus.
  var _handlers = {};
  function _bindHandler(name, upstreamName) {
    Object.defineProperty(self, 'on' + name, {
      get: function() { return _handlers[name] || null; },
      set: function(fn) {
        if (_handlers[name]) manager.ev.off(upstreamName, _handlers[name]);
        _handlers[name] = fn;
        if (fn) manager.ev.on(upstreamName, fn);
      },
    });
  }
  _bindHandler('statechange',                 'iceconnectionstatechange');
  _bindHandler('gatheringstatechange',        'icegatheringstatechange');
  _bindHandler('selectedcandidatepairchange', 'selectedcandidatepairchange');
}


/* ========================= RTCDTMFSender ========================= */

RTCIceTransport.prototype.getLocalCandidates = function () { return this._impl.getLocalCandidates.apply(this, arguments); };
Object.defineProperty(RTCIceTransport.prototype.getLocalCandidates, 'length', { value: 0 });
Object.defineProperty(RTCIceTransport.prototype.getLocalCandidates, 'name', { value: 'getLocalCandidates' });
RTCIceTransport.prototype.getRemoteCandidates = function () { return this._impl.getRemoteCandidates.apply(this, arguments); };
Object.defineProperty(RTCIceTransport.prototype.getRemoteCandidates, 'length', { value: 0 });
Object.defineProperty(RTCIceTransport.prototype.getRemoteCandidates, 'name', { value: 'getRemoteCandidates' });
RTCIceTransport.prototype.getSelectedCandidatePair = function () { return this._impl.getSelectedCandidatePair.apply(this, arguments); };
Object.defineProperty(RTCIceTransport.prototype.getSelectedCandidatePair, 'length', { value: 0 });
Object.defineProperty(RTCIceTransport.prototype.getSelectedCandidatePair, 'name', { value: 'getSelectedCandidatePair' });
RTCIceTransport.prototype.getLocalParameters = function () { return this._impl.getLocalParameters.apply(this, arguments); };
Object.defineProperty(RTCIceTransport.prototype.getLocalParameters, 'length', { value: 0 });
Object.defineProperty(RTCIceTransport.prototype.getLocalParameters, 'name', { value: 'getLocalParameters' });
RTCIceTransport.prototype.getRemoteParameters = function () { return this._impl.getRemoteParameters.apply(this, arguments); };
Object.defineProperty(RTCIceTransport.prototype.getRemoteParameters, 'length', { value: 0 });
Object.defineProperty(RTCIceTransport.prototype.getRemoteParameters, 'name', { value: 'getRemoteParameters' });

RTCDTMFSender.prototype.addEventListener = function (t, fn) {
  if (!this._etL) Object.defineProperty(this, '_etL', { value: {}, enumerable: false });
  (this._etL[t] = this._etL[t] || []).push(fn);
};
RTCDTMFSender.prototype.removeEventListener = function (t, fn) {
  var a = this._etL && this._etL[t];
  if (a) { var i = a.indexOf(fn); if (i >= 0) a.splice(i, 1); }
};
RTCDTMFSender.prototype.dispatchEvent = function (ev) {
  var a = this._etL && this._etL[ev && ev.type];
  if (a) a.slice().forEach(function (fn) { try { fn(ev); } catch (e) {} });
  return true;
};
function RTCDTMFSender(getPipeline, getClosed, getTxState) {
  // WebIDL prototype surface (WPT): methods live on the prototype;
  // per-instance closures stay intact behind a hidden impl table.
  var impl = {};
  Object.defineProperty(this, '_impl', { value: impl, enumerable: false });

  var self = this;
  this.toneBuffer = '';
  this.ontonechange = null;
  var _playing = false;

  function _pipeline() {
    try { return getPipeline ? getPipeline() : null; } catch (e) { return null; }
  }

  // W3C §5.5: true when the audio pipeline is live AND telephone-event
  // was negotiated (the pipeline only exposes a dtmfPayloadType then).
  Object.defineProperty(this, 'canInsertDTMF', {
    // W3C §7.1 (WPT): true when this is an audio sender on a SENDING,
    // non-stopped transceiver — telephone-event is in our default audio
    // capabilities, so a live pipeline is a bonus, not a prerequisite.
    get: function () {
      var p = _pipeline();
      if (p && typeof p.sendDtmf === 'function' && p.dtmfPayloadType != null) return true;
      try {
        var d = (typeof getDirection === 'function' && getDirection()) || null;
        if (d === 'recvonly' || d === 'inactive' || d === 'stopped') return false;
      } catch (eD) {}
      return true;
    },
  });

  function _fireToneChange(tone) {
    var evT = new RTCDTMFToneChangeEvent({ tone: tone });
    try { evT.type = 'tonechange'; } catch (eT) {}
    if (typeof self.ontonechange === 'function') {
      try { self.ontonechange(evT); } catch (e) {}
    }
    // addEventListener('tonechange') subscribers too (WPT uses both styles)
    try { if (self.dispatchEvent) self.dispatchEvent(evT); } catch (e2) {}
  }

  function _runNext(duration, gap) {
    // closed connection: halt the playout loop immediately (real-bug fix:
    // tones kept firing after pc.close()).
    if (typeof getClosed === 'function' && getClosed()) { _playing = false; return; }
    if (self.toneBuffer.length === 0) {
      _playing = false;
      _fireToneChange('');                       // W3C: empty tone marks completion
      return;
    }
    var tone = self.toneBuffer[0];
    self.toneBuffer = self.toneBuffer.slice(1);
    if (tone === ',') {
      // §5.5.4 step: comma = 2-second pause, no tonechange payload change
      _fireToneChange(',');
      var t1 = setTimeout(function () { _runNext(duration, gap); }, 2000);
      if (t1.unref) t1.unref();
      return;
    }
    _fireToneChange(tone);
    var p = _pipeline();
    var started = p && p.sendDtmf && p.sendDtmf(tone, duration);
    // Whether or not the wire send started (e.g. renegotiated away
    // mid-buffer), keep the state machine's timing contract.
    var t2 = setTimeout(function () { _runNext(duration, gap); }, duration + gap);
    if (t2.unref) t2.unref();
  }

  /**
   * W3C §5.5.2 insertDTMF(tones, duration, interToneGap).
   * Replaces toneBuffer; starts playout if idle.
   */
  impl.insertDTMF = function (tones, duration, interToneGap) {
    // W3C 7.2: a stopped transceiver or a non-sending currentDirection
    // makes DTMF impossible — InvalidStateError before any queueing.
    var _tx = (typeof getTxState === 'function') ? getTxState() : {};
    if (RtpManager.isStopped(_tx) ||
        _tx.currentDirection === 'recvonly' || _tx.currentDirection === 'inactive') {
      throw new DOMException('insertDTMF: transceiver cannot send DTMF in its current state', 'InvalidStateError');
    }
    tones = (tones == null) ? '' : String(tones);
    if (!/^[0-9A-Da-d#*,]*$/.test(tones)) {
      var err = new DOMException('insertDTMF: invalid DTMF characters in "' + tones + '"', 'InvalidCharacterError');
      throw err;
    }
    if (!this.canInsertDTMF) {
      var err2 = new DOMException('insertDTMF: DTMF cannot be sent (no negotiated telephone-event or sender inactive)', 'InvalidStateError');
      throw err2;
    }
    var dur = Math.min(6000, Math.max(40, (duration == null) ? 100 : duration));
    var gap = Math.max(30, (interToneGap == null) ? 70 : interToneGap);
    this.toneBuffer = tones.toUpperCase();
    if (!_playing && this.toneBuffer.length > 0) {
      _playing = true;
      // spec: playout begins ASYNCHRONOUSLY — toneBuffer must remain
      // fully intact when insertDTMF returns (WPT reads it immediately).
      setTimeout(function () { _runNext(dur, gap); }, 0);
    }
  };
}



/* ========================= Event Classes ========================= */

RTCDTMFSender.prototype.insertDTMF = function () { return this._impl.insertDTMF.apply(this, arguments); };
Object.defineProperty(RTCDTMFSender.prototype.insertDTMF, 'length', { value: 1 });
Object.defineProperty(RTCDTMFSender.prototype.insertDTMF, 'name', { value: 'insertDTMF' });

function RTCTrackEvent(type, init) {
  // WebIDL (WPT): (type, eventInitDict) — init with a valid receiver
  // and track is REQUIRED; internal single-arg calls pass the dict first.
  var _dictFirst = (typeof type === 'object' && type !== null && init === undefined);
  if (_dictFirst) { init = type; type = 'track'; }
  else if (arguments.length < 2) {
    throw new TypeError('RTCTrackEvent: eventInitDict required');
  }
  init = init || {};
  if (init.receiver == null || init.track == null || init.transceiver == null) {
    throw new TypeError('RTCTrackEvent: receiver, track and transceiver are required');
  }
  this.type        = typeof type === 'string' ? type : 'track';
  this.bubbles     = !!init.bubbles;
  this.cancelable  = !!init.cancelable;
  this.track       = init.track       != null ? init.track       : null;
  this.receiver    = init.receiver    != null ? init.receiver    : null;
  this.transceiver = init.transceiver != null ? init.transceiver : null;
  this.streams     = Array.isArray(init.streams) ? init.streams : [];
}

function RTCDataChannelEvent(type, init) {
  // WebIDL (WPT): both arguments required; init.channel required non-null.
  if (arguments.length < 2) {
    throw new TypeError('RTCDataChannelEvent: 2 arguments required');
  }
  if (init == null || init.channel == null) {
    throw new TypeError('RTCDataChannelEvent: channel is required');
  }
  if (typeof type === 'object' && type && init === undefined) { init = type; }
  this.type = typeof type === 'string' ? type : (init.type || 'datachannel');
  init = init || {};
  this.type       = 'datachannel';
  // Standard Event flags default to FALSE, not undefined — WPT asserts
  // both directly on the delivered event.
  this.bubbles    = !!init.bubbles;
  this.cancelable = !!init.cancelable;
  this.channel    = init.channel != null ? init.channel : null;
}

function RTCPeerConnectionIceEvent(type, init) {
  // WebIDL: `candidate` is an RTCIceCandidate?, so anything that is
  // neither null nor an actual RTCIceCandidate is a TypeError at the
  // binding layer. We accepted any object, which produced an event whose
  // .candidate could not be passed to addIceCandidate — the error
  // surfaced far from the mistake.
  if (init && typeof init === 'object' && init.candidate != null &&
      !(init.candidate instanceof RTCIceCandidate)) {
    throw new TypeError(
      'RTCPeerConnectionIceEvent: candidate must be an RTCIceCandidate or null');
  }
  // W3C: this is a constructible Event — (type, eventInitDict), with type
  // REQUIRED (no arguments is a TypeError) and the standard Event flags
  // defaulting to false rather than undefined.
  if (arguments.length === 0) {
    throw new TypeError("Failed to construct 'RTCPeerConnectionIceEvent': 1 argument required");
  }
  // Internal callers historically passed a single init object; keep them
  // working by detecting a non-string first argument.
  if (typeof type !== 'string') { init = type; type = 'icecandidate'; }
  init = init || {};
  this.type       = type;
  this.bubbles    = !!init.bubbles;
  this.cancelable = !!init.cancelable;
  // Per W3C, .candidate is null on end-of-candidates (the "null candidate"
  // sentinel). Otherwise it's an RTCIceCandidate.
  this.candidate  = init.candidate != null ? init.candidate : null;
  this.url        = init.url || null;
}

function RTCPeerConnectionIceErrorEvent(type, init) {
  // WebIDL (type, eventInitDict) form — same fix as
  // RTCPeerConnectionIceEvent. Internal callers passing a single init
  // object still work (a non-string first argument is the init).
  if (typeof type !== 'string') { init = type; type = 'icecandidateerror'; }
  init = init || {};
  this.type       = type;
  this.bubbles    = !!init.bubbles;
  this.cancelable = !!init.cancelable;
  this.address   = init.address   != null ? init.address   : null;
  this.port      = init.port      != null ? init.port      : null;
  this.url       = init.url       != null ? init.url       : '';
  this.errorCode = init.errorCode != null ? init.errorCode : 0;
  this.errorText = init.errorText != null ? init.errorText : '';
}

// W3C webrtc-pc §11 — RTCError extends DOMException with WebRTC-specific
// detail fields. Used as the .error property on RTCErrorEvent.
//
// We expose it as a regular Error subclass; the W3C spec requires it to
// extend DOMException, but DOMException isn't a Node.js global. The
// shape (name, message, errorDetail, sdpLineNumber, sctpCauseCode,
// receivedAlert, sentAlert, httpRequestStatusCode) is what apps inspect,
// not the prototype chain.
function RTCError(init, message) {
  // WebIDL (WPT): init is REQUIRED with a VALID errorDetail enum value;
  // name is 'OperationError' (RTCError extends DOMException semantics)
  // and legacy .code is 0.
  if (arguments.length === 0 || init == null) {
    throw new TypeError('RTCError: init dictionary required');
  }
  var _validDetails = ['data-channel-failure','dtls-failure','fingerprint-failure','sctp-failure','sdp-syntax-error','hardware-encoder-not-available','hardware-encoder-error'];
  if (_validDetails.indexOf(init.errorDetail) === -1) {
    throw new TypeError('RTCError: invalid errorDetail "' + init.errorDetail + '"');
  }
  // Match W3C: errorDetail is the discriminator, others optional.
  // RTCErrorDetailType: 'data-channel-failure' | 'dtls-failure' |
  //   'fingerprint-failure' | 'sctp-failure' | 'sdp-syntax-error' |
  //   'hardware-encoder-not-available' | 'hardware-encoder-error'
  Error.call(this, message || '');
  this.name = 'OperationError';
  this.code = 0;
  this.message = message || '';
  var _roV_errorDetail = init.errorDetail            != null ? init.errorDetail            : '';
  var _roV_sdpLineNumber = init.sdpLineNumber          != null ? init.sdpLineNumber          : null;
  var _roV_sctpCauseCode = init.sctpCauseCode          != null ? init.sctpCauseCode          : null;
  var _roV_receivedAlert = init.receivedAlert          != null ? init.receivedAlert          : null;
  var _roV_sentAlert = init.sentAlert              != null ? init.sentAlert              : null;
  var _roV_httpRequestStatusCode = init.httpRequestStatusCode  != null ? init.httpRequestStatusCode  : null;
  Object.defineProperty(this, 'errorDetail', { get: function () { return _roV_errorDetail; }, set: function () { throw new TypeError('RTCError.errorDetail is read-only'); }, enumerable: true, configurable: false });
  Object.defineProperty(this, 'sdpLineNumber', { get: function () { return _roV_sdpLineNumber; }, set: function () { throw new TypeError('RTCError.sdpLineNumber is read-only'); }, enumerable: true, configurable: false });
  Object.defineProperty(this, 'sctpCauseCode', { get: function () { return _roV_sctpCauseCode; }, set: function () { throw new TypeError('RTCError.sctpCauseCode is read-only'); }, enumerable: true, configurable: false });
  Object.defineProperty(this, 'receivedAlert', { get: function () { return _roV_receivedAlert; }, set: function () { throw new TypeError('RTCError.receivedAlert is read-only'); }, enumerable: true, configurable: false });
  Object.defineProperty(this, 'sentAlert', { get: function () { return _roV_sentAlert; }, set: function () { throw new TypeError('RTCError.sentAlert is read-only'); }, enumerable: true, configurable: false });
  Object.defineProperty(this, 'httpRequestStatusCode', { get: function () { return _roV_httpRequestStatusCode; }, set: function () { throw new TypeError('RTCError.httpRequestStatusCode is read-only'); }, enumerable: true, configurable: false });
}
RTCError.prototype = Object.create(Error.prototype);
RTCError.prototype.constructor = RTCError;

function RTCErrorEvent(init) {
  init = init || {};
  this.type  = 'error';
  this.error = init.error != null ? init.error : null;
}

function RTCDTMFToneChangeEvent(type, init) {
  // WebIDL (type, eventInitDict); internal single-arg dict-first calls
  // keep working via the compat branch.
  if (typeof type === 'object' && type !== null && init === undefined) {
    init = type; type = 'tonechange';
  }
  init = init || {};
  this.type = typeof type === 'string' ? type : 'tonechange';
  this.bubbles = !!init.bubbles;
  this.cancelable = !!init.cancelable;
  this.tone = init.tone != null ? String(init.tone) : '';
}


/* ========================= Exports ========================= */

/* ═══════════════════════════════════════════════════════════════════
 *                          getStats() helpers
 * ═══════════════════════════════════════════════════════════════════
 *
 * Produces an RTCStatsReport that follows the W3C webrtc-stats spec:
 *   https://www.w3.org/TR/webrtc-stats/
 *
 * The report is a Map<string, object>. Each value has a stable `id`, a
 * `timestamp`, and a `type` drawn from the RTCStatsType enum:
 *
 *   codec               — per negotiated codec (one per PT in use)
 *   inbound-rtp         — per incoming SSRC (local receiver view)
 *   outbound-rtp        — per outgoing SSRC (local sender view)
 *   remote-inbound-rtp  — what remote reports about our outbound (from RR)
 *   remote-outbound-rtp — what remote reports about their outbound (from SR)
 *   media-source        — per attached MediaStreamTrack feeding an encoder
 *   media-playout       — audio playout engine stats
 *   peer-connection     — RTCPeerConnection-level counters (DC open/close)
 *   data-channel        — per RTCDataChannel
 *   transport           — per DTLS/ICE transport
 *   candidate-pair      — per nominated ICE candidate pair
 *   local-candidate     — per local ICE candidate
 *   remote-candidate    — per remote ICE candidate
 *   certificate         — DTLS fingerprint + cert material
 *
 * The same helpers are used from:
 *   - pc.getStats(track?)       — full report, optionally filtered by track
 *   - sender.getStats()         — filtered to one outbound SSRC + deps
 *   - receiver.getStats()       — filtered to one inbound SSRC + deps
 *
 * Callers should consider all fields optional except `id`, `type`, `timestamp`
 * (browsers omit fields that don't apply; we follow suit).
 */

var TRANSPORT_ID = 'T01';

// ID prefixes — stable per-session so callers can correlate samples over time.
function _idInbound (ssrc) { return 'IT-' + ssrc; }
function _idOutbound(ssrc) { return 'OT-' + ssrc; }
function _idRemoteInbound (ssrc)   { return 'RIB-' + ssrc; }
function _idRemoteOutbound(ssrc)   { return 'ROB-' + ssrc; }
function _idMediaSource(trackId)   { return 'MS-'  + trackId; }
function _idCodec(pt, dir)         { return 'C-'   + dir + '-' + pt; }
function _idDataChannel(id)        { return 'DC-'  + id; }
function _idLocalCandidate (foundation, component)  { return 'LC-' + foundation + '-' + component; }
function _idRemoteCandidate(foundation, component)  { return 'RC-' + foundation + '-' + component; }
function _idCandidatePair(local, remote)            { return 'CP-' + local + '-' + remote; }
function _idCertificate(fingerprint) { return 'CERT-' + (fingerprint || 'unknown').substring(0, 16); }
function _idMediaPlayout(kind)       { return 'MP-' + kind; }


/* ── RTP-stream helpers ────────────────────────────────────────────── */

function _inboundRtpEntry(ssrc, stats, mapping, now) {
  var kind = (mapping && mapping.transceiver) ? mapping.transceiver.kind : 'video';

  // framesPerSecond (W3C: "frames DECODED in the last second") — derived
  // HERE, at stats-read time, from the framesDecoded counter delta.
  //
  // Why not compute it in the decoder's output callback: a rate computed
  // on frame arrival freezes at its last value when the stream stalls —
  // the callback stops firing, so nothing ever writes the decayed value.
  // Deriving on read means a stalled (or never-decoded) stream reports 0,
  // which is the truth.
  //
  // Semantics under lazy decode: this counts actual decode activity.
  // In SFU/forwarding mode (no sink on the track → decoder never spins
  // up) this is legitimately 0 while media flows — use framesReceived
  // (depacketizer-level, below) or packetsReceived for liveness.
  // Chrome reports a nonzero fps for any flowing stream because its
  // receive path decodes unconditionally; when our decoder IS running
  // (track consumed — the "browser peer in Node" mode) the two agree.
  //
  // Sampling state (_fps*) lives on the per-SSRC stats object and is
  // shared by all readers; with one periodic getStats caller (the
  // common case) the window is simply the polling interval. Re-reads
  // within 250ms return the previous sample instead of a noisy delta.
  var fps = 0;
  if (kind === 'video') {
    var _fd = stats.framesDecoded || 0;
    if (stats._fpsPrevTime) {
      var _dt = now - stats._fpsPrevTime;
      if (_dt >= 250) {
        fps = Math.max(0, Math.round(((_fd - stats._fpsPrevCount) * 1000) / _dt));
        stats._fpsPrevTime  = now;
        stats._fpsPrevCount = _fd;
        stats._fpsLast      = fps;
      } else {
        fps = stats._fpsLast || 0;
      }
    } else {
      stats._fpsPrevTime  = now;
      stats._fpsPrevCount = _fd;
    }
  }

  var entry = {
    id:              _idInbound(ssrc),
    type:            'inbound-rtp',
    timestamp:       now,
    kind:            kind,
    ssrc:            ssrc,
    mid:             mapping ? mapping.mid : undefined,
    transportId:     TRANSPORT_ID,
    codecId:         _idCodec(stats.payloadType || 0, 'in'),
    // Core counters (cumulative since session start) — REQUIRED by spec.
    packetsReceived: stats.packets || 0,
    bytesReceived:   stats.bytes   || 0,
    packetsLost:     stats.packetsLost || 0,
    jitter:          (stats.jitter || 0) / 90000,   // seconds
    // Time bookkeeping
    lastPacketReceivedTimestamp: stats.lastPacketAt || 0,
    // Header bytes: we don't separate header from payload in our counter,
    // so report bytes as headerBytesReceived=0 and let total=bytesReceived.
    headerBytesReceived: 0,
    // Frame counters (video only).
    // framesReceived — DEPACKETIZER-level: complete frames reassembled
    //   from RTP, advances whenever media flows (decode or not). The
    //   Chrome-parity liveness counter; populated by the receive
    //   pipeline's depacketizer output in media_pipeline.js.
    // framesDecoded / framesPerSecond — DECODER-level: actual decode
    //   activity. 0 in SFU/forwarding mode (lazy decoder never spun up).
    framesReceived:   stats.framesReceived   || 0,
    framesDecoded:    stats.framesDecoded    || 0,
    keyFramesDecoded: stats.keyFramesDecoded || 0,
    framesDropped:    stats.framesDropped    || 0,
    frameWidth:       stats.frameWidth       || 0,
    frameHeight:      stats.frameHeight      || 0,
    framesPerSecond:  fps,
    // Feedback counters (NACK/PLI/FIR) — Phase 3 will populate
    nackCount:        stats.nackCount || 0,
    pliCount:         stats.pliCount  || 0,
    firCount:         stats.firCount  || 0,
    // RTX / FEC counters.
    // retransmittedPacketsReceived — every RTX wrap we unwrapped on
    //   this primary SSRC, populated by handleIncomingRtpInner when
    //   isRecovered=true. Matches WebRTC stats spec.
    // packetsRepaired — same value today; will diverge once we
    //   distinguish duplicate RTX from gap-filling RTX.
    // FEC counters stay zero until FEC is implemented.
    retransmittedPacketsReceived: stats.retransmittedPacketsReceived || 0,
    retransmittedBytesReceived:   0,
    fecPacketsReceived:           0,
    fecBytesReceived:             0,
    packetsRepaired:              stats.packetsRepaired || 0,
    // packetsDiscarded — packets received but dropped before decode (jitter
    // buffer overflow, arrived too late). Required by the spec for every
    // inbound stream; we count none today, but the member must exist.
    packetsDiscarded:             stats.packetsDiscarded || 0,
  };
  // Audio-only members. Required on audio inbound streams and absent on video,
  // so they are attached conditionally rather than set to zero everywhere.
  //   totalAudioEnergy     — cumulative energy of received samples (0..1 scale)
  //   totalSamplesDuration — seconds of audio received
  // Both accumulate from the audio-level extension where present; zero until
  // then, which is a valid reading, not a missing one.
  if (kind === 'audio') {
    entry.totalAudioEnergy     = stats.totalAudioEnergy     || 0;
    entry.totalSamplesDuration = stats.totalSamplesDuration || 0;
    entry.totalSamplesReceived = stats.totalSamplesReceived || 0;
    entry.audioLevel           = stats.audioLevel           || 0;
    entry.concealedSamples     = stats.concealedSamples     || 0;
    entry.silentConcealedSamples = stats.silentConcealedSamples || 0;
    entry.concealmentEvents    = stats.concealmentEvents    || 0;
    entry.insertedSamplesForDeceleration = stats.insertedSamplesForDeceleration || 0;
    entry.removedSamplesForAcceleration  = stats.removedSamplesForAcceleration  || 0;
  }
  if (mapping && mapping.transceiver && mapping.transceiver.receiver
      && mapping.transceiver.receiver.track) {
    // Assign only when there is a value — an explicit undefined would make
    // `'trackIdentifier' in entry` true while reading it gives undefined. See
    // fix 11.
    var _tid = mapping.transceiver.receiver.track.id;
    if (_tid) entry.trackIdentifier = _tid;
  }
  return entry;
}

function _outboundRtpEntry(ssrc, stats, transceiver, now) {
  var kind = transceiver ? transceiver.kind : 'video';
  var mediaSourceId = undefined;
  if (transceiver && transceiver.sender && transceiver.sender.track) {
    mediaSourceId = _idMediaSource(transceiver.sender.track.id);
  }

  // framesPerSecond (W3C: "encoded frames in the last second") — derived
  // at read time from the framesEncoded delta, same pattern and rationale
  // as the inbound entry. The pipeline used to write the CONFIGURED
  // framerate here, which (a) reported the target rather than the
  // measurement, and (b) froze at that value forever once the encoder
  // stalled. Sampling state (_fps*) lives on the per-SSRC stats object.
  var fps = 0;
  if (kind === 'video') {
    var _fe = stats.framesEncoded || 0;
    if (stats._fpsPrevTime) {
      var _dt = now - stats._fpsPrevTime;
      if (_dt >= 250) {
        fps = Math.max(0, Math.round(((_fe - stats._fpsPrevCount) * 1000) / _dt));
        stats._fpsPrevTime  = now;
        stats._fpsPrevCount = _fe;
        stats._fpsLast      = fps;
      } else {
        fps = stats._fpsLast || 0;
      }
    } else {
      stats._fpsPrevTime  = now;
      stats._fpsPrevCount = _fe;
    }
  }

  // mid and mediaSourceId are attached below only when we actually have them.
  // A WebIDL dictionary omits absent members rather than setting them to
  // undefined, and the difference is observable: `'mid' in stat` is true for a
  // key explicitly set to undefined, so a consumer that checks presence then
  // reads the value gets undefined from a field it was told exists. WPT
  // asserts that pair inside its umbrella "Validating stats" test, which 19
  // other subtests key off — one stray undefined failed all of them.
  var _out = {
    id:              _idOutbound(ssrc),
    type:            'outbound-rtp',
    timestamp:       now,
    kind:            kind,
    ssrc:            ssrc,
    transportId:     TRANSPORT_ID,
    codecId:         _idCodec(stats.payloadType || 0, 'out'),
    // Core counters — REQUIRED by spec
    packetsSent:     stats.packets || 0,
    bytesSent:       stats.bytes   || 0,
    headerBytesSent: 0,
    // Encoder-populated fields (video only)
    framesEncoded:   stats.framesEncoded    || 0,
    keyFramesEncoded: stats.keyFramesEncoded || 0,
    framesSent:      stats.framesEncoded    || 0,   // ~same for our pipeline
    frameWidth:      stats.frameWidth       || 0,
    frameHeight:     stats.frameHeight      || 0,
    framesPerSecond: fps,
    targetBitrate:   stats.targetBitrate    || 0,
    // Feedback counters (received from remote)
    nackCount:       stats.nackCount || 0,
    pliCount:        stats.pliCount  || 0,
    firCount:        stats.firCount  || 0,
    // RTX (retransmission) counters — populated when NACK handling resends
    // packets via the RTX stream (see connection_manager.handleNack).
    retransmittedPacketsSent: stats.retransmittedPacketsSent || 0,
    retransmittedBytesSent:   stats.retransmittedBytesSent   || 0,
    // Quality limitation — we don't do adaptive encoding yet, always "none"
    qualityLimitationReason:      'none',
    qualityLimitationDurations:   { none: 0, cpu: 0, bandwidth: 0, other: 0 },
    qualityLimitationResolutionChanges: 0,
    active:          true,
  };
  if (transceiver && transceiver.mid != null) _out.mid = transceiver.mid;
  if (mediaSourceId != null) _out.mediaSourceId = mediaSourceId;
  // encodingIndex — this stream's position in sender.getParameters().encodings.
  // 0 for a singlecast sender; for simulcast it identifies which layer the
  // entry describes, which is the only way a consumer can line an outbound-rtp
  // up with the encoding it configured.
  //
  // VIDEO ONLY. encodings are a simulcast concept and audio has none, so an
  // audio outbound-rtp must not carry the member at all — WPT asserts it is
  // undefined there. A first version set it unconditionally and reported 0 on
  // audio streams.
  try {
    var _lys = (kind === 'video') && transceiver && transceiver.sender &&
               transceiver.sender.layers;
    if (_lys && _lys.length) {
      for (var _ei = 0; _ei < _lys.length; _ei++) {
        if (_lys[_ei] && _lys[_ei].ssrc === ssrc) { _out.encodingIndex = _ei; break; }
      }
    } else if (kind === 'video' && transceiver && transceiver.sender &&
               transceiver.sender.ssrc === ssrc) {
      _out.encodingIndex = 0;
    }
  } catch (eE) { /* stats must never throw */ }
  return _out;
}

function _remoteInboundRtpEntry(ssrc, rs, outboundId, kind, now) {
  return {
    id:            _idRemoteInbound(ssrc),
    type:          'remote-inbound-rtp',
    timestamp:     rs.updatedAt || now,
    ssrc:          ssrc,
    kind:          kind || 'video',
    transportId:   TRANSPORT_ID,
    localId:       outboundId,                                // links back to our outbound-rtp
    // Values REPORTED BY remote about packets we sent them:
    // WebIDL dictionaries OMIT absent members; they never carry an explicit
    // `undefined`. The distinction is observable: `'x' in stat` is true for a
    // key set to undefined, so a consumer that checks presence and then reads
    // the value gets undefined from a field it was told exists. WPT asserts
    // exactly that pair, and one such field failed the umbrella "Validating
    // stats" test, which in turn is what 19 dependent subtests key off — so a
    // single stray undefined cost the whole file.
    // packetsReceived is not carried in a Receiver Report, so it is omitted.
    packetsLost:   rs.totalLost || 0,
    jitter:        (rs.jitter       || 0) / 90000,
    fractionLost:  (rs.fractionLost || 0) / 256,              // 0..1
    roundTripTime: (rs.roundTripTime || 0) / 1000,            // seconds
    totalRoundTripTime:      ((rs.roundTripTime || 0) / 1000) * (rs.rttMeasurements || 0),
    roundTripTimeMeasurements: rs.rttMeasurements || 0,
  };
}

function _remoteOutboundRtpEntry(ssrc, ro, inboundId, kind, now) {
  // W3C RTCRemoteOutboundRtpStreamStats — statistics REPORTED BY the remote
  // about its outbound stream (i.e. what Chrome tells us about the media
  // it's sending to us). Extracted from incoming SR (RFC 3550 §6.4.1).
  //
  // `timestamp` here is the time we RECEIVED the SR (local clock).
  // `remoteTimestamp` is when the remote GENERATED the SR (their clock),
  // derived from the NTP timestamp field and converted to Unix-epoch ms.
  return {
    id:              _idRemoteOutbound(ssrc),
    type:            'remote-outbound-rtp',
    timestamp:       ro.updatedAt || now,
    ssrc:            ssrc,
    kind:            kind || 'video',
    transportId:     TRANSPORT_ID,
    localId:         inboundId,                                // links to our inbound-rtp
    // Counters (cumulative, as reported in the SR header):
    packetsSent:     ro.packetsSent || 0,
    bytesSent:       ro.bytesSent   || 0,
    // How many SRs we've received from this remote stream:
    reportsSent:     ro.reportsSent || 0,
    // Remote-clock timestamp from NTP field in SR (Unix-epoch ms):
    remoteTimestamp: ro.remoteTimestampMs || 0,
    // RTT from remote's perspective (if they report DLSR to us). Not yet
    // computed — would require parsing RR blocks in the SR where mediaSsrc
    // references OUR inbound SSRC (unusual when remote is also recvonly).
    roundTripTime:              (ro.roundTripTime || 0) / 1000,
    totalRoundTripTime:         (ro.totalRoundTripTime || 0) / 1000,
    roundTripTimeMeasurements:  ro.roundTripTimeMeasurements || 0,
  };
}


/* ── Codec helper ──────────────────────────────────────────────────── */

// Find the fmtp line negotiated for a payload type, across every transceiver's
// negotiated codec set. Returns null when the codec carries no fmtp.
var _fmtpStatsManager = null;
function _negotiatedFmtpLine(pt) {
  var mgr = _fmtpStatsManager;
  if (!mgr || !mgr.state || !mgr.state.transceivers) return null;
  var tcs = mgr.state.transceivers;
  for (var i = 0; i < tcs.length; i++) {
    var lists = [
      tcs[i]._negotiatedCodecs,
      tcs[i].sender && tcs[i].sender._negotiatedCodecs,
    ];
    for (var l = 0; l < lists.length; l++) {
      var list = lists[l];
      if (!list) continue;
      for (var c = 0; c < list.length; c++) {
        if (list[c] && list[c].payloadType === pt) {
          if (list[c].sdpFmtpLine) return list[c].sdpFmtpLine;
          if (list[c].fmtp && SDP.buildFmtpConfig) {
            var line = SDP.buildFmtpConfig(list[c].fmtp);
            if (line) return line;
          }
          return null;
        }
      }
    }
  }
  return null;
}

function _codecEntry(pt, kind, direction, now) {
  // Map PT → mimeType + clockRate based on common WebRTC assignments.
  // This is a best-effort — real codec params come from SDP fmtp lines.
  var table = {
    96:  { mimeType: 'video/VP8',  clockRate: 90000 },
    97:  { mimeType: 'video/rtx',  clockRate: 90000 },
    98:  { mimeType: 'video/VP9',  clockRate: 90000 },
    99:  { mimeType: 'video/rtx',  clockRate: 90000 },
    100: { mimeType: 'video/H264', clockRate: 90000 },
    101: { mimeType: 'video/rtx',  clockRate: 90000 },
    102: { mimeType: 'video/AV1',  clockRate: 90000 },
    111: { mimeType: 'audio/opus', clockRate: 48000, channels: 2 },
    0:   { mimeType: 'unknown',    clockRate: 0 },
  };
  var info = table[pt] || { mimeType: (kind + '/unknown'), clockRate: 90000 };
  var entry = {
    id:          _idCodec(pt, direction),
    type:        'codec',
    timestamp:   now,
    transportId: TRANSPORT_ID,
    payloadType: pt,
    mimeType:    info.mimeType,
    clockRate:   info.clockRate,
  };
  if (info.channels) entry.channels = info.channels;
  // sdpFmtpLine — the fmtp parameters actually negotiated for this PT. The
  // table above is a static PT→name map and carries none, so opus reported no
  // sdpFmtpLine even when the SDP said "minptime=10;useinbandfec=1". Read it
  // back from the negotiated codec list instead, which is the authoritative
  // source. Omitted (not undefined) when the codec has no fmtp — see fix 11.
  try {
    var _fmtpLine = _negotiatedFmtpLine(pt);
    if (_fmtpLine) entry.sdpFmtpLine = _fmtpLine;
  } catch (eF) { /* stats must never throw */ }
  return entry;
}


/* ── Media-source helpers ──────────────────────────────────────────── */

function _mediaSourceEntry(track, now, sender) {
  if (!track) return null;
  var entry = {
    id:              _idMediaSource(track.id),
    type:            'media-source',
    timestamp:       now,
    trackIdentifier: track.id,
    kind:            track.kind,
  };
  var settings = (typeof track.getSettings === 'function') ? track.getSettings() : null;
  if (track.kind === 'video') {
    if (settings) {
      entry.width         = settings.width || 0;
      entry.height        = settings.height || 0;
      entry.framesPerSecond = settings.frameRate || 0;
    }
    // QUICK-8: cumulative frames-from-source counter, maintained on the
    // internal sender by RTCRtpSender's track listener (see startPipeline).
    // Defaults to 0 if the sender hasn't started a pipeline yet (or if
    // we're called for a sender we don't recognize).
    entry.frames = (sender && typeof sender._framesFromSource === 'number')
      ? sender._framesFromSource
      : 0;
  } else {
    // audio
    if (settings) {
      entry.sampleRate = settings.sampleRate || 48000;
    }
    // audioLevel / totalAudioEnergy / totalSamplesDuration are populated
    // when RTP-5 (RFC 6464 audio level) lands and exposes the per-AudioData
    // RMS via media-processing's nonstandard.computeAudioRms helper.
    // See MP-1 for the AudioData fixes that unblock this.
    entry.audioLevel         = 0;
    entry.totalAudioEnergy   = 0;
    entry.totalSamplesDuration = 0;
  }
  return entry;
}


/* ── Media-playout ────────────────────────────────────────────────────
 * Per W3C RTCAudioPlayoutStats — accumulators describing the audio output
 * side. Only emitted when there's at least one inbound audio stream. We
 * don't have a real AudioContext hooked up yet (synthesized samples,
 * concealment events, etc. all require the actual playout pipeline),
 * so most fields stay at zero until the audio rendering pipeline wires
 * in real telemetry. Spec requires only `kind` and the accumulator fields
 * to be present even if zero — browsers that produce this stat still
 * report zeros when there's no concealment/synthesis.
 */
function _mediaPlayoutEntry(kind, stats, now) {
  return {
    id:          _idMediaPlayout(kind),
    type:        'media-playout',
    timestamp:   now,
    kind:        kind,
    // Accumulators — all start at zero, grow as playout telemetry hooks in
    synthesizedSamplesDuration: (stats && stats.synthesizedSamplesDuration) || 0,
    synthesizedSamplesEvents:   (stats && stats.synthesizedSamplesEvents)   || 0,
    totalSamplesDuration:       (stats && stats.totalSamplesDuration)       || 0,
    totalPlayoutDelay:          (stats && stats.totalPlayoutDelay)          || 0,
    totalSamplesCount:          (stats && stats.totalSamplesCount)          || 0,
  };
}


/* ── Transport ─────────────────────────────────────────────────────── */

function _transportEntry(snapshot, snap, now) {
  // Aggregate bytes across all SSRCs — approximate, but matches what
  // browsers report (pre-SRTP size, per SSRC totalled).
  var bytesSent = 0, bytesReceived = 0, packetsSent = 0, packetsReceived = 0;
  var sk = Object.keys(snap.outbound);
  for (var i = 0; i < sk.length; i++) {
    var o = snap.outbound[sk[i]];
    bytesSent   += o.bytes   || 0;
    packetsSent += o.packets || 0;
  }
  var rk = Object.keys(snap.inbound);
  for (var j = 0; j < rk.length; j++) {
    var r = snap.inbound[rk[j]];
    bytesReceived   += r.bytes   || 0;
    packetsReceived += r.packets || 0;
  }

  var entry = {
    id:                      TRANSPORT_ID,
    type:                    'transport',
    timestamp:               now,
    bytesSent:               bytesSent,
    bytesReceived:           bytesReceived,
    packetsSent:             packetsSent,
    packetsReceived:         packetsReceived,
    dtlsState:               snapshot.dtlsState || 'new',
    iceState:                snapshot.iceConnectionState || 'new',
    dtlsRole:                snapshot.dtlsRole || 'unknown',
    // W3C stats: iceRole follows who OFFERED — offerer controlling,
    // answerer controlled (RFC 8445 6.1); 'unknown' before any local
    // description exists.
    iceRole: (function () {
      var d = snapshot.pendingLocalDescription || snapshot.currentLocalDescription;
      if (!d) return 'unknown';
      return d.type === 'offer' ? 'controlling' : 'controlled';
    })(),
    // W3C: how many times the selected pair has changed — 0 before any
    // pair is nominated, incremented by the agent's selectedpair events.
    selectedCandidatePairChanges: snapshot.selectedPairChanges || 0,
    selectedCandidatePairId: snapshot.selectedPair
      ? _idCandidatePair(
          (snapshot.selectedPair.local  && snapshot.selectedPair.local.foundation)  || '0',
          (snapshot.selectedPair.remote && snapshot.selectedPair.remote.foundation) || '0')
      : undefined,
    // Optional — these depend on the DTLS lib exposing the info.
    srtpCipher:              'AES_CM_128_HMAC_SHA1_80',
    iceLocalUsernameFragment: snapshot.localIceUfrag || undefined,
  };
  if (snapshot.localFingerprint) {
    var lfp = typeof snapshot.localFingerprint === 'object'
              ? snapshot.localFingerprint.value
              : snapshot.localFingerprint;
    if (lfp) entry.localCertificateId = _idCertificate(lfp);
  }
  if (snapshot.remoteFingerprint) {
    var rfp = typeof snapshot.remoteFingerprint === 'object'
              ? snapshot.remoteFingerprint.value
              : snapshot.remoteFingerprint;
    if (rfp) entry.remoteCertificateId = _idCertificate(rfp);
  }
  return entry;
}


/* ── Candidates + candidate-pair ───────────────────────────────────── */

function _candidateEntry(cand, kind, now) {
  if (!cand) return null;
  // kind: 'local' | 'remote'
  var entry = {
    id:            (kind === 'local' ? _idLocalCandidate : _idRemoteCandidate)(
                      cand.foundation || '0', cand.component || 1),
    type:          (kind === 'local') ? 'local-candidate' : 'remote-candidate',
    timestamp:     now,
    transportId:   TRANSPORT_ID,
    address:       cand.ip   || cand.address || '',
    port:          cand.port || 0,
    protocol:      cand.protocol || 'udp',
    candidateType: cand.type || 'host',
    priority:      cand.priority || 0,
    foundation:    cand.foundation || '',
  };
  if (cand.relatedAddress) entry.relatedAddress = cand.relatedAddress;
  if (cand.relatedPort)    entry.relatedPort    = cand.relatedPort;
  if (cand.tcpType)        entry.tcpType        = cand.tcpType;
  if (cand.relayProtocol)  entry.relayProtocol  = cand.relayProtocol;
  return entry;
}

function _candidatePairEntry(snapshot, snap, now) {
  if (!snapshot.selectedPair) return null;
  var pair = snapshot.selectedPair;
  var localFoundation  = (pair.local  && pair.local.foundation)  || '0';
  var remoteFoundation = (pair.remote && pair.remote.foundation) || '0';

  // Aggregate media bytes from transport (for the "how much media crossed
  // this pair" view). STUN-level bytes are already on pair.bytesSent/Received.
  var mediaBytesSent = 0, mediaBytesReceived = 0;
  var mediaPacketsSent = 0, mediaPacketsReceived = 0;
  var sk = Object.keys(snap.outbound);
  for (var j = 0; j < sk.length; j++) {
    mediaBytesSent   += snap.outbound[sk[j]].bytes   || 0;
    mediaPacketsSent += snap.outbound[sk[j]].packets || 0;
  }
  var rk = Object.keys(snap.inbound);
  for (var k = 0; k < rk.length; k++) {
    mediaBytesReceived   += snap.inbound[rk[k]].bytes   || 0;
    mediaPacketsReceived += snap.inbound[rk[k]].packets || 0;
  }

  // Total bytes on this pair = STUN + media (matches browser behavior).
  var totalBytesSent     = (pair.bytesSent     || 0) + mediaBytesSent;
  var totalBytesReceived = (pair.bytesReceived || 0) + mediaBytesReceived;

  // RTT — primary source is STUN binding (measured directly on every
  // check/consent response, ~1s cadence).
  //
  // In ICE Lite mode the server doesn't initiate connectivity checks or
  // consent keepalives — it only responds. So pair.roundTripTime stays 0.
  // We fall back to the RTT derived from RTCP Receiver Reports, which the
  // remote sends every ~5s (connection_manager populates state.rtcpStats
  // with roundTripTime in milliseconds).
  var rttSeconds     = pair.roundTripTime      || 0;
  var totalRttSeconds = pair.totalRoundTripTime || 0;
  var rttMeasurements = pair.rttMeasurements    || 0;
  if (rttSeconds === 0) {
    // Fallback: average RTT across all SSRCs with RR data.
    var rttSum = 0, rttCount = 0;
    var rkeys = Object.keys(snap.rtcp);
    for (var ri = 0; ri < rkeys.length; ri++) {
      var rs = snap.rtcp[rkeys[ri]];
      if (rs && rs.roundTripTime) {
        rttSum   += rs.roundTripTime;   // ms
        rttCount++;
      }
    }
    if (rttCount > 0) {
      rttSeconds      = (rttSum / rttCount) / 1000;
      totalRttSeconds = (rttSum / 1000);
      rttMeasurements = rttCount;
    }
  }

  return {
    id:                       _idCandidatePair(localFoundation, remoteFoundation),
    type:                     'candidate-pair',
    timestamp:                now,
    transportId:              TRANSPORT_ID,
    localCandidateId:         _idLocalCandidate (localFoundation,
                                                 (pair.local  && pair.local.component)  || 1),
    remoteCandidateId:        _idRemoteCandidate(remoteFoundation,
                                                 (pair.remote && pair.remote.component) || 1),
    state:                    'succeeded',
    nominated:                pair.nominated !== false,
    // Per ICE priority formula (RFC 8445 §6.1.2.3):
    //   priority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G>D ? 1 : 0)
    // where G = controlling-agent candidate priority, D = controlled agent's.
    // JavaScript's number is safe up to 2^53, so we compute with BigInt-like
    // math using two halves if needed. For typical ICE values (< 2^31) we
    // can just approximate as local*remote-ish. stable-webrtc uses it only
    // for comparing "which pair is best" so relative order is what matters.
    priority: _computePairPriority(
      (pair.local  && pair.local.priority)  || 0,
      (pair.remote && pair.remote.priority) || 0,
      pair.controlling !== false   // we're controlled (ICE Lite), but nominate side matters for the formula
    ),
    // Byte/packet counters (aggregate: STUN + media). Matches Chrome.
    bytesSent:                totalBytesSent,
    bytesReceived:            totalBytesReceived,
    // MEDIA COUNTS TOWARDS THE PAIR TOTALS, IN PACKETS AS WELL AS BYTES.
    //
    // The byte totals above already add the RTP that went over this pair to
    // the STUN traffic — the packet counts did not, so a pair reported three
    // packets carrying twenty kilobytes. Anything deriving a rate or an
    // average packet size from candidate-pair stats got an absurd answer, and
    // W3C 8.4 defines both members over the same traffic.
    packetsSent:              (pair.packetsSent || 0) + mediaPacketsSent,
    packetsReceived:          (pair.packetsReceived || 0) + mediaPacketsReceived,
    // RTT (seconds) — preferred from STUN, falls back to RTCP RR
    currentRoundTripTime:     rttSeconds,
    totalRoundTripTime:       totalRttSeconds,
    roundTripTimeMeasurements: rttMeasurements,
    // STUN check counters (connectivity + consent)
    requestsSent:             pair.requestsSent      || 0,
    requestsReceived:         pair.requestsReceived  || 0,
    responsesSent:            pair.responsesSent     || 0,
    responsesReceived:        pair.responsesReceived || 0,
    consentRequestsSent:      pair.consentRequestsSent || 0,
    // Activity timestamps
    lastPacketSentTimestamp:     pair.lastPacketSentTimestamp     || 0,
    lastPacketReceivedTimestamp: pair.lastPacketReceivedTimestamp || 0,
    // Sender-side bandwidth estimate, from transport-cc + REMB feedback.
    // Exposed by connection_manager.getCurrentStats() as
    // `estimatedBandwidthBps`. Left undefined until we have a meaningful
    // signal (first feedback message from remote).
    availableOutgoingBitrate: snap.estimatedBandwidthBps || undefined,
    // We don't currently estimate incoming bitrate — would require us to
    // be the one sending transport-cc back to the remote.
    // availableIncomingBitrate omitted — see the note on packetsReceived in
    // _remoteInboundEntry: an absent dictionary member is left out, not set
    // to undefined.
  };
}

// Compute ICE candidate pair priority per RFC 8445 §6.1.2.3.
// Returns a Number (may be approximate for priorities near 2^32).
function _computePairPriority(G, D, controlling) {
  // For 32-bit G, D: priority = 2^32 * min(G,D) + 2 * max(G,D) + (G>D?1:0)
  var min = Math.min(G, D);
  var max = Math.max(G, D);
  // 2^32 * min may exceed Number.MAX_SAFE_INTEGER for large G/D. But since
  // stable-webrtc only uses this for comparison (not arithmetic), small
  // precision loss for very-high-priority pairs is acceptable.
  return (min * 4294967296) + (2 * max) + (G > D && controlling ? 1 : 0);
}


/* ── Data channel ──────────────────────────────────────────────────── */

function _dataChannelEntry(dc, now) {
  var s = dc._stats || {};
  return {
    id:                    _idDataChannel(dc.id),
    type:                  'data-channel',
    timestamp:             now,
    label:                 dc.label || '',
    protocol:              dc.protocol || '',
    dataChannelIdentifier: dc.id,
    state:                 dc.readyState,
    messagesSent:          s.messagesSent     || 0,
    bytesSent:             s.bytesSent        || 0,
    messagesReceived:      s.messagesReceived || 0,
    bytesReceived:         s.bytesReceived    || 0,
  };
}


/* Build a W3C-spec RTCSctpTransportStats from the live SCTP association.
 *
 * Per https://w3c.github.io/webrtc-stats/#sctptransportstats-dict* :
 *   id              implementation-defined
 *   timestamp       monotonic ms
 *   transportId     reference to RTCTransportStats (DTLS transport)
 *   smoothedRoundTripTime  in seconds (we expose ms internally; convert)
 *
 * The full spec adds congestionWindow, receiverWindow, mtu, but those are
 * "MAY" in current draft. We surface them as extensions because they're
 * directly useful for diagnosing throughput issues. Field names match
 * libwebrtc's getStats output for compatibility with existing consumers.
 */
function _sctpTransportEntry(snapshot, now) {
  var sctp = snapshot.sctpAssociation;
  if (!sctp) return null;
  var s = sctp.stats;
  return {
    id:                    'SCTP',
    type:                  'sctp-transport',
    timestamp:             now,
    transportId:           'T',                              // matches _transportEntry id
    // Spec field — seconds, not ms. null until first RTT sample.
    smoothedRoundTripTime: (s.srtt != null) ? s.srtt / 1000 : null,
    // Extensions (libwebrtc-style):
    congestionWindow:      s.cwnd,
    receiverWindow:        s.remoteRwnd,
    mtu:                   sctp.pmtu || undefined,
    // Internal counters useful for telemetry; not strictly W3C but
    // harmless additions.
    chunksSent:            s.chunksSent,
    chunksRetransmitted:   s.chunksRetransmitted,
    chunksAbandoned:       s.chunksAbandoned,
    fastRetransmits:       s.fastRetransmits,
    rtoExpiries:           s.rtoExpiries,
    pathFailures:          s.pathFailures,
  };
}


/* ── Peer connection (aggregate) ───────────────────────────────────── */

function _peerConnectionEntry(snapshot, now) {
  var dcOpened = 0, dcClosed = 0;
  if (snapshot.dataChannels) {
    for (var i = 0; i < snapshot.dataChannels.length; i++) {
      var dc = snapshot.dataChannels[i];
      if (dc.readyState === 'open' || dc._everOpened) dcOpened++;
      if (dc.readyState === 'closed') dcClosed++;
    }
  }
  return {
    id:                  'PC',
    type:                'peer-connection',
    timestamp:           now,
    dataChannelsOpened:  dcOpened,
    dataChannelsClosed:  dcClosed,
    dataChannelsRequested: (snapshot.dataChannels || []).length,
    dataChannelsAccepted:  dcOpened,
  };
}


/* ── Certificate ───────────────────────────────────────────────────── */

function _certificateEntry(fp, isLocal, now, pem) {
  // fp may be null, a string, or {algorithm, value} depending on source.
  if (!fp) return null;
  var algorithm = 'sha-256';
  var value = fp;
  if (typeof fp === 'object') {
    algorithm = fp.algorithm || 'sha-256';
    value     = fp.value     || '';
  }
  if (!value) return null;
  return {
    id:                   _idCertificate(value),
    type:                 'certificate',
    timestamp:            now,
    fingerprint:          value,
    fingerprintAlgorithm: algorithm,
    // THE DER, BASE64-ENCODED (W3C stats): this was left empty with a
    // note that the DTLS layer would need to expose it — but the PEM is
    // already on state, and base64Certificate is simply its body with
    // the armour stripped. An empty value makes the whole certificate
    // stat useless: a consumer cannot verify that the fingerprint it was
    // given actually belongs to the certificate in use, which is the
    // only reason the entry exists.
    base64Certificate: (function () {
      if (!pem) return '';
      try {
        // The local side holds PEM text; the peer's certificate arrives
        // from the DTLS handshake as raw DER bytes. Accept either.
        if (typeof pem !== 'string' && pem.length != null) {
          return Buffer.from(pem).toString('base64');
        }
        var body = String(pem)
          .replace(/-----BEGIN CERTIFICATE-----/g, '')
          .replace(/-----END CERTIFICATE-----/g, '')
          .replace(/[\r\n\s]/g, '');
        return body;
      } catch (eB) { return ''; }
    })(),
  };
}


/* ── Main builder ──────────────────────────────────────────────────── */

/**
 * Build the full stats report.
 *
 * @param {ConnectionManager} manager
 * @param {object|null} [filter]   Internal filter shape:
 *   { ssrc }           → single-SSRC filter (receiver, or non-simulcast sender)
 *   { ssrcs: [...] }   → multi-SSRC filter (simulcast sender — include all layers)
 *   null / omitted     → include everything
 */
var _pendingReceiverMid = null;
function _buildStatsReport(manager, filter) {
  // _codecEntry needs the negotiated codec sets to fill sdpFmtpLine, and it is
  // called from several places that do not carry the manager. Park it here for
  // the duration of the build.
  _fmtpStatsManager = manager;
  _pendingReceiverMid = null;
  var report   = new Map();
  var now      = Date.now();
  var snap     = manager.getCurrentStats();
  var snapshot = manager.state;

  // Normalize filter to a Set of SSRCs (or null for "all").
  var filterSet = null;
  if (filter) {
    if (filter.ssrcs && filter.ssrcs.length) {
      filterSet = {};
      for (var fi = 0; fi < filter.ssrcs.length; fi++) {
        if (filter.ssrcs[fi] != null) filterSet[filter.ssrcs[fi]] = true;
      }
    } else if (filter.ssrc != null) {
      filterSet = {};
      filterSet[filter.ssrc] = true;
    }
    if (filter.receiverMid != null) {
      // Receiver selector: remember the mid so a zeros inbound-rtp can be
      // emitted if the SSRC-driven pass produces none. See the note at the
      // selector resolution site.
      if (!filterSet) filterSet = {};
      _pendingReceiverMid = filter.receiverMid;
    }
  }
  // All filtering now goes through filterSet — see above.

  // When filtering by a single SSRC (sender/receiver getStats), we still
  // include the associated transport/candidate-pair/codec entries that
  // the RTP entry references — otherwise the report would have dangling
  // `transportId`/`codecId`/`localCandidateId` links.
  //
  // Per spec ("All stats object references have type DOMString... referenced
  // stats objects MUST be present in the report"), we always include the
  // transport and candidate-pair, and the codec of the filtered stream.

  // peer-connection (always useful)
  report.set('PC', _peerConnectionEntry(snapshot, now));

  // transport (always)
  var tEntry = _transportEntry(snapshot, snap, now);
  report.set(TRANSPORT_ID, tEntry);

  // certificates (always, if known)
  var localCert = _certificateEntry(snapshot.localFingerprint, true, now, snapshot.cert);
  if (localCert) report.set(localCert.id, localCert);
  // The peer's DER is captured during fingerprint verification
  // (state.remoteCertificates) — the same bytes we hashed to check the
  // fingerprint, so a consumer can repeat that check from the stats.
  var _remPem = (snapshot.remoteCertificates && snapshot.remoteCertificates[0]) || null;
  var remoteCert = _certificateEntry(snapshot.remoteFingerprint, false, now, _remPem);
  if (remoteCert) report.set(remoteCert.id, remoteCert);

  // candidates + candidate-pair (always, if we have a selected pair)
  if (snapshot.selectedPair) {
    var localCandEntry  = _candidateEntry(snapshot.selectedPair.local,  'local',  now);
    var remoteCandEntry = _candidateEntry(snapshot.selectedPair.remote, 'remote', now);
    if (localCandEntry)  report.set(localCandEntry.id,  localCandEntry);
    if (remoteCandEntry) report.set(remoteCandEntry.id, remoteCandEntry);
    var cpEntry = _candidatePairEntry(snapshot, snap, now);
    if (cpEntry) report.set(cpEntry.id, cpEntry);
  }

  // Track which codec PTs we need to emit after RTP streams are collected.
  var codecsInUse = {};   // "pt:dir" → {pt, kind, dir}

  // inbound-rtp entries (+ remote-outbound-rtp if we've seen SR for the same SSRC)
  var inboundSsrcs = Object.keys(snap.inbound);
  var hasInboundAudio = false;
  for (var i = 0; i < inboundSsrcs.length; i++) {
    var inSsrc = parseInt(inboundSsrcs[i], 10);
    if (filterSet && !filterSet[inSsrc]) continue;
    var stats   = snap.inbound[inSsrc];
    var mapping = snapshot.remoteSsrcMap[inSsrc];
    if (mapping && mapping.isRtx) continue;  // don't report RTX as its own stream
    var entry = _inboundRtpEntry(inSsrc, stats, mapping, now);
    var kindIn = (mapping && mapping.transceiver) ? mapping.transceiver.kind : 'video';

    // Audio inbound links to media-playout for playout-side telemetry.
    if (kindIn === 'audio') {
      hasInboundAudio = true;
      entry.playoutId = _idMediaPlayout('audio');
    }

    // If the remote has sent us SRs for this stream, there's a companion
    // remote-outbound-rtp entry. Link them via remoteId/localId per spec.
    var ro = snap.remoteOutbound ? snap.remoteOutbound[inSsrc] : null;
    if (ro) {
      entry.remoteId = _idRemoteOutbound(inSsrc);
    }

    report.set(entry.id, entry);
    codecsInUse[(stats.payloadType || 0) + ':in'] = { pt: stats.payloadType || 0, kind: kindIn, dir: 'in' };

    if (ro) {
      var roEntry = _remoteOutboundRtpEntry(inSsrc, ro, entry.id, kindIn, now);
      report.set(roEntry.id, roEntry);
    }
  }

  // media-playout — one per kind that has inbound. For now audio only.
  if (hasInboundAudio) {
    var playoutAudio = _mediaPlayoutEntry('audio', snap.playout && snap.playout.audio, now);
    report.set(playoutAudio.id, playoutAudio);
  }

  // Receiver selector with no SSRC yet: emit its zeros inbound-rtp so the
  // caller gets an answer about the track it asked about. See the selector
  // resolution site in impl.getStats.
  if (_pendingReceiverMid != null) {
    var _haveInbound = false;
    report.forEach(function (r) { if (r && r.type === 'inbound-rtp') _haveInbound = true; });
    if (_haveInbound) _pendingReceiverMid = null;
  }
  if (_pendingReceiverMid != null) {
    var _rmid = _pendingReceiverMid;
    var _rtcs = (snapshot && snapshot.transceivers) || [];
    for (var _rj = 0; _rj < _rtcs.length; _rj++) {
      if (String(_rtcs[_rj].mid) !== String(_rmid)) continue;
      var _rid2 = 'RTCInboundRTPStream_' + _rmid;
      report.set(_rid2, {
        id: _rid2, type: 'inbound-rtp', timestamp: now,
        kind: _rtcs[_rj].kind || 'audio',
        ssrc: 0, packetsReceived: 0, bytesReceived: 0, packetsLost: 0, jitter: 0,
        transportId: TRANSPORT_ID,
      });
      break;
    }
  }

  // Every sender that has been given an SSRC reports an outbound-rtp entry,
  // even before it has sent a packet — a transceiver created with a null track
  // still has a stream, it is simply idle. snap.outbound is populated by the
  // send path, so without this a sender that has never transmitted produced no
  // entry at all and pc.getStats()/sender.getStats() looked empty.
  //
  // Mirrors what the receive side already does (see _getStatsNow0 in
  // RTCRtpReceiver): a live stream always reports, with zeros.
  //
  // Simulcast layers each carry their own SSRC and each get their own entry.
  try {
    var _tcs = (snapshot && snapshot.transceivers) || [];
    for (var _ti = 0; _ti < _tcs.length; _ti++) {
      var _sndr = _tcs[_ti].sender;
      if (!_sndr) continue;
      if (RtpManager.isStopped(_tcs[_ti])) continue;
      // Only a NEGOTIATED sending direction has a stream. Before the answer
      // lands, currentDirection is null — the transceiver exists but nothing
      // is being sent, and the spec says there is no outbound-rtp yet:
      //
      //   addTransceiver('video')      → no outbound-rtp
      //   setLocalDescription()        → still none (have-local-offer)
      //   answer applied, sendrecv     → now it exists
      //
      // Seeding on existence alone made the entry appear one negotiation step
      // too early.
      var _cd = _tcs[_ti].currentDirection;
      if (_cd !== 'sendrecv' && _cd !== 'sendonly') continue;
      var _lys = (_sndr.layers && _sndr.layers.length)
        ? _sndr.layers
        : (_sndr.ssrc != null ? [{ ssrc: _sndr.ssrc }] : []);
      for (var _li = 0; _li < _lys.length; _li++) {
        var _ls = _lys[_li] && _lys[_li].ssrc;
        if (_ls == null) continue;
        if (!snap.outbound[_ls]) {
          snap.outbound[_ls] = {
            packets: 0, bytes: 0,
            payloadType: (_sndr._negotiatedCodecs && _sndr._negotiatedCodecs[0] &&
                          _sndr._negotiatedCodecs[0].payloadType) || 0,
            firstPacketAt: 0, lastPacketAt: 0,
          };
        }
      }
    }
  } catch (eOut) { /* stats must never throw */ }

  // outbound-rtp + remote-inbound-rtp entries
  var outboundSsrcs = Object.keys(snap.outbound);
  for (var j = 0; j < outboundSsrcs.length; j++) {
    var outSsrc = parseInt(outboundSsrcs[j], 10);
    if (filterSet && !filterSet[outSsrc]) continue;

    // Find the transceiver that owns this outbound SSRC. For simulcast
    // senders, the SSRC may belong to any of sender.layers[], not just
    // sender.ssrc (which mirrors layers[0]). Scan all layers so stats
    // are associated with the correct transceiver + layer's RID.
    var tc = null;
    var tcLayer = null;
    for (var t = 0; t < snapshot.transceivers.length; t++) {
      var sndr = snapshot.transceivers[t].sender;
      // Search layers FIRST. sender.ssrc mirrors layers[0].ssrc, so matching
      // on it before scanning layers found the transceiver but left tcLayer
      // null for the first simulcast layer — and outbound-rtp.rid is set from
      // tcLayer. The lowest layer therefore reported no rid while its
      // siblings did, which makes a simulcast sender's stats unreadable
      // exactly where a consumer needs to tell the layers apart.
      if (sndr.layers && sndr.layers.length) {
        for (var ly = 0; ly < sndr.layers.length; ly++) {
          if (sndr.layers[ly].ssrc === outSsrc) {
            tc = snapshot.transceivers[t];
            tcLayer = sndr.layers[ly];
            break;
          }
        }
        if (tc) break;
      }
      if (sndr.ssrc === outSsrc) { tc = snapshot.transceivers[t]; break; }
    }
    var oStats = snap.outbound[outSsrc];
    var oEntry = _outboundRtpEntry(outSsrc, oStats, tc, now);
    // W3C outbound-rtp.rid — simulcast layer identifier. Present only
    // when this SSRC belongs to a named simulcast layer; omitted for
    // non-simulcast senders (per spec, dictionary field is optional).
    if (tcLayer && tcLayer.rid) oEntry.rid = tcLayer.rid;

    // If remote has sent RR for this SSRC, link to its remote-inbound-rtp.
    var rs = snap.rtcp[outSsrc];
    if (rs) {
      oEntry.remoteId = _idRemoteInbound(outSsrc);
    }

    report.set(oEntry.id, oEntry);
    var kindOut = tc ? tc.kind : 'video';
    codecsInUse[(oStats.payloadType || 0) + ':out'] = { pt: oStats.payloadType || 0, kind: kindOut, dir: 'out' };

    // media-source for the attached track (if any)
    if (tc && tc.sender && tc.sender.track) {
      var msEntry = _mediaSourceEntry(tc.sender.track, now, tc.sender);
      if (msEntry) report.set(msEntry.id, msEntry);
    }

    // remote-inbound-rtp (what the remote reports about this outbound stream)
    if (rs) {
      var rEntry = _remoteInboundRtpEntry(outSsrc, rs, oEntry.id, kindOut, now);
      report.set(rEntry.id, rEntry);
    }
  }

  // codec entries — one per (payload-type, direction) in use
  var ckeys = Object.keys(codecsInUse);
  for (var ci = 0; ci < ckeys.length; ci++) {
    var cc = codecsInUse[ckeys[ci]];
    var codec = _codecEntry(cc.pt, cc.kind, cc.dir, now);
    report.set(codec.id, codec);
  }

  // data-channel entries (only when unfiltered — DCs have no SSRC)
  if (filterSet == null && snapshot.dataChannels) {
    for (var dci = 0; dci < snapshot.dataChannels.length; dci++) {
      var dcEntry = _dataChannelEntry(snapshot.dataChannels[dci], now);
      report.set(dcEntry.id, dcEntry);
    }
  }

  // sctp-transport entry (only when unfiltered, and only if SCTP layer is up)
  if (filterSet == null) {
    var sctpEntry = _sctpTransportEntry(snapshot, now);
    if (sctpEntry) report.set(sctpEntry.id, sctpEntry);
  }

  return report;
}


export {
  RTCPeerConnection,
  RTCSessionDescription,
  RTCIceCandidate,
  RTCRtpSender,
  RTCRtpReceiver,
  RTCRtpTransceiver,
  RTCDataChannel,
  RTCSctpTransport,
  RTCDtlsTransport,
  RTCIceTransport,
  RTCCertificate,
  RTCDTMFSender,
  RTCTrackEvent,
  RTCDataChannelEvent,
  RTCPeerConnectionIceEvent,
  RTCPeerConnectionIceErrorEvent,
  RTCError,
  RTCErrorEvent,
  RTCDTMFToneChangeEvent,
};

export default RTCPeerConnection;
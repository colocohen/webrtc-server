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
import { getSupportedVideoCodecs, getSupportedAudioCodecs, MediaStreamTrack } from 'media-processing';

// Debug logging gate. Set WEBRTC_DEBUG=1 in env to enable diagnostic
// '[api-diag]' lines that trace track/datachannel/pipeline lifecycle.
// Off by default — keeps production output clean. Apps that need to
// debug a connection issue can flip the env var without code changes.
var _DBG = (typeof process !== 'undefined' &&
            process.env &&
            (process.env.WEBRTC_DEBUG === '1' ||
             process.env.WEBRTC_DEBUG === 'true'));
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
  if (config.bundlePolicy != null &&
      config.bundlePolicy !== 'balanced' &&
      config.bundlePolicy !== 'max-bundle' &&
      config.bundlePolicy !== 'max-compat') {
    throw new TypeError('RTCPeerConnection: invalid bundlePolicy "' +
      config.bundlePolicy + '" (expected "balanced", "max-bundle", or "max-compat")');
  }
  if (config.rtcpMuxPolicy != null && config.rtcpMuxPolicy !== 'require') {
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
  // NOTE: iceCandidatePoolSize is round-tripped via getConfiguration but
  // does not actually pre-gather. TODO: implement pre-gather pool.

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
      config = Object.assign({}, config, {
        cert: c0._cert,
        key:  c0._key,
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
    // W3C §4.3.2: returns null until a remote description has been set,
    // then true if the remote indicated trickle support (via
    // a=ice-options:trickle), else false. We're permissive here — once
    // a remote description is set we assume trickle support unless we
    // explicitly stored otherwise. (cm.js doesn't currently parse
    // ice-options on the remote side; trickle support is the WebRTC
    // norm, so true is the correct optimistic default.)
    get: function() {
      if (!manager.state.currentRemoteDescription &&
          !manager.state.pendingRemoteDescription) {
        return null;
      }
      return true;
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

  // SDP descriptions — pending || current (browser-compatible)
  Object.defineProperty(this, 'localDescription', {
    get: function() { return manager.state.pendingLocalDescription || manager.state.currentLocalDescription; },
  });
  Object.defineProperty(this, 'remoteDescription', {
    get: function() { return manager.state.pendingRemoteDescription || manager.state.currentRemoteDescription; },
  });
  Object.defineProperty(this, 'currentLocalDescription', {
    get: function() { return manager.state.currentLocalDescription; },
  });
  Object.defineProperty(this, 'currentRemoteDescription', {
    get: function() { return manager.state.currentRemoteDescription; },
  });
  Object.defineProperty(this, 'pendingLocalDescription', {
    get: function() { return manager.state.pendingLocalDescription; },
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
          if (_handlers[name]) ev.removeListener(name, _handlers[name]);
          _handlers[name] = fn;
          if (fn) ev.on(name, fn);
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
  var _iceCandHandler = null;
  var _iceCandErrHandler = null;
  ev.on('icecandidate', function (payload) {
    if (!_iceCandHandler) return;
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
    _iceCandHandler(new RTCPeerConnectionIceEvent({ candidate: candidate }));
  });
  Object.defineProperty(self, 'onicecandidate', {
    get: function() { return _iceCandHandler; },
    set: function(fn) { _iceCandHandler = fn; },
  });

  ev.on('icecandidateerror', function (payload) {
    if (!_iceCandErrHandler) return;
    _iceCandErrHandler(new RTCPeerConnectionIceErrorEvent(payload || {}));
  });
  Object.defineProperty(self, 'onicecandidateerror', {
    get: function() { return _iceCandErrHandler; },
    set: function(fn) { _iceCandErrHandler = fn; },
  });

  // ondatachannel — wraps internal channel → RTCDataChannel
  var _dcHandler = null;
  ev.on('datachannel', function(internal) {
    _diag('[api-diag] datachannel event received, _dcHandler=' + (_dcHandler ? 'set' : 'null') +
                ' channel=' + (internal && internal.channel && internal.channel.label));
    if (_dcHandler) {
      var wrapped = new RTCDataChannel(internal.channel, manager);
      _dcHandler(new RTCDataChannelEvent({ channel: wrapped }));
    }
  });
  Object.defineProperty(self, 'ondatachannel', {
    get: function() { return _dcHandler; },
    set: function(fn) {
      _diag('[api-diag] ondatachannel setter called, fn=' + (fn ? 'function' : 'null'));
      _dcHandler = fn;
    },
  });

  // ontrack — wraps manager's track:new into RTCTrackEvent
  var _trackHandler = null;
  ev.on('track:new', function(info) {
    _diag('[api-diag] track:new fired — mid=' + info.mid + ' kind=' + info.kind);

    // Ensure the transceiver wrapper exists. Its _receiver was created at
    // construction time with the (then-null) track; we now inject the real
    // track and let the pipeline start.
    var transceiver = _tcCache(info.transceiver);
    transceiver._receiver._setTrack(info.track);

    _diag('[api-diag] track:new — _trackHandler=' + (_trackHandler ? 'set' : 'null') +
                ' transceiver._receiver.track=' + (transceiver._receiver.track ? 'set' : 'null'));

    if (_trackHandler) {
      // streams: per W3C §5.1 step 8, the array of MediaStreams the
      // remote sender associated with this track via msid (or the
      // empty array if none). Skip nullish entries from cm.js's
      // info.stream (single-stream channel).
      var trackStreams = [];
      if (info.stream) trackStreams.push(info.stream);
      else if (Array.isArray(info.streams)) {
        for (var ts = 0; ts < info.streams.length; ts++) {
          if (info.streams[ts]) trackStreams.push(info.streams[ts]);
        }
      }
      _trackHandler(new RTCTrackEvent({
        track:       info.track,
        receiver:    transceiver._receiver,
        transceiver: transceiver,
        streams:     trackStreams,
      }));
    }
  });
  Object.defineProperty(self, 'ontrack', {
    get: function() { return _trackHandler; },
    set: function(fn) { _trackHandler = fn; },
  });


  // ── Transceiver wrapper cache ──

  var _tcMap = {};
  function _tcCache(internal) {
    if (_tcMap[internal.mid]) return _tcMap[internal.mid];
    var w = new RTCRtpTransceiver(internal, manager);
    _tcMap[internal.mid] = w;
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

  this.createOffer = function (options) {
    return new Promise(function (resolve, reject) {
      manager.createOffer(options, function (err, desc) {
        if (err) reject(err); else resolve(desc);
      });
    });
  };

  this.createAnswer = function (options) {
    return new Promise(function (resolve, reject) {
      manager.createAnswer(options, function (err, desc) {
        if (err) reject(err); else resolve(desc);
      });
    });
  };

  this.setLocalDescription = function (desc) {
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
      if (desc.type === 'pranswer') {
        var nsErr = new Error('setLocalDescription: pranswer is not supported');
        nsErr.name = 'NotSupportedError';
        return Promise.reject(nsErr);
      }
    }
    return new Promise(function (resolve, reject) {
      manager.setLocalDescription(desc, function (err, result) {
        if (err) reject(err); else resolve(result);
      });
    });
  };

  this.setRemoteDescription = function (desc) {
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
      if (desc.type === 'pranswer') {
        var nsErrR = new Error('setRemoteDescription: pranswer is not supported');
        nsErrR.name = 'NotSupportedError';
        return Promise.reject(nsErrR);
      }
    }
    return new Promise(function (resolve, reject) {
      manager.setRemoteDescription(desc, function (err, result) {
        if (err) reject(err); else resolve(result);
      });
    });
  };


  // ── ICE ──

  this.addIceCandidate = function (candidate) {
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

    if (!isEndOfCandidates) {
      // Spec: TypeError if both sdpMid and sdpMLineIndex are null.
      // (0 is a valid sdpMLineIndex — distinguish absence from zero.)
      var hasMid   = (candidate.sdpMid != null);
      var hasMLine = (candidate.sdpMLineIndex != null);
      if (!hasMid && !hasMLine) {
        return Promise.reject(new TypeError(
          'addIceCandidate: candidate must specify sdpMid or sdpMLineIndex'));
      }
    }

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

  this.restartIce = function() {
    if (manager.state.closed) {
      var err = new Error('restartIce: peer connection is closed');
      err.name = 'InvalidStateError';
      throw err;
    }
    manager.restartIce();
  };


  // ── Configuration ──

  this.getConfiguration = function() {
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

  this.setConfiguration = function(newConfig) {
    if (newConfig == null) return;
    // W3C §4.4.1.4 — setConfiguration. Three classes of checks:
    //   1. Connection state: closed PCs reject (InvalidStateError).
    //   2. Immutable fields: bundlePolicy / rtcpMuxPolicy / certificates
    //      can't be changed after construction (InvalidModificationError
    //      if the new value differs from the current one).
    //   3. Enum/range validation: same as constructor, but raises errors
    //      with the spec-required name (TypeError).

    if (manager.state.closed) {
      var eClosed = new Error('setConfiguration: peer connection is closed');
      eClosed.name = 'InvalidStateError';
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
    if (newConfig.rtcpMuxPolicy != null && newConfig.rtcpMuxPolicy !== 'require') {
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
    if (newConfig.bundlePolicy != null && newConfig.bundlePolicy !== manager.state.bundlePolicy) {
      var e1 = new Error('setConfiguration: bundlePolicy cannot be changed after construction');
      e1.name = 'InvalidModificationError';
      throw e1;
    }
    if (newConfig.rtcpMuxPolicy != null &&
        newConfig.rtcpMuxPolicy !== (manager.state.rtcpMuxPolicy || 'require')) {
      var e2 = new Error('setConfiguration: rtcpMuxPolicy cannot be changed after construction');
      e2.name = 'InvalidModificationError';
      throw e2;
    }
    if (newConfig.certificates != null) {
      // Spec: if newConfig.certificates differs from the initial
      // certificates set, throw InvalidModificationError. We don't
      // currently do a deep equality check — we conservatively reject
      // any attempt to set, which is stricter than spec but safe
      // (no app actually relies on echoing the same array back).
      var e3 = new Error('setConfiguration: certificates cannot be changed after construction');
      e3.name = 'InvalidModificationError';
      throw e3;
    }

    // Apply mutable fields.
    if (newConfig.iceServers) manager.state.iceServers = newConfig.iceServers;
    // Per W3C §4.4.1.4, iceTransportPolicy changes take effect on the next
    // ICE gathering round (i.e. next ICE restart) — the running IceAgent
    // instance keeps its current policy until restartIce() is called.
    if (newConfig.iceTransportPolicy) {
      manager.state.iceTransportPolicy = newConfig.iceTransportPolicy;
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

  this.addTrack = function(track /*, ...streams */) {
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
      var closedErr = new Error('addTrack: peer connection is closed');
      closedErr.name = 'InvalidStateError';
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
        var dupErr = new Error('addTrack: track is already part of this connection');
        dupErr.name = 'InvalidAccessError';
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
      if (tc.currentDirection === 'stopped' || tc.direction === 'stopped') continue;
      reused = tc;
      break;
    }

    var internal;
    if (reused) {
      internal = reused;
      internal.sender.track = track;
      // Promote direction to include send. 'recvonly' → 'sendrecv';
      // 'inactive' → 'sendonly'. Leave 'sendrecv'/'sendonly' alone.
      if (internal.direction === 'recvonly') internal.direction = 'sendrecv';
      else if (internal.direction === 'inactive') internal.direction = 'sendonly';
    } else {
      internal = manager.addTransceiver(kind, { direction: 'sendrecv' });
      internal.sender.track = track;
    }

    // Build / fetch the public sender wrapper. Cache by transceiver so
    // multiple getSenders() calls return the same object identity.
    var tcWrapper = _tcCache(internal);
    // If we reused a transceiver, the cached wrapper already has a sender.
    // Tear its listeners down cleanly (pli / encodings-updated) before
    // replacing — otherwise we leak listeners and the stale sender keeps
    // reacting to events.
    if (reused && tcWrapper._sender && typeof tcWrapper._sender._stop === 'function') {
      try { tcWrapper._sender._stop(); } catch (e) {}
    }
    tcWrapper._sender = new RTCRtpSender(internal, track, manager);
    // Stash streams for setStreams() / getStreams() — until QUICK-1+2 lands
    // these don't propagate to SDP, but they survive on the sender.
    if (streams.length) tcWrapper._sender._streams = streams.slice();
    manager.updateNegotiationNeededFlag();
    return tcWrapper._sender;
  };

  this.removeTrack = function(sender) {
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
      var closedErrR = new Error('removeTrack: peer connection is closed');
      closedErrR.name = 'InvalidStateError';
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
      var err = new Error('removeTrack: sender is not part of this connection');
      err.name = 'InvalidAccessError';
      throw err;
    }
    // No-op on stopped transceivers.
    if (internal.currentDirection === 'stopped' || internal.direction === 'stopped') return;
    // Only fire negotiationneeded if something actually changed.
    var changed = false;
    if (internal.sender.track !== null) {
      internal.sender.track = null;
      changed = true;
    }
    if (internal.direction === 'sendrecv') {
      internal.direction = 'recvonly';
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

  this.addTransceiver = function(kindOrTrack, init) {
    if (manager.state.closed) {
      var closedErr = new Error('addTransceiver: peer connection is closed');
      closedErr.name = 'InvalidStateError';
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
      var encs = init.sendEncodings;
      var seenRids = {};
      var anyRid = false;
      var allRid = true;
      for (var ei = 0; ei < encs.length; ei++) {
        var enc = encs[ei] || {};
        if (typeof enc.maxFramerate === 'number' && enc.maxFramerate < 0) {
          throw new RangeError('addTransceiver: encoding maxFramerate must be >= 0');
        }
        if (typeof enc.scaleResolutionDownBy === 'number' && enc.scaleResolutionDownBy < 1) {
          throw new RangeError('addTransceiver: encoding scaleResolutionDownBy must be >= 1');
        }
        if (enc.rid != null) {
          anyRid = true;
          if (!/^[A-Za-z0-9_-]{1,32}$/.test(enc.rid)) {
            throw new TypeError('addTransceiver: invalid rid "' + enc.rid + '" (must match [A-Za-z0-9_-]{1,32})');
          }
          if (seenRids[enc.rid]) {
            throw new TypeError('addTransceiver: duplicate rid "' + enc.rid + '"');
          }
          seenRids[enc.rid] = true;
        } else {
          allRid = false;
        }
      }
      // Spec: rid must be on all or none.
      if (anyRid && !allRid) {
        throw new TypeError('addTransceiver: rid must be present on all encodings or none');
      }
    }

    var internal = manager.addTransceiver(kind, init);
    if (track) internal.sender.track = track;
    manager.updateNegotiationNeededFlag();
    return _tcCache(internal);
  };

  this.getSenders = function() {
    var result = [];
    for (var i = 0; i < manager.state.transceivers.length; i++) {
      var t = manager.state.transceivers[i];
      if (t.currentDirection !== 'stopped') {
        result.push(_tcCache(t).sender);
      }
    }
    return result;
  };

  this.getReceivers = function() {
    var result = [];
    for (var i = 0; i < manager.state.transceivers.length; i++) {
      var t = manager.state.transceivers[i];
      if (t.currentDirection !== 'stopped') {
        result.push(_tcCache(t).receiver);
      }
    }
    return result;
  };

  this.getTransceivers = function() {
    // Note: omits stopped transceivers per spec
    var result = [];
    for (var i = 0; i < manager.state.transceivers.length; i++) {
      var t = manager.state.transceivers[i];
      if (t.currentDirection !== 'stopped') {
        result.push(_tcCache(t));
      }
    }
    return result;
  };


  // ── DataChannel ──

  this.createDataChannel = function(label, options) {
    options = options || {};

    // W3C §6.2: createDataChannel on a closed PC throws InvalidStateError.
    if (manager.state.closed) {
      var closedErr = new Error('createDataChannel: peer connection is closed');
      closedErr.name = 'InvalidStateError';
      throw closedErr;
    }

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
      if (typeof options.id !== 'number' || options.id < 0 || options.id > 65534) {
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
          var inUseErr = new Error('createDataChannel: id ' + options.id + ' is already in use');
          inUseErr.name = 'OperationError';
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
      var syntErr = new Error('createDataChannel: maxRetransmits and maxPacketLifeTime are mutually exclusive');
      syntErr.name = 'SyntaxError';
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

  this.getStats = function(selector) {
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

    // W3C §4.4.1.10: if PC is closed, reject with InvalidStateError.
    if (manager.state.closed) {
      var closedErr = new Error('PC is closed');
      closedErr.name = 'InvalidStateError';
      return Promise.reject(closedErr);
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

  this.getIdentityAssertion = function() {
    return Promise.resolve('');
  };

  this.setIdentityProvider = function(provider, options) {
    // No-op until IdP support lands (API-6).
  };


  // ── Lifecycle ──

  this.close = function() {
    // W3C §4.4.1.10: close() is a no-op on an already-closed PC.
    // manager.close() also guards on state.closed, but we want to skip
    // the per-transceiver pipeline teardown loop too — calling _stop()
    // twice on already-stopped pipelines would be wasted (try/catch
    // makes it safe, but skipping is cleaner and avoids spurious
    // "stopping already-stopped pipeline" log lines).
    if (manager.state.closed) return;
    // Stop every active send + receive pipeline (frees encoders, decoders,
    // depacketizers, jitter buffers, and the event subscriptions they hold).
    for (var mid in _tcMap) {
      if (!Object.prototype.hasOwnProperty.call(_tcMap, mid)) continue;
      var wrapper = _tcMap[mid];
      if (wrapper && wrapper._sender && typeof wrapper._sender._stop === 'function') {
        try { wrapper._sender._stop(); } catch (e) {}
      }
      if (wrapper && wrapper._receiver && typeof wrapper._receiver._stop === 'function') {
        try { wrapper._receiver._stop(); } catch (e) {}
      }
    }
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
  this.addEventListener = function(name, fn, options) {
    if (typeof fn !== 'function') return;
    if (options && typeof options === 'object' && options.once) {
      ev.once(name, fn);
    } else {
      ev.on(name, fn);
    }
  };
  this.removeEventListener = function(name, fn) {
    if (typeof fn !== 'function') return;
    ev.off(name, fn);
  };
  // dispatchEvent is part of EventTarget. The W3C spec says it returns
  // false if the event was canceled (preventDefault), true otherwise.
  // Our event objects are plain shapes (not real Event instances) and
  // none of our internal events are cancelable, so we always return true.
  // We forward to the EventEmitter so apps can synthesize and dispatch
  // events against the PC if they need to.
  this.dispatchEvent = function(event) {
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
  // W3C §4.10. Returns Promise<RTCCertificate>.
  // keygenAlgorithm — null/undefined defaults to ECDSA P-256.
  // Strings 'ECDSA' or 'RSASSA-PKCS1-v1_5' use defaults for that family.
  // Object form: { name, namedCurve?, modulusLength?, publicExponent?, hash? }
  // Invalid input rejects with NotSupportedError per spec.
  return import('./cert.js').then(function(mod) {
    try {
      var generated = mod.generateCertificate({ keygenAlgorithm: keygenAlgorithm });
      return new RTCCertificate(generated);
    } catch (e) {
      // Translate cert.js's TypeError into the spec-mandated
      // NotSupportedError. Keep the message.
      var err = new Error(e && e.message || String(e));
      err.name = 'NotSupportedError';
      throw err;
    }
  });
};


/* ========================= RTCRtpSender ========================= */

function RTCRtpSender(internal, track, manager) {
  var self = this;
  this._internal = internal;
  this._manager = manager;
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
  this.dtmf = (internal.kind === 'audio') ? new RTCDTMFSender() : null;
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
    encodings: (internal.sender.encodings || [{}]).map(function (e) {
      return {
        rid:                   e.rid || null,
        active:                e.active !== false,
        maxBitrate:            e.maxBitrate   || 0,
        maxFramerate:          e.maxFramerate || 0,
        scaleResolutionDownBy: e.scaleResolutionDownBy || 1,
        scalabilityMode:       e.scalabilityMode || null,
        priority:              'low',
        networkPriority:       'low',
      };
    }),
    headerExtensions: [],
    rtcp: { cname: manager.state.localCname, reducedSize: true },
    codecs: [],
    degradationPreference: 'balanced',
  };

  function startPipeline() {
    if (pipeline) return;                         // already running
    if (!self.track) return;                      // nothing to send
    if (internal.sender.ssrc == null) return;     // SSRC not assigned yet

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
        var _codecMeta = _CODEC_MAP_VIDEO[_codecKey];

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
        var _audioNegCodecs = internal.sender && internal.sender._negotiatedCodecs;
        if (_audioNegCodecs && _audioNegCodecs.length) {
          for (var _aci = 0; _aci < _audioNegCodecs.length; _aci++) {
            var _anc = _audioNegCodecs[_aci];
            if (_anc && _anc.name && _anc.name.toLowerCase() === 'opus') {
              _negotiatedAudioPt = _anc.payloadType;
              break;
            }
          }
        }

        // Register the outbound audio stream with MediaTransport so RTCP SR
        // can extrapolate rtpTimestamp using the codec's clockRate. The
        // current audio pipeline is Opus-only; the negotiated PT is read
        // from sender._negotiatedCodecs above.
        var _audioCodecMeta = _CODEC_MAP_AUDIO['opus'];
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

  this.replaceTrack = function(newTrack) {
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
      var closedErr = new Error('replaceTrack: peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return Promise.reject(closedErr);
    }
    if (internal.currentDirection === 'stopped' || internal.direction === 'stopped') {
      var stoppedErr = new Error('replaceTrack: transceiver is stopped');
      stoppedErr.name = 'InvalidStateError';
      return Promise.reject(stoppedErr);
    }
    if (newTrack && newTrack.kind && newTrack.kind !== internal.kind) {
      return Promise.reject(new TypeError(
        'replaceTrack: kind mismatch — sender kind is "' + internal.kind +
        '" but track kind is "' + newTrack.kind + '"'
      ));
    }
    stopPipeline();
    // self.track is a getter backed by internal.sender.track, so a
    // single assignment updates both views.
    internal.sender.track = newTrack;
    if (newTrack) startPipeline();
    return Promise.resolve();
  };

  this.setStreams = function(/* ...streams */) {
    // W3C §5.2.5.5 — associates this sender with one or more MediaStreams.
    // The streams identify the track in the SDP via the msid attribute,
    // letting the remote PC group tracks into stream events.
    //
    // Full multi-msid SDP support is deferred (see ROADMAP QUICK-1+2 and
    // QUICK-1-2-PLAN.md). For now setStreams is a no-op that swallows the
    // arguments — apps that don't depend on stream grouping continue to
    // work, and feature-detection (`'setStreams' in sender`) succeeds.
    // TODO (QUICK-1+2): plumb streams through to msid generation in sdp.js.
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

  this.getParameters = function() {
    // Issue a new transactionId per spec (required to be different each
    // call — setParameters() rejects if transactionId doesn't match the
    // most recent getParameters).
    currentParams.transactionId =
      Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
    // Return a shallow clone so caller mutations don't corrupt our state.
    return {
      transactionId:    currentParams.transactionId,
      encodings:        currentParams.encodings.map(function(e) { return Object.assign({}, e); }),
      headerExtensions: currentParams.headerExtensions.slice(),
      rtcp:             Object.assign({}, currentParams.rtcp),
      codecs:           currentParams.codecs.slice(),
      degradationPreference: currentParams.degradationPreference,
    };
  };

  this.setParameters = function(params) {
    // W3C §5.2.4 validation order:
    //   1. transactionId match (InvalidStateError)
    //   2. transceiver stopped → InvalidStateError
    //   3. encodings.length / order / read-only changes → InvalidModificationError
    //   4. scaleResolutionDownBy < 1 or maxFramerate < 0 → RangeError
    //   5. priority enum mismatch → TypeError

    // Spec requires transactionId to match the last getParameters().
    if (currentParams.transactionId &&
        params && params.transactionId !== currentParams.transactionId) {
      var txErr = new Error(
        'setParameters: transactionId mismatch (must call getParameters() first)');
      txErr.name = 'InvalidStateError';
      return Promise.reject(txErr);
    }

    // Per spec, stopped transceiver → InvalidStateError ("not running").
    if (internal.currentDirection === 'stopped' || internal.direction === 'stopped') {
      var stoppedErr = new Error('setParameters: transceiver is stopped');
      stoppedErr.name = 'InvalidStateError';
      return Promise.reject(stoppedErr);
    }

    // W3C §5.2: encodings.length in setParameters must equal the current
    // count; the app can't add or remove layers via setParameters (that
    // would require renegotiation via addTransceiver). RIDs also must
    // match — they're identifiers, not mutable fields.
    if (params.encodings) {
      if (params.encodings.length !== currentParams.encodings.length) {
        var lenErr = new Error(
          'setParameters: encodings.length changed (' + currentParams.encodings.length +
          ' → ' + params.encodings.length + '); renegotiate via addTransceiver instead');
        lenErr.name = 'InvalidModificationError';
        return Promise.reject(lenErr);
      }
      var validPrios = ['very-low', 'low', 'medium', 'high'];
      for (var vi = 0; vi < params.encodings.length; vi++) {
        var srcEnc = params.encodings[vi];
        if (!srcEnc) continue;
        var srid = srcEnc.rid;
        var crid = currentParams.encodings[vi].rid;
        if (srid != null && crid != null && srid !== crid) {
          var ridErr = new Error(
            'setParameters: rid at index ' + vi + ' changed ("' + crid + '" → "' + srid + '")');
          ridErr.name = 'InvalidModificationError';
          return Promise.reject(ridErr);
        }
        // RangeError checks (spec §5.2.4): scaleResolutionDownBy must be
        // >= 1.0 and maxFramerate must be >= 0.0.
        if (typeof srcEnc.scaleResolutionDownBy === 'number' &&
            srcEnc.scaleResolutionDownBy < 1) {
          return Promise.reject(new RangeError(
            'setParameters: encodings[' + vi + '].scaleResolutionDownBy must be >= 1.0'));
        }
        if (typeof srcEnc.maxFramerate === 'number' && srcEnc.maxFramerate < 0) {
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
        if (typeof src.maxBitrate === 'number') {
          dst.maxBitrate = src.maxBitrate;
          if (tdst) tdst.maxBitrate = src.maxBitrate;
        }
        if (typeof src.maxFramerate === 'number') {
          dst.maxFramerate = src.maxFramerate;
          if (tdst) tdst.maxFramerate = src.maxFramerate;
        }
        if (typeof src.scaleResolutionDownBy === 'number') {
          dst.scaleResolutionDownBy = src.scaleResolutionDownBy;
          if (tdst) tdst.scaleResolutionDownBy = src.scaleResolutionDownBy;
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

    // Per spec, a new transactionId is generated after successful apply.
    currentParams.transactionId = '';
    return Promise.resolve();
  };

  this.getStats = function() {
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
      var pErr = new Error('createEncodedStreams: pipeline not ready (no track yet?)');
      pErr.name = 'InvalidStateError';
      throw pErr;
    }
    return pipeline.takeStreams();
  };
}

// QUICK-5: Map from media-processing codec name to WebRTC mimeType,
// clockRate, and (for audio) channels. Codecs in this table are those
// we actually support packetizing in rtp-packet AND encoding/decoding
// in media-processing. Codecs that media-processing supports but
// aren't WebRTC-relevant (mp3, aac, flac, vorbis, raw pcm) are filtered.
//
// Multiple media-processing names can map to the same WebRTC capability
// (e.g. 'g711-alaw' and 'alaw' → both PCMA). The final list is deduplicated
// by mimeType+clockRate+channels.
var _CODEC_MAP_VIDEO = {
  'vp8':  { mimeType: 'video/VP8',  clockRate: 90000 },
  'vp9':  { mimeType: 'video/VP9',  clockRate: 90000 },
  'av1':  { mimeType: 'video/AV1',  clockRate: 90000 },
  'h264': { mimeType: 'video/H264', clockRate: 90000 },
  'h265': { mimeType: 'video/H265', clockRate: 90000 },
};
var _CODEC_MAP_AUDIO = {
  'opus':       { mimeType: 'audio/opus', clockRate: 48000, channels: 2 },
  'g711-alaw':  { mimeType: 'audio/PCMA', clockRate: 8000,  channels: 1 },
  'alaw':       { mimeType: 'audio/PCMA', clockRate: 8000,  channels: 1 },
  'g711-ulaw':  { mimeType: 'audio/PCMU', clockRate: 8000,  channels: 1 },
  'ulaw':       { mimeType: 'audio/PCMU', clockRate: 8000,  channels: 1 },
  // Telephony "comfort noise" — a future addition (not in media-processing
  // today). We don't list it. mp3/aac/flac/vorbis/pcm are non-WebRTC.
};

function _capabilityKey(c) {
  return c.mimeType + '|' + c.clockRate + '|' + (c.channels || 0);
}

RTCRtpSender.getCapabilities = function(kind) {
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

  var raw = (kind === 'video') ? getSupportedVideoCodecs() : getSupportedAudioCodecs();
  var codecMap = (kind === 'video') ? _CODEC_MAP_VIDEO : _CODEC_MAP_AUDIO;

  // Map + filter + deduplicate
  var seen = {};
  var codecs = [];
  for (var i = 0; i < raw.length; i++) {
    var entry = codecMap[raw[i]];
    if (!entry) continue;                        // not WebRTC-relevant
    var key = _capabilityKey(entry);
    if (seen[key]) continue;                     // duplicate (e.g. alaw + g711-alaw)
    seen[key] = true;
    // Spread into a fresh object so callers can't mutate our table.
    var out = { mimeType: entry.mimeType, clockRate: entry.clockRate };
    if (entry.channels !== undefined) out.channels = entry.channels;
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
        pipeline = createAudioReceivePipeline({
          track:   self.track,
          manager: manager,
          ssrc:    ssrc,
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
      var err = new Error('createEncodedStreams: already called');
      err.name = 'InvalidStateError';
      throw err;
    }
    if (!pipeline || typeof pipeline.takeStreams !== 'function') {
      var e2 = new Error('createEncodedStreams: pipeline not ready (no track yet?)');
      e2.name = 'InvalidStateError';
      throw e2;
    }
    _encodedStreamsTaken = true;
    return pipeline.takeStreams();
  };

  this.getParameters = function() {
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
      rtcp:             { cname: '', reducedSize: false },
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
          mimeType:    c.mimeType,
          clockRate:   c.clockRate,
        };
        if (c.channels)    codecOut.channels = c.channels;
        if (c.sdpFmtpLine) codecOut.sdpFmtpLine = c.sdpFmtpLine;
        result.codecs.push(codecOut);
      }
    }

    // rtcp.cname — comes from the remote sender's SSRC declarations
    // (a=ssrc <id> cname:<value>). currentLocalDescription is OUR side, so
    // for receive-side cname we actually want currentRemoteDescription.
    // Per spec, rtcp.cname in receiveParameters is the REMOTE peer's CNAME.
    //
    // Symmetric with the local lookup above: read parsedCurrentRemoteSdp
    // (maintained by sdp_offer_answer.js's _commitDescription) instead of
    // re-parsing currentRemoteDescription.sdp on every call.
    var rParsed = manager.state && manager.state.parsedCurrentRemoteSdp;
    if (rParsed && rParsed.media) {
      for (var ri = 0; ri < rParsed.media.length; ri++) {
        if (String(rParsed.media[ri].mid) === String(mid)) {
          var rSection = rParsed.media[ri];
          // Take cname from the first SSRC entry that has one.
          if (Array.isArray(rSection.ssrcs)) {
            for (var si = 0; si < rSection.ssrcs.length; si++) {
              if (rSection.ssrcs[si].cname) {
                result.rtcp.cname = rSection.ssrcs[si].cname;
                break;
              }
            }
          }
          // reducedSize: spec field for whether RR/SR use reduced-size
          // RTCP (RFC 5506). sdp.js may parse a=rtcp-rsize as a
          // section-level flag; check defensively.
          if (rSection.rtcpRsize) result.rtcp.reducedSize = true;
          break;
        }
      }
    }

    return result;
  };

  this.getContributingSources = function() {
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

    var nowWall = (typeof performance !== 'undefined' && performance.now)
                  ? performance.now()
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

  this.getSynchronizationSources = function() {
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
      };
      if (e.audioLevel !== undefined) out.audioLevel = e.audioLevel;
      result.push(out);
    }
    // Spec: most recent first.
    result.sort(function(a, b) { return b.timestamp - a.timestamp; });
    return result;
  };

  this.getStats = function() {
    // Spec: returns stats for this receiver's inbound stream. The ssrc comes
    // from the transceiver's remote SSRC mapping. If the receiver hasn't been
    // wired to an SSRC yet (track:new hasn't fired), returns an empty report.
    var ssrc = findRemoteSsrc();
    if (ssrc == null) return Promise.resolve(new Map());
    return Promise.resolve(_buildStatsReport(manager, { ssrc: ssrc }));
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
  return RTCRtpSender.getCapabilities(kind);
};


/* ========================= RTCRtpTransceiver ========================= */

function RTCRtpTransceiver(internal, manager) {
  this._internal = internal;
  this._sender = new RTCRtpSender(internal, internal.sender.track, manager);
  this._receiver = new RTCRtpReceiver(internal.receiver.track, internal.kind, manager, internal);
  var self = this;

  Object.defineProperty(this, 'mid', {
    // W3C §5.4.2: mid is null until the m-section's mid is established
    // (post-SDP exchange). Coerce undefined to null defensively.
    get: function() { return internal.mid != null ? internal.mid : null; },
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
    get: function() { return internal.currentDirection === 'stopped'; },
  });
  // 'stopped' is a valid currentDirection but NOT a valid value to set
  // directly — apps reach it only via transceiver.stop().
  var VALID_SET_DIRECTIONS = ['sendrecv', 'sendonly', 'recvonly', 'inactive'];
  Object.defineProperty(this, 'direction', {
    get: function() { return internal.direction; },
    set: function(dir) {
      if (VALID_SET_DIRECTIONS.indexOf(dir) < 0) {
        throw new TypeError('Invalid RTCRtpTransceiverDirection: ' + dir +
          ' (use transceiver.stop() to stop)');
      }
      // W3C §5.5.4.4: reject if the transceiver has been stopped.
      if (internal.currentDirection === 'stopped') {
        var err = new Error('Cannot set direction on a stopped transceiver');
        err.name = 'InvalidStateError';
        throw err;
      }
      if (dir === internal.direction) return;   // no-op, spec: don't fire
      internal.direction = dir;
      // W3C §5.3: setting direction fires negotiationneeded (debounced in cm.js).
      manager.updateNegotiationNeededFlag();
    },
  });

  this.stop = function() {
    // W3C §5.4.3.6 — mark transceiver as stopped, stop both directions,
    // fire negotiationneeded (the stop propagates via SDP renegotiation
    // which sets port=0 on the m-line to signal the peer).
    if (internal.currentDirection === 'stopped') return;   // idempotent
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
    internal.currentDirection = 'stopped';
    internal.direction = 'stopped';
    manager.updateNegotiationNeededFlag();
  };

  this.setCodecPreferences = function(codecs) {
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
        var modErr = new Error(
          'setCodecPreferences: list contains only auxiliary codecs (RTX/RED/FEC/CN); ' +
          'must include at least one media codec'
        );
        modErr.name = 'InvalidModificationError';
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
          var unsupErr = new Error(
            'setCodecPreferences: codec "' + want.mimeType + '" @ ' +
            want.clockRate + ' Hz is not supported by the receiver'
          );
          unsupErr.name = 'InvalidAccessError';
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

function RTCDataChannel(internal, manager) {
  var self = this;
  // manager is optional for backward compat; without it, maxMessageSize
  // checks fall back to the WebRTC default of 256KB.

  // Read-only properties
  Object.defineProperty(this, 'id', {
    get: function() { return internal.id; },
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
  this.send = function(data) {
    // W3C §6.2: must throw InvalidStateError unless readyState === 'open'.
    // 'connecting' → not yet negotiated; 'closing'/'closed' → gone.
    if (internal.readyState !== 'open') {
      var err = new Error('RTCDataChannel.send: readyState is "' +
                          internal.readyState + '", not "open"');
      err.name = 'InvalidStateError';
      throw err;
    }

    // W3C §6.2.4 — accepted types: string, Blob, ArrayBuffer, ArrayBufferView.
    // Node 18+ has a global Blob; we detect it by feature (rather than
    // reference) so the check works whether the host has Blob or not.
    var isBlob = (data != null && typeof data === 'object' &&
                  typeof data.arrayBuffer === 'function' &&
                  typeof data.size === 'number');
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
      data.arrayBuffer().then(function (ab) {
        if (internal.readyState !== 'open') return;
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

    internal.send(data);
  };

  this.close = function() {
    // Per RFC 8831 §6.7, close() issues an SCTP stream reset so the peer
    // learns the channel is gone. internal.close() should send a
    // DATA_CHANNEL_ACK/reset over the SCTP stream; the stream reset logic
    // itself lives in sctp.js. This call is a no-op if already closing/closed.
    if (internal.readyState === 'closed' || internal.readyState === 'closing') return;
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

  this.addEventListener = function(name, fn, options) {
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
  this.removeEventListener = function(name, fn) {
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
  this.dispatchEvent = function(event) {
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

function RTCSessionDescription(init) {
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
  init = init || {};
  this.candidate = init.candidate || '';
  this.sdpMid = init.sdpMid || null;
  this.sdpMLineIndex = init.sdpMLineIndex != null ? init.sdpMLineIndex : null;
  this.usernameFragment = init.usernameFragment || null;

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
    if (s.indexOf('a=') === 0) s = s.slice(2);
    if (s.indexOf('candidate:') === 0) s = s.slice('candidate:'.length);
    var tokens = s.trim().split(/\s+/);
    if (tokens.length >= 8 && tokens[6] === 'typ') {
      this.foundation = tokens[0];
      var cId        = parseInt(tokens[1], 10);
      this.component = cId === 1 ? 'rtp' : (cId === 2 ? 'rtcp' : null);
      this.protocol  = tokens[2].toLowerCase();
      this.priority  = parseInt(tokens[3], 10);
      this.address   = tokens[4];
      this.port      = parseInt(tokens[5], 10);
      this.type      = tokens[7];
      // Optional trailing key-value pairs
      for (var i = 8; i + 1 < tokens.length; i += 2) {
        var key = tokens[i], val = tokens[i + 1];
        if (key === 'raddr')   this.relatedAddress = val;
        else if (key === 'rport')   this.relatedPort    = parseInt(val, 10);
        else if (key === 'tcptype') this.tcpType        = val;
        else if (key === 'ufrag' && !this.usernameFragment) this.usernameFragment = val;
        else if (key === 'relay-protocol' || key === 'relayProtocol') {
          // RFC 8836 §3 + W3C §4.10.1.1 — the transport between client and TURN.
          this.relayProtocol = val.toLowerCase();
        }
      }
    }
  }
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

  this.getFingerprints = function() {
    return [{ algorithm: 'sha-256', value: generated.fingerprint }];
  };

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

function RTCSctpTransport(manager) {
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
    get: function() { return manager.state.maxMessageSize; },
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

function RTCDtlsTransport(manager) {
  var self = this;
  // iceTransport is set by the RTCPeerConnection singleton factory (see
  // _getDtlsTransport in api.js). Keep it as a plain writable property so
  // the factory can link the two classes after construction.
  this.iceTransport = null;

  Object.defineProperty(this, 'state', {
    get: function() { return manager.state.dtlsState; },
  });

  this.getRemoteCertificates = function() {
    // Returns ArrayBuffer[] of peer certificates from the DTLS handshake.
    // manager.state.remoteCertificates is populated by dtls_session when
    // the handshake completes; may be null/empty before that.
    var certs = manager.state.remoteCertificates;
    if (!certs || !certs.length) return [];
    var out = [];
    for (var i = 0; i < certs.length; i++) {
      var c = certs[i];
      // Normalize Buffer ↔ ArrayBuffer per spec.
      if (Buffer.isBuffer(c)) {
        out.push(c.buffer.slice(c.byteOffset, c.byteOffset + c.byteLength));
      } else if (c instanceof ArrayBuffer) {
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

function RTCIceTransport(manager) {
  var self = this;

  // Helpers to reach the live ICE agent. Agent is created lazily in manager
  // on first gather/setLocalDescription — may be null early in lifecycle.
  function _agent() { return manager.iceAgent || null; }

  Object.defineProperty(this, 'role', {
    get: function() {
      var a = _agent();
      return a ? a.role : 'controlling';
    },
  });

  Object.defineProperty(this, 'component', {
    get: function() { return 'rtp'; },
  });

  Object.defineProperty(this, 'state', {
    get: function() { return manager.state.iceConnectionState; },
  });

  Object.defineProperty(this, 'gatheringState', {
    get: function() { return manager.state.iceGatheringState; },
  });

  this.getLocalCandidates = function() {
    var a = _agent();
    return a ? a.localCandidates.slice() : [];
  };

  this.getRemoteCandidates = function() {
    var a = _agent();
    return a ? a.remoteCandidates.slice() : [];
  };

  this.getSelectedCandidatePair = function() {
    var a = _agent();
    if (!a || !a.selectedPair) return null;
    var p = a.selectedPair;
    // Agent's selectedPair shape is internal; expose {local, remote} per spec.
    return { local: p.local || null, remote: p.remote || null };
  };

  this.getLocalParameters = function() {
    var a = _agent();
    if (!a) return null;
    var p = a.localParameters;
    return p ? { usernameFragment: p.ufrag, password: p.pwd } : null;
  };

  this.getRemoteParameters = function() {
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

function RTCDTMFSender() {
  this.toneBuffer = '';
  // ontonechange — receives RTCDTMFToneChangeEvent. Settable field;
  // never actually dispatched until DTMF emission lands (API-3).
  this.ontonechange = null;

  // W3C §5.5: canInsertDTMF reports whether DTMF can be sent now.
  // Returns true only when:
  //   • The sender's transceiver is sending audio (currentDirection
  //     includes "send")
  //   • The negotiated codec list includes telephone-event
  // Both depend on telephone-event packetization that we haven't
  // wired yet (API-3); for now report false so feature-detection
  // code knows DTMF is unavailable rather than getting silent failures.
  Object.defineProperty(this, 'canInsertDTMF', {
    get: function() {
      // TODO (API-3): return true when telephone-event has been
      // negotiated in the m=audio section AND the transceiver is in
      // a sending direction.
      return false;
    },
  });

  this.insertDTMF = function(tones, duration, interToneGap) {
    // DTMF over RTP per RFC 4733 (telephone-event payload type) is not
    // yet implemented — see ROADMAP API-3. Storing the requested tones
    // in toneBuffer matches the spec field shape; actually emitting
    // them on the wire requires a telephone-event packetizer + codec
    // negotiation in SDP.
    this.toneBuffer = tones || '';
  };
}


/* ========================= Event Classes ========================= */

function RTCTrackEvent(init) {
  init = init || {};
  this.type        = 'track';
  this.track       = init.track       != null ? init.track       : null;
  this.receiver    = init.receiver    != null ? init.receiver    : null;
  this.transceiver = init.transceiver != null ? init.transceiver : null;
  this.streams     = Array.isArray(init.streams) ? init.streams : [];
}

function RTCDataChannelEvent(init) {
  init = init || {};
  this.type    = 'datachannel';
  this.channel = init.channel != null ? init.channel : null;
}

function RTCPeerConnectionIceEvent(init) {
  init = init || {};
  this.type      = 'icecandidate';
  // Per W3C, .candidate is null on end-of-candidates (the "null candidate"
  // sentinel). Otherwise it's an RTCIceCandidate.
  this.candidate = init.candidate != null ? init.candidate : null;
  this.url       = init.url || null;
}

function RTCPeerConnectionIceErrorEvent(init) {
  init = init || {};
  this.type      = 'icecandidateerror';
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
  init = init || {};
  // Match W3C: errorDetail is the discriminator, others optional.
  // RTCErrorDetailType: 'data-channel-failure' | 'dtls-failure' |
  //   'fingerprint-failure' | 'sctp-failure' | 'sdp-syntax-error' |
  //   'hardware-encoder-not-available' | 'hardware-encoder-error'
  Error.call(this, message || '');
  this.name = 'RTCError';
  this.message = message || '';
  this.errorDetail            = init.errorDetail            != null ? init.errorDetail            : '';
  this.sdpLineNumber          = init.sdpLineNumber          != null ? init.sdpLineNumber          : null;
  this.sctpCauseCode          = init.sctpCauseCode          != null ? init.sctpCauseCode          : null;
  this.receivedAlert          = init.receivedAlert          != null ? init.receivedAlert          : null;
  this.sentAlert              = init.sentAlert              != null ? init.sentAlert              : null;
  this.httpRequestStatusCode  = init.httpRequestStatusCode  != null ? init.httpRequestStatusCode  : null;
}
RTCError.prototype = Object.create(Error.prototype);
RTCError.prototype.constructor = RTCError;

function RTCErrorEvent(init) {
  init = init || {};
  this.type  = 'error';
  this.error = init.error != null ? init.error : null;
}

function RTCDTMFToneChangeEvent(init) {
  init = init || {};
  this.type = 'tonechange';
  this.tone = init.tone != null ? init.tone : '';
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
    // Decoder-populated fields (video only)
    framesDecoded:    stats.framesDecoded    || 0,
    keyFramesDecoded: stats.keyFramesDecoded || 0,
    framesDropped:    stats.framesDropped    || 0,
    frameWidth:       stats.frameWidth       || 0,
    frameHeight:      stats.frameHeight      || 0,
    framesPerSecond:  stats.framesPerSecond  || 0,
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
  };
  if (mapping && mapping.transceiver && mapping.transceiver.receiver
      && mapping.transceiver.receiver.track) {
    entry.trackIdentifier = mapping.transceiver.receiver.track.id || undefined;
  }
  return entry;
}

function _outboundRtpEntry(ssrc, stats, transceiver, now) {
  var kind = transceiver ? transceiver.kind : 'video';
  var mediaSourceId = undefined;
  if (transceiver && transceiver.sender && transceiver.sender.track) {
    mediaSourceId = _idMediaSource(transceiver.sender.track.id);
  }
  return {
    id:              _idOutbound(ssrc),
    type:            'outbound-rtp',
    timestamp:       now,
    kind:            kind,
    ssrc:            ssrc,
    mid:             transceiver ? transceiver.mid : undefined,
    transportId:     TRANSPORT_ID,
    codecId:         _idCodec(stats.payloadType || 0, 'out'),
    mediaSourceId:   mediaSourceId,
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
    framesPerSecond: stats.framesPerSecond  || 0,
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
    packetsReceived: undefined,                                // not in RR
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
  var sk = Object.keys(snap.outbound);
  for (var j = 0; j < sk.length; j++) mediaBytesSent += snap.outbound[sk[j]].bytes || 0;
  var rk = Object.keys(snap.inbound);
  for (var k = 0; k < rk.length; k++) mediaBytesReceived += snap.inbound[rk[k]].bytes || 0;

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
    packetsSent:              pair.packetsSent     || 0,
    packetsReceived:          pair.packetsReceived || 0,
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
    availableIncomingBitrate: undefined,
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

function _certificateEntry(fp, isLocal, now) {
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
    base64Certificate:    '',                // DTLS lib would need to expose this
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
function _buildStatsReport(manager, filter) {
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
  var localCert = _certificateEntry(snapshot.localFingerprint, true, now);
  if (localCert) report.set(localCert.id, localCert);
  var remoteCert = _certificateEntry(snapshot.remoteFingerprint, false, now);
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
      if (sndr.ssrc === outSsrc) { tc = snapshot.transceivers[t]; break; }
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
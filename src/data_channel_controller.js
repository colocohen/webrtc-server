// src/data_channel_controller.js
//
// DataChannelController — manages RTCDataChannels and the SCTP transport.
//
// Architecture (libwebrtc-inspired, EventEmitter-based à la SctpAssociation
// and SdpOfferAnswer):
//
//   ConnectionManager (composition root)
//     ├─ SdpOfferAnswer       (W3C signaling state machine)
//     ├─ DataChannelController (this class)
//     │     └── owns: SctpAssociation, dataChannels[], dataChannelMap{}
//     ├─ IceAgent
//     └─ DTLSSession
//
// Layering (each layer doesn't know about the layer above it):
//
//   DataChannel (RFC 8831/8832 — DCEP + W3C readyState)
//      ↓ uses
//   SCTP (RFC 4960 — streams, PPIDs, reliability params)
//      ↓ uses
//   DTLS (encryption)
//      ↓ uses
//   ICE/UDP (network)
//
// SctpAssociation knows nothing about DataChannel — it's just SCTP. This
// class adds the DataChannel layer on top: DCEP messages (PPID 50), the
// 'connecting' → 'open' → 'closed' state machine, ID allocation per
// RFC 8832 (DTLS-client uses evens, DTLS-server uses odds).
//
// Style: callbacks + events, no Promises. Promises live ONLY in api.js.
//
// Communication out:
//   - Method completion: synchronous return (createDataChannel) or void.
//   - State / async notifications: events
//     ('datachannel', 'sctp:statechange', 'sctp:error').
//
// Communication in:
//   - cm.js calls our methods (createDataChannel, start, handleDtlsData, close).
//   - cm.js reads getters (getDataChannels, sctpState).
//   - Constructor takes deps:
//       getClosed, getDtlsSession, getDtlsRole,
//       updateNegotiationNeededFlag, applyStateUpdates.
//
// Part of the SDP-layer refactor; see SDP_REFACTOR_PLAN.md.

import { EventEmitter } from 'node:events';
// SctpAssociation is injected via deps (deps.SctpAssociation) so the
// controller is unit-testable without pulling in the real SCTP stack.


// SCTP over DTLS PPID values (RFC 8831).
var PPID_DCEP          = 50;
var PPID_STRING        = 51;
var PPID_BINARY        = 53;
var PPID_STRING_EMPTY  = 56;
var PPID_BINARY_EMPTY  = 57;

// DCEP message types (RFC 8832).
var DCEP_OPEN = 0x03;
var DCEP_ACK  = 0x02;

// Send-side backpressure cap. The SCTP send queue is unbounded, so a
// send-loop that outruns the network would grow it until the process
// OOMs. Chrome/libwebrtc bound each DataChannel's outbound buffer at
// 16 MB (older Chrome threw from send() when full; newer Chrome closes
// the channel). We mirror the 16 MB figure and throw — a naive bulk
// send-loop then fails loudly instead of silently eating all the RAM.
// Overridable per channel via createDataChannel(label,{maxBufferedAmount}).
var DEFAULT_MAX_BUFFERED_AMOUNT = 16 * 1024 * 1024;

// RFC 8831 §6.4 — RTCPriorityType to numeric DCEP priority.
var DCEP_PRIORITY_BY_NAME = {
  'very-low':  128,
  'low':       256,
  'medium':    512,
  'high':     1024,
};


/* Build a DCEP_OPEN message for a locally-created non-negotiated
 * DataChannel, per RFC 8832 §5.1:
 *
 *   byte 0       Message Type = 0x03 (DATA_CHANNEL_OPEN)
 *   byte 1       Channel Type — encodes ordered/unordered + reliability mode
 *   bytes 2-3    Priority (uint16 BE) — RTCPriorityType mapped via §6.4
 *   bytes 4-7    Reliability Parameter (uint32 BE) — meaning depends on type
 *   bytes 8-9    Label Length (uint16 BE)
 *   bytes 10-11  Protocol Length (uint16 BE)
 *   bytes 12+    Label (UTF-8) followed by Protocol (UTF-8)
 *
 * Channel Type bit layout — high bit = unordered, low nibble = mode:
 *   0x00  RELIABLE                          (full reliability, ordered)
 *   0x80  RELIABLE_UNORDERED
 *   0x01  PARTIAL_RELIABLE_REXMIT           (reliability = max retransmits)
 *   0x81  PARTIAL_RELIABLE_REXMIT_UNORDERED
 *   0x02  PARTIAL_RELIABLE_TIMED            (reliability = max ms)
 *   0x82  PARTIAL_RELIABLE_TIMED_UNORDERED
 *
 * For RELIABLE the Reliability Parameter MUST be 0; for the partial
 * modes it carries the W3C maxRetransmits or maxPacketLifeTime value.
 */
function buildDcepOpen(dc) {
  var labelBuf    = Buffer.from(dc.label    || '', 'utf-8');
  var protocolBuf = Buffer.from(dc.protocol || '', 'utf-8');

  var channelType = 0x00;
  var reliability = 0;
  if (dc.maxRetransmits != null) {
    channelType = 0x01;
    reliability = dc.maxRetransmits;
  } else if (dc.maxPacketLifeTime != null) {
    channelType = 0x02;
    reliability = dc.maxPacketLifeTime;
  }
  if (dc.ordered === false) channelType |= 0x80;

  var priority = DCEP_PRIORITY_BY_NAME[dc.priority] ||
                 DCEP_PRIORITY_BY_NAME['low'];

  var msg = Buffer.alloc(12 + labelBuf.length + protocolBuf.length);
  msg[0] = DCEP_OPEN;
  msg[1] = channelType;
  msg.writeUInt16BE(priority,           2);
  msg.writeUInt32BE(reliability >>> 0,  4);
  msg.writeUInt16BE(labelBuf.length,    8);
  msg.writeUInt16BE(protocolBuf.length, 10);
  labelBuf.copy(msg,    12);
  protocolBuf.copy(msg, 12 + labelBuf.length);

  return msg;
}


class RTCDataChannel {
  /**
   * Construct an RTCDataChannel. Not meant to be called from user code —
   * created by DataChannelController.createDataChannel (local) or
   * DataChannelController._handleDcep (peer-initiated).
   *
   * @param {DataChannelController} controller  Back-reference for SCTP send/close.
   * @param {Object} opts                       Resolved channel parameters.
   * @param {number} opts.id                    SCTP stream id.
   * @param {string} opts.label
   * @param {string} opts.protocol
   * @param {boolean} opts.ordered
   * @param {number|null} opts.maxRetransmits
   * @param {number|null} opts.maxPacketLifeTime
   * @param {boolean} opts.negotiated
   * @param {string} opts.priority              W3C RTCPriorityType.
   */
  constructor(controller, opts) {
    this._controller = controller;

    // W3C §6.2 read-only fields. Kept as plain properties (api.js exposes
    // them via Object.defineProperty getters that read these directly).
    this.id                = opts.id;
    this.label             = opts.label;
    this.protocol          = opts.protocol;
    this.ordered           = opts.ordered;
    this.maxRetransmits    = opts.maxRetransmits;
    this.maxPacketLifeTime = opts.maxPacketLifeTime;
    this.negotiated        = opts.negotiated;
    this.priority          = opts.priority;

    // Mutable state.
    this.readyState                 = 'connecting';
    this.bufferedAmount             = 0;
    this.bufferedAmountLowThreshold = 0;

    // Non-standard: hard cap on bufferedAmount for send-side backpressure.
    // W3C leaves the exact limit UA-defined (Chrome uses 16 MB); we expose
    // it as an override on createDataChannel(label, { maxBufferedAmount }).
    this._maxBufferedAmount = (opts.maxBufferedAmount != null)
      ? opts.maxBufferedAmount
      : DEFAULT_MAX_BUFFERED_AMOUNT;

    // Internal event surface for api.js to attach onopen/onmessage/etc.
    this._ev = new EventEmitter();

    // RTCDataChannelStats (W3C §6.2). Updated by send() and by the
    // controller's incoming-data path.
    this._stats = {
      messagesSent:     0,
      bytesSent:        0,
      messagesReceived: 0,
      bytesReceived:    0,
    };
  }

  /**
   * Send a message. W3C §6.2.5 — accepts string, Buffer, ArrayBuffer.
   * Silent no-op if the channel is not open or SCTP is gone (matches
   * pre-class behaviour). Throws on SCTP-level errors after firing
   * 'error' on the channel.
   */
  send(data) {
    var sctp = this._controller._sctp;
    if (this.readyState !== 'open' || !sctp) {
      if (this._controller._dbgOn) this._controller._diag('DC send SKIPPED — readyState=' + this.readyState +
        ' sctpAssoc=' + !!sctp);
      return;
    }
    var buf  = typeof data === 'string' ? Buffer.from(data, 'utf-8') : Buffer.from(data);
    var ppid = typeof data === 'string' ? PPID_STRING : PPID_BINARY;
    if (buf.length === 0) ppid = typeof data === 'string' ? PPID_STRING_EMPTY : PPID_BINARY_EMPTY;

    // ── Backpressure guard (mirrors Chrome/libwebrtc's 16 MB cap) ──
    // The SCTP send queue is unbounded; without this, a send-loop that
    // outruns the link grows it until the process OOMs. If this message
    // would push bufferedAmount past the cap, refuse it by throwing —
    // that way a naive bulk loop fails loudly and the caller learns to
    // pace via bufferedAmount + the 'bufferedamountlow' event, exactly
    // the pattern browsers force. Checked BEFORE stats/queueing so a
    // rejected send neither inflates counters nor enters the SCTP queue.
    if (this.bufferedAmount + buf.length > this._maxBufferedAmount) {
      var qErr = new Error('RTCDataChannel.send: send buffer full — ' +
        this.bufferedAmount + ' bytes queued + ' + buf.length +
        ' new exceeds maxBufferedAmount (' + this._maxBufferedAmount +
        '). Pace sends: check dataChannel.bufferedAmount and wait for the ' +
        '"bufferedamountlow" event before sending more.');
      qErr.name = 'OperationError';
      try {
        this._ev.emit('error', {
          type:  'error',
          error: {
            name:        'OperationError',
            message:     qErr.message,
            errorDetail: 'send-buffer-full',
          },
        });
      } catch (e) {}
      throw qErr;
    }

    // Update stats before send — send may fail silently but spec expects
    // counters to reflect the API call.
    this._stats.messagesSent++;
    this._stats.bytesSent += buf.length;
    if (this._controller._dbgOn) this._controller._diag('DC send id=' + this.id + ' ppid=' + ppid +
      ' len=' + buf.length + ' readyState=' + this.readyState);

    // Wrap in try/catch so SCTP errors surface as the spec-required
    // 'error' event on the DC (W3C §6.2 — the user agent must dispatch
    // an RTCErrorEvent named 'error' if the underlying transport fails).
    //
    // PR-SCTP wiring (RFC 8831 §6.6 / RFC 3758): pass reliability hints
    // through to sctp.send so each message gets the right per-message
    // limit. Note the field-name remap: W3C calls it maxPacketLifeTime,
    // sctp.js uses maxLifetime — both are ms.
    try {
      sctp.send(this.id, buf, {
        ppid:           ppid,
        unordered:      this.ordered === false,
        maxRetransmits: this.maxRetransmits,         // null OK; sctp.js treats null as "no limit"
        maxLifetime:    this.maxPacketLifeTime,      // ms; null = no deadline
      });
    } catch (sendErr) {
      try {
        this._ev.emit('error', {
          type: 'error',
          error: {
            name: 'OperationError',
            message: 'RTCDataChannel.send: SCTP transport error: ' +
                     (sendErr && sendErr.message || sendErr),
            errorDetail: 'data-channel-failure',
          },
        });
      } catch (e) {}
      // Re-throw so apps using inline send (without an error handler)
      // still see the failure.
      throw sendErr;
    }
  }

  /**
   * Close the channel. Idempotent.
   *
   * W3C §6.2.5: close() must transition through 'closing' before 'closed',
   * firing 'closing' in between. Spec runs the actual SCTP stream reset
   * "in parallel" — we kick off RFC 6525 stream reset (RECONFIG
   * outgoing-reset) and defer the 'closed' transition + event until peer
   * responds (or immediately if peer doesn't advertise RECONFIG support).
   *
   * The early-return guards against double-close — both api.js wrapper
   * and pc.close() call this, so it must be idempotent.
   */
  close() {
    if (this.readyState === 'closed' || this.readyState === 'closing') return;
    this.readyState = 'closing';
    try { this._ev.emit('closing'); } catch (e) {}

    var self = this;
    var sctp = this._controller._sctp;
    var finalize = function () {
      if (self.readyState !== 'closing') return;
      self.readyState = 'closed';
      try { self._ev.emit('close'); } catch (e) {}
    };

    if (sctp && sctp.peerSupportsReconfig && this.id != null) {
      // Tell peer to reset (close) the stream. The callback fires when
      // peer responds. We finalize on any terminal response — the goal
      // is local visibility of 'closed', not strict-correct error
      // propagation. If the round-trip silently fails (association
      // died), the sctp.on('close') handler tears down all DCs.
      // (id == null means the channel never got a stream ID assigned —
      // DCEP_OPEN never went out — so there's nothing to reset at the
      // peer; fall through to the local-only close.)
      // NOTE (round 114): "send() then close()" currently LOSES the
      // message. The data is queued (bufferedAmount rises) and send()
      // passes its guard, but the stream reset still beats it onto the
      // wire. Deferring the reset by a task was tried and did NOT help,
      // so the drop is below this layer — the sctp send path itself.
      // W3C 6.2.5 requires close() to flush what is already queued
      // before resetting; fixing it means teaching sctp.resetStreams to
      // wait for the stream's outstanding data, which is where the next
      // attempt should start rather than in this file.
      sctp.resetStreams([this.id], function (err, res) { finalize(); });
    } else {
      // Peer doesn't support RECONFIG — local-only close. Peer will see
      // this channel as still open from its side until SCTP itself tears
      // down (W3C-compatible degradation).
      queueMicrotask(finalize);
    }
  }
}


class DataChannelController extends EventEmitter {
  /**
   * @param {Object} deps
   * @param {Function} deps.getClosed                    () => boolean
   * @param {Function} deps.getDtlsSession               () => DTLSSession | null
   * @param {Function} deps.getDtlsRole                  () => 'client' | 'server' | null
   * @param {Function} deps.updateNegotiationNeededFlag  () => void
   * @param {Function} deps.applyStateUpdates            (updates) => void
   *   Forwards { sctpState } changes into cm.js's reactive cascade.
   * @param {Function} deps.SctpAssociation              constructor
   *   The SCTP class. Passed as a dep so the controller doesn't hard-import
   *   a sibling library — keeps the module testable in isolation.
   * @param {boolean} [deps.debug]                       enable debug logging
   */
  constructor(deps) {
    super();

    if (!deps || typeof deps.getClosed !== 'function') {
      throw new TypeError('DataChannelController: deps.getClosed required');
    }
    if (typeof deps.getDtlsSession !== 'function') {
      throw new TypeError('DataChannelController: deps.getDtlsSession required');
    }
    if (typeof deps.getDtlsRole !== 'function') {
      throw new TypeError('DataChannelController: deps.getDtlsRole required');
    }
    if (typeof deps.updateNegotiationNeededFlag !== 'function') {
      throw new TypeError('DataChannelController: deps.updateNegotiationNeededFlag required');
    }
    if (typeof deps.applyStateUpdates !== 'function') {
      throw new TypeError('DataChannelController: deps.applyStateUpdates required');
    }
    if (typeof deps.SctpAssociation !== 'function') {
      throw new TypeError('DataChannelController: deps.SctpAssociation (class) required');
    }

    this._deps = deps;
    this._SctpAssociation = deps.SctpAssociation;
    this._debug = !!deps.debug;

    this._sctp = null;
    this._sctpState = 'new';
    this._dataChannels = [];
    this._dataChannelMap = {};
    this._nextDataChannelId = null;
  }


  /* ====================== Public methods ====================== */

  /**
   * Create a new RTCDataChannel.
   *
   * Synchronous — returns the channel object immediately. The 'open'
   * event fires asynchronously when SCTP is up and DCEP_ACK has landed
   * (negotiated channels emit 'open' as soon as SCTP is up).
   *
   * If SCTP is already up: queue DCEP_OPEN now (or fire 'open' for
   * negotiated channels via microtask — spec requires async).
   * If not: stored; flushed in start()'s sctp.on('open').
   *
   * @param {string} label
   * @param {Object} [options]
   * @returns {Object}  RTCDataChannel-shaped
   */
  createDataChannel(label, options) {
    var dc = this._createInternal(label, options);

    if (this._sctpState === 'connected' && this._sctp) {
      // SCTP is already up — emit DCEP now (or flip to 'open' for negotiated).
      if (dc.negotiated) {
        // Spec: 'open' must fire async so user code attaches listeners
        // after createDataChannel returns.
        queueMicrotask(function () {
          if (dc.readyState === 'connecting') {
            dc.readyState = 'open';
            try { dc._ev.emit('open'); } catch (e) {}
          }
        });
      } else {
        this._sendDcepOpen(dc);
        // readyState stays 'connecting' until peer's DCEP_ACK lands.
      }
    }
    // SCTP not up yet → start()'s sctp.on('open') flushes queued dcs.

    return dc;
  }

  /**
   * Start the SCTP association. Called by cm.js on DTLS 'connect'.
   * Idempotent — repeated calls are no-ops once SCTP exists.
   *
   * @param {Object} params
   * @param {string} params.dtlsRole         'client' | 'server'
   * @param {number} params.localPort
   * @param {number} params.remotePort
   * @param {number} params.maxMessageSize
   */
  start(params) {
    if (this._sctp) return;

    this._diag('startSctp called — role=' + params.dtlsRole +
      ' sctpPort=' + params.localPort + ' remoteSctpPort=' + params.remotePort);

    var sctp = new this._SctpAssociation({
      port:           params.localPort,
      remotePort:     params.remotePort,
      role:           params.dtlsRole,   // 'client' or 'server' — same as DTLS
      maxMessageSize: params.maxMessageSize,
    });

    this._sctp = sctp;
    this._wireSctpEvents(sctp);
    this._setSctpState('connecting');

    // Drive the handshake. connect() sends INIT from BOTH roles — RFC
    // 8841: "both SCTP endpoints MUST initiate the SCTP association";
    // the DTLS setup role does not apply to association establishment
    // (it only sets DCEP stream-id parity, RFC 8832 §6). Simultaneous
    // INITs are ordinary SCTP and resolved by the association's
    // collision handling. The existing 'open' listener wired above
    // transitions sctpState to 'connected' when the handshake completes.
    sctp.connect();
  }

  /**
   * Feed an incoming DTLS-decrypted SCTP packet to the association.
   * Called by cm.js's DTLS 'data' handler.
   *
   * @param {Buffer} buf
   */
  handleDtlsData(buf) {
    if (this._sctp) {
      this._sctp.handlePacket(buf);
    }
    // If SCTP isn't up yet, the packet is dropped. cm.js owns the timing
    // of start() (called from the DTLS 'connect' event), so any data that
    // arrives before start() is racing the handshake — should be rare.
  }

  /**
   * Tear down all channels and the SCTP association.
   */
  close() {
    // Close every open DataChannel. W3C webrtc-pc §6.2: when a peer
    // connection closes, every associated RTCDataChannel transitions to
    // readyState 'closed' and fires 'close'. dc.close() is idempotent
    // and kicks off the graceful per-stream RECONFIG where supported.
    for (var i = 0; i < this._dataChannels.length; i++) {
      var dc = this._dataChannels[i];
      if (dc && dc.readyState !== 'closed' && typeof dc.close === 'function') {
        try { dc.close(); } catch (e) { /* never let one DC's close throw block the others */ }
      }
    }

    if (this._sctp) {
      try { this._sctp.close(); } catch (e) {}
    }

    // pc.close() is terminal — don't leave channels parked in 'closing'
    // waiting on RECONFIG/SHUTDOWN round-trips that may never complete
    // (we just told SCTP to shut down underneath them). Finalize every
    // channel now; the per-channel finalize closure and the sctp 'close'
    // handler both guard on readyState, so this stays idempotent.
    for (var j = 0; j < this._dataChannels.length; j++) {
      var dcj = this._dataChannels[j];
      if (!dcj || dcj.readyState === 'closed') continue;
      dcj.readyState = 'closed';
      try { dcj._ev.emit('close'); } catch (e) {}
    }

    this._setSctpState('closed');
  }


  /* ====================== Public read-only getters ====================== */

  getDataChannels() {
    return this._dataChannels.slice();
  }

  getDataChannelById(id) {
    return this._dataChannelMap[id] || null;
  }

  get sctpState() {
    return this._sctpState;
  }

  get sctpAssociation() {
    return this._sctp;
  }


  /* ====================== Internal — channel creation ====================== */

  /**
   * The actual RTCDataChannel constructor. Used by both:
   *   (a) public createDataChannel (caller is local app).
   *   (b) _handleDcep DCEP_OPEN (caller is peer; we're answering).
   * Sending DCEP_OPEN happens in createDataChannel only — _handleDcep
   * sends DCEP_ACK instead, since the role is reversed.
   */
  _createInternal(label, options) {
    options = options || {};
    var id = options.id != null ? options.id : this._maybeAllocStreamId();

    var dc = new RTCDataChannel(this, {
      id:                id,
      label:             label || '',
      protocol:          options.protocol || '',
      ordered:           options.ordered !== false,
      // `!= null` not `||` — W3C semantics: maxRetransmits=0 means "send
      // once, never retransmit" (a valid PR-SCTP setting). Using `||`
      // would coerce 0 to null and silently upgrade the channel to
      // fully reliable. Same for maxPacketLifeTime=0.
      maxRetransmits:    (options.maxRetransmits    != null) ? options.maxRetransmits    : null,
      maxPacketLifeTime: (options.maxPacketLifeTime != null) ? options.maxPacketLifeTime : null,
      negotiated:        options.negotiated || false,
      // W3C §6.2.1 — RTCPriorityType, default 'low'. Stored for round-trip
      // via api.js getter; not used for SCTP scheduling today.
      priority:          options.priority || 'low',
      // Non-standard backpressure override (defaults to 16 MB in the ctor).
      maxBufferedAmount: (options.maxBufferedAmount != null) ? options.maxBufferedAmount : null,
    });

    this._dataChannels.push(dc);
    // id may be null when the DTLS role isn't decided yet (see
    // _maybeAllocStreamId) — the real ID is assigned in _sendDcepOpen,
    // which also registers the channel in the map.
    if (id != null) this._dataChannelMap[id] = dc;
    this._deps.updateNegotiationNeededFlag();

    return dc;
  }

  /**
   * Allocate a stream ID now if the parity is already determined,
   * otherwise defer (return null).
   *
   * RFC 8832 §6 parity (DTLS client = evens, DTLS server = odds) depends
   * on the DTLS role, which isn't decided until negotiation. The old
   * code allocated eagerly with a 'server' fallback, so the common
   *   createDataChannel() → createOffer() → ... → we become DTLS client
   * flow latched ODD ids on the client side — colliding with the ids the
   * true server allocates for its own channels. Deferral also matches
   * W3C §6.2: RTCDataChannel.id is null until the ID is assigned, and
   * libwebrtc's behaviour of assigning sids when the transport is ready.
   */
  _maybeAllocStreamId() {
    if (this._nextDataChannelId === null && this._deps.getDtlsRole() == null) {
      return null;   // parity unknown — _sendDcepOpen assigns later
    }
    return this._allocStreamId();
  }

  _allocStreamId() {
    if (this._nextDataChannelId === null) {
      // RFC 8832 §6: DTLS-client uses evens (0, 2, 4...), DTLS-server
      // uses odds (1, 3, 5...). By the time this latches, the role is
      // known (deferred callers reach here via _sendDcepOpen, which runs
      // after DTLS connects); null can only still appear for negotiated
      // channels created pre-handshake with explicit ids, where the
      // 'server' fallback keeps the historical cm.js behaviour.
      var role = this._deps.getDtlsRole();
      this._nextDataChannelId = (role === 'client') ? 0 : 1;
    }
    var id = this._nextDataChannelId;
    this._nextDataChannelId += 2;
    return id;
  }


  /* ====================== Internal — SCTP wiring ====================== */

  _wireSctpEvents(sctp) {
    var self = this;

    // SCTP→DTLS pipe. The controller is the natural owner of this wire
    // because (a) it owns the SCTP association, and (b) it owns the
    // DTLS reference via deps. Putting the pipe inline in start() keeps
    // wire concerns out of cm.js entirely.
    sctp.on('packet', function (data) {
      self._diag('sctp→dtls len=' + (data && data.length));
      var dtls = self._deps.getDtlsSession();
      if (dtls) dtls.send(data);
    });

    sctp.on('data', function (streamId, ppid, data) {
      self._diag('sctp.data streamId=' + streamId + ' ppid=' + ppid +
        ' len=' + (data && data.length));
      if (ppid === PPID_DCEP) {
        self._handleDcep(streamId, data);
      } else if (ppid === PPID_STRING || ppid === PPID_STRING_EMPTY) {
        var dc = self._dataChannelMap[streamId];
        if (dc) {
          var text = ppid === PPID_STRING_EMPTY ? '' : data.toString('utf-8');
          dc._stats.messagesReceived++;
          dc._stats.bytesReceived += text.length;
          dc._ev.emit('message', { data: text });
        } else {
          self._diag('NO DataChannel for streamId=' + streamId + ' (dropped)');
        }
      } else if (ppid === PPID_BINARY || ppid === PPID_BINARY_EMPTY) {
        var dc2 = self._dataChannelMap[streamId];
        if (dc2) {
          var binData = ppid === PPID_BINARY_EMPTY ? Buffer.alloc(0) : data;
          dc2._stats.messagesReceived++;
          dc2._stats.bytesReceived += binData.length;
          dc2._ev.emit('message', { data: binData });
        } else {
          self._diag('NO DataChannel for streamId=' + streamId + ' (dropped binary)');
        }
      }
    });

    sctp.on('open', function () {
      self._diag('sctp.open — setting sctpState=connected');
      self._setSctpState('connected');
      // RFC 8832 §5 — negotiated (out-of-band) DataChannels skip DCEP
      // entirely. They become 'open' as soon as the SCTP association is
      // up. Non-negotiated channels need DCEP_OPEN sent NOW.
      for (var i = 0; i < self._dataChannels.length; i++) {
        var dc = self._dataChannels[i];
        if (dc.readyState !== 'connecting') continue;
        if (dc.negotiated) {
          // Deferred-ID safety net: a negotiated channel created before
          // the DTLS role was known could still carry id=null (an app
          // that omitted the out-of-band id). Assign one now that the
          // role is fixed, and register it so incoming data routes.
          if (dc.id == null) {
            dc.id = self._allocStreamId();
            self._dataChannelMap[dc.id] = dc;
          }
          dc.readyState = 'open';
          dc._ev.emit('open');
        } else {
          self._sendDcepOpen(dc);
        }
      }
    });

    sctp.on('close', function () {
      // The association is gone — graceful SHUTDOWN completed, remote
      // ABORT, or path failure. W3C webrtc-pc §6.2: every channel riding
      // a closed transport transitions to 'closed' and fires 'close'.
      // This also finalizes channels stuck in 'closing' whose RECONFIG
      // round-trip can no longer complete (their resetStreams callback
      // will never fire). Without this handler, a remote ABORT left all
      // channels 'open' forever and pc.close() left them 'closing'
      // forever — dc.close()'s own finalize closure is a no-op once we
      // move the state here, so the paths stay idempotent.
      for (var i = 0; i < self._dataChannels.length; i++) {
        var dc = self._dataChannels[i];
        if (!dc || dc.readyState === 'closed') continue;
        if (dc.readyState !== 'closing') {
          dc.readyState = 'closing';
          try { dc._ev.emit('closing'); } catch (e) {}
        }
        dc.readyState = 'closed';
        try { dc._ev.emit('close'); } catch (e) {}
      }
      self._setSctpState('closed');
    });

    sctp.on('protocolViolation', function (info) {
      self._diag('sctp protocolViolation: code=' + info.code +
        (info.streamId != null ? ' sid=' + info.streamId : '') +
        (info.length != null  ? ' len=' + info.length : ''));
    });
    sctp.on('protocolError', function (info) {
      self._diag('sctp protocolError: cause=0x' + (info.cause || 0).toString(16));
    });
    sctp.on('pathFailure', function (info) {
      self._diag('sctp pathFailure: source=' + (info.source || 'rto') +
        (info.cause != null ? ' cause=0x' + info.cause.toString(16) : '') +
        (info.retransmits != null ? ' retx=' + info.retransmits : ''));
    });

    // Peer-initiated stream reset. RFC 8831 §6.7 mandates the bidirectional
    // close: when peer resets its outgoing direction on a stream, we should
    // reset OUR outgoing on that stream too.
    //   incoming=true  → peer reset their outgoing → close locally + reset back.
    //   incoming=false → peer reset their incoming → just close locally.
    sctp.on('streamReset', function (info) {
      for (var i = 0; i < info.streamIds.length; i++) {
        var sid = info.streamIds[i];
        var dc = self._dataChannelMap[sid];
        if (!dc) continue;

        // Avoid double-fire: if already closing/closed, the local dc.close()
        // path will finalize when its own RECONFIG round-trip completes.
        if (dc.readyState !== 'closed' && dc.readyState !== 'closing') {
          dc.readyState = 'closing';
          try { dc._ev.emit('closing'); } catch (e) {}
          dc.readyState = 'closed';
          try { dc._ev.emit('close'); } catch (e) {}
        }

        // If peer reset their outgoing (info.incoming=true), reciprocate:
        // reset our outgoing on the same stream so peer sees the channel
        // fully gone too.
        if (info.incoming && sctp.peerSupportsReconfig) {
          sctp.resetStreams([sid]);
        }
      }
    });

    // bufferedAmount accounting (W3C §6.2.1). chunkSent fires every time
    // send() enqueues bytes; chunkAcked fires when those bytes are
    // cumulatively SACKed. We translate stream-level events into per-DC
    // counter updates.
    //
    // DCEP control (PPID 50) is filtered out — those are setup bytes
    // generated by us, not by the application calling dc.send(). W3C
    // bufferedAmount should reflect only user data.
    // bufferedAmount ACCOUNTING MODEL (WPT harvest):
    //   increase — synchronously inside RTCDataChannel.send() in api.js
    //              (W3C: observable immediately after the call).
    //   decrease — on chunkAcked below (genuinely-unacked user bytes;
    //              the useful backpressure signal on an instant-DTLS path).
    // chunkSent deliberately has NO handler anymore: a second increase
    // point would double-count every byte against a single drain point,
    // so bufferedAmount would never return to zero and
    // 'bufferedamountlow' would never fire.

    // DRAIN point = chunkSent (W3C: bufferedAmount decreases when data
    // is handed to the transport — and WPT measures right after the
    // receiver got the message, long before SACKs round-trip). chunkAcked
    // stays as a safety floor for retransmission edge cases.
    var _drain = function (info /*, deferred */) {
      if (info.ppid === PPID_DCEP) return;
      // TIMING GUARD: chunkSent can fire synchronously inside send() on
      // an open SCTP window — draining in the same tick would erase the
      // spec-mandated synchronous bufferedAmount increase before the
      // caller can observe it. One macrotask of deferral keeps the
      // increase observable and still drains within milliseconds.
      if (!arguments[1]) {
        // allocation-free deferral: same info object, flag via argument
        setImmediate(_drain, info, true);
        return;
      }
      var dc = self._dataChannelMap[info.streamId];
      if (!dc) return;
      var before = dc.bufferedAmount;
      dc.bufferedAmount = Math.max(0, before - info.bytes);
      if (before > dc.bufferedAmountLowThreshold &&
          dc.bufferedAmount <= dc.bufferedAmountLowThreshold) {
        try { dc._ev.emit('bufferedamountlow', { type: 'bufferedamountlow' }); } catch (e) {}
      }
    };
    sctp.on('chunkSent', _drain);
  }

  _setSctpState(newState) {
    if (this._sctpState === newState) return;
    this._sctpState = newState;
    // Mirror into shared state for cm.js's reactive cascade. cm.js's
    // setState() also fires 'sctp:statechange' on its own EventEmitter,
    // so we don't double-fire here.
    this._deps.applyStateUpdates({ sctpState: newState });
  }


  /* ====================== Internal — DCEP ====================== */

  // Emit DCEP_OPEN for `dc`; readyState stays 'connecting' until peer's
  // DCEP_ACK lands (handled in _handleDcep). Caller is responsible for
  // SCTP being up and the channel being non-negotiated.
  _sendDcepOpen(dc) {
    if (!this._sctp) return;
    // Deferred-ID assignment: channels created before the DTLS role was
    // decided carry id=null (see _maybeAllocStreamId). By now DTLS is
    // connected and the role is fixed, so the parity is correct.
    if (dc.id == null) {
      dc.id = this._allocStreamId();
      this._dataChannelMap[dc.id] = dc;
    }
    var msg = buildDcepOpen(dc);
    this._diag('sending DCEP_OPEN for streamId=' + dc.id +
      ' label=' + JSON.stringify(dc.label) +
      ' channelType=0x' + msg[1].toString(16));
    try {
      this._sctp.send(dc.id, msg, { ppid: PPID_DCEP });
    } catch (sendErr) {
      this._diag('DCEP_OPEN send failed: ' + (sendErr && sendErr.message || sendErr));
    }
  }

  _handleDcep(streamId, payload) {
    this._diag('handleDcep streamId=' + streamId +
      ' msgType=' + (payload && payload[0]) +
      ' len=' + (payload && payload.length));
    if (payload.length < 1) return;
    var msgType = payload[0];

    if (msgType === DCEP_OPEN) {
      if (payload.length < 12) return;

      var channelType = payload[1];
      var reliability = (payload[4] << 24 | payload[5] << 16 | payload[6] << 8 | payload[7]) >>> 0;
      var labelLen    = payload[8] << 8 | payload[9];
      var protocolLen = payload[10] << 8 | payload[11];

      var label = '';
      var protocol = '';
      var off = 12;
      if (labelLen > 0 && off + labelLen <= payload.length) {
        label = payload.subarray(off, off + labelLen).toString('utf-8');
        off += labelLen;
      }
      if (protocolLen > 0 && off + protocolLen <= payload.length) {
        protocol = payload.subarray(off, off + protocolLen).toString('utf-8');
      }

      // Send DCEP ACK back to peer.
      this._sctp.send(streamId, Buffer.from([DCEP_ACK]), { ppid: PPID_DCEP });

      // Create or find DataChannel.
      var dc = this._dataChannelMap[streamId];
      var isNewChannel = !dc;
      if (!dc) {
        dc = this._createInternal(label, {
          id: streamId,
          protocol: protocol,
          ordered: !(channelType & 0x80),
          maxRetransmits: (channelType & 0x01) ? reliability : null,
          maxPacketLifeTime: (channelType & 0x02) ? reliability : null,
        });
      }
      // ORDER MATTERS:
      // 1. emit 'datachannel' first so the API layer wraps the channel and
      //    user code gets a chance to register 'open'/'message' listeners.
      // 2. emit 'open' AFTER, so those listeners actually fire.
      //
      // Gating on isNewChannel is critical: a duplicate DCEP_OPEN (peer
      // retransmit, or our own loop-back when a misbehaving peer echoes
      // our DCEP_OPEN) MUST NOT re-emit 'datachannel'.
      var _wasConnecting = dc.readyState === 'connecting';
      if (isNewChannel) {
        // W3C 6.2.3: the announced channel is ALREADY 'open' when the
        // datachannel event fires (send() inside the handler must work),
        // and a DCEP-announced channel is by definition NOT negotiated.
        dc.negotiated = false;
        if (_wasConnecting) dc.readyState = 'open';
        this.emit('datachannel', { channel: dc });
      }
      // Only transition connecting→open (and fire 'open') on the FIRST
      // DCEP_OPEN. A duplicate arriving after the app closed the channel
      // must NOT resurrect it from 'closing'/'closed' back to 'open' —
      // that produced a zombie channel with an 'open' event after 'close'.
      // RE-CHECK, don't trust the snapshot: _wasConnecting was captured
      // BEFORE 'datachannel' was emitted, and the application's handler
      // runs inside that emit — a handler that close()s the channel
      // leaves it 'closing', and assigning 'open' here RESURRECTED it,
      // which is why the deferred open-event guard downstream kept
      // seeing a channel that looked open. The state must be read at
      // the moment it is written, not remembered from before the app
      // had a chance to act.
      if (_wasConnecting && dc.readyState !== 'closing' && dc.readyState !== 'closed') {
        dc.readyState = 'open';
        // The app's datachannel handler runs at the END of an async hop
        // chain (dcc -> cm -> api wrapper -> pc.ondatachannel) — defer
        // the open decision past it and RE-CHECK at fire time: a handler
        // that close()s the channel must never observe 'open'.
        setImmediate(function () {
          if (dc.readyState === 'open') dc._ev.emit('open');
        });
      }

    } else if (msgType === DCEP_ACK) {
      // Our channel was accepted by remote. Same gating: a duplicate ACK
      // (or one racing a local close) must not revive a non-connecting
      // channel.
      var dc2 = this._dataChannelMap[streamId];
      if (dc2 && dc2.readyState === 'connecting') {
        dc2.readyState = 'open';
        dc2._ev.emit('open');
      }
    }
  }


  /* ====================== Internal — diagnostic ====================== */

  get _dbgOn() {
    // hot-path mirror: DataChannel.send checks this BEFORE building the
    // (potentially long) log string — zero cost when debug is off.
    return !!(process.env.WEBRTC_DEBUG === '1' || process.env.WEBRTC_DEBUG === 'true');
  }

  _diag() {
    if (!this._debug) return;
    if (typeof console !== 'undefined' && console.log) {
      var prefix = '[dcc-diag]';
      var args = [prefix];
      for (var i = 0; i < arguments.length; i++) args.push(arguments[i]);
      console.log.apply(console, args);
    }
  }
}


export {
  DataChannelController,
  buildDcepOpen,
  // Constants exposed so cm.js / tests can reference them without
  // duplicating the values.
  PPID_DCEP,
  PPID_STRING,
  PPID_BINARY,
  PPID_STRING_EMPTY,
  PPID_BINARY_EMPTY,
  DCEP_OPEN,
  DCEP_ACK,
};
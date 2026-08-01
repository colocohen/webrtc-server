// src/connection_manager.js
// Internal WebRTC connection engine.
// Manages: ICE ↔ DTLS ↔ SCTP ↔ SRTP pipeline, reactive state machine.
// NOT imported by users — api.js wraps this with browser-compatible API.

import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { DTLSSession } from 'lemon-tls';
import * as SDP from './sdp.js';
import { IceAgent } from 'turn-server';
import { SctpAssociation } from './sctp.js';

// Transport controller — ICE/DTLS/SCTP-from-SDP plumbing. Functions here
// own the translation between SDP and the transport stack. They take
// state as a parameter (no shadow state). See transport_controller.js
// and SDP_REFACTOR_PLAN.md.
import * as TransportController from './transport_controller.js';

// RTP transmission manager — transceiver creation, mid allocation, SSRC
// lookups, direction commit, negotiation-needed check. Functions here
// take state as a parameter. See rtp_transmission_manager.js and
// SDP_REFACTOR_PLAN.md.
import * as RtpManager from './rtp_transmission_manager.js';

// Media session factory — builds offers and answers from current state.
// Functions here take state + options and return SDP strings.
// See media_session_factory.js and SDP_REFACTOR_PLAN.md.
import * as MediaSessionFactory from './media_session_factory.js';

// SDP offer/answer state machine — the W3C signaling control plane.
// EventEmitter-based class with private state (libwebrtc-style /
// SctpAssociation-style). See sdp_offer_answer.js and
// SDP_REFACTOR_PLAN.md.
import { SdpOfferAnswer } from './sdp_offer_answer.js';

// DataChannel + SCTP transport. Owns SctpAssociation lifecycle, DCEP
// (RFC 8832), DataChannel readyState machine, and ID allocation.
// See data_channel_controller.js and SDP_REFACTOR_PLAN.md.
import { DataChannelController } from './data_channel_controller.js';

// MediaTransport — data plane orchestrator. Owns RTCP send/receive,
// scheduling timers (SR/RR/REMB, TCC feedback, NACK feedback). Subsequent
// milestones move RTP send/receive, NACK retransmit, and BWE here too.
// See media_transport.js.
import { MediaTransport } from './media_transport.js';

// Media pipeline — rtp-packet
import {
  JitterBuffer, SrtpSession,
  VP8Depacketizer, VP9Depacketizer, H264Depacketizer, AV1Depacketizer, OpusDepacketizer,
  VP8Packetizer, VP9Packetizer, H264Packetizer, OpusPacketizer,
  SenderBuffer, NackThrottle,
  BandwidthEstimator,
  RtpHeaderStamper,
} from 'rtp-packet';

// Media objects — media-processing
import { MediaStreamTrack, MediaStream } from 'media-processing';

// ──────────────────────────────────────────────────────────────────
//  Per-codec keyframe peeking (RTP-1)
// ──────────────────────────────────────────────────────────────────
//
// NackGenerator's gap-detection logic uses an isKeyframe flag to
// decide whether a freshly-arrived packet should evict missing
// entries below it (a keyframe resets the decoder, so older missing
// packets are useless and shouldn't be retransmitted). To populate
// that flag, we need to peek into each incoming RTP payload using
// codec-specific rules (different bit positions per codec).
//
// rtp-packet exposes peekKeyframe(payload) as a pure static method
// on each Depacketizer class. We pre-bind to a single dispatch table
// keyed by lowercase codec name so the per-packet lookup is one
// hash get + one function call — no allocation, no class instances.
//
// Lookup happens once per SSRC (cached on the rtpStats entry), so
// the hot path inside handleIncomingRtpInner is just an indirect
// function call with the cached reference.
var PEEK_KEYFRAME_BY_CODEC = {
  vp8:  VP8Depacketizer.peekKeyframe,
  vp9:  VP9Depacketizer.peekKeyframe,
  h264: H264Depacketizer.peekKeyframe,
  av1:  AV1Depacketizer.peekKeyframe,
  opus: OpusDepacketizer.peekKeyframe,
};

function resolvePeekKeyframeFn(codecName) {
  if (!codecName) return null;
  return PEEK_KEYFRAME_BY_CODEC[codecName.toLowerCase()] || null;
}

// Debug logging gate (mirrors api.js). '[cm-diag]' lines trace state-
// machine transitions, RTP/RTCP routing decisions, and SCTP send paths.
// Off by default — set WEBRTC_DEBUG=1 to enable.
var _DBG = (typeof process !== 'undefined' &&
            process.env &&
            (process.env.WEBRTC_DEBUG === '1' ||
             process.env.WEBRTC_DEBUG === 'true'));
function _diag() {
  if (!_DBG) return;
  if (typeof console !== 'undefined' && console.log) {
    console.log.apply(console, arguments);
  }
}


/* ========================= Constants ========================= */

var DEFAULT_ICE_SERVERS = [
  { urls: 'stun:stun.l.google.com:19302' },
];

// Synthetic packet-loss simulation moved to media_transport.js (controlled
// via the same DROP_RTP_PCT env var; only the implementation moved).

var DEPACKETIZERS = {
  'VP8':  VP8Depacketizer,
  'VP9':  VP9Depacketizer,
  'H264': H264Depacketizer,
  'opus': OpusDepacketizer,
};

// SCTP/DCEP constants (PPID_*, DCEP_*) live in data_channel_controller.js
// since they're consumed only by DataChannel logic.


/* ========================= ConnectionManager ========================= */

function ConnectionManager(config) {
  if (!(this instanceof ConnectionManager)) return new ConnectionManager(config);

  config = config || {};
  var self = this;
  var ev = new EventEmitter();

  // ── Router merge ──
  // When config.router is provided, fold its socket(s) + announcedAddresses
  // into config. Explicit fields in config still win — this is a fill-in,
  // not an override. This is how { router } acts as sugar for
  // { socket, socket6, announcedAddresses } all pointing at the router.
  if (config.router) {
    if (!config.socket  && config.router.socket4) config.socket  = config.router.socket4;
    if (!config.socket6 && config.router.socket6) config.socket6 = config.router.socket6;
    if (!config.announcedAddresses && config.router.announcedAddresses) {
      config.announcedAddresses = config.router.announcedAddresses;
    }
  }

  // ── ICE mode resolution ──
  // Explicit config.mode wins. Otherwise: any external socket ⇒ 'lite'
  // (server scenario); no socket ⇒ 'full' (browser-like client scenario).
  // This mirrors IceAgent's own default so behaviour stays consistent
  // whether the hint comes from here or the agent itself.
  var resolvedMode = (config.mode === 'lite' || config.mode === 'full')
    ? config.mode
    : ((config.socket || config.socket6) ? 'lite' : 'full');

  /* ====================== State ====================== */

  var state = {
    // Connection lifecycle
    signalingState: 'stable',
    iceConnectionState: 'new',
    iceGatheringState: 'new',
    connectionState: 'new',
    dtlsState: 'new',
    sctpState: 'new',
    srtpState: 'new',

    // Config
    iceServers: config.iceServers || DEFAULT_ICE_SERVERS,
    iceTransportPolicy: config.iceTransportPolicy || 'all',
    bundlePolicy: config.bundlePolicy || 'max-bundle',
    mode: resolvedMode,
    announcedAddresses: config.announcedAddresses || null,

    // Identity
    // JSEP (RFC 8829 §5.2.1): <sess-id> MUST be representable by a
    // 64-bit signed integer and MUST be less than 2^63-1; RECOMMENDED
    // construction is a 64-bit quantity with the highest bit cleared and
    // the remaining 63 bits cryptographically random (what Chrome does —
    // at most 19 digits). The previous scheme concatenated Date.now()
    // (13 digits) with a uint32 (up to 10 digits), producing up to 23
    // digits — a numeric string that overflows u64/i64 parsers and
    // crashed webrtc-rs during interop ("number too large to fit in
    // target type"). Randomness also satisfies RFC 8866 §5.2 global
    // uniqueness without collision risk across PCs created in the same
    // millisecond.
    localSessionId: (function () {
      var b = crypto.randomBytes(8);
      b[0] &= 0x7F;   // clear the top bit → value < 2^63
      return b.readBigUInt64BE(0).toString();
    })(),
    localCname: crypto.randomBytes(8).toString('hex'),

    // ICE
    localIceUfrag: null,
    localIcePwd: null,
    remoteIceUfrag: null,
    remoteIcePwd: null,
    remoteIceLite: false,
    remoteCandidates: [],
    // Local candidates gathered in the CURRENT gathering phase (full-ICE
    // mode only; lite candidates are read synchronously off the agent).
    // Consumed by:
    //   (a) the in-place localDescription patch in the agent's
    //       'candidate' handler (JSEP §4.1.13/14 — the description
    //       exposes candidates gathered since it was set), and
    //   (b) MediaSessionFactory via prepareForCreateOffer/Answer, so
    //       SUBSEQUENT offers/answers embed the roster (JSEP §5.2.2:
    //       "for each candidate gathered during the most recent
    //       gathering phase, an a=candidate line MUST be added").
    // Reset on ICE restart (new gathering phase → new roster).
    localGatheredCandidates: [],
    selectedPair: null,

    // DTLS
    dtlsRole: null,
    localFingerprint: null,
    remoteFingerprint: null,
    dtlsSession: null,
    dtlsBuffer: [],

    // Certificate
    cert: config.cert || null,
    key: config.key || null,

    // SRTP
    srtpKeys: null,
    srtpSession: null,

    // SDP — pending/current model
    currentLocalDescription: null,
    currentRemoteDescription: null,
    pendingLocalDescription: null,
    pendingRemoteDescription: null,
    // parsedLocalSdp tracks pendingLocal OR currentLocal (the same view as
    // pc.localDescription exposes). parsedCurrentLocalSdp tracks ONLY the
    // current — needed by MediaSessionFactory.buildOffer for renegotiation
    // pinning, where we want the previously-completed round, not whatever
    // pending offer we may have in flight.
    parsedLocalSdp: null,
    parsedCurrentLocalSdp: null,
    parsedRemoteSdp: null,
    parsedCurrentRemoteSdp: null,
    lastOffer: null,
    lastAnswer: null,

    // Media
    transceivers: [],
    localSsrcs: {},
    remoteSsrcMap: {},
    mediaReceivers: {},

    // DataChannel / SCTP — most state lives in DataChannelController.
    // sctpPort/remoteSctpPort/maxMessageSize stay here because they're
    // populated by SDP parsing (TransportController.applyRemoteDescription)
    // before SCTP starts, and the controller reads them via start({...})
    // when DTLS connects.
    sctpPort: 5000,
    remoteSctpPort: 5000,
    maxMessageSize: 262144,
    // RFC 8841: filled from peer's SDP a=max-message-size on
    // setRemoteDescription. Until then, null = peer hasn't told us yet.
    remoteMaxMessageSize: null,
    // Effective send-side cap = min(local advertise, peer advertise).
    // Becomes the sctp.maxMessageSize when the SCTP layer starts.
    sendMaxMessageSize: 262144,

    // Transport
    remoteAddress: null,

    // RTP stats (per SSRC)
    //   rtpStats            — inbound  (populated by handleIncomingRtp)
    //   outboundStats       — outbound (populated by sendRtp)
    //   rtcpStats           — aggregated RTT, RR fractionLost, etc. (from remote RR)
    //   remoteOutboundStats — what the remote reports about THEIR outbound
    //                         streams (from SR). Indexed by remote SSRC.
    //
    // Per-inbound-stream fields in rtpStats[ssrc] (see _ensureInboundStats):
    //   packets, bytes, packetsLost, highestSeq, cycles, baseSeq, jitter
    //     — populated on each received RTP packet
    //   lastSR (middle32 of NTP ts), lastSRTime (ms)
    //     — updated on each received SR; used in outgoing RR's DLSR field
    //       so the remote can compute RTT from its side.
    //
    // Retransmission (RFC 4585 NACK + RFC 4588 RTX):
    //   senderBuffer        — ring buffer of recently-sent plaintext RTP
    //                         packets (per SSRC), used to serve NACKs.
    //   rtxStreams          — map of primary SSRC → RtxStream instance,
    //                         which generates RTX-formatted packets with
    //                         auto-incrementing sequence numbers.
    //   nackThrottle        — dedup guard against NACK storms (refuses
    //                         to retransmit the same (ssrc, seq) more
    //                         than once per 100ms window).
    rtpStats: {},
    outboundStats: {},
    rtcpStats: {},
    remoteOutboundStats: {},
    // SRTP profile negotiated via DTLS use_srtp (RFC 5764). IANA number:
    // 0x0001 = AES_CM_128_HMAC_SHA1_80, 0x0007 = AEAD_AES_128_GCM.
    // Set by the 'clienthello' handler (server) or read from the peer's
    // hello in extractSrtpKeys (client).
    negotiatedSrtpProfile: null,

    senderBuffer: new SenderBuffer(),
    rtxStreams: {},
    nackThrottle: new NackThrottle(),

    // Bandwidth estimation (sender-side) — consumes transport-cc and REMB
    // feedback from the remote to produce a single availableOutgoingBitrate
    // value. Exposed via getEstimatedBandwidth() so api.js and user code
    // can react by re-configuring encoders.
    bandwidthEstimator: new BandwidthEstimator({
      startBps: 500 * 1000,         // 500 kbps initial estimate
      minBps:   50 * 1000,          // never go below 50 kbps
      maxBps:   10 * 1000 * 1000,   // cap at 10 Mbps (well above VP8 typical max)
    }),

    // Outgoing RTP header-extension stamper. On every sendRtp() we call
    // stamper.stamp(pkt) to apply abs-send-time (extmap:2), transport-cc
    // (extmap:3), and optionally mid (extmap:4). The stamper owns the per-session
    // counters/state for these extensions — extMap comes from the SDP
    // a=extmap: lines (see SDP.js). Using a stamper (rather than inline
    // code in sendRtp) matches the design of libwebrtc's RTPSenderEgress
    // and pion's HeaderExtensionInterceptor, and keeps the orchestrator
    // free of RTP-protocol knowledge.
    headerStamper: new RtpHeaderStamper({
      // CRITICAL: these IDs MUST match the extension IDs we advertise
      // in our SDP (DEFAULT_VIDEO_EXTENSIONS in sdp.js). The stamper
      // puts extensions in outgoing packets using these IDs; peers
      // look up each extension's ID in the negotiated extmap. Any
      // drift here silently poisons transport-cc / abs-send-time /
      // RID extraction on the peer side.
      //
      // If DEFAULT_VIDEO_EXTENSIONS in sdp.js changes, these IDs must
      // be updated to stay in lockstep.
      extMap: {
        'audio-level':               1,   // RFC 6464 (DEFAULT_AUDIO_EXTENSIONS id 1)
        'abs-send-time':             2,   // matches DEFAULT_VIDEO_EXTENSIONS
        'transport-cc':              3,
        'mid':                       4,
        'rtp-stream-id':            11,   // RFC 8852 (simulcast layer id)
        'repaired-rtp-stream-id':   12,   // RFC 8852 (RTX pairing)
      },
    }),

    // Transport-CC feedback generators — one per incoming media SSRC.
    // Populated lazily when the first RTP packet with a transport-cc
    // extension arrives on a new SSRC. Drained by the rtcpTimer every
    // tccFeedbackIntervalMs (default 100ms), emitting an RTCP feedback
    // packet that the remote consumes to adjust its sending rate.
    //
    // Symmetric counterpart to bandwidthEstimator above: that one is
    // sender-side (we tell the remote, "here's how we received your
    // packets"), this is receiver-side (they tell us, vice versa).
    tccFeedbackGenerators: {},
    tccFeedbackIntervalMs: 100,

    // NACK generators — receive-side counterpart to the SenderBuffer/
    // RtxStream/NackThrottle trio above. One generator per primary
    // incoming SSRC, populated lazily in handleIncomingRtp when a packet
    // on a non-RTX SSRC arrives. Drained every nackFeedbackIntervalMs
    // (same cadence as transport-cc, since both are fast-feedback).
    //
    // The generator owns its own gap detection, RTT-aware retry timing,
    // reordering tolerance (libwebrtc-style histogram), and PLI
    // escalation logic. The drain timer just reads its 16-bit seq list
    // and ships it as RTCP NACK; no wire-format knowledge here.
    nackGenerators: {},
    nackFeedbackIntervalMs: 100,
    // Track the transport-cc RTP header extension ID negotiated *by the
    // remote* (may differ from the one we stamp on outgoing packets).
    // Set from SDP on each setRemoteDescription; null means no transport-cc
    // on the incoming side and we skip feedback generation.
    remoteTransportCcExtId: null,

    // RID / repaired-RID header extension IDs (RFC 8852), set from the
    // remote offer's a=extmap lines. Used by handleIncomingRtp to learn
    // the SSRC→RID mapping at runtime — the only reliable way to associate
    // simulcast layers when the offerer doesn't declare a=ssrc-group:SIM
    // (Firefox) or doesn't declare SSRCs at all (Chrome). Browsers stop
    // emitting these extensions once the binding is established (RFC 8852
    // §3.1: "once the RID has been bound to an SSRC"), so we latch the
    // first observed value per SSRC.
    remoteRidExtId:         null,
    remoteRepairedRidExtId: null,

    // Playout telemetry — per-kind ('audio', 'video') aggregates populated
    // by receive pipelines when the decoder emits frames/audioData. Used
    // by getStats' 'media-playout' entries. Receive pipelines call
    // manager.updatePlayoutStats(kind, patch) to contribute here.
    playoutStats: {
      audio: null,
      video: null,
    },

    // Flags
    closed: false,

    // W3C §4.3.3 Operations chain, negotiation-needed flag, and
    // needsIceRestart live in the SdpOfferAnswer instance (created below).
    // See sdp_offer_answer.js.
  };


  /* ====================== SDP offer/answer state machine ====================== */
  //
  // EventEmitter-based class that owns the W3C signaling control plane:
  // the operations chain, the negotiation-needed flag, signalingState,
  // and the public methods (createOffer / createAnswer / setLocal /
  // setRemote / addIceCandidate / restartIce). cm.js wires up the
  // runtime preludes via deps callbacks (prepareForCreateOffer/Answer)
  // and forwards W3C-surface events through the manager's EventEmitter.

  var sdpOA = new SdpOfferAnswer({
    sharedState: state,
    getClosed:   function () { return state.closed; },

    // Runtime prelude for createOffer: ensure local creds + fingerprint,
    // bring up the iceAgent in lite mode, fold in any pending ICE restart.
    // Returns the DTLS setup attribute and lite-mode candidate list.
    // Synchronous today (lite gather is sync); the callback shape lets
    // us go async later without changing the class.
    prepareForCreateOffer: function (iceRestart, cb) {
      ensureIceCredentials(iceRestart);
      if (iceRestart) {
        // New gathering phase (RFC 8829 §3.5.1) — the previous roster is
        // authenticated against the old creds and must not leak into the
        // restart offer. The agent will re-emit fresh candidates after
        // setLocalDescription, repopulating this and re-patching the new
        // pending description.
        state.localGatheredCandidates = [];
      }
      if (iceRestart && iceAgent && typeof iceAgent.restart === 'function') {
        iceAgent.restart();
        iceAgent.setLocalParameters({
          ufrag: state.localIceUfrag,
          pwd:   state.localIcePwd,
        });
      }
      ensureFingerprint();
      prepareIceForSdp();
      cb(null, {
        setup:          setupForRole() || 'actpass',
        // Candidates to embed at SDP-build time. Lite: the agent's sync
        // gather result (unchanged behavior). Full: the roster gathered
        // so far — JSEP §5.2.2 requires subsequent offers to carry every
        // candidate of the most recent gathering phase (Chrome does).
        // Empty roster (first offer, or right after ICE restart) → null,
        // preserving the trickle-from-scratch shape.
        liteCandidates: (state.mode === 'lite' && iceAgent)
          ? iceAgent.localCandidates
          : (state.localGatheredCandidates.length > 0
              ? state.localGatheredCandidates : null),
      });
    },

    // Runtime prelude for createAnswer. Same shape as the offer prelude
    // but no ICE restart concept (we're answering an offer); `setup` is
    // either our pinned DTLS role or echoes the remote's offer per
    // RFC 5763 negotiation (resolveSetup).
    prepareForCreateAnswer: function (cb) {
      ensureIceCredentials();
      ensureFingerprint();
      prepareIceForSdp();
      var remoteSetup = state.parsedRemoteSdp &&
                        state.parsedRemoteSdp.media[0] &&
                        state.parsedRemoteSdp.media[0].setup;
      var chosenSetup = setupForRole() || SDP.resolveSetup(remoteSetup);
      _diag('[cm] prepareForCreateAnswer — state.dtlsRole:', state.dtlsRole,
            'setupForRole():', setupForRole(),
            'remoteSetup:', remoteSetup,
            '→ chosen setup:', chosenSetup);
      cb(null, {
        setup:          chosenSetup,
        // Same roster logic as prepareForCreateOffer — see comment there.
        liteCandidates: (state.mode === 'lite' && iceAgent)
          ? iceAgent.localCandidates
          : (state.localGatheredCandidates.length > 0
              ? state.localGatheredCandidates : null),
      });
    },

    // setLocalDescription / setRemoteDescription mutate signaling state
    // and trigger reactive cascades (ICE creds, DTLS role, gathering).
    // The class doesn't know about cascades — it forwards updates here.
    applyStateUpdates: function (updates) {
      setState(updates);
    },

    // After a local description lands, the RtpHeaderStamper's extmap must
    // be synced to whatever IDs the SDP actually advertises (RFC 5285 §6 —
    // the answerer typically echoes the offerer's IDs). Implementation
    // lives on MediaTransport which owns the stamper.
    syncStamperExtMap: function (parsedSdp) {
      mediaTransport.syncExtMap(parsedSdp);
    },

    // setRemoteDescription needs the live iceAgent to push remote
    // candidates into it. The agent is lazily created (ensureIceAgent),
    // so the class can't capture it once at construction time — it must
    // be queried each call. Returns null until the agent exists.
    getIceAgent: function () {
      return iceAgent;
    },

    // Per-application post-processing of a parsed remote SDP. Lives in
    // cm.js because it touches MediaReceivers, jitter buffers, simulcast
    // SSRC reconciliation — runtime concerns the class doesn't own.
    processRemoteMedia: function (parsedSdp) {
      processRemoteMedia(parsedSdp);
    },

    // Diagnostic logger. Gated by WEBRTC_DEBUG env var in cm.js. The
    // class uses this for the same diagnostics the original cm.js
    // setRemoteDescription emitted, so debugging output is unchanged.
    diag: _diag,
  });

  // SdpOfferAnswer fires 'negotiationneeded' through its own EventEmitter;
  // propagate to cm.js's ev so api.js (which listens on the manager) keeps
  // receiving it through the existing path.
  sdpOA.on('negotiationneeded', function () {
    ev.emit('negotiationneeded');
  });


  /* ====================== DataChannel + SCTP ====================== */

  // DataChannelController owns the SCTP association, all DataChannels,
  // and DCEP. cm.js wires it up here and forwards DTLS data into it
  // (see startDtls's session.on('data') below).

  var dcController = new DataChannelController({
    getClosed:                   function () { return state.closed; },
    getDtlsSession:              function () { return state.dtlsSession; },
    getDtlsRole:                 function () { return state.dtlsRole; },
    updateNegotiationNeededFlag: function () { sdpOA.updateNegotiationNeededFlag(); },
    applyStateUpdates:           function (updates) { setState(updates); },
    SctpAssociation:             SctpAssociation,
    debug:                       _DBG,
  });

  // Re-emit peer-initiated DataChannel as the manager's 'datachannel'
  // event. api.js exposes this via pc.ondatachannel.
  dcController.on('datachannel', function (info) {
    ev.emit('datachannel', info);
  });

  // Backward-compat: api.js still reads state.dataChannels and
  // state.sctpAssociation in a few places (stats, gating). Expose them
  // as proxy getters on state so external readers don't need to know
  // about the controller. Internal cm.js code uses dcController directly.
  Object.defineProperty(state, 'dataChannels', {
    get: function () { return dcController.getDataChannels(); },
    enumerable: true,
  });
  Object.defineProperty(state, 'sctpAssociation', {
    get: function () { return dcController.sctpAssociation; },
    enumerable: true,
  });


  /* ====================== Media Transport (RTCP layer) ====================== */

  // RTCP send/receive, RTP send/receive, NACK retransmit, scheduling timers,
  // BWE feedback dispatch. Most data-plane state still lives in shared state;
  // a future milestone moves it into the class.
  var mediaTransport = new MediaTransport({
    getClosed:    function () { return state.closed; },
    sharedState:  state,
    getIceAgent:  function () { return iceAgent; },
    getSrtpSession: function () { return state.srtpSession; },
    findRemoteSsrcForMid: function (mid) {
      return findRemoteSsrcForMid(mid);
    },
    findPrimaryForRtx: function (mapping) {
      return findPrimaryForRtx(mapping);
    },
    resolvePeekKeyframeFn: function (codecName) {
      return resolvePeekKeyframeFn(codecName);
    },
    diag:  _diag,
    debug: _DBG,
  });

  // Re-emit MediaTransport events on the manager's EventEmitter. media_pipeline.js
  // and api.js listen on `manager.ev` so we forward the relevant events.
  mediaTransport.on('rtcp', function (rtcp, rinfo, parsed) {
    ev.emit('rtcp', rtcp, rinfo, parsed);
  });
  mediaTransport.on('rtp', function (rtp, rinfo, info) {
    ev.emit('rtp', rtp, rinfo, info);
  });
  mediaTransport.on('pli', function (mediaSsrc) {
    ev.emit('pli', mediaSsrc);
  });
  mediaTransport.on('rtt:update', function (rttMs) {
    ev.emit('rtt:update', rttMs);
  });
  mediaTransport.on('ssrc:rid-learned', function (info) {
    ev.emit('ssrc:rid-learned', info);
  });


  /* ====================== ICE Agent (lazy) ====================== */

  var iceAgent = null;

  function ensureIceAgent() {
    if (iceAgent) return iceAgent;

    // ICE role selection:
    //   - mode='lite': MUST be controlled (RFC 8445 §6.1.1). Always. This is
    //     independent of offerer/answerer order — a lite server renegotiating
    //     via createOffer does NOT become controlling.
    //   - mode='full': offerer is controlling, answerer is controlled
    //     (RFC 8445 §6.1.3.1). Role-conflict resolution (RFC 8445 §7.3.1.1)
    //     corrects via tie-breaker if we guessed wrong.
    var controlling = (state.mode === 'lite')
      ? false
      : (state.signalingState === 'have-local-offer');

    iceAgent = new IceAgent({
      mode:               state.mode,
      iceServers:         state.iceServers,
      iceTransportPolicy: state.iceTransportPolicy,
      includeLoopback:    config.includeLoopback || false,
      controlling:        controlling,
      trickle:            true,
      // External socket mode (shared UDP port — server scenario).
      socket:             config.socket  || null,
      socket6:            config.socket6 || null,
      // Announced addresses override bind-IP when set (needed for NAT /
      // cloud / 0.0.0.0 bind — see IceAgent.gatherHostCandidates).
      announcedAddresses: state.announcedAddresses,
    });

    // turn-server emits a single 'candidate' event. A null candidate is the
    // end-of-candidates signal (the previous in-repo ice.js used a separate
    // 'gatheringcomplete' event). Map both to the browser-shaped
    // 'icecandidate' event that api.js/consumers expect.
    //
    // In lite mode we suppress these: candidates travel inside the SDP
    // (see createOffer/createAnswer), so re-emitting them via trickle
    // would duplicate each candidate on the wire. The null terminator is
    // still emitted so that consumers relying on it (e.g. "gathering
    // done → send SDP") get their signal.
    iceAgent.on('candidate', function(candidate) {
      if (state.closed) return;
      if (candidate === null) {
        // Gathering complete. In full mode, finalize the local description
        // in place: a=end-of-candidates + default-candidate m=/c= promotion
        // (browser-parity — JSEP §4.1.13/14 + §5.2.2). Lite mode already
        // baked all of this in at SDP-build time (MSF endOfCandidates), so
        // it's skipped — finalize is idempotent anyway, but skipping keeps
        // the lite path byte-identical to before.
        if (state.mode !== 'lite') {
          // Coherence before observability: candidates gathered before the
          // description existed live only in the roster — fold them in,
          // then finalize (default-candidate port promotion,
          // end-of-candidates), so the end-of-candidates event below and
          // the 'complete' state flip both expose a fully-formed SDP.
          syncGatheredCandidatesIntoLocalDescription();
          finalizeLocalCandidatesInDescription();
        }
        ev.emit('icecandidate', { candidate: null });
        return;
      }
      if (state.mode === 'lite') return;

      // Roster bookkeeping for the current gathering phase. Deduped so a
      // re-emitted candidate (agent-level gather retriggers) can't double
      // up in descriptions or subsequent offers.
      var isNewCandidate = _rememberGatheredCandidate(candidate);

      // Per RFC 8839 §5.1.1 + W3C: with BUNDLE the trickled candidate's
      // sdpMid should match the BUNDLE-tagged section — the first
      // non-rejected section in our local description. Hardcoding '0'
      // pointed at section[0], which can be a rejected (port=0) slot
      // recycled after a transceiver.stop() — the peer would then route
      // the candidate to a dead m-section. Resolve the actual mid; fall
      // back to '0' on the very rare paths where parsedLocalSdp isn't
      // populated yet (in practice the full-mode candidate emission
      // runs after setLocalDescription's cascade, so it is).
      var _target = resolveBundleTarget();
      var bundleMid = _target.mid;
      var bundleIdx = _target.idx;

      // Write the candidate into the live local description (JSEP
      // §4.1.13/14: pending/currentLocalDescription include "any local
      // candidates that have been generated by the ICE agent since the
      // local description was set"). Without this, one-shot signaling
      // (WHIP/WHEP, HTTP POST) reads a candidate-less SDP forever and
      // only trickle over a side channel works.
      if (isNewCandidate) {
        patchLocalDescriptionWithCandidate(candidate, bundleMid, bundleIdx);
      }

      ev.emit('icecandidate', {
        candidate: SDP.buildCandidateString(candidate),
        sdpMid: bundleMid,
        sdpMLineIndex: bundleIdx,
      });
    });

    iceAgent.on('statechange', function(newState) {
      if (state.closed) return;
      setState({ iceConnectionState: newState });
    });

    iceAgent.on('gatheringstatechange', function(newState) {
      if (state.closed) return;
      // setState emits 'icegatheringstatechange' synchronously while
      // applying the update (before cascades run) — so a listener reading
      // localDescription inside the event observes whatever the SDP is at
      // this exact moment. Establish the JSEP view invariant FIRST: fold
      // the roster in and finalize, then flip the state. Without this
      // ordering, the flip raced the (separately-evented) finalize and a
      // fast reader saw a placeholder-port, candidate-less answer.
      if (newState === 'complete') {
        syncGatheredCandidatesIntoLocalDescription();
        if (state.mode !== 'lite') {
          finalizeLocalCandidatesInDescription();
        }
      }
      setState({ iceGatheringState: newState });
    });

    iceAgent.on('selectedpair', function(pair) {
      if (state.closed) return;
      state.selectedPair = pair;
      state.remoteAddress = { address: pair.remote.ip, port: pair.remote.port };
      // Forward to manager event bus so RTCIceTransport.onselectedcandidatepairchange
      // listeners work regardless of whether they subscribed before or after
      // the ICE agent was created.
      ev.emit('selectedcandidatepairchange', pair);
    });

    // Agent emits 'candidateerror' when srflx/relay gathering fails (STUN
    // timeout, TURN auth fail, etc). Translate to the W3C-shaped
    // icecandidateerror event — api.js consumes this and wraps in
    // RTCPeerConnectionIceErrorEvent.
    iceAgent.on('candidateerror', function(err) {
      if (state.closed) return;
      // err shape: { type: 'srflx'|'relay', server, error }
      // Normalize to spec shape: { address, errorCode, errorText, port, url }
      var e = err || {};
      ev.emit('icecandidateerror', {
        url:       e.server || null,
        errorText: (e.error && (e.error.message || String(e.error))) || 'gather failed',
        errorCode: (e.error && e.error.code) || 0,
        address:   null,
        port:      null,
      });
    });

    // Incoming packets from ICE → demux by type
    iceAgent.on('packet', function(buf, rinfo, type) {
      if (state.closed) return;

      // Diagnostic: tally packet types for 30 seconds so we can see if RTCP
      // arrives at all, and which type the classifier assigned.
      if (!state._diagPktCounts) state._diagPktCounts = { dtls:0, rtp:0, rtcp:0, unknown:0 };
      state._diagPktCounts[type || 'unknown']++;
      if (!state._diagPktCountsTimer) {
        state._diagPktCountsTimer = setInterval(function () {
          _diag('[cm-diag] demux counts:', JSON.stringify(state._diagPktCounts));
        }, 5000);
        if (state._diagPktCountsTimer.unref) state._diagPktCountsTimer.unref();
      }

      if (type === 'dtls') {
        if (state.dtlsSession) {
          state.dtlsSession.feedDatagram(new Uint8Array(buf));
        } else {
          state.dtlsBuffer.push(new Uint8Array(buf));
        }
      } else if (type === 'rtp') {
        mediaTransport.handleIncomingRtp(buf, rinfo);
      } else if (type === 'rtcp') {
        mediaTransport.handleIncomingRtcp(buf, rinfo);
      }
    });

    // Feed any remote candidates that arrived before agent was created
    if (state.remoteIceUfrag && state.remoteIcePwd) {
      iceAgent.setRemoteParameters({
        ufrag:   state.remoteIceUfrag,
        pwd:     state.remoteIcePwd,
        iceLite: state.remoteIceLite,
      });
    }
    for (var i = 0; i < state.remoteCandidates.length; i++) {
      iceAgent.addRemoteCandidate(state.remoteCandidates[i]);
    }

    return iceAgent;
  }

  // Lazy ICE credentials — only generated when SDP needs them
  function ensureIceCredentials(forceNew) {
    TransportController.ensureLocalIceCreds(state, forceNew);
  }

  // Bring up the ICE agent early so local candidates are available at
  // SDP-build time. Used by createOffer/createAnswer in lite mode to put
  // candidates inline in the SDP (half-trickle — RFC 8838 §4.4), avoiding
  // the separate trickle exchange entirely.
  //
  // In lite mode, gather() is synchronous — no STUN/TURN, just reading
  // socket.address() or announcedAddresses — so by the time this function
  // returns, iceAgent.localCandidates is fully populated.
  //
  // In full mode, this does nothing special: the agent is also created on
  // setLocalDescription via the setState cascade, and trickle delivers
  // candidates asynchronously. Calling this in full mode would start
  // gather() prematurely (before the remote creds are in), so we skip it.
  function prepareIceForSdp() {
    if (state.mode !== 'lite') return;
    if (iceAgent) return;

    ensureIceAgent();
    iceAgent.setLocalParameters({
      ufrag: state.localIceUfrag,
      pwd:   state.localIcePwd,
    });
    if (config.router) {
      config.router._registerAgent(iceAgent);
    }
    iceAgent.gather();   // synchronous in lite mode

    // ── DIAGNOSTIC ──
    // In lite mode, localCandidates should be populated right after gather().
    // If it's empty, something is wrong — log enough state to diagnose.
    // Gated by _DBG so production runs aren't spammed with this on every
    // createOffer/createAnswer.
    if (_DBG) {
      try {
        var cands = iceAgent.localCandidates || [];
        _diag('[prepareIceForSdp] after gather: ' + cands.length + ' local candidates');
        for (var i = 0; i < cands.length; i++) {
          var c = cands[i];
          _diag('  #' + i + ':', c.type, c.ip + ':' + c.port, 'proto=' + c.protocol, 'prio=' + c.priority);
        }
        var ctx = iceAgent.context;
        if (ctx) {
          _diag('  agent.mode=' + ctx.mode +
                      ' gatherState=' + ctx.gatheringState +
                      ' externalSocket=' + (!!ctx.externalSocket) +
                      ' externalSocket6=' + (!!ctx.externalSocket6) +
                      ' announced=' + JSON.stringify(ctx.announcedAddresses));
          if (ctx.externalSocket) {
            try { _diag('  socket.address()=', ctx.externalSocket.address()); }
            catch (e) { _diag('  socket.address() threw:', e.message); }
          }
        }
      } catch (e) {
        _diag('[prepareIceForSdp] diag error:', e.message);
      }
    }
  }


  /* ====================== Local candidates ⇄ local description ====================== */
  //
  // Full-ICE mode gathers candidates asynchronously, AFTER the local
  // description was committed. Browsers surface each gathered candidate
  // into the live description (W3C webrtc-pc "surface the candidate":
  // "add candidate to connection.[[PendingLocalDescription]].sdp"), and
  // on completion promote the default candidate into the m=/c= lines.
  // These helpers replicate that. Lite mode never enters here — its
  // candidates are embedded synchronously at build time (prepareIceForSdp
  // → liteCandidates) and the 'candidate' handler's lite guard holds.

  function _candidateKey(c) {
    return [c.foundation, c.component || 1,
            String(c.protocol || '').toLowerCase(),
            c.ip, c.port, c.type].join('/');
  }

  // Returns true if the candidate is new to the current gathering phase.
  function _rememberGatheredCandidate(candidate) {
    var key = _candidateKey(candidate);
    for (var i = 0; i < state.localGatheredCandidates.length; i++) {
      if (_candidateKey(state.localGatheredCandidates[i]) === key) return false;
    }
    state.localGatheredCandidates.push(candidate);
    return true;
  }

  // Replace (never mutate) the active local description object. Browsers
  // hand out a NEW RTCSessionDescription on each read after a candidate
  // lands; the object an app captured earlier keeps its old .sdp. Since
  // _commitDescription stores the very object the user passed to
  // setLocalDescription, mutating desc.sdp in place would rewrite the
  // user's own variable — swap the slot instead.
  function _swapLocalDescription(newSdp) {
    var desc = state.pendingLocalDescription || state.currentLocalDescription;
    if (!desc) return;
    var newDesc = { type: desc.type, sdp: newSdp };
    if (state.pendingLocalDescription) state.pendingLocalDescription = newDesc;
    else state.currentLocalDescription = newDesc;
  }

  // Keep the parsed views coherent with a string-level patch. The
  // 'candidate' handler's bundleMid resolution and MSF's renegotiation
  // pinning both read these — a stale parsed view would silently diverge
  // from the SDP string the user sees.
  function _syncParsedCandidate(parsed, idx, c) {
    if (!parsed || !parsed.media || !parsed.media[idx]) return;
    var m = parsed.media[idx];
    if (!m.candidates) m.candidates = [];
    m.candidates.push({
      foundation:     String(c.foundation),
      component:      c.component || 1,
      protocol:       c.protocol,
      priority:       c.priority,
      ip:             c.ip,
      port:           c.port,
      type:           c.type,
      relatedAddress: c.relatedAddress || null,
      relatedPort:    c.relatedPort != null ? c.relatedPort : null,
      tcpType:        c.tcpType || null,
    });
  }

  function _syncParsedFinalize(parsed, defCand) {
    if (!parsed || !parsed.media) return;
    for (var i = 0; i < parsed.media.length; i++) {
      var m = parsed.media[i];
      if (m.port === 0) continue;
      if (m.candidates && m.candidates.length > 0) m.endOfCandidates = true;
      if (defCand) m.port = defCand.port;
    }
  }

  // Resolve the BUNDLE-tagged target for candidate placement: the first
  // non-rejected m-section of the local description (RFC 8839 §5.1.1 +
  // W3C). Shared by the incremental emission path and the roster sync.
  function resolveBundleTarget() {
    var mid = '0', idx = 0;
    var localSdp = state.parsedLocalSdp;
    if (localSdp && localSdp.media) {
      for (var bi = 0; bi < localSdp.media.length; bi++) {
        if (localSdp.media[bi].port !== 0) {
          mid = String(localSdp.media[bi].mid);
          idx = bi;
          break;
        }
      }
    }
    return { mid: mid, idx: idx };
  }

  // JSEP §4.1.13/14 invariant: a local description slot reflects every
  // candidate gathered in the current phase. The incremental emission
  // path maintains this from the moment a description exists — but this
  // library deliberately gathers EARLY (agent up at answer-prep time so
  // one-shot signaling gets inline candidates), so candidates can be
  // gathered BEFORE any local description is installed. Those live only
  // in the roster; patchLocalDescriptionWithCandidate dropped them (no
  // description to patch), and nothing ever re-applied them — a fast
  // machine answered with zero candidates and a placeholder port.
  //
  // This function re-establishes the invariant from the roster at any
  // point. Idempotent by construction: SDP.addCandidate returns the
  // string unchanged for an already-present candidate, and the patcher
  // treats identity as no-op — so it is safe to call from multiple
  // coherence points (cascade, gathering-done, pre-complete).
  function syncGatheredCandidatesIntoLocalDescription() {
    if (state.mode === 'lite') return;   // lite bakes candidates at build time
    var desc = state.pendingLocalDescription || state.currentLocalDescription;
    if (!desc || !desc.sdp) return;
    if (state.localGatheredCandidates.length === 0) return;
    var target = resolveBundleTarget();
    for (var i = 0; i < state.localGatheredCandidates.length; i++) {
      patchLocalDescriptionWithCandidate(
        state.localGatheredCandidates[i], target.mid, target.idx);
    }
  }

  function patchLocalDescriptionWithCandidate(candidate, bundleMid, bundleIdx) {
    var desc = state.pendingLocalDescription || state.currentLocalDescription;
    if (!desc || !desc.sdp) return;

    var patched = SDP.addCandidate(desc.sdp, candidate, bundleMid);
    if (patched === desc.sdp) return;   // mid not found — warned inside addCandidate

    var patchedPending = !!state.pendingLocalDescription;
    _swapLocalDescription(patched);

    // parsedLocalSdp tracks pending-or-current (same view the patched slot
    // exposes) — always sync. parsedCurrentLocalSdp tracks ONLY current:
    // sync it only when current was the patched slot, and only when it's a
    // distinct object (after a local answer both point at the same parse —
    // syncing twice would duplicate the candidate).
    _syncParsedCandidate(state.parsedLocalSdp, bundleIdx, candidate);
    if (!patchedPending &&
        state.parsedCurrentLocalSdp !== state.parsedLocalSdp) {
      _syncParsedCandidate(state.parsedCurrentLocalSdp, bundleIdx, candidate);
    }
  }

  function finalizeLocalCandidatesInDescription() {
    var desc = state.pendingLocalDescription || state.currentLocalDescription;
    if (!desc || !desc.sdp) return;
    if (state.localGatheredCandidates.length === 0) return;   // nothing gathered

    var finalizedPending = !!state.pendingLocalDescription;
    var finalized = SDP.finalizeCandidates(desc.sdp, state.localGatheredCandidates);
    _swapLocalDescription(finalized);

    var defCand = SDP.selectDefaultCandidate(state.localGatheredCandidates);
    _syncParsedFinalize(state.parsedLocalSdp, defCand);
    if (!finalizedPending &&
        state.parsedCurrentLocalSdp !== state.parsedLocalSdp) {
      _syncParsedFinalize(state.parsedCurrentLocalSdp, defCand);
    }
  }


  /* ====================== Reactive State ====================== */

  function setState(updates) {
    if (!updates || typeof updates !== 'object') return;
    if (state.closed) return;

    var changed = false;

    // Apply updates
    for (var key in updates) {
      if (updates[key] !== state[key]) {
        state[key] = updates[key];
        changed = true;

        // Emit state change events
        if (key === 'signalingState') ev.emit('signalingstatechange');
        if (key === 'iceConnectionState') ev.emit('iceconnectionstatechange');
        if (key === 'iceGatheringState') ev.emit('icegatheringstatechange');
        if (key === 'connectionState') ev.emit('connectionstatechange');
        if (key === 'sctpState') ev.emit('sctp:statechange', state.sctpState);
        // Fires on every transition ('new' → 'connecting' → 'connected' →
        // 'failed'/'closed'). Consumed by RTCDtlsTransport.onstatechange.
        if (key === 'dtlsState') ev.emit('dtls:statechange', state.dtlsState);
      }
    }

    if (!changed) return;

    // ══════════════════════════════════════════
    //  REACTIVE CASCADES
    //  Each cascade checks CONDITIONS, not what changed.
    //  Guards (e.g. dtlsState === 'new') prevent re-triggering.
    // ══════════════════════════════════════════

    // 1. ICE Agent: create + gather when local description is set
    //    Trigger: setLocalDescription called → signalingState changed
    if (state.localIceUfrag && !iceAgent &&
        (state.signalingState === 'have-local-offer' ||
         (state.signalingState === 'stable' && state.currentLocalDescription))) {
      ensureIceAgent();
      iceAgent.setLocalParameters({
        ufrag: state.localIceUfrag,
        pwd:   state.localIcePwd,
      });

      // Register with WebRTCRouter for shared-socket demuxing. Must happen
      // AFTER setLocalParameters (router needs the correct ufrag) and
      // BEFORE gather (so we don't miss any 'selectedpair' events).
      // Explicit pass-through: only registers if the user supplied a router
      // in config — no WeakMap / socket-based auto-discovery.
      if (config.router) {
        config.router._registerAgent(iceAgent);
      }

      iceAgent.gather();
    }

    // 2. ICE Remote: pass remote credentials to agent when available
    //    Trigger: setRemoteDescription called → remoteIceUfrag set
    if (iceAgent && state.remoteIceUfrag && state.remoteIcePwd) {
      iceAgent.setRemoteParameters({
        ufrag:   state.remoteIceUfrag,
        pwd:     state.remoteIcePwd,
        iceLite: state.remoteIceLite,
      });
    }

    // 2b. Local description ↔ gathered-candidate coherence (JSEP
    //     §4.1.13/14). Trigger: setLocalDescription committed a slot →
    //     signalingState changed. This library gathers early (agent up at
    //     answer-prep), so the roster may already hold candidates emitted
    //     before any description existed; fold them into the fresh slot.
    //     Condition-not-history per the cascade doctrine; idempotent via
    //     SDP.addCandidate identity, so re-runs are no-ops.
    if (state.localGatheredCandidates.length > 0 &&
        (state.pendingLocalDescription || state.currentLocalDescription)) {
      syncGatheredCandidatesIntoLocalDescription();
    }

    // 3. DTLS: ICE connected + role known → start handshake
    //    Trigger: ICE agent emits 'connected'
    if ((state.iceConnectionState === 'connected' || state.iceConnectionState === 'completed') &&
        state.dtlsState === 'new' && state.dtlsRole !== null) {
      setState({ dtlsState: 'connecting' });
      startDtls();
    }

    // 3b. Surface handshake progress (W3C webrtc-pc §4.3.3 connectionState
    //     derivation: any transport in 'connecting' ⇒ PC 'connecting').
    //     Previously the PC jumped straight new → connected, so a stalled
    //     DTLS handshake left connectionState frozen at 'new' with no
    //     observable transition at all — apps saw ICE connect and then
    //     silence. Now they see 'connecting', and the watchdog in
    //     startDtls guarantees an eventual 'failed' if DTLS never lands.
    if (state.dtlsState === 'connecting' && state.connectionState === 'new') {
      setState({ connectionState: 'connecting' });
    }

    // 4. Connection ready: DTLS connected → update connectionState
    //    Trigger: onDtlsConnected → setState({ dtlsState: 'connected' })
    if (state.dtlsState === 'connected' && state.connectionState !== 'connected') {
      setState({ connectionState: 'connected' });
    }

    // 5. SRTP: DTLS connected + media in SDP → derive keys
    //    Trigger: dtlsState → 'connected'
    if (state.dtlsState === 'connected' && state.srtpState === 'new' && hasMediaInSdp()) {
      var srtpSession = extractSrtpKeys();
      if (srtpSession) {
        // Note: since the fromDtlsKeyingMaterial migration this holds the
        // SrtpSession itself, not a raw key struct. Nothing reads it (the
        // data plane goes through getSrtpSession() → state.srtpSession);
        // kept only as a state-inspection breadcrumb.
        state.srtpKeys = srtpSession;
        state.srtpState = 'ready';
        ev.emit('srtp:ready');
        mediaTransport.startRtcpTimer();
      }
    }

    // 6. SCTP: DTLS connected + DataChannel NEGOTIATED → start association.
    //    Trigger: dtlsState → 'connected'. The cascade marks 'connecting'
    //    immediately for visibility; dcController.start() will transition
    //    the state to 'connected' when the SCTP handshake completes.
    //
    //    The negotiation gate (remoteSctpPort != null, i.e. the remote
    //    description carried an accepted m=application with a=sctp-port)
    //    is essential: an SCTP association only exists when the SDP
    //    negotiated one (RFC 8841 — the association is described BY the
    //    m=application section; libwebrtc likewise brings up its SCTP
    //    transport only for a negotiated data section). Media-only
    //    sessions previously fired an INIT into the DTLS anyway; lenient
    //    peers ignored it, but strict ones (libdatachannel) answer with
    //    a fatal alert and tear the whole connection down post-connect.
    if (state.dtlsState === 'connected' && state.sctpState === 'new' &&
        state.remoteSctpPort != null) {
      state.sctpState = 'connecting';
      dcController.start({
        dtlsRole:       state.dtlsRole,
        localPort:      state.sctpPort,
        remotePort:     state.remoteSctpPort,
        maxMessageSize: state.sendMaxMessageSize,
      });
    }

    // 7. Terminal DTLS failure → release the ICE transport.
    //    dtlsState 'failed' is terminal in this state machine: nothing
    //    ever resets it to 'new', and cascade 3 only starts DTLS from
    //    'new', so once DTLS has failed the session can never recover —
    //    yet the ICE agent previously kept running its consent checks,
    //    keepalives, and sockets, producing dead-session chatter
    //    (disconnected/connected flapping observed AFTER connectionState
    //    already reported 'failed') and leaking timers+sockets on servers
    //    handling many peers. Close the agent to stop all of it; its
    //    'statechange' → 'closed' propagates to iceConnectionState via
    //    the existing handler.
    //
    //    Scoped to DTLS failure only: an ICE-level failure
    //    (iceConnectionState 'failed') is recoverable via restartIce()
    //    per W3C §5.6 and MUST NOT tear the agent down.
    //
    //    iceAgent is intentionally NOT nulled: cascade 1's `!iceAgent`
    //    guard would otherwise re-create (and re-gather) a fresh agent on
    //    the next unrelated setState while local descriptions still
    //    exist. One-shot flag rather than a state probe so re-entrant
    //    cascade passes (agent close emits events synchronously) can't
    //    double-close.
    if (state.dtlsState === 'failed' && iceAgent &&
        !state._iceClosedAfterDtlsFailure) {
      state._iceClosedAfterDtlsFailure = true;
      try { iceAgent.close(); } catch (e) {}
    }
  }


  /* ====================== Operations chain (W3C §4.3.3) ====================== */
  //
  // The chain primitive lives in SdpOfferAnswer (callback-based, no
  // Promises). Public methods on `manager` (createOffer, setLocal, etc.)
  // call sdpOA.chainOperation directly. api.js wraps those in Promises
  // for the W3C surface.

  function rejectPendingOperations() {
    sdpOA.rejectPendingOperations();
  }


  /* ====================== Negotiation-needed flag ====================== */
  //
  // The full algorithm + its flag live in SdpOfferAnswer. cm.js exposes
  // a thin wrapper here so existing call sites (api.js mutations,
  // addTransceiverInternal) can fire the flag without reaching into sdpOA.

  function updateNegotiationNeededFlag() {
    sdpOA.updateNegotiationNeededFlag();
  }

  // Re-evaluate the flag when signalingState transitions to 'stable'. This
  // covers the post-stable cascade of W3C §4.4.1.6 step 11.10: any mutation
  // that landed during a non-stable round had its updateFlag aborted at
  // step 3 (signalingState != stable), leaving it to this listener to
  // re-run the algorithm now that the round is done.
  ev.on('signalingstatechange', function () {
    if (state.signalingState === 'stable') {
      sdpOA.updateNegotiationNeededFlag();
    }
  });


  /* ====================== SDP Operations ====================== */

  // Map our stored DTLS role → the a=setup value to put in SDP.
  // Returns null if we don't have a role yet (first offer), so the caller can
  // fall back to 'actpass' or resolveSetup(remote).
  //
  // Once DTLS is established, we MUST keep using the same role forever (RFC
  // 8842). Otherwise Chrome throws:
  //   "Failed to set SSL role for the transport"
  function setupForRole() {
    return TransportController.dtlsRoleForSdp(state);
  }

  // createOffer / createAnswer / setLocalDescription / setRemoteDescription
  // / addIceCandidate / restartIce logic lives entirely in SdpOfferAnswer.
  // No local wrappers — public callers go through manager.X (which routes
  // through the chain to sdpOA).

  /* ====================== DTLS ====================== */

  function startDtls() {
    if (state.dtlsSession) return;

    // Defensive: DTLS shouldn't start before the local fingerprint/cert were
    // generated (ensureFingerprint runs in createOffer/createAnswer). If we
    // reach here without them, there's a state-machine ordering bug that
    // should be surfaced loudly rather than turning into a cryptic OpenSSL
    // PEM parse error deep inside lemon-tls.
    if (!state.cert || !state.key) {
      console.error('[dtls] startDtls called but no cert/key present.',
        'cert=', state.cert, 'key=', state.key,
        'iceConnectionState=', state.iceConnectionState,
        'dtlsRole=', state.dtlsRole,
        'localFingerprint=', state.localFingerprint);
      throw new Error('startDtls: cert/key not yet initialized (ensureFingerprint must run first)');
    }

    var certStr = typeof state.cert === 'string' ? state.cert : state.cert.toString();
    var keyStr  = typeof state.key  === 'string' ? state.key  : state.key.toString();

    // Validate PEM shape before handing to lemon-tls, so a malformed cert
    // gives a clear diagnostic rather than ERR_OSSL_PEM_NO_START_LINE from
    // deep inside OpenSSL.
    if (!/^-----BEGIN /.test(certStr)) {
      console.error('[dtls] cert is not a PEM string. typeof=', typeof state.cert,
                    'length=', certStr.length,
                    'first 120 chars:', JSON.stringify(certStr.substring(0, 120)));
      throw new Error('startDtls: cert does not appear to be PEM');
    }
    if (!/^-----BEGIN /.test(keyStr)) {
      console.error('[dtls] key is not a PEM string. typeof=', typeof state.key,
                    'length=', keyStr.length,
                    'first 120 chars:', JSON.stringify(keyStr.substring(0, 120)));
      throw new Error('startDtls: key does not appear to be PEM');
    }

    var isServer = (state.dtlsRole === 'server');
    var session = new DTLSSession({
      cert: certStr,
      key:  keyStr,
      isServer: isServer,
      maxVersion: 'DTLSv1.2',
      rejectUnauthorized: false,
      // WebRTC mandates mutual authentication: both peers exchange
      // fingerprints via SDP and both verify the peer cert against
      // it (RFC 8827 §6.5). In TLS, a server only receives a client
      // certificate if it explicitly requests one — without this
      // flag, getPeerCertificate() returns empty on the server side
      // and fingerprint verification fails with "peer presented no
      // certificate". rejectUnauthorized stays false because we do
      // fingerprint-based verification ourselves (verifyDtlsFingerprint),
      // not CA-based — WebRTC certs are self-signed.
      requestCert: isServer,
      cipherSuites: [0xC02B, 0xC02C, 0xC02F, 0xC030],
    });

    // ── use_srtp negotiation (RFC 5764 §4.1) ──
    //
    // Wire format of the extension body:
    //   uint16 profiles_length | uint16 profile[] | uint8 mki_length | mki
    //
    // Supported profiles, preference-ordered. GCM first: rtp-packet
    // implements both, and AEAD_AES_128_GCM measured FASTER than
    // AES_CM_128_HMAC_SHA1_80 in Node (single AEAD pass vs CTR+HMAC).
    //   0x0007 = SRTP_AEAD_AES_128_GCM      (RFC 7714)
    //   0x0001 = SRTP_AES128_CM_HMAC_SHA1_80 (RFC 5764)
    //   0x0008 = SRTP_AEAD_AES_256_GCM      (RFC 7714 §11.2)
    // Order matches libwebrtc: GCM-128 first (its default when GCM is
    // enabled), then GCM-256, then the legacy CM fallback.
    var SRTP_PROFILE_PREFERENCE = [0x0007, 0x0008, 0x0001];

    function _buildUseSrtpExt(profiles) {
      var body = new Uint8Array(2 + profiles.length * 2 + 1);
      body[0] = 0; body[1] = profiles.length * 2;
      for (var pi = 0; pi < profiles.length; pi++) {
        body[2 + pi * 2]     = (profiles[pi] >> 8) & 0xFF;
        body[2 + pi * 2 + 1] =  profiles[pi]       & 0xFF;
      }
      // trailing byte = MKI length 0
      return { type: 14, data: body };
    }

    function _parseUseSrtpProfiles(extData) {
      // Returns the uint16 profile list, or [] on malformed input.
      if (!extData || extData.length < 3) return [];
      var listLen = (extData[0] << 8) | extData[1];
      if (listLen % 2 !== 0 || 2 + listLen > extData.length) return [];
      var out = [];
      for (var o = 2; o < 2 + listLen; o += 2) {
        out.push((extData[o] << 8) | extData[o + 1]);
      }
      return out;
    }

    if (isServer) {
      // DTLS server: per RFC 5764 §4.1.2 we must answer with EXACTLY ONE
      // profile chosen from the CLIENT's offered list. The 'clienthello'
      // event fires synchronously before lemon-tls builds the ServerHello,
      // so setting local_extensions inside the handler lands the answer in
      // the ServerHello.
      session.on('clienthello', function (rawData, message) {
        // Primary source: the parsed ClientHello handed to the event —
        // available on every lemon-tls version. Fallback: the session
        // accessor (needs lemon-tls with the pre-emit extension store).
        var ext = null;
        if (message && Array.isArray(message.extensions)) {
          for (var mi = 0; mi < message.extensions.length; mi++) {
            if (message.extensions[mi] && message.extensions[mi].type === 14) {
              ext = message.extensions[mi];
              break;
            }
          }
        }
        if (!ext && typeof session.getRemoteExtension === 'function') {
          ext = session.getRemoteExtension(14);   // use_srtp
        }
        var offered = ext ? _parseUseSrtpProfiles(ext.data) : [];
        var chosen = null;
        for (var i = 0; i < SRTP_PROFILE_PREFERENCE.length && chosen == null; i++) {
          if (offered.indexOf(SRTP_PROFILE_PREFERENCE[i]) >= 0) {
            chosen = SRTP_PROFILE_PREFERENCE[i];
          }
        }
        if (chosen == null) {
          // Peer offered nothing we support (or no use_srtp at all).
          // Fall back to answering CM — Chrome always offers it; a peer
          // that truly can't do CM will abort on its side per RFC 5764.
          _diag('[cm-diag] use_srtp: no mutual profile in client offer ' +
            JSON.stringify(offered) + ' — answering CM');
          chosen = 0x0001;
        }
        state.negotiatedSrtpProfile = chosen;
        session.set_context({ local_extensions: [_buildUseSrtpExt([chosen])] });
        _diag('[cm-diag] use_srtp: client offered ' + JSON.stringify(offered) +
          ' → answering 0x' + chosen.toString(16).padStart(4, '0'));
      });
    } else {
      // DTLS client: offer our full preference list in the ClientHello;
      // read the server's single choice from its hello after connect
      // (in extractSrtpKeys, via getRemoteExtension).
      session.set_context({
        local_extensions: [_buildUseSrtpExt(SRTP_PROFILE_PREFERENCE)],
      });
    }

    state.dtlsSession = session;

    // ── DTLS handshake watchdog + reconciliation ──
    // lemon-tls's retransmit timer only guards OUR un-acked flights; once
    // the peer's flight is received, processHandshakeRecord treats it as
    // an implicit ACK. If the handshake then stalls (peer goes silent, or
    // a processing bug swallows the flight), NO timer is left running and
    // the connection previously hung forever in dtlsState 'connecting'
    // with connectionState frozen.
    //
    // Two layers of defense:
    //   1. RECONCILE (every 5s while connecting): if the DTLS session's
    //      own state says 'connected' but our 'connect' listener was
    //      somehow never invoked (missed event — e.g. a stale/patched
    //      lemon-tls build), recover by driving onDtlsConnected directly,
    //      and log loudly so the missed event gets reported instead of
    //      masked. connectionState derives from the handshake itself —
    //      never from SCTP — so this covers media-only sessions too.
    //   2. HARD FAIL (30s): still 'connecting' AND the session really
    //      isn't connected → surface OperationError + 'failed' rather
    //      than hanging. 30s covers the full worst-case retransmit
    //      schedule (1s doubling × 6) with margin.
    state._dtlsReconcileTimer = setInterval(function () {
      if (state.closed || state.dtlsState !== 'connecting') return;
      if (session.connected) {
        console.warn('[dtls] session reports connected but the connect ' +
          'event was never observed — recovering via reconciliation. ' +
          'This indicates a missed-event bug or a stale lemon-tls build; ' +
          'please report it with WEBRTC_DEBUG=1 output.');
        onDtlsConnected(session);
      }
    }, 5000);
    if (state._dtlsReconcileTimer.unref) state._dtlsReconcileTimer.unref();

    state._dtlsWatchdog = setTimeout(function () {
      state._dtlsWatchdog = null;
      if (state.closed || state.dtlsState !== 'connecting') return;
      // Last-chance reconcile before declaring failure.
      if (session.connected) {
        console.warn('[dtls] connect event missed for 30s; recovering at ' +
          'watchdog deadline. Please report with WEBRTC_DEBUG=1 output.');
        onDtlsConnected(session);
        return;
      }
      var toErr = new Error('DTLS handshake timed out after 30s (state still connecting)');
      toErr.name = 'OperationError';
      try { ev.emit('dtls:error', toErr); } catch (e) {}
      try { session.close(); } catch (e) {}
      setState({ dtlsState: 'failed', connectionState: 'failed' });
    }, 30000);
    if (state._dtlsWatchdog.unref) state._dtlsWatchdog.unref();

    session.on('packet', function(data) { if (iceAgent) iceAgent.send(data); });
    session.on('connect', function() { onDtlsConnected(session); });

    var _dtlsDataCount = 0;
    session.on('data', function(data) {
      var buf = Buffer.from(data);
      _dtlsDataCount++;
      if (_dtlsDataCount <= 5 || _dtlsDataCount % 50 === 0) {
        _diag('[cm-diag] dtls.data #' + _dtlsDataCount + ' len=' + buf.length +
                    ' sctpAssoc=' + !!dcController.sctpAssociation + ' dtlsState=' + state.dtlsState);
      }
      if (state.dtlsState === 'connecting') onDtlsConnected(session);
      // If SCTP isn't up yet, kick it. The dcController.start() call here
      // is rare — usually the setState cascade in onDtlsConnected has
      // already started it. This is a defensive fallback in case data
      // races ahead of the cascade. Same negotiation gate as cascade 6:
      // without a negotiated m=application there is no association to
      // kick — and inbound DTLS application data in that state is not
      // SCTP traffic for us to answer.
      if (!dcController.sctpAssociation && state.remoteSctpPort != null) {
        dcController.start({
          dtlsRole:       state.dtlsRole,
          localPort:      state.sctpPort,
          remotePort:     state.remoteSctpPort,
          maxMessageSize: state.sendMaxMessageSize,
        });
      }
      dcController.handleDtlsData(buf);
    });

    session.on('error', function(err) {
      if (state._dtlsWatchdog) { clearTimeout(state._dtlsWatchdog); state._dtlsWatchdog = null; }
      if (state._dtlsReconcileTimer) { clearInterval(state._dtlsReconcileTimer); state._dtlsReconcileTimer = null; }
      ev.emit('dtls:error', err);
      // Any DTLS error transitions to 'failed' (W3C webrtc-pc): not just
      // handshake-time errors. A post-handshake fatal alert (steady-state
      // error: bad MAC, decryption failure, peer-initiated close_notify
      // followed by error) is still a connection failure that must
      // propagate to connectionState. Skip if already in a terminal state
      // to avoid a redundant transition.
      if (state.dtlsState !== 'closed' && state.dtlsState !== 'failed') {
        setState({ dtlsState: 'failed', connectionState: 'failed' });
      }
    });

    // Feed buffered DTLS packets
    for (var i = 0; i < state.dtlsBuffer.length; i++) {
      session.feedDatagram(state.dtlsBuffer[i]);
    }
    state.dtlsBuffer = [];
  }

  /**
   * Extract SRTP keys from the DTLS session's master secret (RFC 5764).
   *
   * This used to live in ./srtp.js along with the full SRTP engine, but
   * that file was mostly a duplicate of rtp-packet/srtp.js. The only
   * webrtc-specific bit was this DTLS → SRTP bridge, so it moved here.
   * Ideally lemon-tls would expose exportKeyingMaterial() directly (RFC 5705);
   * until then we do the TLS 1.2 PRF ourselves.
   */
  function extractSrtpKeys() {
    if (!state.dtlsSession || !state.dtlsSession.tls) return null;
    var tls = state.dtlsSession.tls;
    var secrets = tls.getTrafficSecrets();
    if (!secrets) return null;

    // ── Resolve the negotiated SRTP profile ──
    // Server side: we picked it in the 'clienthello' handler.
    // Client side: the server's hello carries its single choice in the
    // use_srtp extension — read it from the remote extensions.
    var profile = state.negotiatedSrtpProfile;
    if (profile == null) {
      var ext = tls.getRemoteExtension ? tls.getRemoteExtension(14) : null;
      if (ext && ext.data && ext.data.length >= 4) {
        var listLen = (ext.data[0] << 8) | ext.data[1];
        if (listLen >= 2 && 2 + listLen <= ext.data.length) {
          profile = (ext.data[2] << 8) | ext.data[3];   // server answers ONE
        }
      }
    }
    if (profile == null) profile = 0x0001;   // legacy peers: CM
    state.negotiatedSrtpProfile = profile;

    // ── Export keying material (RFC 5764 §4.2) ──
    // Preferred path: lemon-tls's RFC 5705 / RFC 8446 exporter.
    // Fallback: local TLS 1.2 PRF (kept for older lemon-tls builds).
    var wantLen = SrtpSession.keyingMaterialLength(profile);
    var material = (typeof tls.exportKeyingMaterial === 'function')
      ? tls.exportKeyingMaterial(wantLen, 'EXTRACTOR-dtls_srtp')
      : null;

    if (!material || material.length !== wantLen) {
      // Fallback: manual TLS 1.2 PRF over master secret + hello randoms.
      if (!secrets.masterSecret || !secrets.localRandom || !secrets.remoteRandom) return null;
      var clientRandom = secrets.isServer ? secrets.remoteRandom : secrets.localRandom;
      var serverRandom = secrets.isServer ? secrets.localRandom : secrets.remoteRandom;
      var seed = Buffer.concat([Buffer.from(clientRandom), Buffer.from(serverRandom)]);
      material = _tls12Prf(Buffer.from(secrets.masterSecret), 'EXTRACTOR-dtls_srtp', seed, wantLen);
    }

    // ── Slice per RFC 5764 §4.2 + build the session (rtp-packet does both;
    //    accepts the profile as the IANA number directly) ──
    state.srtpSession = SrtpSession.fromDtlsKeyingMaterial(
      profile, material, secrets.isServer
    );
    _diag('[cm-diag] SRTP session ready: profile=0x' +
      profile.toString(16).padStart(4, '0') +
      ' (' + state.srtpSession.profile + ')');
    return state.srtpSession;
  }

  /**
   * DTLS fingerprint verification — W3C webrtc-pc §5.5 + RFC 8842 §5.
   *
   * After the DTLS handshake completes, compute SHA-* over the leaf cert's
   * DER bytes and compare against state.remoteFingerprint (parsed from
   * a=fingerprint in remote SDP). If they don't match, an MITM is
   * underway — bail with InvalidStateError.
   *
   * The peer cert chain is reachable via dtlsSession.getPeerCertificate()
   * which lemon-tls returns as Array<{cert: Buffer, ...}> (DER bytes
   * for the leaf are at chain[0].cert).
   *
   * Returns { ok: true } on success, { ok: false, reason } on failure.
   */
  function verifyDtlsFingerprint(dtlsSession) {
    if (!state.remoteFingerprint) {
      return { ok: false, reason: 'remote SDP did not declare a=fingerprint' };
    }
    if (typeof dtlsSession.getPeerCertificate !== 'function') {
      return { ok: false, reason: 'DTLSSession.getPeerCertificate() not available' };
    }
    var chain = dtlsSession.getPeerCertificate();
    if (!chain || !chain.length) {
      return { ok: false, reason: 'peer presented no certificate' };
    }
    var leafDer = chain[0] && chain[0].cert;
    if (!leafDer) {
      return { ok: false, reason: 'leaf certificate has no DER bytes' };
    }

    // Map SDP algorithm names (RFC 8122 §5) to Node's hash names.
    // sha-1 is technically still allowed by RFC 8122 but actively
    // discouraged — Chrome announces sha-256 by default. We support it
    // here for interop with legacy peers but don't recommend it.
    var algo = String(state.remoteFingerprint.algorithm || '').toLowerCase();
    var nodeAlgo = null;
    if      (algo === 'sha-256') nodeAlgo = 'sha256';
    else if (algo === 'sha-384') nodeAlgo = 'sha384';
    else if (algo === 'sha-512') nodeAlgo = 'sha512';
    else if (algo === 'sha-1')   nodeAlgo = 'sha1';
    else return { ok: false, reason: 'unsupported fingerprint algorithm: ' + algo };

    // Compute the digest and format as colon-separated hex (RFC 8122 §5).
    var digest = crypto.createHash(nodeAlgo).update(leafDer).digest();
    var parts = [];
    for (var i = 0; i < digest.length; i++) {
      var byte = digest[i].toString(16);
      parts.push(byte.length === 1 ? '0' + byte : byte);
    }
    var computedFp = parts.join(':').toUpperCase();

    // Normalize announced value — strip whitespace, uppercase.
    var announcedFp = String(state.remoteFingerprint.value || '')
      .toUpperCase()
      .replace(/\s+/g, '');

    if (computedFp !== announcedFp) {
      return {
        ok: false,
        reason: 'fingerprint mismatch (algo=' + algo +
                ' computed=' + computedFp.substring(0, 17) + '...' +
                ' announced=' + announcedFp.substring(0, 17) + '...)',
      };
    }
    return { ok: true };
  }


  function onDtlsConnected(dtlsSession) {
    // Idempotency: lemon-tls may fire 'connect' multiple times under
    // unusual conditions, and the safety-net dispatch from session.on('data')
    // can also reach here. Once we've made a decision (connected or failed),
    // don't re-verify — the second pass would either be wasted work
    // (success) or erroneously override a valid 'connected' state.
    if (state.dtlsState === 'connected' || state.dtlsState === 'failed' ||
        state.dtlsState === 'closed') {
      return;
    }

    // W3C webrtc-pc §5.5 + RFC 8842 §5: MUST verify that the peer cert's
    // SHA-* hash matches a=fingerprint from the remote SDP. Without this,
    // an on-path attacker can MITM the DTLS handshake and decrypt all
    // SRTP traffic.
    var verification = verifyDtlsFingerprint(dtlsSession);
    if (!verification.ok) {
      _diag('[cm-diag] DTLS fingerprint verification FAILED: ' + verification.reason);
      // Console error is appropriate even when _DBG is off — this is a
      // potential security incident, not a debug breadcrumb.
      console.error('[dtls] FINGERPRINT VERIFICATION FAILED — closing connection:',
                    verification.reason);
      try { dtlsSession.close(); } catch (e) {}
      // Emit a structured error so apps can surface the failure to the
      // user. errorDetail uses the W3C webrtc-pc RTCErrorDetailType
      // enumeration value reserved for this case.
      var fpErr = new Error('DTLS fingerprint verification failed: ' + verification.reason);
      fpErr.name = 'OperationError';
      fpErr.errorDetail = 'fingerprint-failure';
      try { ev.emit('dtls:error', fpErr); } catch (e) {}
      // Transition to failed states. Apps watching connectionState /
      // dtlsState will see the failure; setState's cascade handles
      // downstream events (connectionstatechange, dtls:statechange).
      setState({
        dtlsState:       'failed',
        connectionState: 'failed',
      });
      return;
    }
    _diag('[cm-diag] DTLS fingerprint verified ✓');
    if (state._dtlsWatchdog) { clearTimeout(state._dtlsWatchdog); state._dtlsWatchdog = null; }
    if (state._dtlsReconcileTimer) { clearInterval(state._dtlsReconcileTimer); state._dtlsReconcileTimer = null; }
    setState({ dtlsSession: dtlsSession, dtlsState: 'connected' });
  }



  /* ====================== Incoming RTP/RTCP ====================== */

  /**
   * Handle an incoming SRTP packet on the data path.
   *
   * Outer entry point: handles SRTP decryption only. The body of the
   * receive pipeline lives in handleIncomingRtpInner so that we can
   * recurse into it cleanly when an RTX packet (RFC 4588) is unwrapped:
   * the recursion takes a *plaintext* RTP packet, so it must not pass
   * through decryption a second time. Splitting the function in two
   * keeps the decryption step in exactly one place.
   */


  /* ====================== Media Pipeline ====================== */

  function createMediaReceiver(mid, kind, codecs) {
    // Returns just the codec info we need. The actual depacketizer + decoder
    // are built by api.js (RTCRtpReceiver) using the modern rtp-packet API
    // which requires {output, error} options. Previously we constructed the
    // depacketizer here with `new DepacketizerClass()` (no options) — that
    // threw with the post-Phase-1 rtp-packet redesign.
    var primaryCodec = null;
    for (var c = 0; c < codecs.length; c++) {
      if (codecs[c].name.toLowerCase() !== 'rtx') { primaryCodec = codecs[c]; break; }
    }
    if (!primaryCodec) return null;

    return {
      mid: mid, kind: kind, codec: primaryCodec,
      depacketizer: null, packetCount: 0,
    };
  }

  function processRemoteMedia(parsed) {
    for (var i = 0; i < parsed.media.length; i++) {
      var m = parsed.media[i];
      if (m.type !== 'audio' && m.type !== 'video') continue;

      var existing = findTransceiverByMid(m.mid);

      // Simulcast reconciliation (RFC 8853). If we offered simulcast on this
      // m-section, the peer's answer will carry a=simulcast:recv with the
      // layers they accept. Layers they dropped or paused (syntax: "l;m~h"
      // means h is paused) must stop being encoded/sent on our side.
      //
      // When m.simulcast is missing entirely but we offered simulcast, the
      // peer does not understand simulcast — treat as layer[0]-only.
      if (existing && existing.sender && existing.sender.layers &&
          existing.sender.layers.length > 1 && existing.sender.encodings) {
        var acceptedRids = null;   // null = unknown (no simulcast block)
        var pausedRids   = {};
        if (m.simulcast) {
          // RFC 8853: accept list is in the direction opposite to ours.
          // We offered dir=send, peer answers dir=recv (mirror). Some impls
          // emit both — we take whichever matches 'recv'.
          var list = null;
          if (m.simulcast.dir1 === 'recv') list = m.simulcast.list1 || '';
          else if (m.simulcast.dir2 === 'recv') list = m.simulcast.list2 || '';
          else list = '';
          acceptedRids = {};
          // Parse comma-separated alternative groups and semicolon-separated
          // simulcast streams. We treat any RID that appears as "accepted"
          // and track ~ prefix as "paused on arrival".
          var entries = list.split(/[,;]/);
          for (var ei = 0; ei < entries.length; ei++) {
            var e = entries[ei].trim();
            if (!e) continue;
            var paused = false;
            if (e.charAt(0) === '~') { paused = true; e = e.slice(1); }
            acceptedRids[e] = true;
            if (paused) pausedRids[e] = true;
          }
        }
        // Apply to each layer: if accepted and not paused → active;
        // otherwise → inactive. Encoder stops emitting, packets stop flowing.
        var encodingsChanged = false;
        for (var lyi = 0; lyi < existing.sender.layers.length; lyi++) {
          var layerRid = existing.sender.layers[lyi].rid;
          if (!layerRid) continue;
          var enc = existing.sender.encodings[lyi];
          if (!enc) continue;
          var newActive = enc.active;
          if (acceptedRids === null) {
            if (lyi > 0) newActive = false;
          } else if (!acceptedRids[layerRid]) {
            newActive = false;
          } else if (pausedRids[layerRid]) {
            newActive = false;
          }
          if (newActive !== enc.active) {
            enc.active = newActive;
            encodingsChanged = true;
          }
        }
        // Notify RTCRtpSender (api.js) so it can re-apply the new layer
        // state to the live pipeline. Without this, the encoder would
        // keep pumping frames for dropped layers until the next explicit
        // setParameters() call from the app.
        if (encodingsChanged) {
          ev.emit('transceiver:encodings-updated', { mid: existing.mid });
        }
      }

      if (existing && existing.receiver.track) continue;

      // Only wire up a receiver / fire ontrack when the peer actually intends
      // to send media on this m-section. That requires BOTH:
      //   (a) their direction is sendrecv or sendonly (they declare sending)
      //   (b) they declared at least one SSRC (so we know what to demux)
      //      OR they declared simulcast (Chrome-style: RIDs without SSRCs
      //      — SSRCs get learned at runtime from the rtp-stream-id
      //      extension on incoming packets).
      //
      // Without (a), a track:new event lies to user code ("here is a track
      // that will never carry media"); without (b), there's nothing to bind
      // the receiver to.
      //
      // If we're skipping, still materialize a transceiver entry so the
      // RTCPeerConnection API reports it correctly (getTransceivers, etc.).
      var peerSends      = (m.direction === 'sendrecv' || m.direction === 'sendonly');
      var hasRemoteSsrcs = m.ssrcs && m.ssrcs.length > 0;
      var hasSimulcast   = !!(m.simulcast &&
                              (m.simulcast.dir1 === 'send' || m.simulcast.dir2 === 'send'));
      // Build the per-direction negotiated codec list once for this
      // m-section. The peer's offer enumerates codecs with their PTs;
      // because our negotiateCodecs uses remote.payloadType (sdp.js
      // line 572), the PTs in the answer match the offer's PTs.
      // Storing the offerer's primary-codec list (RTX filtered out) on
      // sender._negotiatedCodecs gives downstream consumers (encoders,
      // packetizers, future getStats) the right PT/codec mapping for
      // outgoing RTP — without this, packetizers fall back to libwebrtc
      // defaults (PT 96/111) and peers that announced different PTs
      // (Firefox VP8=120, Opus=109) silently drop our packets.
      var _senderCodecs = [];
      if (m.codecs) {
        for (var _msi = 0; _msi < m.codecs.length; _msi++) {
          var _mscodec = m.codecs[_msi];
          if (!_mscodec || !_mscodec.name) continue;
          if (_mscodec.name.toLowerCase() === 'rtx') continue;
          _senderCodecs.push(_mscodec);
        }
      }

      // Compute whether the peer's offer declares simulcast in the SEND
      // direction (i.e., peer wants to send multiple layers, we receive).
      // Used by api.js's RTCRtpReceiver to decide between simulcast and
      // single-stream pipelines. Storing the boolean on the transceiver
      // keeps SDP traversal in cm.js (this layer owns SDP→state plumbing)
      // and api.js as a thin W3C wrapper.
      //
      // Detection rules (matching the prior api.js isRemoteSimulcast):
      //   - a=simulcast:send l;m;h  → simulcast
      //   - >1 a=rid:X send         → simulcast (Chrome's pre-simulcast-attr style)
      var _remoteSimulcast = false;
      if (m.simulcast &&
          (m.simulcast.dir1 === 'send' || m.simulcast.dir2 === 'send')) {
        _remoteSimulcast = true;
      } else if (m.rids) {
        var _sendCount = 0;
        for (var _ri = 0; _ri < m.rids.length; _ri++) {
          if (m.rids[_ri].direction === 'send') _sendCount++;
        }
        if (_sendCount > 1) _remoteSimulcast = true;
      }

      // CRITICAL: m.direction comes from the parsed SDP, which is in the
      // OFFERER'S perspective (sdp.js parseRemoteSdp doesn't normalize it).
      // When we're the answerer (peer offered new media), our transceiver's
      // direction must be the REVERSE — peer's "sendonly" means we receive,
      // so OUR transceiver is "recvonly". Storing the offerer's perspective
      // would leave t.direction !== t.currentDirection forever after
      // applyDirectionsFromAnswer commits the (correctly) flipped direction
      // to currentDirection, which makes checkIfNegotiationIsNeeded return
      // true on every cycle → infinite negotiationneeded loop.
      //
      // Only `!existing` branches need this: existing transceivers were
      // created by US (via addTransceiver/addTrack) with the right
      // perspective and we don't overwrite. New transceivers from a remote
      // SDP only appear on remote OFFERS (answers can't introduce new
      // m-sections per JSEP §5.3.1) so REVERSE_DIRECTION always applies.
      var _ourDirection = m.direction
        ? (SDP.REVERSE_DIRECTION[m.direction] || m.direction)
        : 'sendrecv';

      if (!peerSends || (!hasRemoteSsrcs && !hasSimulcast)) {
        if (!existing) {
          var _sender = {
            track: null, ssrc: null, rtxSsrc: null,
            layers: [{ rid: null, ssrc: null, rtxSsrc: null }],
            encodings: [{
              rid: null, active: true, maxBitrate: 0, maxFramerate: 0,
              scaleResolutionDownBy: 1, scalabilityMode: null,
            }],
            _negotiatedCodecs: _senderCodecs,
          };
          state.transceivers.push({
            mid: m.mid,
            sender:   _sender,
            receiver: { track: null },
            direction:        _ourDirection,
            currentDirection: null,
            kind:             m.type,
            remoteCodecs:     m.codecs,
            remoteExtensions: m.extensions,
            remoteSimulcast:  _remoteSimulcast,
          });
        } else {
          // Refresh on renegotiation — peer may have dropped/reordered codecs.
          if (existing.sender) existing.sender._negotiatedCodecs = _senderCodecs;
          existing._negotiatedCodecs = _senderCodecs;
          existing.remoteSimulcast = _remoteSimulcast;
        }
        continue;
      }

      var receiver = createMediaReceiver(m.mid, m.type, m.codecs);
      if (receiver) state.mediaReceivers[m.mid] = receiver;

      var transceiver;
      if (existing) {
        transceiver = existing;
        // Refresh on renegotiation
        if (transceiver.sender) transceiver.sender._negotiatedCodecs = _senderCodecs;
        transceiver._negotiatedCodecs = _senderCodecs;
        // FlexFEC: surface the negotiated PT to media_transport's receive
        // path (one PT per session is sufficient — flexfec-03 protects
        // whole streams, pairing rides in a=ssrc-group:FEC-FR).
        if (_senderCodecs) {
          for (var _ffi = 0; _ffi < _senderCodecs.length; _ffi++) {
            if (_senderCodecs[_ffi] && _senderCodecs[_ffi].flexfecPayloadType != null) {
              state.flexfecPayloadType = _senderCodecs[_ffi].flexfecPayloadType;
              break;
            }
          }
        }
        transceiver.remoteSimulcast = _remoteSimulcast;
      } else {
        transceiver = {
          mid: m.mid,
          sender: {
            track: null, ssrc: null, rtxSsrc: null,
            layers: [{ rid: null, ssrc: null, rtxSsrc: null }],
            encodings: [{
              rid: null, active: true, maxBitrate: 0, maxFramerate: 0,
              scaleResolutionDownBy: 1, scalabilityMode: null,
            }],
            _negotiatedCodecs: _senderCodecs,
          },
          receiver: { track: null },
          direction: _ourDirection,
          currentDirection: null,
          kind: m.type,
          remoteCodecs: m.codecs,
          remoteExtensions: m.extensions,
          remoteSimulcast: _remoteSimulcast,
          // Codec negotiation: pick the first non-RTX codec as primary.
          // This matches createMediaReceiver's selection. Phase 1.5 (preferred
          // codec list, priority ordering) can override this.
          negotiatedCodec: receiver ? receiver.codec : null,
        };
        state.transceivers.push(transceiver);
      }

      // Map SSRCs
      for (var s = 0; s < m.ssrcs.length; s++) {
        state.remoteSsrcMap[m.ssrcs[s].id] = {
          mid: m.mid, transceiver: transceiver, receiver: receiver,
          isRtx: false,   // primary by default; RTX entries overwrite below
          rid:   null,    // filled in below when simulcast is declared
        };
      }
      for (var g = 0; g < m.ssrcGroups.length; g++) {
        var group = m.ssrcGroups[g];
        if (group.semantics === 'FID' && group.ssrcs.length >= 2) {
          // Second SSRC in an FID group is the RTX (retransmission) stream.
          // It carries the same video payload wrapped in RTP PT rtx (RFC 4588).
          // We still map it so we can route RTX packets later (Phase 6),
          // but mark it so RTCRtpReceiver doesn't pick it as the primary.
          //
          // primarySsrc is recorded directly from the FID group's first
          // SSRC. The data plane (media_transport.js's _handleIncomingRtpInner)
          // checks `_mapping.primarySsrc` first and only falls back to the
          // findPrimaryForRtx scan if the field is null — so for any RTX
          // stream declared via ssrc-group:FID in the offer, recovery is
          // O(1) per packet. Without this stamp, non-simulcast RTX would
          // route through findPrimaryForRtx which historically required
          // rid != null and silently failed for plain (non-simulcast)
          // Chrome offers; the fallback now handles non-simulcast too,
          // but caching here is both faster and makes the data plane's
          // intent explicit.
          state.remoteSsrcMap[group.ssrcs[1]] = {
            mid: m.mid, transceiver: transceiver, receiver: receiver,
            isRtx: true,
            rid:   null,
            primarySsrc: group.ssrcs[0],
          };
        }
      }

      // Simulcast SSRC→RID inference (RFC 8853 / Chrome-style SDP).
      // Publisher's offer typically declares:
      //   a=ssrc-group:SIM <s1> <s2> <s3>     — the primary SSRCs in simulcast order
      //   a=simulcast:send l;m;h              — the RID list in the matching order
      // We pair them by index: s1↔l, s2↔m, s3↔h. This lets the receiver
      // pre-populate SSRC→RID on the map; packets also carry the RID in
      // the rtp-stream-id extension at runtime so we could reconcile
      // later if a mismatch is detected.
      //
      // If either SIM or simulcast is missing, we leave rid=null and
      // fall back to the single-layer path (one primary SSRC per mid).
      var simGroup = null;
      for (var gi = 0; gi < m.ssrcGroups.length; gi++) {
        if (m.ssrcGroups[gi].semantics === 'SIM') {
          simGroup = m.ssrcGroups[gi];
          break;
        }
      }
      if (simGroup && m.simulcast) {
        // Peer's direction in their offer is 'send'; in their answer they
        // echo 'recv'. Either way the RID list ordering is the same.
        var ridList = null;
        if (m.simulcast.dir1 === 'send' || m.simulcast.dir1 === 'recv') {
          ridList = m.simulcast.list1 || '';
        } else if (m.simulcast.dir2 === 'send' || m.simulcast.dir2 === 'recv') {
          ridList = m.simulcast.list2 || '';
        } else {
          ridList = '';
        }
        // Strip ~ (paused) prefix; split by ; (simulcast streams); ignore
        // alternative groups (,) for RID inference.
        var ridsInOrder = ridList.split(';').map(function (r) {
          r = r.trim();
          if (r.charAt(0) === '~') r = r.slice(1);
          // Alternative groups use ',' — take the first alternative.
          var comma = r.indexOf(',');
          return comma >= 0 ? r.slice(0, comma).trim() : r;
        }).filter(function (r) { return !!r; });

        var simSsrcs = simGroup.ssrcs;
        for (var si = 0; si < simSsrcs.length && si < ridsInOrder.length; si++) {
          var primarySsrc = simSsrcs[si];
          var rid = ridsInOrder[si];
          if (state.remoteSsrcMap[primarySsrc]) {
            state.remoteSsrcMap[primarySsrc].rid = rid;
          }
          // Also tag the paired RTX SSRC so stats can attribute correctly.
          for (var gi2 = 0; gi2 < m.ssrcGroups.length; gi2++) {
            var fg = m.ssrcGroups[gi2];
            if (fg.semantics !== 'FID') continue;
            if (fg.ssrcs[0] === primarySsrc && fg.ssrcs.length >= 2) {
              if (state.remoteSsrcMap[fg.ssrcs[1]]) {
                state.remoteSsrcMap[fg.ssrcs[1]].rid = rid;
              }
            }
          }
        }
      }

      // Create MediaStreamTrack + MediaStream
      var track = new MediaStreamTrack({
        kind:  m.type,
        label: m.mid + '_' + m.type,
      });
      var stream = new MediaStream();
      stream.addTrack(track);
      transceiver.receiver.track = track;

      // The receive pipeline (jitter buffer → depacketizer → decoder → track._push)
      // is built by api.js when it handles the 'track:new' event. connection_manager
      // only routes decrypted RTP via the 'rtp' event. Keep the depacketizer that
      // createMediaReceiver assigned so we can throw it away here — it's dead code
      // from the old, pre-Phase 2 design (api.js now owns that wiring).
      if (receiver) {
        receiver.depacketizer = null;
      }

      // Emit for api.js to wrap in RTCTrackEvent
      ev.emit('track:new', {
        mid: m.mid,
        kind: m.type,
        track: track,
        stream: stream,
        transceiver: transceiver,
        receiver: receiver,
      });
    }
  }

  /* ====================== Transport ====================== */


  /* ====================== Transceivers ====================== */

  function addTransceiverInternal(kind, init) {
    // Pure transceiver creation (state.transceivers.push, state.localSsrcs[mid])
    // lives in rtp_transmission_manager.js. The wiring below — RTX mappings,
    // header-stamper RID registration, and updateNegotiationNeededFlag —
    // is data-plane / control-plane glue that stays with cm.js.
    var transceiver = RtpManager.createTransceiver(state, kind, init);
    var layers = transceiver.sender.layers;

    // Register the RTX mapping for every layer so that incoming NACKs on
    // any layer can be served via RFC 4588. Assumes video PT=96/RTX PT=97
    // for all layers; when a non-default codec negotiates, remoteSDP
    // parser overrides these.
    if (kind === 'video') {
      for (var mi = 0; mi < layers.length; mi++) {
        mediaTransport.setRtxMapping(layers[mi].ssrc, layers[mi].rtxSsrc, 97);
      }
    }

    // Register RIDs with the stamper so outgoing packets from each layer
    // carry the correct rtp-stream-id extension (RFC 8852). Non-simulcast
    // layers (rid=null) are skipped inside registerTransceiverLayer.
    for (var sli = 0; sli < layers.length; sli++) {
      mediaTransport.registerTransceiverLayer(layers[sli]);
    }

    updateNegotiationNeededFlag();
    return transceiver;
  }

  function getNextMid() {
    return RtpManager.getNextMid(state);
  }


  /* ====================== Helpers ====================== */

  function hasMediaInSdp() {
    var parsed = state.parsedRemoteSdp;
    if (!parsed) return false;
    for (var i = 0; i < parsed.media.length; i++) {
      if (parsed.media[i].type === 'audio' || parsed.media[i].type === 'video') return true;
    }
    return false;
  }

  function ensureFingerprint() {
    TransportController.ensureLocalFingerprint(state);
  }


  function findTransceiverByMid(mid) {
    return RtpManager.findByMid(state, mid);
  }

  function findRemoteSsrcForMid(mid) {
    return RtpManager.findRemoteSsrcForMid(state, mid);
  }

  /**
   * Find the primary SSRC that an RTX SSRC repairs. Implementation lives
   * in rtp_transmission_manager.js; see there for the algorithm and
   * caching strategy.
   */
  function findPrimaryForRtx(rtxMapping) {
    return RtpManager.findPrimaryForRtx(state, rtxMapping);
  }

  function close() {
    if (state.closed) return;
    // RTCP / TCC / NACK feedback timers are owned by MediaTransport.
    try { mediaTransport.close(); } catch (e) {}

    var mids = Object.keys(state.mediaReceivers);
    for (var mi = 0; mi < mids.length; mi++) {
      var recv = state.mediaReceivers[mids[mi]];
      if (recv && recv.jitter && recv.jitter.close) recv.jitter.close();
    }

    // DataChannelController owns all channels + the SCTP association.
    // Its close() iterates channels (firing 'close' on each per W3C §6.2)
    // and tears down SCTP.
    try { dcController.close(); } catch (e) {}

    if (iceAgent) { try { iceAgent.close(); } catch (e) {} }
    if (state.dtlsSession) { try { state.dtlsSession.close(); } catch (e) {} }

    // Diagnostic packet-counts timer — installed lazily in iceAgent's
    // 'packet' handler. Without explicit cleanup it keeps firing forever
    // after close (unref'd, so it doesn't keep node alive, but it still
    // accesses partially-torn-down state and burns CPU). Clear it now.
    if (state._diagPktCountsTimer) {
      clearInterval(state._diagPktCountsTimer);
      state._diagPktCountsTimer = null;
    }
    if (state._dtlsWatchdog) {
      clearTimeout(state._dtlsWatchdog);
      state._dtlsWatchdog = null;
    }
    if (state._dtlsReconcileTimer) {
      clearInterval(state._dtlsReconcileTimer);
      state._dtlsReconcileTimer = null;
    }

    // W3C webrtc-pc: when the peer connection closes, every transport
    // state transitions to 'closed' too. Without this, RTCDtlsTransport.state
    // and RTCSctpTransport.state stay stuck at their pre-close values
    // (e.g. 'connected') and onstatechange listeners never fire for the
    // close transition.
    //
    // CRITICAL ORDERING: this setState MUST happen BEFORE state.closed=true.
    // setState's first guard is `if (state.closed) return;` (so post-close
    // mutations don't slip through and fire ghost cascades) — meaning if
    // we set state.closed first, this setState would silently no-op and
    // none of the close-transition events would fire. The cascades after
    // the loop are all guarded against the 'closed' state values, so
    // they're safe to run during this final transition.
    setState({
      signalingState:     'closed',
      iceConnectionState: 'closed',
      connectionState:    'closed',
      dtlsState:          'closed',
      sctpState:          'closed',
    });

    state.closed = true;
    // Reject any in-flight or queued chain operations so their user-facing
    // promises don't leak as "pending forever". Must come after state.closed
    // is set so the rejection error names line up with later checks.
    rejectPendingOperations();
  }


  /* ====================== Public Interface ====================== */

  this.state = state;
  this.ev = ev;

  // Convenience: forward event-emitter interface so consumers don't have to
  // reach into `.ev`. This mirrors the typical EventEmitter surface.
  this.on = function (name, fn) { ev.on(name, fn); return this; };
  this.off = function (name, fn) { ev.off(name, fn); return this; };
  this.emit = function () { return ev.emit.apply(ev, arguments); };

  // SDP — public callback API. Each method takes its domain args plus
  // a Node-style cb(err, result). Ops are serialized through the chain
  // per W3C §4.3.3. api.js wraps these in Promises for the W3C surface.
  this.createOffer = function (options, cb) {
    sdpOA.chainOperation(function (next) {
      sdpOA.createOffer(options || {}, next);
    }, cb);
  };
  this.createAnswer = function (options, cb) {
    sdpOA.chainOperation(function (next) {
      sdpOA.createAnswer(options || {}, next);
    }, cb);
  };
  this.setLocalDescription = function (desc, cb) {
    sdpOA.chainOperation(function (next) {
      sdpOA.setLocalDescription(desc, next);
    }, cb);
  };
  this.setRemoteDescription = function (desc, cb) {
    sdpOA.chainOperation(function (next) {
      sdpOA.setRemoteDescription(desc, next);
    }, cb);
  };
  this.addIceCandidate = function (candidate, cb) {
    sdpOA.chainOperation(function (next) {
      sdpOA.addIceCandidate(candidate, next);
    }, cb);
  };

  // SDP rollback (W3C §4.4.1.5/6). Restores the snapshot SdpOfferAnswer
  // takes before each offer commit. source is 'local' or 'remote' (matching
  // setLocal/RemoteDescription({type:'rollback'}) — api.js maps the W3C
  // surface to this internal call).
  this.rollback = function (source, cb) {
    sdpOA.rollback(source, cb);
  };

  // Exposed so api.js can trigger a negotiation-needed re-evaluation when
  // mutations happen at the api.js layer (addTrack, removeTrack, addTransceiver,
  // createDataChannel, transceiver.direction setter, transceiver.stop(),
  // setCodecPreferences). Implementation of the W3C §4.7.3 algorithm lives
  // in SdpOfferAnswer; this just forwards.
  this.updateNegotiationNeededFlag = updateNegotiationNeededFlag;

  // ICE restart (W3C §4.4.1.6). Logic lives in SdpOfferAnswer.
  this.restartIce = function () {
    sdpOA.restartIce();
  };

  // Media
  this.addTransceiver = addTransceiverInternal;
  this.findTransceiverByMid = findTransceiverByMid;

  // DataChannel — logic lives in DataChannelController. This thin wrapper
  // exists only so api.js's `pc.createDataChannel` doesn't need to know
  // about the controller.
  this.createDataChannel = function (label, options) {
    return dcController.createDataChannel(label, options);
  };

  // Transport — all data-plane send paths live in MediaTransport.
  this.sendRtp     = function (rtpPacket) { mediaTransport.sendRtp(rtpPacket); };
  this.sendRtcp    = function (rtcpPacket) { mediaTransport.sendRtcp(rtcpPacket); };
  this.sendPacket  = function (buf)        { mediaTransport.sendPacket(buf); };

  // Send a PLI for a specific remote SSRC. The argument is an SSRC
  // (number), not a mid (string). Callers that have an SSRC in scope
  // (the typical case — sink-attach hooks, NACK escalation, periodic
  // first-round PLI burst) call this directly. Per-SSRC matches
  // libwebrtc's RTCPSender::BuildPLI which uses a per-instance
  // remote_ssrc_; for simulcast, one PLI per layer's primary SSRC is
  // exactly what's needed (a single mid covers all 3 layers but each
  // has its own SSRC and its own decoder/keyframe state on the peer).
  this.requestKeyframe = function (remoteSsrc) {
    mediaTransport.requestKeyframe(remoteSsrc);
  };

  // Outbound stream registration — called by api.js's RTCRtpSender at
  // pipeline-start time (after SDP negotiation) to publish per-SSRC codec
  // metadata. MediaTransport's RTCP SR builder needs the clockRate to
  // extrapolate rtpTimestamp at SR-emission time per RFC 3550 §6.4.1
  // (the field receivers use to align media streams for lipsync).
  this.registerOutboundStream = function (ssrc, info) {
    mediaTransport.registerOutboundStream(ssrc, info);
  };

  // Transceiver layer registration. api.js calls
  // unregisterTransceiverLayer when transceiver.stop() is invoked, so the
  // header-stamper drops its per-SSRC mapping for that layer.
  this.unregisterTransceiverLayer = function (layer) {
    mediaTransport.unregisterTransceiverLayer(layer);
  };
  Object.defineProperty(this, 'iceAgent', {
    get: function() { return iceAgent; },
  });

  /**
   * Snapshot of raw per-SSRC counters. Used by RTCRtpSender/Receiver/PC
   * getStats() to produce spec-compliant RTCStatsReport entries. The shape
   * is internal — callers should go through the RTC* APIs on the peer
   * connection instead of reading this directly.
   *
   * @returns {object}
   *    inbound       — { [ssrc]: { packets, bytes, packetsLost, jitter, ... } }
   *    outbound      — { [ssrc]: { packets, bytes, ... } }
   *    rtcp          — { [ssrc]: { fractionLost, roundTripTime, ... } }
   *    selectedPair  — ICE pair info if available
   */
  this.getCurrentStats = function () {
    var raw = mediaTransport.getRawStats();
    return {
      inbound:               raw.inbound,
      outbound:              raw.outbound,
      rtcp:                  raw.rtcp,
      remoteOutbound:        raw.remoteOutbound,
      selectedPair:          state.selectedPair || null,
      remoteAddress:         state.remoteAddress || null,
      estimatedBandwidthBps: raw.estimatedBandwidthBps,
      remoteRembBps:         raw.remoteRembBps,
      // Playout telemetry — populated by receive pipelines when decoder
      // output is generated. Keyed by kind ('audio'/'video'). Used by
      // api.js to build the 'media-playout' stats entry.
      playout:               state.playoutStats,
    };
  };

  /**
   * Current sender-side bandwidth estimate in bps, derived from transport-cc
   * delay-gradient analysis and REMB feedback. Use this to drive adaptive
   * encoder bitrate (see RTCRtpSender.setParameters + media pipeline
   * reconfigure).
   */
  this.getEstimatedBandwidth = function () {
    return mediaTransport.getEstimatedBandwidth();
  };

  /**
   * Called by receive pipelines (see media_pipeline.js) each time the
   * decoder produces samples/frames, to contribute to the playout
   * telemetry exposed through getStats' 'media-playout' entries.
   *
   * @param {string} kind   — 'audio' or 'video'
   * @param {object} patch  — partial stats to merge/accumulate. Recognized
   *                          keys: totalSamplesCount, totalSamplesDuration
   *                          (seconds), totalPlayoutDelay (seconds-sum),
   *                          synthesizedSamplesDuration,
   *                          synthesizedSamplesEvents.
   */
  this.updatePlayoutStats = function (kind, patch) {
    if (!kind || !patch) return;
    var cur = state.playoutStats[kind];
    if (!cur) {
      cur = state.playoutStats[kind] = {
        totalSamplesCount:          0,
        totalSamplesDuration:       0,
        totalPlayoutDelay:          0,
        synthesizedSamplesDuration: 0,
        synthesizedSamplesEvents:   0,
      };
    }
    if (typeof patch.totalSamplesCount === 'number')
      cur.totalSamplesCount += patch.totalSamplesCount;
    if (typeof patch.totalSamplesDuration === 'number')
      cur.totalSamplesDuration += patch.totalSamplesDuration;
    if (typeof patch.totalPlayoutDelay === 'number')
      cur.totalPlayoutDelay += patch.totalPlayoutDelay;
    if (typeof patch.synthesizedSamplesDuration === 'number')
      cur.synthesizedSamplesDuration += patch.synthesizedSamplesDuration;
    if (typeof patch.synthesizedSamplesEvents === 'number')
      cur.synthesizedSamplesEvents += patch.synthesizedSamplesEvents;
  };

  // Lifecycle
  this.close = close;

  return this;
}


/* ========================= TLS 1.2 PRF ========================= */
// Used by extractSrtpKeys() to derive SRTP keying material from a DTLS
// session, per RFC 5764. Stays at module level because it has no state.
//
// TODO: when lemon-tls exposes exportKeyingMaterial() (RFC 5705) natively,
// this helper can go away and extractSrtpKeys() can just call it.

function _tls12Prf(secret, label, seed, length) {
  // PRF(secret, label, seed) = P_SHA256(secret, label || seed)
  var fullSeed = Buffer.concat([Buffer.from(label, 'ascii'), seed]);
  return _pHash(secret, fullSeed, length);
}

function _pHash(secret, seed, length) {
  // RFC 5246 §5:  A(0) = seed,  A(i) = HMAC(secret, A(i-1))
  //               output = HMAC(secret, A(i) || seed)   until enough bytes
  var chunks = [];
  var total = 0;
  var a = seed;
  while (total < length) {
    a = crypto.createHmac('sha256', secret).update(a).digest();
    var out = crypto.createHmac('sha256', secret).update(a).update(seed).digest();
    chunks.push(out);
    total += out.length;
  }
  return Buffer.concat(chunks).subarray(0, length);
}


/* ========================= Exports ========================= */

export { ConnectionManager };
export default ConnectionManager;
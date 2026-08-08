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
var _DBG_ON = _DBG;  // cheap hot-path mirror
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
  try {
    if (process.env.WEBRTC_DEBUG === '1' || process.env.WEBRTC_DEBUG === 'true') {
      console.log('[cm-diag] BUILD-STAMP: R105-PIPELINE-RESTORED');
    }
  } catch (eS) {}
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

  // ── mDNS candidates ('auto' from the resolved mode) ──
  // Browsers conceal host candidates behind ".local" names
  // (draft-ietf-mmusic-mdns-ice-candidates), so:
  //   full  (browser-like client, likely on the peer's LAN)  → resolve
  //          inbound ".local" candidates, like a browser would.
  //   lite  (router/socket = cloud server)                   → off. A lite
  //          agent never initiates checks — it learns peer addresses from
  //          inbound check sources — and cloud hosts can't reach the LAN's
  //          multicast group anyway.
  // Explicit config.mdns (false / true / options object) always wins;
  // it is forwarded to IceAgent verbatim. register is never auto-enabled.
  var resolvedMdns = (config.mdns !== undefined)
    ? config.mdns
    : (resolvedMode === 'full');

  // ── Port-mapping assisted gathering ('auto' from the resolved mode) ──
  // full mode = a P2P client application — the same category where
  // qBittorrent / Transmission / Syncthing enable UPnP/NAT-PMP by default,
  // and where the mapping often beats STUN srflx outright (a forwarding
  // rule works behind symmetric NAT; a reflexive mapping does not). The
  // mapped port leads only to the ICE socket, which drops anything that
  // is not credentialed STUN or session DTLS — exposure is equivalent to
  // what srflx already implies. lite (cloud server) → off: public address,
  // no home gateway to ask. Explicit config.portMapping always wins
  // (false disables; an options object customizes and is forwarded
  // verbatim — e.g. { description: 'MyApp' } for the router UI).
  var resolvedPortMapping = (config.portMapping !== undefined)
    ? config.portMapping
    : (resolvedMode === 'full');

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
    bundlePolicy: config.bundlePolicy || 'balanced',
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
    // ── iceCandidatePoolSize pre-gathering (W3C §4.3.1) ──
    // Candidates gathered before any local description exists are held in
    // the roster (localGatheredCandidates) and surfaced only once a
    // description is set — matching browser behavior, where pooled
    // candidates never reach onicecandidate before setLocalDescription.
    pregatherStarted: false,          // pregather() ran (agent up early)
    pregatherFlushed: false,          // deferred candidates surfaced post-SLD
    pregatherGatheringDone: false,    // agent finished gathering pre-SLD
    emittedCandidateKeys: {},         // _candidateKey → true (dedupes flush vs live emission)
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
    // Every configured certificate's fingerprint (only when more than one
    // was supplied) — all of them go into the SDP; see api.js.
    localFingerprints: (config && config._certificateFingerprints) || null,
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

    /**
     * Hold signalingstatechange until the caller says the apply is done.
     * Used by setRemoteDescription so its handler sees the transceivers
     * the description created (see the note in setState).
     */
    holdSignalingEvent: function () { state._holdSignalingEvent = true; },
    /**
     * Run the retirement sweep NOW. Called at the end of a description
     * apply, where the current-description slots are finally promoted —
     * setState runs too early for the answerer, whose slots are updated
     * after it returns, so a sweep keyed on setState alone never saw a
     * complete snapshot on that side.
     */
    retireStoppedNow: function () {
      if (!state.closed) _retireStoppedTransceivers();
    },

    flushSignalingEvent: function () {
      state._holdSignalingEvent = false;
      if (state._pendingSignalingEvent) {
        state._pendingSignalingEvent = false;
        ev.emit('signalingstatechange', { type: 'signalingstatechange' });
      }
      // Then the track events this apply produced, in the order the
      // m-sections appeared.
      var _q = state._pendingTrackEvents;
      state._pendingTrackEvents = null;
      if (_q && _q.length) {
        for (var _qi = 0; _qi < _q.length; _qi++) {
          try { ev.emit('track:new', _q[_qi]); } catch (eT) {}
        }
      }
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
    dbgOn: _DBG,
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
    dbgOn: _DBG,
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
      // mDNS ".local" candidates (draft-ietf-mmusic-mdns-ice-candidates).
      // Resolved above from config.mdns / the ICE mode ('auto').
      mdns:               resolvedMdns,
      // UPnP/NAT-PMP/PCP assisted gathering. Resolved above ('auto').
      portMapping:        resolvedPortMapping,
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

      // Pre-gather phase (iceCandidatePoolSize): while no local description
      // exists, candidates land in the roster ONLY. Patching is impossible
      // (no SDP to patch) and emitting now would leak trickle events before
      // the app has an offer to pair them with — browsers hold pooled
      // candidates until setLocalDescription, and so do we. Cascade 2c
      // flushes them (emission + end-of-candidates) once a description
      // lands; cascade 2b independently folds the roster into the SDP.
      var _hasLocalDesc = !!(state.pendingLocalDescription || state.currentLocalDescription);

      if (candidate === null) {
        if (!_hasLocalDesc && state.pregatherStarted) {
          state.pregatherGatheringDone = true;   // surfaced by cascade 2c
          return;
        }
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
        // NO EMPTY CANDIDATE EVENT. w3c/webrtc-pc#2894 (still unmerged —
        // the WPT that wants it says so itself) adds a per-transport
        // empty candidate before the global null. Emitting it here
        // BREAKS CONNECTIVITY: applications forward every non-null
        // candidate to the peer, and an empty one is end-of-candidates,
        // so the peer stops gathering early and the connection never
        // completes. Verified by the loopback stalling outright. The
        // NULL ordering below is the half that is both correct today and
        // safe.
        var _emitNull = function () {
          if (!state.closed) ev.emit('icecandidate', { candidate: null });
        };
        if (state.iceGatheringState === 'complete') { setTimeout(_emitNull, 0); }
        else { state._emitNullOnComplete = _emitNull; }
        return;
      }
      if (state.mode === 'lite') return;

      // Roster bookkeeping for the current gathering phase. Deduped so a
      // re-emitted candidate (agent-level gather retriggers) can't double
      // up in descriptions or subsequent offers.
      var isNewCandidate = _rememberGatheredCandidate(candidate);

      if (!_hasLocalDesc && state.pregatherStarted) {
        return;   // deferred — cascade 2c emits it after SLD
      }

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
      // ANNOUNCE FIRST, THEN PATCH (W3C 4.4.1.4): a candidate belongs in
      // localDescription only once it has been SURFACED — an application
      // reading localDescription immediately after setLocalDescription
      // must not yet see it. Patching before the event put the candidate
      // in the description ahead of the announcement, which is the wrong
      // way round for anyone who signals the description first and the
      // candidates after. The patch still happens in the same turn, so
      // one-shot signalling (WHIP/WHEP) that reads the description from
      // an icecandidate handler is unaffected.
      if (isNewCandidate) {
        patchLocalDescriptionWithCandidate(candidate, bundleMid, bundleIdx);
      }

      state.emittedCandidateKeys[_candidateKey(candidate)] = true;
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
      // NO TRANSPORTS, NO GATHERING (W3C 4.4.1): a local description with
      // no media and no data channel establishes no ICE transport, so
      // there is nothing to gather for and iceGatheringState must stay
      // 'new'. We ran the phase anyway and fired two events for a
      // connection that could never produce a single candidate.
      var _p = state.parsedLocalSdp;
      var _hasTransports = false;
      if (_p && _p.media) {
        for (var _mi = 0; _mi < _p.media.length; _mi++) {
          if (_p.media[_mi] && _p.media[_mi].port !== 0) { _hasTransports = true; break; }
        }
      }
      if (!_hasTransports) return;
      // setState emits 'icegatheringstatechange' synchronously while
      // applying the update (before cascades run) — so a listener reading
      // localDescription inside the event observes whatever the SDP is at
      // this exact moment. Establish the JSEP view invariant FIRST: fold
      // the roster in and finalize, then flip the state. Without this
      // ordering, the flip raced the (separately-evented) finalize and a
      // fast reader saw a placeholder-port, candidate-less answer.
      if (newState === 'complete') {
        state.iceGatheringEnded = true;
        syncGatheredCandidatesIntoLocalDescription();
        if (state.mode !== 'lite') {
          finalizeLocalCandidatesInDescription();
        }
        // W3C 4.4.1: gathering-state transitions are QUEUED TASKS. Our
        // agent gathers host candidates synchronously inside
        // setLocalDescription, so flipping straight to 'complete' meant
        // 'gathering' was never observable — every state-sequence test
        // (and any app watching the phase) missed it. Publish
        // 'gathering' first, then complete on the next macrotask.
        // BOTH transitions are queued tasks: WPT reads gatheringState
        // immediately after `await setLocalDescription()` and requires
        // 'new' there, then observes 'gathering' and finally 'complete'.
        // Publishing either flip synchronously inside SLD breaks that
        // sequence, so the phase advances one macrotask at a time and
        // stops dead if the connection closes in between.
        setTimeout(function () {
          if (state.closed) return;
          if (state.iceGatheringState !== 'gathering') {
            setState({ iceGatheringState: 'gathering' });
          }
          setTimeout(function () {
            if (state.closed) return;   // close freezes the phase
            setState({ iceGatheringState: 'complete' });
          }, 0);
        }, 0);
        return;
      }
      if (newState === 'gathering') {
        // Same queued-task rule as 'complete': the agent starts
        // gathering synchronously inside setLocalDescription, but the
        // observable transition belongs to a later task (W3C 4.4.1) —
        // reading gatheringState right after `await sLD()` must still
        // see 'new'.
        setTimeout(function () {
          if (state.closed) return;
          setState({ iceGatheringState: 'gathering' });
        }, 0);
        return;
      }
      setState({ iceGatheringState: newState });
    });

    iceAgent.on('selectedpair', function(pair, prev) {
      if (state.closed) return;
      // stats: selectedCandidatePairChanges counts nominations after the
      // first one (W3C: it is 0 until a pair is selected, then counts
      // subsequent switches).
      state.selectedPairChanges = (state.selectedPairChanges || 0) + (prev ? 1 : 0);
      // ── [ice-diag] ALWAYS-ON: selected-pair changes are rare and are the
      // prime suspect for mid-session one-directional path death (all
      // outbound DTLS/SRTP retargets instantly via agent.send()). Log the
      // full 5-tuple of new AND previous so a switch is undeniable.
      var _fmt = function (p) {
        if (!p) return '(none)';
        return (p.local && p.local.ip) + ':' + (p.local && p.local.port) +
               ' [' + (p.local && p.local.type) + '] → ' +
               (p.remote && p.remote.ip) + ':' + (p.remote && p.remote.port) +
               ' [' + (p.remote && p.remote.type) + '] prio=' + p.priority;
      };
      _diag('[ice-diag] SELECTED PAIR ' + (prev ? 'SWITCH' : 'set') +
                  ' @' + new Date().toISOString().slice(11, 23) +
                  '\n[ice-diag]   new:  ' + _fmt(pair) +
                  (prev ? '\n[ice-diag]   prev: ' + _fmt(prev) : ''));
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
      // err shape: { type: 'srflx'|'relay'|'mdns', server, address?, error }
      // Normalize to spec shape: { address, errorCode, errorText, port, url }
      //
      // errorCode semantics (W3C webrtc-pc §4.3.2 / RFC 5389): codes in
      // 300-699 are STUN/TURN ERROR RESPONSES relayed from the server;
      // 701 means the server never answered (timeout / unreachable / DNS
      // failure) or gathering failed locally. Our agent's gather errors
      // are plain Errors without a .code — previously mapped to 0, which
      // no spec-following app filters for; every real-world failure
      // (broken STUN server, dead TURN, CGNAT) is a 701.
      var e = err || {};
      var _code = 701;
      if (e.error && typeof e.error.code === 'number' &&
          e.error.code >= 300 && e.error.code <= 699) {
        _code = e.error.code;   // genuine STUN/TURN error response
      }
      ev.emit('icecandidateerror', {
        url:       e.server || null,
        errorText: (e.error && (e.error.message || String(e.error))) || 'gather failed',
        errorCode: _code,
        address:   e.address || null,
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

      // ── [ice-diag] per-SOURCE tally: key = remote address:port + type.
      // When a direction dies we'll see its source's counter freeze between
      // dumps; when the peer switches sending ports a NEW source appears.
      // Cheap (object bump per packet), dumped with the 5s counts below.
      if (!state._diagSrcCounts) state._diagSrcCounts = {};
      var _sk = rinfo.address + ':' + rinfo.port + '/' + (type || '?');
      state._diagSrcCounts[_sk] = (state._diagSrcCounts[_sk] || 0) + 1;

      if (!state._diagPktCountsTimer) {
        state._diagPktCountsTimer = setInterval(function () {
          _diag('[cm-diag] demux counts:', JSON.stringify(state._diagPktCounts));
          _diag('[ice-diag] sources @' + new Date().toISOString().slice(11, 23) +
                      ' ' + JSON.stringify(state._diagSrcCounts));
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

  // W3C 4.4.1 / JSEP 5.2.2 final step: once a negotiation COMPLETES
  // (both descriptions applied, signalingState back to 'stable'), any
  // transceiver that is stopped AND whose m-section was negotiated as
  // rejected (port 0 on both sides) is REMOVED from [[Transceivers]].
  // Without this the list grows forever — every stop() leaks a slot,
  // and long-lived connections (an SFU rotating publishers) accumulate
  // dead transceivers that still cost an m-section in every offer.
  function _retireStoppedTransceivers() {
    try {
      // OPEN (round 144): the ANSWERER does not retire. Its inputs are
      // correct at rest — both descriptions show the mid at port 0, the
      // transceiver reads currentDirection 'stopped', and its mid is
      // still set — yet it stays in the list, so the sweep must be
      // running while signalingState is not yet 'stable' and never being
      // re-triggered afterwards. The offerer retires correctly because
      // its last apply lands in 'stable' directly. The fix is a
      // re-trigger once the answerer reaches stable, not a change to the
      // conditions below.
      if (state.signalingState !== 'stable') return;
      var lp = state.parsedCurrentLocalSdp, rp = state.parsedCurrentRemoteSdp;
      if (!lp || !lp.media) return;
      var rejectedMids = {};
      for (var li = 0; li < lp.media.length; li++) {
        var lm = lp.media[li];
        if (lm && lm.mid != null && lm.port === 0) rejectedMids[String(lm.mid)] = true;
      }
      if (rp && rp.media) {
        for (var ri = 0; ri < rp.media.length; ri++) {
          var rm = rp.media[ri];
          // both sides must agree the section is dead
          if (rm && rm.mid != null && rm.port !== 0) delete rejectedMids[String(rm.mid)];
        }
      }
      for (var ti = state.transceivers.length - 1; ti >= 0; ti--) {
        var t = state.transceivers[ti];
        var stopped = (RtpManager.isStopped(t));
        if (stopped && t.mid != null && rejectedMids[String(t.mid)]) {
          // W3C 5.4: once the negotiation that retired the section
          // completes, the transceiver is DIS-ASSOCIATED — its mid reads
          // null again. Apps hold transceiver references across a stop
          // (that is why getTransceivers keeps exposing them), and a
          // stale mid on a retired object points at an m-line that no
          // longer exists.
          var _deadMid = String(t.mid);
          // W3C 5.4 completes the pair here: stop() sets DIRECTION to
          // 'stopped' and leaves currentDirection null; the negotiation
          // that actually retires the m-section is what makes
          // currentDirection 'stopped' too. Setting it at stop() time
          // (as we once did) was too early — this is the right moment.
          t.currentDirection = 'stopped';
          t.mid = null;
          t._associated = false;
          t._srdCreated = false;
          t._adopted = false;
          state.transceivers.splice(ti, 1);
          if (state.localSsrcs) delete state.localSsrcs[_deadMid];
        }
      }
    } catch (eRet) {}
  }

  function _markAssociatedFromApplied() {
    try {
      var descs = [state.parsedLocalSdp, state.parsedRemoteSdp];
      for (var di = 0; di < descs.length; di++) {
        var d = descs[di];
        if (!d || !d.media) continue;
        for (var mi2 = 0; mi2 < d.media.length; mi2++) {
          var midv = d.media[mi2].mid;
          if (midv == null) continue;
          for (var ti2 = 0; ti2 < state.transceivers.length; ti2++) {
            var tW = state.transceivers[ti2];
            if (String(tW.mid) !== String(midv)) continue;
            // POISON GATE (the actor-3 root): a raw mid match may be a
            // BIRTH-MID COLLISION — an app-created transceiver whose
            // internal mid equals a remote m-line's mid. Only legitimate
            // owners get marked: already-associated, SRD-created, or
            // explicitly adopted. App-created transceivers gain
            // association ONLY through the local-offer binding step.
            // BOTH sides (the trap named cm:1150 on the LOCAL walk as
            // the sixth setter): a raw mid match is never enough —
            // association enters ONLY via SRD-creation, adoption, or
            // the local-offer binding step.
            if (!RtpManager.isLegitimateOwner(tW)) continue;
            tW._associated = true;
          }
        }
      }
      // JSEP binding step — MUST run AFTER the marking loops (the
      // answer-apply grab bug: binding before marking saw legitimate
      // owners as unmarked, judged their m-lines orphaned, and grabbed
      // the send transceiver). Marking first, binding second.: applying a LOCAL OFFER
      // binds each not-yet-owned m-line to the first UNASSOCIATED
      // transceiver of the same kind, in order — writing the assigned
      // mid back onto the transceiver. Without this, a transceiver
      // born mid-0 that the offer serialized as mid-3 stayed orphaned,
      // and the peer's answer built a RECEIVER on our own send m-line.
      var dLoc = state.parsedLocalSdp;
      if (dLoc && dLoc.media) {
        for (var bi = 0; bi < dLoc.media.length; bi++) {
          var bm = dLoc.media[bi];
          if (!bm || bm.mid == null) continue;
          if (bm.type !== 'audio' && bm.type !== 'video') continue;
          var owned = false;
          for (var oi = 0; oi < state.transceivers.length; oi++) {
            if (state.transceivers[oi]._associated &&
                String(state.transceivers[oi].mid) === String(bm.mid)) { owned = true; break; }
          }
          if (owned) continue;
          for (var ui = 0; ui < state.transceivers.length; ui++) {
            var ut = state.transceivers[ui];
            if (ut._associated) continue;
            if (ut.kind !== bm.type) continue;
            if (RtpManager.isStopped(ut)) continue;
            // RE-KEY the send-side state (the mid-3 no-RTP bug): ssrc
            // allocation lives in state.localSsrcs keyed by the BIRTH
            // mid — rebinding the transceiver's mid without re-keying
            // left the send machinery looking up an empty slot, so no
            // a=ssrc in the offer and no RTP ever transmitted. (Same
            // re-key the adoption path already does at its own site.)
            RtpManager.rebindMid(state, ut, bm.mid);
            ut._associated = true;
            break;
          }
        }
      }
    } catch (eAssoc) {}
  }

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
        if (key === 'parsedRemoteSdp' || key === 'parsedLocalSdp' ||
            key === 'parsedCurrentRemoteSdp' || key === 'parsedCurrentLocalSdp') {
          _markAssociatedFromApplied();
          // The retirement sweep needs BOTH parsedCurrent{Local,Remote}Sdp
          // in place. setState applies keys one at a time, so running it
          // inline saw a half-updated snapshot and never retired
          // anything — defer it one macrotask, past the whole apply.
          if (!state._retireScheduled) {
            state._retireScheduled = true;
            setTimeout(function () {
              state._retireScheduled = false;
              if (!state.closed) _retireStoppedTransceivers();
            }, 0);
          }
        }
        // REACHING 'stable' IS ITSELF A RETIREMENT TRIGGER. The sweep
        // refuses to run outside 'stable', and on the ANSWERER the
        // description applies land while the state is still
        // have-remote-offer — so every scheduled sweep returned early and
        // nothing re-triggered it once the answer settled. The offerer
        // never showed this because its final apply enters 'stable'
        // directly. Scheduling here, on the transition itself, is the
        // trigger that was missing; the sweep's own conditions are
        // unchanged and still require both sides to show port 0.
        if (key === 'signalingState' && updates[key] === 'stable' &&
            !state.closed && !state._closing) {
          state._retireOnBatchEnd = true;
        }
        if (key === 'signalingState' && !state.closed && !state._closing) {
          // W3C 4.4.3: close() sets signalingState to 'closed' WITHOUT
          // firing signalingstatechange — the transition is silent.
        // WPT harvest (mid-null-until-associated): after any successful
        // description apply, mark transceivers whose mid appears in an
        // APPLIED description as associated — the public transceiver.mid
        // gate reads this. Internal allocation stays at birth.
        _markAssociatedFromApplied();
        _retireStoppedTransceivers();
        // THE EVENT WAITS FOR THE MEDIA (W3C 4.4.1.6). setState applies
        // keys one at a time and signalingState usually comes first, so
        // the event fired before parsedRemoteSdp was stored and long
        // before processRemoteMedia had created the transceivers the
        // description implies. A handler is entitled to see them:
        // getTransceivers() inside signalingstatechange returned EMPTY.
        // When a caller declares it will finish the apply itself (the
        // setRemoteDescription path does), the event is held and released
        // by flushSignalingEvent() once the media pass is done. Every
        // other caller is unaffected and still emits inline.
        if (state._holdSignalingEvent) {
          state._pendingSignalingEvent = true;
        } else {
          ev.emit('signalingstatechange', { type: 'signalingstatechange' });
        }
      }
        if (key === 'iceConnectionState') ev.emit('iceconnectionstatechange');
        if (key === 'iceGatheringState') {
          ev.emit('icegatheringstatechange');
          if (state.iceGatheringState === 'complete' && state._emitNullOnComplete) {
            var _n = state._emitNullOnComplete;
            state._emitNullOnComplete = null;
            setTimeout(_n, 0);
          }
        }
        if (key === 'connectionState' && !state.closed && !state._closing) ev.emit('connectionstatechange', { type: 'connectionstatechange' });
        if (key === 'sctpState') ev.emit('sctp:statechange', state.sctpState);
        // Fires on every transition ('new' → 'connecting' → 'connected' →
        // 'failed'/'closed'). Consumed by RTCDtlsTransport.onstatechange.
        // W3C 4.4.3, same rule signalingState already follows: close()
        // moves every transport to 'closed' SILENTLY. We fired
        // statechange during close(), so a handler ran against a
        // connection that was already torn down — the state is observable
        // afterwards, the transition is not.
        if (key === 'dtlsState' && !state._closing) {
          ev.emit('dtls:statechange', state.dtlsState);
        }
      }
    }

    // RETIRE AT THE END OF THE BATCH, SYNCHRONOUSLY. The sweep needs
    // every key of this update in place, which is why it used to be
    // deferred a macrotask — but a deferral is too late for callers that
    // read getTransceivers() immediately after awaiting the apply (the
    // spec, and WPT, expect the lists to be clear the moment
    // offer/answer resolves). Running it here gives the sweep the
    // complete snapshot without any delay. The macrotask schedule below
    // stays as a backstop for updates that arrive outside setState.
    if (state._retireOnBatchEnd || state.signalingState === 'stable') {
      // Also run whenever the batch LEAVES us in 'stable', not only when
      // this batch carried the transition. The answerer's final apply
      // promotes its current descriptions in a separate step, so the
      // batch that flipped signalingState and the batch that completed
      // the snapshot are not always the same one — keying strictly on
      // the transition missed the callee every time.
      state._retireOnBatchEnd = false;
      if (!state.closed) _retireStoppedTransceivers();
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
    // OPEN (round 152), and now precisely located. W3C 4.4.1.4 says a
    // candidate reaches localDescription only after it has been SURFACED
    // through onicecandidate; ours is there immediately after
    // setLocalDescription, with ZERO events delivered.
    // FOUR fixes were built and measured, and none moved it:
    //   • folding the gathered roster after the pooled-candidate flush;
    //   • gating that fold on emittedCandidateKeys (announced only);
    //   • emitting the per-candidate icecandidate event BEFORE patching;
    //   • deferring every patch onto the macrotask api.js uses to
    //     deliver icecandidate.
    // Since no patch path can still be responsible, the candidate is
    // already inside the SDP TEXT that setLocalDescription stores —
    // createOffer's output is clean, so the line is added during the
    // commit itself. _commitDescription's serialisation is where the
    // next attempt belongs, not anywhere in the candidate plumbing.
    // WHY ALL FOUR FAILED, found afterwards and worth more than any of
    // them: setLocalDescription itself spends a MACROTASK internally
    // (the _yieldBeforeWork seam from round 109), so a setTimeout(0)
    // added here fires INSIDE the caller's await window — the deferral
    // never actually lands after the operation resolves. Timing tricks
    // cannot fix this.
    // THE ORDERING CONTRACT WAS BUILT (round 154) and it WORKS for this
    // test: cm exposes foldCandidateOnDelivery, api.js calls it from its
    // icecandidate handler right before invoking the application
    // callback, and the bulk fold is gated on a deliveredCandidateKeys
    // ledger stamped there. Measured exactly right — 0 candidates
    // immediately after setLocalDescription, 1 inside the handler,
    // 1 afterwards — and candidate-in-sdp went CLEAN.
    // IT WAS STILL REVERTED. Holding candidates out of the description
    // until delivery costs RTCIceTransport 12 to 6 and
    // iceGatheringState 5 to 4: those tests read the description as the
    // authoritative candidate list, and so does anything that signals an
    // SDP without trickle. Six subtests and a real interop property for
    // one subtest is the wrong trade.
    // Doing this properly means the description keeping its candidates
    // while only the PUBLIC getters filter undelivered ones — a
    // read-side view, not a write-side delay. That is the next attempt.
    // All four attempts were withdrawn: each one adds a macrotask to the
    // ICE path, which is real risk for zero measured gain.
    if (state.localGatheredCandidates.length > 0 &&
        (state.pendingLocalDescription || state.currentLocalDescription)) {
      syncGatheredCandidatesIntoLocalDescription();
    }

    // 2c. iceCandidatePoolSize flush (W3C §4.3.1 / JSEP pooled candidates).
    //     Trigger: first description committed after a pre-gather run.
    //     Candidates gathered before ANY description existed were held
    //     (see the 'candidate' handler gate) — surface them now as
    //     icecandidate events, in gather order, exactly once (the
    //     emittedCandidateKeys ledger also protects against overlap with
    //     live-emitted candidates from a still-running gather). 2b above
    //     already folded them into the SDP; this step is observability
    //     only. If gathering had already finished pre-SLD, finish the
    //     sequence the way a live completion would: finalize + null.
    if (state.pregatherStarted && !state.pregatherFlushed &&
        (state.pendingLocalDescription || state.currentLocalDescription) &&
        state.mode !== 'lite') {
      state.pregatherFlushed = true;
      var _pgTarget = resolveBundleTarget();
      for (var _pgi = 0; _pgi < state.localGatheredCandidates.length; _pgi++) {
        var _pgc = state.localGatheredCandidates[_pgi];
        var _pgk = _candidateKey(_pgc);
        if (state.emittedCandidateKeys[_pgk]) continue;
        state.emittedCandidateKeys[_pgk] = true;
        ev.emit('icecandidate', {
          candidate: SDP.buildCandidateString(_pgc),
          sdpMid: _pgTarget.mid,
          sdpMLineIndex: _pgTarget.idx,
        });
      }
      if (state.pregatherGatheringDone) {
        finalizeLocalCandidatesInDescription();
        ev.emit('icecandidate', { candidate: null });
      }
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
      // DTLS 1.3 (RFC 9147), with automatic fallback. Chrome 137+ and
      // Firefox negotiate 1.3 for WebRTC — it is the prerequisite for
      // post-quantum key exchange — and offering only 1.2 meant every
      // modern browser silently downgraded to talk to us. lemon-tls
      // already implements 1.3 end to end (version selection, the
      // different record layer, and the RFC 8446 exporter_master_secret
      // that DTLS-SRTP key derivation depends on); we were the ones
      // capping it. A peer that speaks only 1.2 still negotiates 1.2,
      // because offering a version never removes the older ones.
      // DTLS 1.2 for now. Chrome 137+ and Firefox negotiate DTLS 1.3
      // when offered, and lemon-tls implements it — a local loopback
      // completes a 1.3 handshake (version reads 0xFEFC), carries a data
      // channel and derives SRTP keys correctly. But against Chrome the
      // handshake gets as far as Finished and then the connection dies:
      // Chrome's flight arrives and is read in full (ServerHello,
      // EncryptedExtensions, CertificateRequest, Certificate,
      // CertificateVerify, Finished), so version selection, the 1.3
      // record layer and the key schedule are all fine — what Chrome
      // rejects is something in OUR reply, and there is no falling back
      // once 1.3 has been selected.
      // To retry: set 'DTLSv1.3' here AND put the 1.3 cipher suites
      // (0x1301/0x1302/0x1303) first in the list below — a 1.2-only
      // cipher list makes a 1.3 handshake fail with "No cipher suite in
      // common". lemon-tls logs both directions under WEBRTC_DEBUG=1.
      maxVersion: 'DTLSv1.3',
      minVersion: 'DTLSv1.2',
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
      // TLS 1.3 suites FIRST, then the 1.2 ones. The 1.3 suites use a
      // different numbering space entirely (RFC 8446 B.4) and a list of
      // only 1.2 suites means a 1.3 handshake has nothing to select —
      // "No cipher suite in common with the peer", which is exactly what
      // offering DTLS 1.3 with this list produced.
      //   0x1301 TLS_AES_128_GCM_SHA256        (mandatory in RFC 8446)
      //   0x1302 TLS_AES_256_GCM_SHA384
      //   0x1303 TLS_CHACHA20_POLY1305_SHA256
      // The 1.2 suites stay so a peer that negotiates 1.2 is unaffected;
      // RFC 8827 requires TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 there.
      // TLS 1.3 suites FIRST — they live in a different numbering space
      // (RFC 8446 B.4), and a 1.2-only list makes a 1.3 handshake fail
      // with "No cipher suite in common with the peer". The 1.2 suites
      // stay for peers that negotiate 1.2 (RFC 8827 mandates
      // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 there).
      cipherSuites: [0x1301, 0x1302, 0x1303, 0xC02B, 0xC02C, 0xC02F, 0xC030],
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
      var toErr = new DOMException('DTLS handshake timed out after 30s (state still connecting)', 'OperationError');
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
    // Fulfill the long-documented contract: expose the peer chain's DER
    // bytes for RTCDtlsTransport.getRemoteCertificates().
    state.remoteCertificates = chain.map(function (c) { return c && c.cert; })
      .filter(function (d) { return !!d; });

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
      var fpErr = new DOMException('DTLS fingerprint verification failed: ' + verification.reason, 'OperationError');
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
      // A REJECTED section (port 0) still MAPS to a transceiver — WPT
      // asserts getTransceivers().length after such an offer — but it is
      // born STOPPED and fires NO track event. Two rules ride on this
      // flag below: no ontrack, and no resurrection of a transceiver the
      // retirement sweep is about to collect.
      var _rejectedSection = !!(m && m.port === 0);
      // A rejected section in an ANSWER is the peer confirming OUR
      // rejection — the transceiver already exists (stopped, awaiting
      // retirement) and must not be recreated, or the sweep and this
      // loop cancel out and the list never shrinks. In a remote OFFER a
      // port-0 section is new information and does map to a transceiver
      // (born stopped, no track event).
      if (_rejectedSection && state.signalingState !== 'have-remote-offer') continue;
      if (m.type !== 'audio' && m.type !== 'video') continue;

      var existing = findTransceiverByMid(m.mid);
      if (!existing) {
        // JSEP offer-processing reuse (the true adoption site — the
        // legacy loop below sits in a branch this path never reaches):
        // claim the first UNASSOCIATED same-kind transceiver, unless
        // adopting would strand a send intent on a no-send m-line.
        // NOTE (round-87): WPT's *DoesntPair tests want a remote OFFER to
        // never pair with a locally-created transceiver. Enforcing that
        // BREAKS THE FIELD — the glare/perfect-negotiation legs of the
        // regression went red immediately (the engine relies on its
        // sendonly transceivers being adopted into the peer's m-lines).
        // Field wins: pairing stays, with the send-strand compat guard
        // below as the safety rule. Roughly six WPT subtests are the
        // deliberate cost.
        for (var _ja = 0; _ja < state.transceivers.length; _ja++) {
          var _jt = state.transceivers[_ja];
          if (_jt._associated) continue;
          if (_jt.kind !== m.type) continue;
          if (RtpManager.isStopped(_jt)) continue;
          if (_jt.sender && _jt.sender.track &&
              (m.direction === 'sendonly' || m.direction === 'inactive')) continue;
          RtpManager.rebindMid(state, _jt, m.mid);
          _jt._adopted = true;
          _jt._associated = true;
          existing = _jt;
          break;
        }
      }
      // DIRECTION-UPGRADE (real-world bug found by micro): a section that
      // was previously non-receiving (mic-muted join) and is NOW
      // receiving must surface its track on THIS pass — the birth-track
      // already exists on the transceiver; we emit track:new for it once.
      // OPEN (round 140): a renegotiation that ADDS a stream to a track
      // is not announced. The offer carries both msids correctly and the
      // receive side stays silent, so an application that grouped tracks
      // with setStreams never learns about the new grouping.
      // Attempted: re-surfacing the track when the msid SET changes,
      // gated so an unchanged renegotiation stays quiet. The event then
      // fired but carried ONE stream (the update path here builds its
      // stream from m.msid alone, not from the msids list the way the
      // creation path does), and the quiet-gate did not hold. Reverted.
      // The fix belongs with this path's stream construction: it needs
      // the same multi-msid handling the creation path got in round 127,
      // and only then does the re-surface gate make sense.
      // A CHANGED STREAM SET RE-SURFACES THE TRACK (W3C 5.1 step 8): a
      // renegotiation that puts the track into another stream is news
      // and must be announced. Keyed on the msid SET so an unchanged
      // renegotiation stays silent. Now that this path builds ALL the
      // streams (above), the re-surfaced event carries the full set —
      // which is what round 140 was missing.
      var _msidKeyU = ((m.msids && m.msids.length) ? m.msids.slice().sort().join('|')
                                                   : String(m.msid || ''));
      var _msidChangedU = !!(existing && existing._trackSurfaced &&
                             existing._lastMsidKey !== undefined &&
                             existing._lastMsidKey !== _msidKeyU);
      if (existing) existing._lastMsidKey = _msidKeyU;
      if (existing && (!existing._trackSurfaced || _msidChangedU) &&
          m.port !== 0 && m.direction !== 'inactive' && m.direction !== 'recvonly' &&
          existing.receiver && existing.receiver.track) {
        existing._trackSurfaced = true;
        try {
          var _upSid = m.msid ? String(m.msid).split(' ')[0] : null;
          if (!state._remoteStreams) state._remoteStreams = {};
          var _upStream = (_upSid && state._remoteStreams[_upSid]) || new MediaStream();
          if (_upSid && !state._remoteStreams[_upSid]) {
            try { Object.defineProperty(_upStream, 'id', { value: _upSid, configurable: true }); } catch (eI) {}
            state._remoteStreams[_upSid] = _upStream;
          }
          _upStream.addTrack(existing.receiver.track);
          // MULTI-STREAM on the UPDATE path, matching what the creation
          // path got in round 127: a track may belong to several
          // MediaStreams, one per a=msid line. Building only from m.msid
          // meant a renegotiation that ADDED a stream announced a single
          // one, so an app that grouped tracks with setStreams never saw
          // the new grouping.
          var _upAll = [_upStream];
          var _upList = (m.msids && m.msids.length) ? m.msids : [];
          for (var _u = 0; _u < _upList.length; _u++) {
            var _uid = String(_upList[_u]).split(' ')[0];
            if (!_uid || _uid === '-' || _uid === _upSid) continue;
            var _us = state._remoteStreams[_uid];
            if (!_us) {
              _us = new MediaStream();
              try { Object.defineProperty(_us, 'id', { value: _uid, configurable: true }); } catch (eU2) {}
              state._remoteStreams[_uid] = _us;
            }
            if (_us.getTracks().indexOf(existing.receiver.track) === -1) {
              _us.addTrack(existing.receiver.track);
            }
            if (_upAll.indexOf(_us) === -1) _upAll.push(_us);
          }
          try { existing.receiver.track.muted = false; } catch (eM) {}
          ev.emit('track:new', {
            mid: m.mid, kind: m.type,
            transceiver: existing,               // the handler REQUIRES this
            track: existing.receiver.track, stream: _upStream,
            streamsAnnounced: (_upAll.length > 1) ? _upAll : null,
          });
        } catch (eUp) {}
      }

      // Negotiated-RTX override (code-review finding: the birth-time
      // setRtxMapping assumes PT 96/97; the comment there promised "the
      // remoteSDP parser overrides these" — this IS that override, which
      // did not previously exist). Once the remote description names the
      // actual apt pairing for this m-section, re-register every video
      // layer's RTX mapping with the negotiated rtx payload type.
      // Idempotent: runs on every SRD, so renegotiations stay correct.
      // Falls through silently when no apt is found (keeps the default).
      if (existing && m.type === 'video' && existing.sender &&
          existing.sender.layers && Array.isArray(m.rtp)) {
        var _rtxPtByApt = {};
        if (Array.isArray(m.fmtp)) {
          for (var _fi = 0; _fi < m.fmtp.length; _fi++) {
            var _am = /(?:^|;)\s*apt=(\d+)/.exec(m.fmtp[_fi].config || '');
            if (_am) _rtxPtByApt[parseInt(_am[1], 10)] = m.fmtp[_fi].payload;
          }
        }
        // Our sender's primary pt on this m-line: the remote's pt for our
        // codec (offer/answer intersection — the wire pt follows the
        // remote's numbering).
        var _primaryPt = null;
        for (var _ri = 0; _ri < m.rtp.length; _ri++) {
          var _cn = (m.rtp[_ri].codec || '').toLowerCase();
          if (_cn === 'vp8' || _cn === 'vp9' || _cn === 'h264' || _cn === 'h265' || _cn === 'av1') {
            _primaryPt = m.rtp[_ri].payload;
            break;   // first video codec in the remote's preference order
          }
        }
        var _negRtxPt = (_primaryPt != null) ? _rtxPtByApt[_primaryPt] : null;
        if (_negRtxPt != null) {
          for (var _li = 0; _li < existing.sender.layers.length; _li++) {
            var _L = existing.sender.layers[_li];
            if (_L.ssrc != null && _L.rtxSsrc != null) {
              mediaTransport.setRtxMapping(_L.ssrc, _L.rtxSsrc, _negRtxPt);
            }
          }
          if (_negRtxPt !== 97) {
            _diag('[cm-diag] negotiated RTX pt override: mid=' + m.mid +
                  ' primary=' + _primaryPt + ' rtx=' + _negRtxPt);
          }
        }
      }

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
          // JSEP §5.10 REUSE (real-bug fix): an unassociated, non-stopped
          // local transceiver of the same kind is ADOPTED for this m-line
          // instead of duplicating. MID is a free-form token (RFC 5888) —
          // the remote's choice wins; we adopt it into the internal
          // namespace and re-key everything hanging off the old mid.
          for (var _ri = 0; _ri < state.transceivers.length; _ri++) {
            var _rt = state.transceivers[_ri];
            if (_rt._associated) continue;
            if (_rt.kind !== m.type) continue;
            if (RtpManager.isStopped(_rt)) continue;
            // JSEP compatibility (the ADOPTION-SWALLOW field bug): a
            // transceiver that intends to SEND must NOT be adopted into
            // a remote m-line where we cannot send (their sendonly/
            // inactive) — that strands the track on a recvonly answer
            // and negotiationneeded never fires.
            if (_rt.sender && _rt.sender.track &&
                (m.direction === 'sendonly' || m.direction === 'inactive')) continue;
            var _oldMid = _rt.mid;
            if (String(_oldMid) === String(m.mid)) {
              // Same-mid adoption: previously this skipped and RELIED on
              // the raw association walk to mark it — the poison gate
              // now blocks that path, so adoption must claim ownership
              // here itself (no re-key needed).
              _rt._adopted = true;
              existing = _rt;
              break;
            }
            _rt.mid = m.mid;
            _rt._adopted = true;   // legitimate mid owner (poison gate)
            if (state.localSsrcs && state.localSsrcs[_oldMid]) {
              state.localSsrcs[m.mid] = state.localSsrcs[_oldMid];
              delete state.localSsrcs[_oldMid];
              if (state.localSsrcs[m.mid]) state.localSsrcs[m.mid].msid = state.localSsrcs[m.mid].msid; // keep
            }
            if (state.clientMidBySsrc) {
              for (var _sk in state.clientMidBySsrc) {
                if (String(state.clientMidBySsrc[_sk]) === String(_oldMid)) {
                  state.clientMidBySsrc[_sk] = String(m.mid);
                }
              }
            }
            existing = _rt;
            break;
          }
        }
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
          // WPT/spec: the receiver's track exists FROM transceiver
          // creation (muted, live) — media later reuses this object.
          var _birthTrack = null;
          try {
            _birthTrack = new MediaStreamTrack({ kind: m.type, label: 'remote ' + m.type });
            _birthTrack.muted = true;
          } catch (eBt) {}
          state.transceivers.push({
            _srdCreated: true,   // rollback removes ONLY these (JSEP)
            mid: m.mid,
            sender:   _sender,
            receiver: { track: _birthTrack },
            // W3C 5.10: an SRD-created transceiver's direction is 'recvonly'
            direction:        'recvonly',
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
          receiver: { track: null } /* filled below or by track:new */,
          direction: _rejectedSection ? 'stopped' : 'recvonly',  // W3C 5.10
          currentDirection: null,
          // Birth flags (the shape-2 gap, deferred since round 66): this
          // transceiver was CREATED BY a remote m-line, so it legitimately
          // owns that mid — rollback may remove it, the public mid getter
          // must expose the mid, and every selector may steer it.
          _srdCreated: true,
          _associated: true,
          _rejected: _rejectedSection,
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

      // WPT: rejected m-sections (port 0) and non-receiving directions do
      // not surface tracks NOW — but a later renegotiation may UPGRADE the
      // direction (mic-unmute is the everyday case), so this is a per-pass
      // veto, never a permanent one: we mark the section and fall through
      // on the next pass that allows receiving.
      var _allowRecvNow = !(m.port === 0 || m.direction === 'inactive' || m.direction === 'recvonly');
      if (!_allowRecvNow) {
        var _exT = null;
        for (var _xi = 0; _xi < state.transceivers.length; _xi++) {
          if (String(state.transceivers[_xi].mid) === String(m.mid)) { _exT = state.transceivers[_xi]; break; }
        }
        if (_exT) _exT._trackSurfaced = false;
        continue;
      }
      // Create MediaStreamTrack + MediaStream
      var track = (transceiver.receiver && transceiver.receiver.track) ||
        new MediaStreamTrack({
          kind:  m.type,
          // WPT/browser parity: remote tracks are labeled 'remote <kind>'
          label: 'remote ' + m.type,
        });
      // media has (or is about to) arrive on this track
      try { track.muted = false; } catch (eUm) {}
      // WPT harvest: tracks sharing a remote msid must surface in the
      // SAME MediaStream object (ontrack ordering tests compare object
      // identity), and the stream's id must equal the remote msid token.
      var msidSid = m.msid ? String(m.msid).split(' ')[0] : null;
      if (!state._remoteStreams) state._remoteStreams = {};
      var stream;
      if (msidSid && msidSid !== '-' && state._remoteStreams[msidSid]) {
        stream = state._remoteStreams[msidSid];
      } else {
        // W3C 5.1 step 8: a remote m-line with NO msid (or the '-'
        // placeholder) means the sender associated the track with NO
        // stream — the track event must carry an EMPTY streams array.
        // Synthesising a stream here made every such event report one.
        stream = new MediaStream();
        if (msidSid && msidSid !== '-') {
          try { Object.defineProperty(stream, 'id', { value: msidSid, configurable: true }); } catch (e) {}
          state._remoteStreams[msidSid] = stream;
        }
      }
      stream.addTrack(track);
      // MULTI-STREAM: the track belongs to EVERY stream its m-section
      // named, not just the first. We added it to one, so an app that
      // read stream2.getTracks() found it empty even though the track
      // event correctly listed both streams.
      var _joinList = (m.msids && m.msids.length) ? m.msids : [];
      for (var _j = 0; _j < _joinList.length; _j++) {
        var _jid = String(_joinList[_j]).split(' ')[0];
        if (!_jid || _jid === '-' || _jid === msidSid) continue;
        var _js = state._remoteStreams[_jid];
        if (!_js) {
          _js = new MediaStream();
          try { Object.defineProperty(_js, 'id', { value: _jid, configurable: true }); } catch (eJ) {}
          state._remoteStreams[_jid] = _js;
        }
        if (_js.getTracks().indexOf(track) === -1) _js.addTrack(track);
      }
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
      transceiver._trackSurfaced = true;
      // Record the stream set we just announced, so the update path can
      // tell a CHANGED grouping from an unchanged renegotiation. Without
      // this the first comparison there had nothing to compare against.
      transceiver._lastMsidKey = ((m.msids && m.msids.length)
        ? m.msids.slice().sort().join('|')
        : String(m.msid || ''));
      // W3C 5.1 step 8: with NO msid (or the '-' placeholder) the sender
      // associated this track with NO stream, so the EVENT announces an
      // empty streams array — the stream object still exists internally
      // (the receive pipeline and stream bookkeeping need it), it is
      // simply not reported to the application.
      // MULTI-STREAM (W3C 5.1 step 8): a track may belong to SEVERAL
      // MediaStreams, one per a=msid line. Build (or reuse) a stream for
      // each and announce them all — we only ever announced the first,
      // so an app that received a track shared across two streams saw
      // one and silently lost the grouping the sender intended.
      var _allStreams = [];
      var _msidList = (m.msids && m.msids.length) ? m.msids : (m.msid ? [m.msid] : []);
      for (var _ms = 0; _ms < _msidList.length; _ms++) {
        var _sid2 = String(_msidList[_ms]).split(' ')[0];
        if (!_sid2 || _sid2 === '-') continue;
        var _st2 = state._remoteStreams[_sid2];
        if (!_st2) {
          _st2 = new MediaStream();
          try { Object.defineProperty(_st2, 'id', { value: _sid2, configurable: true }); } catch (eI2) {}
          state._remoteStreams[_sid2] = _st2;
        }
        if (_allStreams.indexOf(_st2) === -1) _allStreams.push(_st2);
      }
      var _noMsid = !(msidSid && msidSid !== '-');
      // No track event for a rejected section — there is no media there.
      if (_rejectedSection) continue;
      // TRACK EVENTS FOLLOW THE STATE EVENT (W3C 4.4.1.6): the order is
      // signalingstatechange first, then ontrack. The transceivers have
      // to exist before the state event fires — which is why the media
      // pass runs first — but its track events must WAIT for that
      // announcement, or a handler that clears its ontrack during
      // signalingstatechange still receives one. Buffered while the
      // state event is held, flushed straight after it, in order.
      var _emitTrack = function (payload) {
        if (state._holdSignalingEvent) {
          (state._pendingTrackEvents = state._pendingTrackEvents || []).push(payload);
        } else {
          ev.emit('track:new', payload);
        }
      };
      _emitTrack({
        streamsAnnounced: _noMsid ? [] : (_allStreams.length > 1 ? _allStreams : null),
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
    // any layer can be served via RFC 4588. PT 96/97 is the PRE-NEGOTIATION
    // default; processRemoteMedia re-registers with the negotiated apt
    // pairing on every SRD (the override this comment used to promise
    // now actually exists — see 'Negotiated-RTX override' there).
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
    // JSEP: a mid MATCH is only meaningful for ASSOCIATED transceivers —
    // an unassociated local transceiver's internal birth-mid colliding
    // with the remote's midspace must NOT capture an incoming m-line
    // (the adoption path, with its compatibility rules, owns that case).
    var t = RtpManager.findByMid(state, mid);
    if (t && !RtpManager.isLegitimateOwner(t)) return null;
    return t;
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
    // W3C 4.4.3: the transitions caused by close() are SILENT for the
    // connection-level states — signalingstatechange and
    // connectionstatechange must NOT fire (WPT asserts both). Transport
    // cascades still need the values applied, so a dedicated flag marks
    // this final transition and the emit sites above honour it.
    state._closing = true;
    setState({
      signalingState:     'closed',
      iceConnectionState: 'closed',
      connectionState:    'closed',
      dtlsState:          'closed',
      sctpState:          'closed',
    });
    state._closing = false;

    state.closed = true;
    // Reject any in-flight or queued chain operations so their user-facing
    // promises don't leak as "pending forever". Must come after state.closed
    // is set so the rejection error names line up with later checks.
    rejectPendingOperations();
  }


  /* ====================== Public Interface ====================== */

  this.state = state;
  this.ev = ev;

  // ── iceCandidatePoolSize pre-gathering (W3C §4.3.1) ──
  // Called by api.js at construction when the app configured a pool.
  // Brings the ICE agent up and starts gathering IMMEDIATELY, so by the
  // time the first offer/answer is created the candidates are already in
  // the roster — shaving the STUN/portmap round-trips (hundreds of ms)
  // off time-to-media. Cascade 1's `!iceAgent` guard makes the normal
  // post-SLD path a no-op afterwards; the 'candidate' handler holds
  // emission until a description exists (cascade 2c flushes).
  //
  // Lite mode: no-op — lite gathers synchronously at SDP-build time
  // (prepareIceForSdp), there is nothing to prewarm.
  //
  // The agent's `controlling` guess is made from signalingState 'stable'
  // (→ controlled); if this side later offers first, RFC 8445 §7.3.1.1
  // role-conflict resolution corrects it via tie-breaker — the same
  // mechanism the late-creation path already relies on (see
  // ensureIceAgent's comment).
  this.pregather = function () {
    if (state.closed) return;
    if (iceAgent) return;               // already up — nothing to prewarm
    if (state.mode === 'lite') return;
    ensureIceCredentials();             // generates ufrag/pwd; SDP build reuses them
    ensureIceAgent();
    iceAgent.setLocalParameters({
      ufrag: state.localIceUfrag,
      pwd:   state.localIcePwd,
    });
    if (config.router) {
      config.router._registerAgent(iceAgent);
    }
    state.pregatherStarted = true;
    iceAgent.gather();
  };

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
  // ICE role tracking — mirror libwebrtc's ACTUAL policy (verified via
  // w3c/webrtc-stats#162): the role is set by the INITIAL offerer and
  // re-determined ONLY on ICE restart, where the restart's offerer
  // becomes controlling (RFC 5245 legacy — removed in RFC 8445, but
  // browsers kept it). Our previous behavior (role frozen at agent
  // birth, 8445-pure) desynced from Chrome across restart cycles: after
  // a browser-initiated recovery restart the roles flipped on their side
  // only, both ended up 'controlled', every consent check 487'd, and ICE
  // reported 'disconnected' (the M2 party storm — see the agent's ROLE
  // CONFLICT diag). Interop beats purity: follow 5245 like the browsers.
  //
  // Restart detection: the offer carries a DIFFERENT ice-ufrag than the
  // one currently in force for that side. Non-restart renegotiations
  // reuse the ufrag and MUST NOT move roles. Lite mode is exempt: a
  // lite agent is ALWAYS controlled (RFC 8445 §6.1.1).
  function _sdpFirstUfrag(sdp) {
    var m = /a=ice-ufrag:([^\r\n]+)/.exec(sdp || '');
    return m ? m[1].trim() : null;
  }
  function trackNegotiationRole(desc, weAreOfferer) {
    if (!desc || desc.type !== 'offer' || !desc.sdp) return;  // answers never move roles
    if (state.mode === 'lite') return;
    var offered = _sdpFirstUfrag(desc.sdp);
    if (offered == null) return;
    var prev = weAreOfferer ? state.localIceUfrag : state.remoteIceUfrag;
    var isRestart = (prev != null && offered !== prev);
    // First negotiation: agent-birth heuristic already set the role; only
    // explicit restarts re-determine it afterwards.
    if (!isRestart) return;
    if (iceAgent && typeof iceAgent.setRole === 'function') {
      iceAgent.setRole(weAreOfferer);
    }
  }

  this.setLocalDescription = function (desc, cb) {
    trackNegotiationRole(desc, true);
    sdpOA.chainOperation(function (next) {
      sdpOA.setLocalDescription(desc, next);
    }, cb);
  };
  this.setRemoteDescription = function (desc, cb) {
    trackNegotiationRole(desc, false);
    sdpOA.chainOperation(function (next) {
      sdpOA.setRemoteDescription(desc, next);
    }, cb);
  };
  this.addIceCandidate = function (candidate, cb) {
    sdpOA.chainOperation(function (next) {
      // W3C 4.4.2 step 3, evaluated WHEN THE OPERATION RUNS: a candidate
      // (including the bare end-of-candidates form) needs a remote
      // description to address. Run time is the only correct moment —
      // with an idle chain after a rollback there is none and this
      // rejects, while during glare the candidate queues behind the
      // in-flight setRemoteDescription and finds one by the time it
      // runs. Checking at call time gives one answer where two are
      // needed.
      if (!state.currentRemoteDescription && !state.pendingRemoteDescription) {
        return next(new DOMException(
          'addIceCandidate: no remote description', 'InvalidStateError'));
      }
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
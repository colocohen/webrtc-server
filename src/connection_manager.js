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

var MEDIA_STALL_MUTE_MS = parseInt(process.env.WEBRTC_MEDIA_STALL_MS || '3000', 10);

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
        // AND START THE NEW PHASE. restart() only ARMS the agent — it clears
        // the checklist and sets _reEmitOnGather — but something has to ask
        // it to gather, exactly as connection setup does. Nothing did, so a
        // restart produced fresh credentials and then zero candidates to
        // authenticate with them, and gathering sat at 'new' forever.
        //
        // With no candidates there are no pairs to check, so the connection
        // an ICE restart exists to rescue never recovered.
        //
        // gather() is idempotent, and the state machine below handles the
        // announcement — the agent reports 'gathering' and later 'complete'
        // exactly as it does for the first negotiation, so the observable
        // sequence is identical and needs no special casing here.
        // Start the new phase on the NEXT task, not inline.
        //
        // prepareForCreateOffer runs during createOffer — before
        // setLocalDescription. Gathering inline meant the whole phase, and
        // both of its state events, completed before the description was even
        // applied, so an application listening after setLocalDescription
        // resolved had already missed them.
        //
        // The initial negotiation does not have this problem because the
        // agent has nothing to re-announce and reports asynchronously. A
        // restart does: the agent re-emits kept candidates immediately.
        // Deferring puts both on the same footing.
        if (typeof iceAgent.gather === 'function') {
          setTimeout(function () {
            if (state.closed) return;
            iceAgent.gather();
          }, 0);
        }
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
    // Record the ICE credentials of a remote description as it is applied.
    // Called for BOTH offers and answers, because that is the only moment we
    // learn what the peer is using — and either can be the one that changes
    // them. Without the answer case, a side that offered the first round had
    // no baseline at all, and the first restart it had to ANSWER looked like
    // a first description and was missed entirely.
    recordRemoteIceCredentials: function (parsed) {
      recordRemoteIceCredentials(parsed);
    },

    // Take ICE gathering back to its initial state. Called by rollback when
    // no local description remains — see the note there.
    resetIceGathering: function () {
      state.localGatheredCandidates = [];
      state.iceGatheringComplete = false;
      // AND the flag anything actually READS.
      //
      // iceGatheringEnded is what api.js consults to decide whether an
      // RTCIceTransport may report 'complete' — a gathering phase that has
      // been reset has not ended, so leaving it true let the transport claim
      // a finished phase for a session that is starting a new one.
      //
      // iceGatheringComplete above is written here and in one other place and
      // read nowhere; the two names are close enough that clearing the wrong
      // one looked correct.
      state.iceGatheringEnded = false;
      if (state.iceGatheringState !== 'new') {
        setState({ iceGatheringState: 'new' });
      }
    },

    prepareForCreateAnswer: function (cb) {
      // ANSWERING AN ICE RESTART RESTARTS OUR SIDE TOO.
      //
      // RFC 8829 3.5.1: a remote offer carrying new ICE credentials IS an ICE
      // restart, and the answerer must supply fresh credentials of its own —
      // a restart replaces the pair on BOTH sides, and connectivity checks
      // authenticate against it.
      //
      // Only createOffer had a restart path, so an answerer kept its old
      // ufrag and pwd. The peer that restarted was left half-restarted: its
      // credentials new, ours stale. In the field that is precisely the
      // network-change case — the side that moved restarts, the side that
      // stayed put never refreshes, and the new candidate pairs are checked
      // against credentials one of them has forgotten.
      //
      // It also left our own restart request outstanding, so
      // negotiationneeded kept firing after a restart the peer had already
      // satisfied.
      var _remoteRestart = _remoteCredentialsChanged();
      ensureIceCredentials(_remoteRestart);
      if (_remoteRestart) {
        state.localGatheredCandidates = [];
        if (iceAgent && typeof iceAgent.restart === 'function') {
          iceAgent.restart();
          iceAgent.setLocalParameters({
            ufrag: state.localIceUfrag,
            pwd:   state.localIcePwd,
          });
          // AND GATHER. Same omission the offer path had (fix 42): restart()
          // only arms the agent. Without this the ANSWERER of a restart
          // rotated its credentials and then gathered nothing, so it had no
          // candidates to pair with the ones the offerer had just sent.
          //
          // The first restart of a session survived it, because the answerer
          // still held the candidates from the original negotiation and could
          // pair against those. A SECOND restart could not — those had been
          // cleared by the first — and the call stopped dead:
          //
          //   after restart#1: ~100 packets per 2s, ice=connected
          //   after restart#2: 0 packets for 10s,   ice=checking
          //
          // Repeated restarts are exactly what a flapping network produces,
          // so this is the case that matters most.
          //
          // Deferred for the same reason as the offer path: this runs while
          // the answer is being prepared, and the gathering phase belongs to
          // the description once it is applied.
          if (typeof iceAgent.gather === 'function') {
            setTimeout(function () {
              if (state.closed) return;
              iceAgent.gather();
            }, 0);
          }
        }
        try { sdpOA.clearNeedsIceRestart(); } catch (eR) {}
      }
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
    // The controller builds RTCError / RTCErrorEvent when the transport
    // fails and cannot import either without a cycle — api.js publishes the
    // constructors on state for exactly this.
    getState:                    function () { return state; },
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
    // Media arriving on an SSRC unmutes the matching receiver track (W3C 5.3).
    //
    // TWO SOURCES OF TRUTH, AND THEIR ORDER MATTERS. `muted` is written both
    // by negotiation (the direction the answer agreed on) and by the data
    // plane (media is or is not arriving). They are not peers:
    //
    //   negotiated direction — a FACT. The peer has agreed not to send.
    //   arriving media       — an OBSERVATION. Packets already in flight,
    //                          or a sender that has not stopped yet.
    //
    // The fact wins. Without that ordering the two raced: setting direction
    // to 'inactive' fired 'mute', a packet still on the wire arrived a
    // moment later and fired 'unmute', and the track ended up unmuted on a
    // transceiver that had been negotiated to receive nothing.
    //
    // So this only ever unmutes a transceiver whose negotiated direction
    // still permits receiving. Direction changes drive muting on their own
    // (see the signalingstatechange handler in api.js); this path exists to
    // report that media has actually started, which negotiation cannot know.
    onFirstInboundPacket: function (ssrc) {
      var mapping = state.remoteSsrcMap && state.remoteSsrcMap[ssrc];
      if (!mapping || mapping.isRtx) return;
      for (var i = 0; i < state.transceivers.length; i++) {
        var tc = state.transceivers[i];
        if (String(tc.mid) !== String(mapping.mid)) continue;
        // Negotiated to receive? currentDirection is the committed answer;
        // before the first answer lands it is null and direction stands in.
        var _dir = tc.currentDirection || tc.direction || 'sendrecv';
        if (_dir !== 'sendrecv' && _dir !== 'recvonly') return;
        var tr = tc.receiver && tc.receiver.track;
        if (!tr || tr.muted !== true) return;
        // Media has started arriving: start (or resume) the currentTime clock.
        // Done here rather than on negotiation because currentTime measures
        // RECEIVED media — a track negotiated but never fed must stay at 0.
        if (!tr._ctFirstPacketAt) tr._ctFirstPacketAt = Date.now();
        tr.muted = false;
        try { tr.dispatchEvent && tr.dispatchEvent({ type: 'unmute' }); } catch (e1) {}
        return;
      }
    },
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
      // 'checking' IS ANNOUNCED ON A QUEUED TASK; every other state inline.
      //
      // Measured: the agent reports 'checking' inside setRemoteDescription,
      // in the same millisecond the promise resolves and just before it —
      // so an application that installs its listener after `await sRD(...)`,
      // which is the ordinary pattern, never sees the transition. It reads
      // 'connected' as the first thing that ever happened.
      //
      // Only this one state is deferred, and that distinction is the whole
      // fix. iceConnectionState is a TRIGGER as well as a report: the cascade
      // starts the DTLS handshake the moment it reads 'connected', so
      // deferring the value wholesale stalls connection setup outright — two
      // earlier attempts did exactly that and were reverted. 'checking' gates
      // nothing, so delaying its announcement by a task costs nothing and
      // makes the sequence observable from where callers actually watch.
      if (newState === 'checking') {
        var _t = setTimeout(function () {
          if (state.closed) return;
          // Only if nothing has moved past it in the meantime — a fast
          // connect can reach 'connected' before this task runs, and
          // announcing 'checking' after that would be a lie.
          if (state.iceConnectionState === 'new') {
            setState({ iceConnectionState: 'checking' });
          }
        }, 0);
        if (_t.unref) _t.unref();
        return;
      }
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
      // EVERY gathering-state announcement is a QUEUED TASK (W3C 4.4.1).
      //
      // The agent reports when it reports: on a first negotiation 'gathering'
      // arrives after setLocalDescription has already resolved, but on a
      // RESTART the whole burst arrives synchronously inside it, because the
      // agent still holds candidates to re-announce. Publishing on arrival
      // therefore delivered the same transition before the promise in one
      // case and after it in the other.
      //
      // An application cannot be asked to install its listener at a different
      // moment depending on which of those it is. Deferring uniformly makes
      // the sequence observable from after the promise resolves in both:
      // harmless when the report was already late, decisive when it was not.
      setTimeout(function () {
        if (state.closed) return;
        setState({ iceGatheringState: newState });
      }, 0);
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
      // W3C 4.8.2 scopes this event to failures gathering FROM A STUN OR TURN
      // SERVER, and makes `url` a required field naming that server. Our ICE
      // agent also reports purely local gather failures — mDNS resolution,
      // and NAT port-mapping ("no gateway answered PCP, NAT-PMP or UPnP-IGD").
      // Those have no server to name, so surfacing them here produced an
      // event with an empty url that does not describe anything the spec
      // defines, and it arrived FIRST — an application inspecting the first
      // error it receives saw a blank one instead of the server that failed.
      //
      // Local failures are still visible through iceGatheringState and the
      // absence of the corresponding candidate type; they are simply not this
      // event.
      if (!e.server) return;

      ev.emit('icecandidateerror', {
        // W3C 4.8.2: url is a DOMString, NOT nullable — an application is
        // entitled to call event.url.includes(...) unconditionally, and WPT
        // does exactly that. Emitting null threw inside the app's handler on
        // every gather error, and since a failing server retries, the throw
        // repeated indefinitely: one run produced 1299 exceptions and starved
        // the encoder into 259 ffmpeg restarts before the file timed out.
        // Fall back to the empty string the event class already defaults to.
        url:       e.server || '',
        errorText: (e.error && (e.error.message || String(e.error))) || 'gather failed',
        errorCode: _code,
        // W3C 4.8.2 ties address and port together: port 0 means "no host
        // candidate address is available", and address MUST be null then.
        // We always sent port: null, and null == 0 is false in JavaScript,
        // so an application following the spec took the "address is present"
        // branch and dereferenced null. WPT does exactly that, and because a
        // failing ICE server keeps retrying, the throw repeated until the
        // file timed out — 1299 exceptions in one run, which also starved
        // the audio encoder into 259 ffmpeg restarts.
        //
        // Report the pair consistently: an address with its port when we
        // have one, and 0/null when we do not.
        // The agent reports the LOCAL address it gathered from as `base` on
        // server-error paths (srflx/relay) and as `address` on local ones
        // (mDNS). Either is the "local address used" the event describes.
        // W3C 4.8.2 makes address and port a PAIR: port 0 means no local
        // address is available, and address MUST be null in that case. So we
        // report both or neither — reporting an address with port 0 is a
        // contradiction a spec-following application will assert on, and WPT
        // does exactly that.
        //
        // The agent gives the local address as `base` on server-error paths
        // (srflx/relay) and as `address` on local ones (mDNS). Only the
        // server paths carry a port, so only they report a pair.
        address:   e.port != null ? (e.base || e.address || null) : null,
        port:      e.port != null ? e.port : 0,
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
  // Did the remote description just bring ICE credentials different from the
  // ones we last saw? That is the wire signal for an ICE restart (RFC 8829
  // 3.5.1), compared against what we recorded on the previous apply.
  // Remember the ICE credentials of a remote description as it is applied.
  // The comparison baseline for detecting a restart (RFC 8829 3.5.1).
  function recordRemoteIceCredentials(parsed) {
    if (!parsed || !parsed.media) return;
    var ufrag = null;
    for (var i = 0; i < parsed.media.length; i++) {
      if (parsed.media[i] && parsed.media[i].iceUfrag) { ufrag = parsed.media[i].iceUfrag; break; }
    }
    if (!ufrag) ufrag = parsed.iceUfrag;
    if (ufrag) state._lastRemoteIceUfrag = ufrag;
  }

  function _remoteCredentialsChanged() {
    var d = state.parsedRemoteSdp;
    if (!d || !d.media || !d.media.length) return false;
    var ufrag = null;
    for (var i = 0; i < d.media.length; i++) {
      if (d.media[i] && d.media[i].iceUfrag) { ufrag = d.media[i].iceUfrag; break; }
    }
    if (!ufrag) ufrag = d.iceUfrag;
    if (!ufrag) return false;
    // Compare against the ufrag of the description we ANSWERED last, not
    // against the most recent one seen — this function runs while the new
    // offer is already applied, so reading and updating in one step compares
    // the offer with itself.
    // READ ONLY. The baseline is recorded on EVERY remote description that is
    // applied — see recordRemoteIceCredentials — because a peer alternates
    // between offering and answering, and a side that offered last round has
    // still seen the other's credentials. Recording only here meant a side
    // that had never answered had no baseline, so the first restart it
    // answered looked like a first description and was missed.
    var prev = state._lastRemoteIceUfrag;
    if (prev == null) return false;      // no baseline yet: not a restart
    return String(prev) !== String(ufrag);
  }

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

  /**
   * Mark transceivers whose mid appears in an applied description.
   *
   * Runs from setState on every parsed-SDP update — INCLUDING the update a
   * rollback performs to restore the previous description. That is what made
   * glare unfixable from the rollback side: the rollback released the
   * transceiver, setState restored the SDP, and this marker immediately
   * re-associated it from that SDP. Measured as two `markAssociated set
   * mid=0` for one implicit rollback.
   *
   * `_offerRolledBack` marks the window between a rollback releasing a
   * transceiver and the next description being applied. Inside it, a mid
   * appearing in the restored SDP is evidence of the description we just
   * discarded, not of one that stands.
   */
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
            if (tW._offerRolledBack) continue;   // released by a rollback
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
            // ONLY BIND AGAINST A LOCAL DESCRIPTION THAT IS STILL CURRENT.
            //
            // This step exists to give a transceiver the mid its own offer
            // assigned it. But parsedLocalSdp survives the retirement of the
            // section it describes, so after a stop/retire cycle it still
            // lists a slot that no longer exists — and this loop then bound
            // a fresh transceiver to that dead slot.
            //
            // The damage was downstream: the transceiver came out
            // _associated, so the adoption loop in processRemoteMedia passed
            // over it when the peer's offer arrived, and built a SECOND
            // transceiver for the recycled m-section. The application ended
            // up holding two where the spec has one, the extra one with no
            // track and no direction.
            //
            // A slot is only bindable if a live transceiver still owns it or
            // it is genuinely free — a slot whose owner has retired is
            // neither, so skip it and let the remote description's own
            // adoption path place this transceiver.
            if (bm.port === 0) continue;
            var _slotOwner = RtpManager.findByMid(state, bm.mid);
            if (_slotOwner && RtpManager.isFullyStopped(_slotOwner)) continue;
            // FULLY stopped only. A transceiver that is merely STOPPING still
            // has a live m-section in this very offer — stop() marks
            // [[Stopping]], and [[Stopped]] only arrives once a negotiation
            // retires the section (W3C 5.4). Skipping those here left them
            // permanently unassociated, so isLegitimateOwner stayed false and
            // every later step that gates on it silently passed them over:
            // the negotiated direction was never recorded and currentDirection
            // stayed null on a transceiver that was still carrying media.
            //
            // The window is real and ordinary — `stop()` called after
            // createOffer but before setLocalDescription lands exactly here.
            if (RtpManager.isFullyStopped(ut)) continue;
            // RE-KEY the send-side state (the mid-3 no-RTP bug): ssrc
            // allocation lives in state.localSsrcs keyed by the BIRTH
            // mid — rebinding the transceiver's mid without re-keying
            // left the send machinery looking up an empty slot, so no
            // a=ssrc in the offer and no RTP ever transmitted. (Same
            // re-key the adoption path already does at its own site.)
            // Do not re-associate a transceiver a rollback just released.
            if (ut._offerRolledBack) continue;
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
        // W3C 4.4.3: the transitions close() causes are SILENT — the same
        // rule signalingState, connectionState and dtlsState already follow
        // through the _closing flag. iceConnectionState was the one that did
        // not, so closing a connection fired one last
        // iceconnectionstatechange announcing 'closed' to a handler with
        // nothing left to act on.
        if (key === 'iceConnectionState' && !state._closing) {
          ev.emit('iceconnectionstatechange');
        }
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

    // MEDIA STOPPING RE-MUTES THE TRACK (W3C 5.3). Fix 23 gave the data plane
    // authority to report that media has STARTED; this is the other half —
    // reporting that it has STOPPED.
    //
    // The negotiated direction cannot cover it. A peer that calls
    // transceiver.stop() or pc.close() stops sending immediately and may never
    // renegotiate, so as far as our SDP is concerned nothing changed. Without
    // this the receiver's track reported muted === false forever on a
    // connection that had gone silent minutes earlier, and no 'mute' event
    // ever fired.
    //
    // Ordering is the same as fix 23: negotiation outranks observation, so a
    // transceiver negotiated NOT to receive is already muted by that path and
    // is left alone here.
    state._mediaStallTimer = setInterval(function () {
      if (state.closed) return;
      var now = Date.now();
      for (var i = 0; i < state.transceivers.length; i++) {
        var tc = state.transceivers[i];
        var tr = tc.receiver && tc.receiver.track;
        if (!tr || tr.muted === true) continue;
        var _dir = tc.currentDirection || tc.direction || '';
        if (_dir !== 'sendrecv' && _dir !== 'recvonly') continue;   // negotiation owns it
        // When did this transceiver last see a packet? Scan its remote SSRCs.
        var last = 0;
        for (var k in state.remoteSsrcMap) {
          if (!Object.prototype.hasOwnProperty.call(state.remoteSsrcMap, k)) continue;
          var mp = state.remoteSsrcMap[k];
          if (!mp || mp.isRtx || String(mp.mid) !== String(tc.mid)) continue;
          var st = state.rtpStats && state.rtpStats[k];
          if (st && st.lastPacketAt > last) last = st.lastPacketAt;
        }
        // Never received anything: the track is still in its born-muted state
        // or was unmuted by something else — either way there is no flow to
        // have stopped, so leave it.
        if (!last) continue;
        if (now - last < MEDIA_STALL_MUTE_MS) continue;
        tr.muted = true;
        try { tr.dispatchEvent && tr.dispatchEvent({ type: 'mute' }); } catch (eMs) {}
      }
    }, 1000);
    if (state._mediaStallTimer.unref) state._mediaStallTimer.unref();

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

  /**
   * Give a REMOTE track a `currentTime` (W3C mediacapture-main).
   *
   * It reports how much media has been received on the track, starting at 0
   * and advancing only while media actually arrives — a track that never
   * receives a packet stays at 0 no matter how long it lives, which is what
   * distinguishes it from wall-clock time.
   *
   * Defined here rather than in media-processing because the track object
   * knows nothing about reception: this layer is the one that sees packets
   * land. It is a getter over the receive clock, so nothing has to be updated
   * per packet.
   */
  function _attachCurrentTime(track) {
    if (!track || 'currentTime' in track) return;
    track._ctFirstPacketAt = 0;   // set on the first inbound packet
    track._ctAccumulated   = 0;   // frozen span across mute/unmute cycles
    Object.defineProperty(track, 'currentTime', {
      enumerable: true,
      get: function () {
        if (!track._ctFirstPacketAt) return track._ctAccumulated;
        return track._ctAccumulated +
               (Date.now() - track._ctFirstPacketAt) / 1000;
      },
    });
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

      // A REMOTE OFFER THAT REJECTS AN EXISTING SECTION STOPS IT NOW.
      //
      // W3C 5.4: a transceiver the peer has stopped goes DIRECTLY to
      // [[Stopped]] — there is no [[Stopping]] step on this side, because
      // nothing is left to negotiate; the peer has already decided. So its
      // direction and currentDirection must read 'stopped' as soon as the
      // offer is applied, before we answer:
      //
      //   await pc2.setRemoteDescription(offerWithRejectedSection);
      //   assert_equals(tc.direction, 'stopped');          // here already
      //   assert_equals(tc.currentDirection, 'stopped');
      //
      // We left it reporting its previous direction ('recvonly') until the
      // local answer was applied, so an application inspecting the
      // transceiver between the two steps saw a live one that was in fact
      // finished. The retirement sweep already removed it correctly at the
      // answer; only the state during negotiation was wrong.
      //
      // The track ends with it, on a task, for the same reason as fix 25.
      if (_rejectedSection && existing) {
        // TWO STEPS, NOT ONE. Applying the peer's rejecting OFFER is only
        // half the negotiation — our answer has yet to be created. W3C 5.4
        // splits what happens at each point:
        //
        //   after their offer is applied   currentDirection = 'inactive'
        //                                  direction        unchanged
        //   after our answer is applied    both become 'stopped'
        //
        // Between the two, the application can still inspect a transceiver
        // that is on its way out but not yet gone, and the spec says it
        // reports its own direction with an inactive current one — the
        // m-section carries no media, but the transceiver has not been
        // retired. Collapsing both steps into 'stopped' at offer time lost
        // that state, and the retirement sweep then ran a round early.
        //
        // 'have-remote-offer' is exactly the window: their offer applied,
        // our answer not yet.
        // WHO STOPPED IT DECIDES. Two cases reach this line and W3C 5.4
        // treats them differently:
        //
        //   THE PEER stopped it — we learn of it from their offer. There is
        //     nothing left for us to negotiate about, so the transceiver goes
        //     straight to [[Stopped]]: direction and currentDirection both
        //     read 'stopped' immediately, before we answer.
        //
        //   WE stopped it — our own stop() marked it [[Stopping]] and this
        //     offer is the round retiring it. It keeps its direction and only
        //     reaches currentDirection 'inactive' here; both become 'stopped'
        //     when the answer lands.
        //
        // `_stopped` is set by our own stop(); its absence means the
        // rejection is news from the peer.
        if (existing._stopped && state.signalingState === 'have-remote-offer') {
          existing.currentDirection = 'inactive';
          continue;
        }
        existing.direction        = 'stopped';
        existing.currentDirection = 'stopped';
        existing._stopped         = true;
        var _rjTrack = existing.receiver && existing.receiver.track;
        if (_rjTrack && _rjTrack.readyState !== 'ended') {
          setTimeout(function () {
            try {
              if (_rjTrack.readyState === 'ended') return;
              if (typeof _rjTrack.stop === 'function') _rjTrack.stop();
              else _rjTrack.readyState = 'ended';
            } catch (eRj) {}
          }, 0);
        }
        continue;
      }
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
          // Glare: a transceiver the implicit rollback just released must not
          // be re-adopted into the peer's colliding m-section — W3C 4.4.1.5
          // gives that section its own. Field reuse carries no flag.
          if (_jt._offerRolledBack) continue;
          if (_jt.sender && _jt.sender.track &&
              (m.direction === 'sendonly' || m.direction === 'inactive')) continue;
          // An application-created transceiver keeps its own identity: the
          // peer's section gets a new one rather than absorbing this. See the
          // note at the addTransceiver call site; internally created
          // transceivers carry no flag and still pair, which is the reuse the
          // engine depends on.
          if (_jt._appCreated) continue;
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
          // Do NOT unmute here. Announcing a track in SDP is not receiving
          // media on it — W3C 5.3 keeps a remote track muted until media
          // actually arrives. The unmute lives on the first-packet path
          // (see _unmuteReceiverForSsrc).
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

      // A transceiver that already has a receiver track needs no NEW track —
      // but it still needs to know whether the peer is still sending.
      //
      // This guard used to skip the whole remainder of the loop, so a
      // renegotiation that turned the section recvonly (the peer called
      // sender.removeTrack) was never processed on the receiving side at all.
      // W3C 5.1 requires the track to leave every stream it was announced in,
      // each firing 'removetrack', and to be muted, firing 'mute' — all while
      // the description is being applied, so the application observes them
      // BEFORE setRemoteDescription resolves.
      //
      // Handle that here, then skip as before.
      if (existing && existing.receiver.track) {
        var _stillSends = (m.direction === 'sendrecv' || m.direction === 'sendonly');
        if (!_stillSends && m.port !== 0) {
          var _rmTrack = existing.receiver.track;
          var _rms = state._remoteStreams || {};
          for (var _rmk in _rms) {
            if (!Object.prototype.hasOwnProperty.call(_rms, _rmk)) continue;
            var _rmStream = _rms[_rmk];
            if (!_rmStream || typeof _rmStream.removeTrack !== 'function') continue;
            var _rmHas = _rmStream.getTracks && _rmStream.getTracks().some(function (x) {
              return x === _rmTrack || (x && x.id === _rmTrack.id);
            });
            if (!_rmHas) continue;
            // removeTrack fires 'removetrack' itself — fix 23 on not
            // dispatching a second time.
            try { _rmStream.removeTrack(_rmTrack); } catch (eRm) {}
          }
          if (_rmTrack.muted !== true) {
            _rmTrack.muted = true;
            try { _rmTrack.dispatchEvent && _rmTrack.dispatchEvent({ type: 'mute' }); } catch (eMu) {}
          }
          existing._trackSurfaced = false;
        }
        continue;
      }

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
            // Same rule on the same-mid path — the exact shape glare takes.
            if (_rt._offerRolledBack) continue;
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
            _attachCurrentTime(_birthTrack);
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

          // ANNOUNCE THE TRACK. This branch handles m-sections with no
          // a=ssrc lines, and it built the receiver track without ever
          // emitting track:new — so ontrack never fired and an application
          // had no way to learn the track existed.
          //
          // a=ssrc is not required. Chrome omits it for simulcast (layer
          // SSRCs are learned from the rid header extension on the first
          // packet), and any offer that describes a receiving m-section
          // without naming SSRCs lands here. The track is real either way;
          // only the SSRC mapping has to wait for media.
          //
          // Streams come from the m-section's msid. 'a=msid:-' means "no
          // stream", which is why an absent or '-' id yields none.
          if (peerSends && _birthTrack) {
            try {
              var _nsTc = state.transceivers[state.transceivers.length - 1];
              var _nsStreams = [];
              // W3C 5.1 / JSEP resolve the stream ids in a fixed order:
              //
              //   1. media-level a=msid          — authoritative when present
              //   2. source-level a=ssrc:N msid  — the legacy form, used only
              //                                    when there is no media-level one
              //   3. neither                     — the track still belongs to a
              //                                    stream; the receiver invents one
              //
              // Only rule 1 was implemented. An offer carrying just
              // `a=ssrc:3 msid:1 2` produced no streams, and one with no msid
              // at all produced none either — in both cases ontrack fired with
              // an empty streams array where the spec requires exactly one.
              var _nsIds = (m.msids && m.msids.length)
                ? m.msids
                : (m.msid ? [m.msid] : []);
              if (!_nsIds.length && m.ssrcs && m.ssrcs.length) {
                for (var _nsS = 0; _nsS < m.ssrcs.length; _nsS++) {
                  var _nsMs = m.ssrcs[_nsS] && m.ssrcs[_nsS].msid;
                  if (_nsMs && _nsIds.indexOf(_nsMs) === -1) _nsIds.push(_nsMs);
                }
              }
              // No msid anywhere: the track is still in a stream. Synthesise a
              // stable id so repeated applies of the same description reuse
              // the same MediaStream object rather than making a new one.
              if (!_nsIds.length) {
                _nsIds = ['msid-less-' + m.mid + ' ' + m.type];
              }
              for (var _nsI = 0; _nsI < _nsIds.length; _nsI++) {
                var _nsSid = String(_nsIds[_nsI]).split(' ')[0];
                if (!_nsSid || _nsSid === '-') continue;
                // _remoteStreams is lazily created by the ssrc path; this
                // branch can run first, so make sure it exists.
                state._remoteStreams = state._remoteStreams || {};
                var _nsSt = state._remoteStreams[_nsSid];
                if (!_nsSt) {
                  _nsSt = new MediaStream();
                  try {
                    Object.defineProperty(_nsSt, 'id', { value: _nsSid, configurable: true });
                  } catch (eNs1) {}
                  state._remoteStreams[_nsSid] = _nsSt;
                }
                if (_nsSt.getTracks().indexOf(_birthTrack) === -1) _nsSt.addTrack(_birthTrack);
                if (_nsStreams.indexOf(_nsSt) === -1) _nsStreams.push(_nsSt);
              }
              // Through the SAME hold-aware queue the ssrc path uses. Track
              // events must follow signalingstatechange (W3C 4.4.1.6), so
              // while that event is held they buffer and flush right after
              // it. Emitting directly delivered this one BEFORE the state
              // event, and an application whose ontrack is installed during
              // setRemoteDescription never saw it.
              var _nsPayload = {
                mid: m.mid, kind: m.type,
                transceiver: _nsTc,
                track: _birthTrack,
                stream: _nsStreams[0] || null,
                streamsAnnounced: _nsStreams.length ? _nsStreams : null,
              };
              if (state._holdSignalingEvent) {
                (state._pendingTrackEvents = state._pendingTrackEvents || []).push(_nsPayload);
              } else {
                ev.emit('track:new', _nsPayload);
              }
            } catch (eNs) { /* announcing must never break the apply */ }
          }
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
      // Born muted; unmuted on the first arriving packet (see
      // _unmuteReceiverForSsrc). 'about to arrive' is not 'arrived'.
      try { track.muted = true; } catch (eUm) {}
      // currentTime reports received media and starts at 0 — see
      // _attachCurrentTime. Applied to whichever object surfaces, including
      // one reused from the transceiver's birth track.
      try { _attachCurrentTime(track); } catch (eCt) {}
      // WPT harvest: tracks sharing a remote msid must surface in the
      // SAME MediaStream object (ontrack ordering tests compare object
      // identity), and the stream's id must equal the remote msid token.
      // Resolve the stream id in the order W3C 5.1 / JSEP define: media-level
      // a=msid first, then source-level a=ssrc:N msid. Reading only the
      // media-level form meant an offer carrying just `a=ssrc:3 msid:1 2`
      // fell through to the synthesised-stream branch below and announced a
      // random id instead of the one the sender named.
      var _msidRaw = m.msid;
      if (!_msidRaw && m.ssrcs && m.ssrcs.length) {
        for (var _mrS = 0; _mrS < m.ssrcs.length; _mrS++) {
          if (m.ssrcs[_mrS] && m.ssrcs[_mrS].msid) { _msidRaw = m.ssrcs[_mrS].msid; break; }
        }
      }
      var msidSid = _msidRaw ? String(_msidRaw).split(' ')[0] : null;
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
      // Same resolution order as the ssrc-less path: media-level a=msid wins,
      // then source-level a=ssrc:N msid, then a synthesised id. See the note
      // there. This path only read the media-level form, so an offer carrying
      // just `a=ssrc:3 msid:1 2` announced no streams.
      var _msidList = (m.msids && m.msids.length) ? m.msids : (m.msid ? [m.msid] : []);
      if (!_msidList.length && m.ssrcs && m.ssrcs.length) {
        _msidList = [];
        for (var _msS = 0; _msS < m.ssrcs.length; _msS++) {
          var _msV = m.ssrcs[_msS] && m.ssrcs[_msS].msid;
          if (_msV && _msidList.indexOf(_msV) === -1) _msidList.push(_msV);
        }
      }
      if (!_msidList.length) _msidList = ['msid-less-' + m.mid + ' ' + m.type];
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
      // Follows the RESOLVED list: a source-level or synthesised id is a
      // stream just as much as a media-level one. Keyed off msidSid alone,
      // this reported "no msid" for both and suppressed the announcement.
      var _noMsid = (_allStreams.length === 0);
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

  // How long a negotiated-receiving track may go without a packet before it is
  // reported muted. Long enough not to trip on ordinary jitter or a brief
  // network stall; short enough that an application learns promptly. Override
  // for tests with WEBRTC_MEDIA_STALL_MS.




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

    // LET THE SCTP ABORT REACH THE WIRE.
    //
    // dcController.close() above sends an SCTP ABORT so the remote peer
    // learns its channels are gone (RFC 4960 3.3.7). That ABORT travels over
    // DTLS — closing the session in this same tick discarded it, and the peer
    // was left holding channels stuck at 'open' with no error and no close,
    // exactly as if we had never told it.
    //
    // One task of delay is enough for the datagram to be handed to the
    // socket. Everything observable locally has already happened: channels
    // are 'closed', signalingState is 'closed', and the connection is
    // unusable — this only defers the physical teardown.
    //
    // Guarded on state.closed so a second close() cannot double-free, and the
    // timer is unref'd so it never holds the process open.
    var _teardown = function () {
      if (iceAgent) { try { iceAgent.close(); } catch (e) {} }
      if (state.dtlsSession) { try { state.dtlsSession.close(); } catch (e) {} }
    };
    var _tdTimer = setTimeout(_teardown, 0);
    if (_tdTimer.unref) _tdTimer.unref();

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
    // ROLES SURVIVE AN ICE RESTART. RFC 8445 7.3.1.1: the controlling and
    // controlled roles are fixed when the session is established and persist
    // for its lifetime — a restart replaces credentials and candidates, not
    // who is in charge of nominating pairs.
    //
    // Re-deriving them from "who offered this time" swapped them whenever the
    // ANSWERER initiated the restart, and because both sides re-derived
    // independently they could land on the same value:
    //
    //   after answerer-initiated restart: pc1=controlled pc2=controlled
    //
    // With no controlling agent nobody nominates a pair, so the restart
    // completes on paper and the connection never selects a path.
    //
    // The role is set once, at agent birth, from the first negotiation. Role
    // CONFLICTS — both sides genuinely believing they are controlling, which
    // happens in glare — are resolved by the tie-breaker in the agent
    // (RFC 8445 7.3.1.1), which is the mechanism the spec provides for it.
    // This function no longer second-guesses that.
    if (!isRestart) return;
    return;
  }

  this.setLocalDescription = function (desc, cb) {
    trackNegotiationRole(desc, true);
    sdpOA.chainOperation(function (next) {
      sdpOA.setLocalDescription(desc, next);
    }, cb);
  };
  // Candidates that arrived before any remote description existed. W3C 4.4.2
  // says such a candidate is BUFFERED and applied once a description lands —
  // not rejected. Rejecting was a field-fatal bug: signalling races are the
  // norm, an application that forwards each candidate the moment it is
  // generated routinely delivers the first one ahead of the SDP, and the
  // rejection meant those candidates were simply lost. With no candidates the
  // connection never left 'new'.
  //
  // It also surfaced as an unhandled rejection, because the idiomatic
  // forwarding line has nothing to catch:
  //
  //   pc1.addEventListener('icecandidate', ({candidate}) =>
  //     pc2.addIceCandidate(candidate));
  //
  // which is exactly what WPT's own exchangeIceCandidates helper does.
  var _pendingRemoteCandidates = [];

  function _flushPendingCandidates() {
    if (!_pendingRemoteCandidates.length) return;
    var queued = _pendingRemoteCandidates;
    _pendingRemoteCandidates = [];
    for (var i = 0; i < queued.length; i++) {
      // Fire and forget: the original caller's promise already resolved when
      // the candidate was accepted into the queue. A candidate that turns out
      // to be malformed is dropped here rather than resurfacing as an
      // unhandled rejection long after the call site is gone.
      (function (entry) {
        try {
          sdpOA.addIceCandidate(entry, function (err) {
            if (err) _diag('[cm-diag] queued candidate rejected on flush: ' +
                           (err && err.message));
          });
        } catch (e) { /* never let a stale candidate break negotiation */ }
      })(queued[i]);
    }
  }

  this.setRemoteDescription = function (desc, cb) {
    trackNegotiationRole(desc, false);
    sdpOA.chainOperation(function (next) {
      sdpOA.setRemoteDescription(desc, function (err) {
        // Apply anything that was waiting on exactly this. Only on success —
        // a failed description leaves us with nothing to address them to.
        if (!err) _flushPendingCandidates();
        next(err);
      });
    }, cb);
  };
  this.addIceCandidate = function (candidate, cb) {
    sdpOA.chainOperation(function (next) {
      // W3C 4.4.2 step 3, evaluated WHEN THE OPERATION RUNS: a candidate
      // (including the bare end-of-candidates form) needs a remote
      // description to address. Run time is the only correct moment —
      // with an idle chain after a rollback there is none, while during
      // glare the candidate queues behind the in-flight
      // setRemoteDescription and finds one by the time it runs. Checking
      // at call time gives one answer where two are needed.
      //
      // With still no description at run time the spec splits two ways, and
      // WPT asserts BOTH:
      //
      //   a real candidate  → reject with InvalidStateError
      //       ('Add ICE candidate before setting remote description should
      //        reject with InvalidStateError')
      //   end-of-candidates → buffer and resolve
      //
      // The end-of-candidates form is the one that matters in practice. The
      // idiomatic forwarding line has nothing to catch:
      //
      //   pc1.addEventListener('icecandidate', ({candidate}) =>
      //     pc2.addIceCandidate(candidate));
      //
      // and it delivers null the moment gathering completes — routinely
      // before the answer has been applied. Rejecting there produced an
      // unhandled rejection that killed negotiation outright: the connection
      // stayed at 'new' forever and no data channel ever opened. WPT's own
      // exchangeIceCandidates helper is written exactly that way.
      if (!state.currentRemoteDescription && !state.pendingRemoteDescription) {
        // Two cases, and WPT asserts both:
        //
        //   No negotiation has started at all — a fresh RTCPeerConnection,
        //   addIceCandidate called out of the blue. There is no session for
        //   the candidate to belong to and never will be until the caller
        //   does something. Reject, per W3C 4.4.2.
        //     ('Add ICE candidate before setting remote description should
        //      reject with InvalidStateError')
        //
        //   Negotiation IS under way — we have a local description, so an
        //   answer is expected and this candidate belongs to that session.
        //   Buffer it and apply it when the description lands.
        //
        // The second case is the common one in real code and the reason this
        // matters. The idiomatic forwarding line has nothing to catch:
        //
        //   pc1.addEventListener('icecandidate', ({candidate}) =>
        //     pc2.addIceCandidate(candidate));
        //
        // and candidates are generated as soon as gathering starts, routinely
        // beating the answer. Rejecting there produced an unhandled rejection
        // that killed negotiation outright — the connection stayed at 'new'
        // forever and no data channel ever opened. WPT's own
        // exchangeIceCandidates helper is written exactly that way.
        var _negotiating = !!(state.currentLocalDescription ||
                              state.pendingLocalDescription);
        if (!_negotiating) {
          return next(new DOMException(
            'addIceCandidate: no remote description', 'InvalidStateError'));
        }
        _pendingRemoteCandidates.push(candidate);
        return next();
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
  // Forward the HINTS too. media_pipeline computes the RFC 6464 audio level
  // per frame and passes it here as the second argument; dropping it meant
  // the header stamper saw `hints === undefined`, its `hints.audioLevel !=
  // null` test never passed, and the extension was never written — on a
  // session that had negotiated it. Everything else in the chain was already
  // built and correct.
  this.sendRtp     = function (rtpPacket, hints) { mediaTransport.sendRtp(rtpPacket, hints); };
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
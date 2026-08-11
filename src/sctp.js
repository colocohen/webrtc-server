// src/sctp.js
// SCTP association — Stream Control Transmission Protocol (RFC 4960).
// Pure transport layer — no WebRTC/DCEP knowledge.
// Emits raw 'data' events: (streamId, ppid, payload).
// Consumers (connection_manager.js) interpret PPIDs and handle DCEP.

import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import flatRanges from 'flat-ranges';


/* ========================= Constants ========================= */

// Chunk types (RFC 4960 §3.2)
var CHUNK_DATA              = 0;
var CHUNK_INIT              = 1;
var CHUNK_INIT_ACK          = 2;
var CHUNK_SACK              = 3;
var CHUNK_HEARTBEAT         = 4;
var CHUNK_HEARTBEAT_ACK     = 5;
var CHUNK_ABORT             = 6;
var CHUNK_SHUTDOWN          = 7;
var CHUNK_SHUTDOWN_ACK      = 8;
var CHUNK_ERROR             = 9;
var CHUNK_COOKIE_ECHO       = 10;
var CHUNK_COOKIE_ACK        = 11;
var CHUNK_SHUTDOWN_COMPLETE = 14;     // RFC 4960 §3.3.13
var CHUNK_FORWARD_TSN       = 0xC0;
// RFC 8260 — user message interleaving. I-DATA carries MID + FSN instead of
// SSN, so fragments of one message no longer need a contiguous TSN range and
// a sender may interleave fragments from several streams.
var CHUNK_I_DATA            = 0x40;
var CHUNK_I_FORWARD_TSN     = 0xC2;
var CHUNK_RECONFIG          = 130;

// INIT parameter types
var PARAM_STATE_COOKIE        = 7;
var PARAM_SUPPORTED_EXTENSIONS = 0x8008;
var PARAM_FORWARD_TSN         = 0xC000;

// RECONFIG parameter types — RFC 6525 §3.1, §4.1
var PARAM_OUTGOING_SSN_RESET   = 0x000D;
var PARAM_INCOMING_SSN_RESET   = 0x000E;
var PARAM_RECONFIG_RESPONSE    = 0x0010;

// RECONFIG response result codes — RFC 6525 §4.4
var RECONFIG_RESULT_SUCCESS_NOTHING_TO_DO = 0;
var RECONFIG_RESULT_SUCCESS_PERFORMED     = 1;
var RECONFIG_RESULT_DENIED                = 2;
var RECONFIG_RESULT_ERROR_WRONG_SSN       = 3;
var RECONFIG_RESULT_ERROR_REQUEST_ALREADY = 4;
var RECONFIG_RESULT_ERROR_BAD_SEQ         = 5;
var RECONFIG_RESULT_IN_PROGRESS           = 6;

// DATA chunk flags
var DATA_FLAG_END       = 0x01;  // E bit — last fragment
var DATA_FLAG_BEGIN     = 0x02;  // B bit — first fragment
var DATA_FLAG_UNORDERED = 0x04;  // U bit

// Association states (RFC 4960 §4)
//
// Pre-Patch-3 there was only STATE_SHUTDOWN, which conflated all the
// post-ESTABLISHED transitional sub-states into one. RFC 4960 §9.2
// defines four distinct states for the shutdown handshake; collapsing
// them is fine for happy-path loopback but breaks under any of:
//   • A retransmitted SHUTDOWN_ACK (we'd have no way to tell that we
//     "already sent SHUTDOWN_ACK and are waiting for SHUTDOWN_COMPLETE"
//     vs "freshly received SHUTDOWN, still need to send SHUTDOWN_ACK").
//   • Simultaneous close (both sides issue SHUTDOWN at the same time).
//   • Application calling close() while peer's SHUTDOWN is in flight.
// SCTP-12 introduces the four sub-states so each transition's
// preconditions and exit conditions are checkable.
var STATE_CLOSED              = 0;
var STATE_COOKIE_WAIT         = 1;
var STATE_COOKIE_ECHOED       = 2;
var STATE_ESTABLISHED         = 3;
var STATE_SHUTDOWN_PENDING    = 4;   // close() called; drain queue (no-op
                                     // until SCTP-1's send queue exists)
var STATE_SHUTDOWN_SENT       = 5;   // SHUTDOWN sent; awaiting SHUTDOWN_ACK
var STATE_SHUTDOWN_RECEIVED   = 6;   // peer's SHUTDOWN received; drain queue
var STATE_SHUTDOWN_ACK_SENT   = 7;   // SHUTDOWN_ACK sent; awaiting
                                     // SHUTDOWN_COMPLETE

// State name table — exposed via the .state getter as user-facing strings.
// Internal code keeps using the numeric STATE_* constants for fast equality
// checks (and to match RFC 4960's machine-readable diagrams); the names are
// only formatted on read. Hyphenated lower-case to match RFC 4960's English
// conventions (e.g. "cookie-wait", "shutdown-ack-sent").
var STATE_NAMES = [
  'closed',              // 0
  'cookie-wait',         // 1
  'cookie-echoed',       // 2
  'established',         // 3
  'shutdown-pending',    // 4
  'shutdown-sent',       // 5
  'shutdown-received',   // 6
  'shutdown-ack-sent',   // 7
];

// Default values
var DEFAULT_A_RWND    = 65535;
var DEFAULT_NUM_STREAMS = 65535;

// SCTP-11: cookie lifetime per RFC 4960 §5.1.5 ("valid life of state cookie").
// Cookies older than this are rejected on COOKIE-ECHO, defending against
// replay attacks where a captured COOKIE-ECHO is replayed minutes later
// to instantiate a phantom association. 60s is the libwebrtc / Linux
// kernel default and matches sctp.h SCTP_DEFAULT_COOKIE_LIFE_SEC.
var DEFAULT_COOKIE_LIFETIME_S = 60;

// SCTP-2: delayed-ACK deadline per RFC 4960 §6.2. Receiver MAY defer
// SACK up to 200ms when the every-other-packet rule isn't yet met.
// Linux SCTP, libwebrtc, and FreeBSD all default to 200ms.
var DEFAULT_DELAYED_ACK_MS = 200;


/* ─── SCTP-1: Reliability constants ───
 *
 * Retransmission Timeout (RFC 4960 §6.3.1). Initial RTO and bounds match
 * libwebrtc rather than the RFC default (3s) — the WebRTC ecosystem
 * standardised on a 1s initial because DataChannel users expect quick
 * recovery on the first lost chunk.
 *
 * Association.Max.Retrans (RFC 4960 §15) — when a single chunk has been
 * retransmitted this many times without being acked, the peer is presumed
 * unreachable and the association is torn down.
 *
 * HB.Interval is 30s of idle time (RFC 4960 §8.3); Path.Max.Retrans is the
 * heartbeat-failure budget before declaring path-down.
 */
var RTO_INITIAL_MS      = 1000;
var RTO_MIN_MS          = 400;
var RTO_MAX_MS          = 60000;
var ASSOC_MAX_RETRANS   = 10;
var FAST_RETRANSMIT_THRESHOLD = 3;        // RFC 4960 §7.2.4
var HEARTBEAT_INTERVAL_MS = 30000;
var HEARTBEAT_MAX_RETRANS = 5;

/* ─── SCTP-3: PMTU fragmentation constants ───
 *
 * PMTU — Path Maximum Transmission Unit. We don't run path-MTU discovery
 * (RFC 4821) and there's no convenient probe in the SCTP-over-DTLS stack.
 * 1200 is libwebrtc's default for WebRTC and is safe over typical IPv6
 * paths (1280 minimum MTU - 40 IPv6 header - 8 UDP header - misc DTLS).
 *
 * One DATA chunk's frame: 12 (SCTP common header) + 4 (chunk header) +
 * 12 (DATA-specific: TSN+streamId+SSN+PPID) + payload. So usable payload
 * per chunk = PMTU - 28 = 1172 by default.
 *
 * Larger user messages are fragmented into N chunks sharing one SSN/PPID,
 * each carrying a distinct contiguous TSN, with BEGIN flag on the first,
 * END on the last, neither on the middles. (Receive side already handles
 * reassembly via fragStore + tryAssemble — see SCTP-5 in ROADMAP.)
 *
 * MAX_MESSAGE_SIZE — hard upper bound on user message size. RFC 8831 §6.6
 * says SCTP must enforce this; the W3C-default for WebRTC is 65536, but
 * libwebrtc and Chrome use 256KB. We default to 256KB and let the upper
 * layer override.
 */
var DEFAULT_PMTU             = 1200;
var SCTP_HEADER_OVERHEAD     = 12;   // common header
var DATA_CHUNK_OVERHEAD      = 16;   // chunk header (4) + DATA metadata (12)
// I-DATA carries four more bytes than DATA: SSN(2)+reserved(2) becomes
// MID(4) plus a PPID-or-FSN word (RFC 8260 2.1). Fragments are correspondingly
// smaller, so this feeds the same maxPerChunk arithmetic.
var I_DATA_CHUNK_OVERHEAD    = 20;   // chunk header (4) + I-DATA metadata (16)
var DEFAULT_MAX_MESSAGE_SIZE = 262144;

// SCTP-8: receive-window accounting. We advertise a dynamic a_rwnd equal
// to (maxReceiveBufferSize − bytes currently held in reassembly/reorder),
// matching pion's getMyReceiverWindowCredit() and usrsctp/Linux. 1 MB is
// pion's default and lifts the receive-direction throughput ceiling far
// above the old fixed 64 KB (which capped browser→server to ~64KB/RTT —
// crippling on high-RTT/TURN paths). Overridable via config.maxReceiveBufferSize.
var DEFAULT_MAX_RECEIVE_BUFFER = 1024 * 1024;


/* ========================= CRC32c ========================= */

var CRC32C_TABLE = null;

function initCrc32cTable() {
  CRC32C_TABLE = new Uint32Array(256);
  for (var i = 0; i < 256; i++) {
    var crc = i;
    for (var j = 0; j < 8; j++) {
      if (crc & 1) crc = (crc >>> 1) ^ 0x82F63B78;
      else crc = crc >>> 1;
    }
    CRC32C_TABLE[i] = crc;
  }
}

function crc32c(buf) {
  if (!CRC32C_TABLE) initCrc32cTable();
  var crc = 0xFFFFFFFF;
  for (var i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ CRC32C_TABLE[(crc ^ buf[i]) & 0xFF];
  }
  return (crc ^ 0xFFFFFFFF) >>> 0;
}


/* ========================= SctpAssociation ========================= */

function SctpAssociation(config) {
  config = config || {};

  var ev = new EventEmitter();
  var self = this;

  // Configuration
  var localPort  = config.port       || 5000;
  var remotePort = config.remotePort || 5000;

  // Role: informational only for association setup — per RFC 8841 BOTH
  // endpoints initiate the SCTP association (connect() sends INIT from
  // either role), so 'client'/'server' no longer gates the handshake.
  // The DataChannel layer still uses it for DCEP stream-id parity
  // (RFC 8832 §6: DTLS client = even ids, DTLS server = odd).
  var role = config.role || 'server';
  if (role !== 'client' && role !== 'server') {
    throw new TypeError("SctpAssociation: role must be 'client' or 'server' (got " + JSON.stringify(role) + ")");
  }
  var isServer = role === 'server';

  // SCTP-12: shutdown retransmit configuration. RFC 4960 §9.2 says
  // SHUTDOWN/SHUTDOWN_ACK use the T2-shutdown timer, bounded by the
  // RTO. Without SCTP-1's RTO state machine we use a fixed value here;
  // tests override to a small number for deterministic short runs.
  var shutdownRtoMs       = config.shutdownRtoMs       || 1000;
  var shutdownMaxRetries  = config.shutdownMaxRetries  || 5;

  // SCTP-1: per-instance overrides for the reliability constants. The
  // module-level RTO_INITIAL_MS / HEARTBEAT_INTERVAL_MS / etc. are sane
  // production defaults; tests need them measured in tens of ms, not
  // tens of seconds, so all of them accept a config override. Mirrors
  // the shutdownRtoMs pattern above.
  var rtoInitialMs            = config.rtoInitialMs            || RTO_INITIAL_MS;
  var rtoMinMs                = config.rtoMinMs                || RTO_MIN_MS;
  var rtoMaxMs                = config.rtoMaxMs                || RTO_MAX_MS;
  var assocMaxRetrans         = config.assocMaxRetrans         || ASSOC_MAX_RETRANS;
  var fastRetransmitThreshold = config.fastRetransmitThreshold || FAST_RETRANSMIT_THRESHOLD;
  var heartbeatIntervalMs     = config.heartbeatIntervalMs     || HEARTBEAT_INTERVAL_MS;
  var heartbeatMaxRetrans     = config.heartbeatMaxRetrans     || HEARTBEAT_MAX_RETRANS;

  // SCTP-3: per-instance PMTU + maxMessageSize. PMTU governs fragmentation
  // on send; maxMessageSize is the hard upper bound on user payload size.
  var pmtu                    = config.pmtu                    || DEFAULT_PMTU;
  var maxMessageSize          = config.maxMessageSize          || DEFAULT_MAX_MESSAGE_SIZE;

  // SCTP-8: receive buffer size that backs the advertised a_rwnd. See
  // myReceiverWindowCredit(). Matches pion's Config.MaxReceiveBufferSize.
  var maxReceiveBufferSize    = config.maxReceiveBufferSize    || DEFAULT_MAX_RECEIVE_BUFFER;

  // SCTP-11: cookie lifetime guards against COOKIE-ECHO replay attacks.
  // Default 60s matches libwebrtc and Linux kernel SCTP. Configure via
  // opts.cookieLifetimeS — set higher for laggy networks where the
  // INIT/COOKIE-ECHO round-trip can exceed the default; set lower for
  // tighter security. (`!= null` instead of `||` so cookieLifetimeS=0
  // is honoured for tests / aggressive deployments.)
  var cookieLifetimeS = (config.cookieLifetimeS != null) ? config.cookieLifetimeS
                                                          : DEFAULT_COOKIE_LIFETIME_S;
  // SCTP-2: delayed-ACK timer. Configure via opts.delayedAckMs. Set to 0
  // to disable delayed ACK (every packet gets SACKed immediately —
  // matches pre-SCTP-2 behaviour, useful for RTT-sensitive testing).
  var delayedAckMs    = (config.delayedAckMs != null)    ? config.delayedAckMs
                                                          : DEFAULT_DELAYED_ACK_MS;

  // Validate config sanity. Bad values here would otherwise produce
  // silent misbehaviour many seconds later (e.g. rto stuck at the floor
  // because rtoMinMs > rtoMaxMs). Catching at construction is cheap and
  // surfaces the typo where it happened.
  if (rtoMinMs > rtoMaxMs) {
    throw new RangeError('SctpAssociation: rtoMinMs (' + rtoMinMs +
                         ') > rtoMaxMs (' + rtoMaxMs + ')');
  }
  if (rtoInitialMs < rtoMinMs || rtoInitialMs > rtoMaxMs) {
    throw new RangeError('SctpAssociation: rtoInitialMs (' + rtoInitialMs +
                         ') outside [' + rtoMinMs + ', ' + rtoMaxMs + ']');
  }
  if (assocMaxRetrans < 1) {
    throw new RangeError('SctpAssociation: assocMaxRetrans must be >= 1');
  }
  if (fastRetransmitThreshold < 1) {
    throw new RangeError('SctpAssociation: fastRetransmitThreshold must be >= 1');
  }
  if (heartbeatMaxRetrans < 1) {
    throw new RangeError('SctpAssociation: heartbeatMaxRetrans must be >= 1');
  }
  if (heartbeatIntervalMs < 1) {
    throw new RangeError('SctpAssociation: heartbeatIntervalMs must be >= 1');
  }
  // SCTP-3: PMTU must leave room for SCTP common header + DATA chunk overhead.
  // pmtu < 29 means 0 bytes of payload would fit, which is useless.
  if (pmtu < SCTP_HEADER_OVERHEAD + DATA_CHUNK_OVERHEAD + 1) {
    throw new RangeError('SctpAssociation: pmtu must be >= ' +
                         (SCTP_HEADER_OVERHEAD + DATA_CHUNK_OVERHEAD + 1) +
                         ' (got ' + pmtu + ')');
  }
  if (maxMessageSize < 1) {
    throw new RangeError('SctpAssociation: maxMessageSize must be >= 1');
  }
  // pion + RFC 4960: the advertised receive window must be at least one
  // MTU (pion enforces a_rwnd >= 1500). A tiny buffer would stall the
  // receive direction, so we reject it at construction.
  if (maxReceiveBufferSize < 1500) {
    throw new RangeError('SctpAssociation: maxReceiveBufferSize must be >= 1500');
  }

  // Association state
  var state = STATE_CLOSED;
  var localVerificationTag = crypto.randomBytes(4).readUInt32BE(0);
  var remoteVerificationTag = 0;
  var localTsn = crypto.randomBytes(4).readUInt32BE(0);   // our next TSN to send
  var remoteTsn = 0;                                       // expected next TSN from peer
  var remoteRwnd = DEFAULT_A_RWND;
  var cookieSecret = crypto.randomBytes(16);

  // Stream state
  var sendSSN = {};      // streamId → next SSN (sequence number within stream)
  // streamId → next MID (RFC 8260 message identifier). Separate from SSN
  // because it must increment for EVERY message, ordered or not: the receiver
  // groups fragments by MID, so two concurrent messages sharing one are
  // indistinguishable. SSN is fixed at 0 for unordered messages, and data
  // channels are unordered.
  //
  // Per stream, not per association: RFC 8260 scopes MID to the stream, and
  // reassembly looks it up inside that stream's fragment store. An
  // association-wide counter also works numerically but wastes the space and
  // — measured — breaks tests that open many channels at once.
  //
  // SCTP-14: TWO counters, not one. RFC 8260 §2.2.1 gives each stream a
  // SEPARATE MID space for ordered and for unordered messages. A single
  // shared counter still yields unique MIDs, so reassembly works — but the
  // ORDERED space then has holes wherever an unordered message consumed a
  // value, and the receiver's in-order gate (deliverAssembled) waits forever
  // for a MID that was never sent. Symptom: mix ordered and unordered sends
  // on one stream and the ordered ones stop arriving entirely.
  var sendMIDOrdered   = {};
  var sendMIDUnordered = {};
  var recvSSN = {};      // streamId → expected next SSN (default 0). Pre-Patch-2
                         // this was declared but never read; Patch 2 makes it
                         // the source of truth for ordered delivery.

  // Per-stream fragment store. Maps streamId → Map<tsn, fragment>. Each entry:
  //   { tsn, ssn, ppid, isBegin, isEnd, isUnordered, payload }
  // Pre-Patch-2 we used `reassembly[streamId] = { ppid, parts: [...] }`,
  // appending in arrival order. That assumed fragments arrived in TSN order,
  // and silently produced corrupted bytes when they didn't. The fragment
  // store keeps every fragment by its TSN; tryAssemble walks it in
  // tsn-arithmetic order looking for a complete BEGIN→END chain whose
  // SSN, PPID, and U-bit all match (RFC 4960 §6.5/§6.6 require that).
  // Fragments are removed from the store once assembled.
  var fragStore = {};

  // Per-stream ordered-delivery hold buffer. Maps streamId → Map<ssn, msg>
  // where msg is { ppid, payload }. When a complete message assembles with
  // an SSN above what we're waiting for (recvSSN[streamId]), we hold it
  // here until the gap fills. Capped per stream to defend against held-
  // back-forever streams (peer-bug or attack).
  var pendingMsgs = {};
  var MAX_PENDING_MSGS_PER_STREAM = 1000;
  // SCTP-11 N4: max fragment-store entries per stream. Defends against
  // BEGIN-only floods that fill memory.
  //
  // SCTP-14: the old value (256) was sized for ONE max-size DataChannel
  // message in flight per stream — 262144B at ~1180B/fragment is ~222
  // fragments, "so this cap never affects legit flows". Interleaving breaks
  // that assumption: under RFC 8260 several messages on the same stream are
  // partially reassembled AT THE SAME TIME, and they all live in this one
  // store. Two 200KB messages interleaved on one stream overflow it, the
  // eviction drops the oldest fragment, and BOTH messages become
  // unassemblable — a silent stall that looks exactly like "nothing
  // arrives".
  //
  // The real bound on this buffer is byte-based and already enforced:
  // myReceiverWindowCredit() advertises (maxReceiveBufferSize − held), so
  // the peer's window closes before memory runs away. This count cap is a
  // secondary guard, so it is sized for the worst legitimate case —
  // maxReceiveBufferSize entirely full of minimum-size fragments — and
  // clamped to a sane range.
  // Sizing must admit BOTH legitimate worst cases at once:
  //   (a) buffer-bound: maxReceiveBufferSize of minimum-size fragments;
  //   (b) message-bound: ONE maxMessageSize message, whose fragment count is
  //       message bytes over the smallest real fragment payload. This can
  //       EXCEED (a): the peer's a_rwnd check admits a fragment while the
  //       buffer is merely not-yet-full, so a 1MB message against a 1MB
  //       buffer needs ~907 slots while (a) alone allows only ~889 — and the
  //       silent oldest-first eviction then discards fragments of a message
  //       that is still assembling. Audit finding: a single maxMessageSize
  //       transfer completed on the wire (fully SACKed) yet never delivered,
  //       with the receiver pinning the remainder in fragStore forever.
  // The true byte-bound remains the advertised-rwnd flow control; this count
  // cap is a secondary DoS guard and must never bind before flow control.
  var _minFragPayload = Math.max(1, pmtu - SCTP_HEADER_OVERHEAD - I_DATA_CHUNK_OVERHEAD);
  var MAX_FRAGS_PER_STREAM = (config.maxFragsPerStream != null)
    ? config.maxFragsPerStream
    : Math.max(256,
               Math.ceil(maxReceiveBufferSize / 1180),
               Math.ceil(maxMessageSize / _minFragPayload) + 8);

  // Receive tracking
  var lastCumulativeTsn = 0;  // highest contiguous TSN we've acked

  // SCTP-12: shutdown timer state. The retransmit timer is restarted
  // each time we send a SHUTDOWN or SHUTDOWN_ACK; cleared on receipt
  // of the corresponding ack chunk or on finalizeClose.
  var shutdownTimer    = null;
  var shutdownRetries  = 0;

  /* ─── SCTP-1: Send queue + RTO + heartbeat state ───
   *
   * Pre-SCTP-1 the sendQueue array was declared but never populated, the
   * RTO state didn't exist, and there was no T3-rtx timer — so DATA chunks
   * were sent fire-and-forget. Reliable mode "worked" only on a clean
   * loopback where loss is impossible. SCTP-1 wires the queue through
   * sendData / handleSack, drives a T3 timer per RFC 4960 §6.3.2, and
   * estimates SRTT/RTTVAR/RTO per §6.3.1.
   *
   * Each sendQueue entry:
   *   tsn             unsigned 32-bit TSN
   *   flags           chunk flags (BEGIN|END|UNORDERED) — preserved verbatim
   *                   for retransmit so we don't recompute fragmentation
   *                   metadata
   *   body            full DATA chunk body (TSN+streamId+SSN+PPID+payload).
   *                   Retransmit just calls sendChunk(CHUNK_DATA, flags, body).
   *   sentAt          ms timestamp of most recent (re)transmission. Updated
   *                   on retransmit so the next RTT sample (if Karn allows)
   *                   measures the latest send. (Karn's algorithm: only
   *                   measure RTT when retransmits === 0.)
   *   retransmits     count. Once > 0 the entry is excluded from RTT
   *                   estimation; once >= ASSOC_MAX_RETRANS the path is
   *                   declared dead and the association tears down.
   *   missingReports  count of SACKs that reported this TSN as missing
   *                   (i.e., a higher TSN was acked but this one wasn't).
   *                   At >= 3 we fast-retransmit per RFC 4960 §7.2.4.
   *
   * Queue invariants:
   *   - Strictly TSN-ordered: sendData appends with the next-monotonic TSN.
   *     Wraparound is fine because we use tsnLeq for comparisons.
   *   - Each entry is either inFlight=true (transmitted, awaiting SACK) or
   *     inFlight=false (rwnd/cwnd-deferred — see SCTP-8/9). Pendings always
   *     follow inFlights in queue order; transmitPending() never reorders.
   */
  var sendQueue = [];

  /* SCTP-8: rwnd enforcement state.
   *
   * outstandingBytes — running sum of payloadLen across sendQueue entries
   * with inFlight=true. Compared against remoteRwnd before transmitting
   * a new chunk. When SACK arrives and chunks drain, this drops; if
   * pending entries are sitting in sendQueue with inFlight=false, they
   * become eligible to transmit.
   *
   * inFlightCount — count of sendQueue entries with inFlight=true. Used
   * to drive T3 lifecycle (timer covers the oldest in-flight, not the
   * oldest queued). When inFlightCount → 0 we clear T3 even if pending
   * entries remain (no point timing-out a chunk we never sent).
   *
   * Queue layout invariant: sendQueue is FIFO. The prefix is in-flight
   * (inFlight=true) chunks; any pending (inFlight=false) suffix follows
   * in order. transmitPending() always promotes the front of the pending
   * suffix, never re-orders.
   */
  var outstandingBytes = 0;
  var inFlightCount    = 0;

  /* SCTP-9: congestion control state (RFC 4960 §7.2.1).
   *
   * The send rate is gated by min(cwnd, remoteRwnd) — SCTP-8 enforces
   * rwnd; SCTP-9 adds cwnd. Together they're the "effective window".
   *
   * cwnd — congestion window in bytes. Initialized to min(4*MTU, max(2*MTU,
   * 4380)) per RFC 4960 §7.2.1, capped at peer's rwnd. Grows as ACKs
   * arrive (slow start: exponential, congestion avoidance: linear) and
   * shrinks on detected loss.
   *
   * ssthresh — slow-start threshold. While cwnd < ssthresh we're in slow
   * start; otherwise congestion avoidance. Initialized to peer's a_rwnd.
   * Halved (with a 4*MTU floor) on loss.
   *
   * partialBytesAcked — accumulator for CA mode (RFC 4960 §7.2.2). In CA
   * we only grow cwnd by 1 MTU when pba reaches cwnd, then reset pba.
   * This gives the linear-growth shape; without it CA would stay flat.
   *
   * State machine triggers:
   *   T3 expiry      → cwnd = 1*MTU,           ssthresh = max(cwnd/2, 4*MTU)
   *                    (slow-start restart — most aggressive backoff)
   *   Fast retx      → cwnd = ssthresh = max(cwnd/2, 4*MTU)
   *                    (go directly to CA — gentler than T3)
   *   ACK in SS      → cwnd += min(bytesAcked, MTU)
   *   ACK in CA      → pba += bytesAcked; if pba >= cwnd: cwnd += MTU; pba -= cwnd
   */
  var cwnd              = Math.min(4 * (config.pmtu || DEFAULT_PMTU),
                                   Math.max(2 * (config.pmtu || DEFAULT_PMTU), 4380));
  var ssthresh          = DEFAULT_A_RWND;     // updated to peer's rwnd on handshake
  var partialBytesAcked = 0;
  // SCTP-9: gate to halve cwnd at most once per loss event. Gets cleared
  // when the cum-ack actually advances (peer caught up — loss recovered).
  var fastRetransmitCutThisRound = false;

  // RTO / RTT state (RFC 4960 §6.3.1).
  // SRTT/RTTVAR are null until the first RTT measurement; before that we
  // use RTO_INITIAL_MS verbatim. After the first sample they're seeded
  // (SRTT=R, RTTVAR=R/2) and updated exponentially (α=1/8, β=1/4).
  var srtt   = null;
  var rttvar = null;
  var rto    = rtoInitialMs;

  // T3-rtx timer — one per association. Started when sendQueue becomes
  // non-empty; cleared when it drains; restarted whenever the oldest chunk
  // changes (i.e., the chunk we're "waiting on" rotates).
  var t3Timer = null;

  // Heartbeat state. Idle paths get a periodic HEARTBEAT every
  // HEARTBEAT_INTERVAL_MS; on each unacked HB we increment hbRetries; at
  // HEARTBEAT_MAX_RETRANS consecutive failures the path is declared dead
  // and the association tears down. Any incoming chunk resets idle.
  var hbTimer            = null;
  var hbLastActivityAt   = 0;     // ms timestamp of last incoming chunk
  var hbRetries          = 0;
  var hbOutstandingNonce = null;  // 16-byte nonce of in-flight HB, or null

  // Stats — exposed via assoc.stats getter; api.js getStats() formats them
  // as RTCSctpTransportStats per W3C webrtc-stats spec.
  var sctpStats = {
    chunksSent:                 0,
    chunksRetransmitted:        0,
    fastRetransmits:            0,
    rtoExpiries:                0,
    pathFailures:               0,
    rttSamples:                 0,
    chunksAbandoned:            0,   // SCTP-6: chunks dropped due to PR-SCTP limits
    chunksBundled:              0,   // SCTP-13: DATA chunks packed into multi-chunk packets
    bundledPackets:             0,   // SCTP-13: packets that carried >1 chunk
  };

  // SCTP-13: set while a coalesced transmit pass is queued on the microtask
  // queue (see scheduleTransmit). Prevents scheduling more than one pass
  // per tick so a same-tick send() burst bundles into one transmit.
  var _transmitScheduled = false;

  // SCTP-14: highest TSN the peer has reported receiving, cumulative or via
  // a gap block. Drives forward-progress detection for the RTO backoff.
  var peerHighestSeen = null;

  /* SCTP-14: the peer's a_rwnd from INIT/INIT-ACK — i.e. its receive buffer
   * when empty. Used as the budget for how much may be left half-assembled
   * over there at once. Captured once, at handshake, because the live rwnd is
   * the very thing this budget is meant to protect. */
  var peerInitialRwnd = 0;

  /* ─── SCTP-14: bidirectional-load detection ───
   *
   * Slicing only shortens the time a message waits in OUR queue. When the
   * peer is also sending hard, the latency an application observes is
   * dominated by the PEER's scheduling of its own bulk traffic, which we
   * cannot touch — our contribution becomes a small term in a large sum, and
   * we are paying the full cost of interleaving for a fraction of the
   * benefit. Measured by the caller on a both-directions-loaded run: p95
   * improved only ~20% while throughput carried the whole overhead.
   *
   * Byte counters over a sliding window, sampled on a coarse clock; a rate
   * ratio is all the decision needs, so there is no need for anything finer.
   */
  var rateRxBytes = 0, rateTxBytes = 0;      // accumulate within the window
  var rateRxPerSec = 0, rateTxPerSec = 0;    // EWMA of the last windows
  var rateWindowStart = 0;
  var bidirectionalLoad = false;             // latched decision
  var bidiStreak = 0;                        // consecutive windows agreeing

  // SCTP-14: running sum of payloadLen over the PENDING region of sendQueue
  // (entries with inFlight === false). Counterpart to outstandingBytes, which
  // covers the in-flight prefix. Maintained incrementally because the pump
  // consults it on every transmit pass and an O(queue) scan there would be
  // quadratic on exactly the large transfers this code exists for.
  var pendingBytes = 0;

  /* ─── SCTP-14: user message interleaving (RFC 8260 §1, head-of-line) ───
   *
   * txJobs holds messages that are still being fed into sendQueue. A job is
   * { payload, cursor, ... }: everything sendData settled up front (TSN-
   * independent metadata — SID, MID, SSN, PPID, PR-SCTP limits) plus how far
   * through the payload the pump has got.
   *
   * Only LONG messages get a job. Short ones are enqueued whole inside
   * sendData exactly as before, so the common path — DCEP, control traffic,
   * ordinary small sends — is untouched, including the tick on which its
   * 'chunkSent' events fire.
   *
   * INTERLEAVE_SYNC_FRAGMENTS — at or below this many fragments a message is
   *   too short to block anything meaningfully, and paying a pump round for
   *   it would only add latency. At the default 1200-byte PMTU this is
   *   ~9.3KB, which covers essentially all control and signalling traffic.
   *
   * INTERLEAVE_QUANTUM — fragments enqueued per job per round. This is the
   *   latency/overhead dial: a small quantum interleaves more finely but
   *   spends more event-loop turns per message. 8 fragments is ~9.4KB per
   *   round, so a message never delays another by more than about that much
   *   plus one turn of the loop.
   */
  var txJobs = [];
  var _txPumpScheduled = false;
  var INTERLEAVE_SYNC_FRAGMENTS = (config.interleaveSyncFragments != null)
    ? config.interleaveSyncFragments : 8;
  var INTERLEAVE_QUANTUM = (config.interleaveQuantum != null)
    ? config.interleaveQuantum : 8;
  /* INTERLEAVE_MAX_ACTIVE — how many long messages may be in progress on the
   * wire at once. Interleaving has a cost that is easy to miss: the receiver
   * holds every partially-assembled message in its fragment store until the
   * message completes, so where the old serial behaviour held ONE message's
   * fragments, interleaving N holds N. Past maxReceiveBufferSize the peer's
   * advertised window collapses and the association degenerates into
   * one-chunk-per-RTT probing — measured here at 32 concurrent 64KB messages
   * against a 1MB buffer: correct, but ~20x slower than serial.
   *
   * Capping the ACTIVE set fixes it without giving up anything: messages past
   * the cap wait in FIFO order and start as earlier ones finish. Latency for
   * short messages is unaffected either way, since those never become jobs —
   * they are enqueued whole inside sendData and overtake the bulk regardless.
   * Interleaving among a handful of bulk transfers is all that head-of-line
   * blocking ever needed; a larger active set only buys buffer pressure. */
  /* Default 2, not 4. Measured on a saturating transfer, throughput falls as
   * this rises (5.31 / 4.75 / 4.19 Mbps at 1 / 2 / 4) because every extra
   * concurrent message is another one the receiver holds half-assembled,
   * spending the window we need. Latency does NOT pay for it: p95 is flat
   * across the whole range, because the win comes from the pump YIELDING so
   * short messages can take TSNs mid-transfer — not from interleaving bulk
   * messages against each other.
   *
   * 1 would be fastest but is a trap: selectActiveJobs always seats the
   * OLDEST job, so at 1 there is no second slot and shortest-remaining-first
   * is effectively off. A 40KB message behind a 256KB one then waits for it
   * — measured 3846ms at 1 versus 360ms at 2. Two is the smallest value that
   * keeps both properties. */
  var INTERLEAVE_MAX_ACTIVE = (config.interleaveMaxActive != null)
    ? config.interleaveMaxActive : 2;
  /* Ceiling on fragments built in one synchronous refill. Bounds the
   * event-loop stall from packet construction (alloc + CRC per fragment)
   * when cwnd is large; whatever is left is picked up by the next pass. */
  var TX_REFILL_BURST = (config.txRefillBurst != null) ? config.txRefillBurst : 64;

  /* interleaveMode:
   *   'always'   — slice every long message (default; the measured behaviour)
   *   'never'    — never slice, identical to the pre-SCTP-14 send path
   *   'adaptive' — slice only while the reverse direction is quiet
   *
   * 'adaptive' exists because interleaving is not free and is not always
   * worth its price. It is NOT the default: the benefit is workload-specific
   * and the switch itself can only ever be a guess about traffic that has not
   * arrived yet, so it should be chosen deliberately, after measuring.
   */
  var interleaveMode = config.interleaveMode || 'always';
  var INTERLEAVE_RATE_WINDOW_MS = (config.interleaveRateWindowMs != null)
    ? config.interleaveRateWindowMs : 500;
  /* Reverse traffic counts as "heavy" at this fraction of our own send rate.
   * 0.5 means the peer is sending at least half what we are — at that point
   * its queue is comparable to ours and its scheduling dominates what the
   * application sees. */
  var INTERLEAVE_BIDI_RATIO = (config.interleaveBidiRatio != null)
    ? config.interleaveBidiRatio : 0.5;
  /* Windows of agreement before flipping, in each direction. Hysteresis: a
   * policy that toggles per burst would slice half a message and enqueue the
   * rest whole, which is the worst of both. */
  var INTERLEAVE_BIDI_STREAK = (config.interleaveBidiStreak != null)
    ? config.interleaveBidiStreak : 3;

  /* ─── SCTP-6: PR-SCTP state ───
   *
   * peerSupportsForwardTsn — set during INIT/INIT-ACK exchange when peer
   * advertises FORWARD-TSN (chunk type 0xC0) in their PARAM_SUPPORTED_
   * EXTENSIONS list. RFC 8831 says we MUST silently degrade to reliable
   * if peer doesn't support PR-SCTP.
   *
   * nextMessageSeq — incrementing tag attached to every fragment of one
   * sendData() call. We use it to identify "all fragments of THIS user
   * message" when abandoning, since PR-SCTP abandonment is per-MESSAGE
   * (abandoning a single fragment leaves an unreassemblable orphan at
   * the peer). Wraps freely; comparison is equality-only, never ordered.
   *
   * lastForwardTsnSent — caches the newCumTsn we put in our most recent
   * FORWARD-TSN. We re-send only when an abandonment would advance it
   * further; otherwise the chunk is identical to the last and would just
   * spam the peer.
   */
  var peerSupportsForwardTsn = false;
  // Set when the peer advertises I-DATA (RFC 8260). Read by stage 2b before
  // any I-DATA is sent; exposed on the public surface so the application can
  // report whether interleaving was negotiated, as Pion does through
  // getStats().
  var peerSupportsIData = false;
  var nextMessageSeq         = 0;
  var lastForwardTsnSent;     // undefined until first FORWARD-TSN sent
  // SCTP-6: highest abandoned SSN per ordered stream since last FORWARD-TSN.
  // Cleared after each emit. Pairs added to FORWARD-TSN body so peer can
  // advance recvSSN past abandoned ordered messages without waiting.
  var abandonedSSNPerStream  = {};
  // SCTP-14: I-FORWARD-TSN skip tracker — streamId+('o'|'u') → highest
  // abandoned 32-bit MID in that stream's ordered/unordered space.
  var abandonedMidPerStream  = {};

  /* ─── SCTP-7: Stream Reset state (RFC 6525) ───
   *
   * peerSupportsReconfig — set during INIT/INIT-ACK when peer advertises
   * RECONFIG (chunk type 130) in PARAM_SUPPORTED_EXTENSIONS. Without it,
   * resetStreams() is a no-op (we mark our local state but the peer keeps
   * the streams open from its side).
   *
   * reconfigReqSeq — 32-bit monotonic counter for OUR outgoing requests.
   * Each RECONFIG we send carries this in the param's "Reconfig Request
   * Sequence Number"; peer echoes it back in the response.
   *
   * lastReconfigPeerReqSeen — peer's request seq from the last incoming
   * RECONFIG we accepted. Used for dup detection (RFC 6525 §5.2.1: if we
   * receive a duplicate request, repeat the previous response).
   *
   * lastReconfigResponseResult — cache of our
   * most recent response so we can replay it on dup.
   *
   * pendingResetRequests — Map<reqSeq, { streamIds, callback, attempts }>
   * tracks outgoing requests awaiting a response from peer. We don't
   * actively retransmit reset requests — they ride on top of SCTP's
   * reliable channel (RECONFIG is sent in DATA chunks? no, control chunks
   * — but they go through sendChunk which doesn't retransmit). For now
   * the upper layer can re-call resetStreams if no response arrives in
   * a reasonable timeout. SCTP-9 / SCTP-13 may revisit.
   */
  var peerSupportsReconfig         = false;
  var reconfigReqSeq               = 0;
  var lastReconfigPeerReqSeen;     // undefined until first peer request seen — both as dup-key and replay trigger
  var lastReconfigResponseResult;  // cached result code for dup replay
  var pendingResetRequests         = new Map();

  // Receive-side TSN tracking — RFC 4960 §6.7.
  //
  // We track which TSNs above lastCumulativeTsn have arrived. Pre-flat-ranges
  // this was a sorted array of individual TSNs (raw 32-bit values), with
  // splice-insert in O(n) and a per-arrival prefix-drain. The two issues
  // that switching to flat-ranges solves:
  //
  //   1. Memory: a clean burst of 2000 contiguous TSNs cost 2000 numbers.
  //      With ranges, the same burst is 2 numbers ([start, end) pair).
  //      Memory drops by ~1000x in the typical no-loss case.
  //
  //   2. Operations are native: gap-block computation IS the range list
  //      (just a format conversion); no separate scan needed. Insert is
  //      a binary search + maybe-merge inside flat-ranges.
  //
  // Wraparound — the trap. flat-ranges compares numerically (a < b in the
  // usual sense), but TSN is modular 32-bit. To avoid wraparound bugs at
  // the 2^32 boundary, we store OFFSETS from lastCumulativeTsn rather than
  // raw TSNs. Offsets are always small positives (typically 1..few thousand).
  // Whenever lastCumulativeTsn advances by Δ, we rebase all offsets by -Δ
  // (rebaseBy below). This keeps flat-ranges in numerically-comparable
  // territory forever.
  //
  // Offset semantics:
  //   offset = (tsn - lastCumulativeTsn) >>> 0
  //   So offset 0 means lastCumulativeTsn itself (already acked, never stored).
  //   Offset 1 is the next-expected TSN — when it arrives the prefix-drain
  //   triggers. Stored ranges are half-open [from, to) per flat-ranges
  //   convention.
  //
  // Capacity cap defends against a misbehaving peer flooding fragmented
  // garbage — typical workload has 1-5 ranges, so 2048 is a generous bound.
  var MAX_RECEIVED_RANGES = 2048;
  var receivedRanges = [];         // flat-ranges of OFFSETS from lastCumulativeTsn
  var dupTsns = [];                // raw TSNs we've seen more than once since last SACK
  var MAX_DUP_TSNS = 32;           // bound the SACK chunk size

  // Flags
  var closed = false;


  /* ========================= Packet parsing ========================= */

  function handlePacket(buf) {
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('SctpAssociation.handlePacket: buf must be a Buffer');
    }
    if (closed) return;
    if (buf.length < 12) {
      try { ev.emit('protocolViolation', { code: 'short-packet', length: buf.length }); } catch (e) {}
      return;
    }

    // Parse SCTP common header
    var srcPort  = buf[0] << 8 | buf[1];
    var dstPort  = buf[2] << 8 | buf[3];
    var vtag     = (buf[4] << 24 | buf[5] << 16 | buf[6] << 8 | buf[7]) >>> 0;
    var checksum = (buf[11] << 24 | buf[10] << 16 | buf[9] << 8 | buf[8]) >>> 0;

    // Verify checksum (CRC32c)
    var copy = Buffer.from(buf);
    copy[8] = copy[9] = copy[10] = copy[11] = 0;
    var computed = crc32c(copy);
    if (computed !== checksum) {
      try { ev.emit('protocolViolation', { code: 'crc-mismatch', expected: checksum, computed: computed }); } catch (e) {}
      return;
    }

    // Verify tag (INIT has tag=0)
    if (vtag !== 0 && vtag !== localVerificationTag) {
      if (state !== STATE_CLOSED && state !== STATE_COOKIE_WAIT) {
        try { ev.emit('protocolViolation', { code: 'vtag-mismatch', expected: localVerificationTag, received: vtag }); } catch (e) {}
        return;
      }
    }

    remotePort = srcPort;

    // SCTP-13: enter "bundling depth" — sendChunk calls during chunk
    // dispatch will accumulate into pendingOutChunks instead of emitting
    // immediately. Flushed at end so all reactive replies (SACK, HB-ACK,
    // FORWARD-TSN, etc.) ride on a single outgoing UDP datagram.
    packetDepth++;
    try {
      var offset = 12;
      while (offset + 4 <= buf.length) {
        var chunkType  = buf[offset];
        var chunkFlags = buf[offset + 1];
        var chunkLen   = buf[offset + 2] << 8 | buf[offset + 3];

        if (chunkLen < 4) break;
        if (offset + chunkLen > buf.length) break;

        var chunkData = buf.subarray(offset + 4, offset + chunkLen);

        handleChunk(chunkType, chunkFlags, chunkData);

        // Pad to 4-byte boundary
        offset += chunkLen;
        if (offset % 4 !== 0) offset += 4 - (offset % 4);
      }
    } finally {
      packetDepth--;
      if (packetDepth === 0) {
        // SCTP-2: decide whether to SACK now or defer per RFC 4960 §6.2.
        //   - SACK every-other packet (sackUnackedPackets >= 1 means this
        //     is the second one — emit).
        //   - SACK immediately on dup or gap.
        //   - delayedAckMs <= 0 disables deferral (every packet SACKs).
        //   - Otherwise defer with a 200ms timer.
        if (sackPendingThisPacket) {
          sackPendingThisPacket = false;
          sackUnackedPackets++;
          if (sackImmediateRequired ||
              sackUnackedPackets >= 2 ||
              delayedAckMs <= 0) {
            sackImmediateRequired = false;
            sendSackAndReset();
          } else {
            scheduleDelayedSack();
          }
        }
        flushOutChunks();
      }
    }
  }

  /* SCTP-2 helpers. sendSackAndReset clears the deferred-SACK state and
   * emits one SACK; called from the every-other-packet rule, from the
   * dup/gap fast path, and from the delayedSackTimer expiry.
   */
  function sendSackAndReset() {
    sackUnackedPackets    = 0;
    sackImmediateRequired = false;
    if (delayedSackTimer) {
      clearTimeout(delayedSackTimer);
      delayedSackTimer = null;
    }
    sendSack();
  }

  function scheduleDelayedSack() {
    if (delayedSackTimer) return;   // already counting down
    delayedSackTimer = setTimeout(function() {
      delayedSackTimer = null;
      // Race guard: state may have changed between schedule and fire.
      if (state !== STATE_ESTABLISHED && state !== STATE_SHUTDOWN_RECEIVED) return;
      sendSackAndReset();
      // sendSack went via direct path (packetDepth=0 here), but it may
      // have queued chunks if we were inside another handlePacket — flush
      // for safety.
      if (packetDepth === 0) flushOutChunks();
    }, delayedAckMs);
    if (delayedSackTimer && typeof delayedSackTimer.unref === 'function') {
      delayedSackTimer.unref();
    }
  }


  /* ========================= Chunk handlers ========================= */

  function handleChunk(type, flags, data) {
    // SCTP-1 heartbeat: any incoming chunk counts as path-active. Reset
    // the idle counter so the heartbeat timer doesn't fire on a busy
    // connection. (Also covers the case where peer initiates HBs and
    // we're the responder — their HEARTBEAT chunk itself proves the path
    // is up, no need for us to also probe.)
    hbLastActivityAt = Date.now();

    if (type === CHUNK_INIT) {
      handleInit(data);
    } else if (type === CHUNK_INIT_ACK) {
      handleInitAck(data);
    } else if (type === CHUNK_COOKIE_ECHO) {
      handleCookieEcho(data);
    } else if (type === CHUNK_COOKIE_ACK) {
      handleCookieAck();
    } else if (type === CHUNK_I_DATA) {
      // RECEIVE-ONLY for now: we parse and reassemble interleaved messages a
      // peer sends us, but do not advertise the extension and never send
      // I-DATA ourselves. A peer only uses I-DATA when BOTH sides negotiated
      // it (RFC 8260 3.1), so nothing reaches this path unless a future
      // change starts advertising — at which point receive is already proven.
      handleIData(flags, data);
    } else if (type === CHUNK_DATA) {
      handleData(flags, data);
    } else if (type === CHUNK_SACK) {
      handleSack(data);
    } else if (type === CHUNK_HEARTBEAT) {
      handleHeartbeat(data);
    } else if (type === CHUNK_HEARTBEAT_ACK) {
      handleHeartbeatAck(data);
    } else if (type === CHUNK_SHUTDOWN) {
      handleShutdown(data);
    } else if (type === CHUNK_SHUTDOWN_ACK) {
      handleShutdownAck();
    } else if (type === CHUNK_SHUTDOWN_COMPLETE) {
      handleShutdownComplete();
    } else if (type === CHUNK_FORWARD_TSN) {
      handleForwardTsn(data);
    } else if (type === CHUNK_I_FORWARD_TSN) {
      handleIForwardTsn(data);              // SCTP-14 / RFC 8260 §2.3.1
    } else if (type === CHUNK_RECONFIG) {
      handleReconfig(data);                 // SCTP-7
    } else if (type === CHUNK_ABORT) {
      handleAbort(data);                    // SCTP-10
    } else if (type === CHUNK_ERROR) {
      handleError(data);                    // SCTP-10
    }
    // Unknown chunk types are silently ignored. RFC 4960 §3.2 actually
    // says we should respond per the chunk's "Action if Unrecognized"
    // bits encoded in its high two bits (silent drop / drop+report /
    // skip / skip+report). For now we treat all as silent drop.
  }


  /* ── INIT (incoming) ── */

  function handleInit(data) {
    if (data.length < 16) {
      try { ev.emit('protocolViolation', { code: 'init-too-short', length: data.length }); } catch (e) {}
      return;
    }

    var initiateTag = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    var aRwnd       = (data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]) >>> 0;
    var numOutbound = data[8] << 8 | data[9];
    var numInbound  = data[10] << 8 | data[11];
    var initialTsn  = (data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15]) >>> 0;

    // RFC 4960 §3.3.2: Initiate Tag MUST NOT be zero.
    if (initiateTag === 0) {
      try { ev.emit('protocolViolation', { code: 'init-zero-tag' }); } catch (e) {}
      return;
    }

    // SCTP-11 N10: INIT collision handling per RFC 4960 §5.2.1 / 5.2.2.
    //
    // If we receive INIT in a state other than CLOSED, several things
    // could be happening:
    //
    //   • Peer crashed and restarted, didn't see our existing association
    //     and is trying to re-establish (RFC 4960 §5.2.4 case).
    //   • Both sides simultaneously sent INIT (rare but valid).
    //   • Replay attack — captured INIT replayed.
    //   • Bug in peer.
    //
    // The full RFC procedure includes "Tie-breaker per Tag" comparison
    // logic (§5.2.4) which is intricate. The pragmatic action that
    // matches libwebrtc: treat ANY INIT as a re-establishment request
    // when we're in COOKIE_WAIT/COOKIE_ECHOED (handshake hasn't
    // completed; peer can legitimately retry). If we're already
    // ESTABLISHED, keep the existing association — the new INIT is
    // either a stale dup (ignore) or peer restarted (we'd see it via
    // path failure / heartbeat anyway).
    if (state === STATE_ESTABLISHED ||
        state === STATE_SHUTDOWN_PENDING ||
        state === STATE_SHUTDOWN_SENT ||
        state === STATE_SHUTDOWN_RECEIVED ||
        state === STATE_SHUTDOWN_ACK_SENT) {
      try { ev.emit('protocolViolation', { code: 'init-in-established', state: state }); } catch (e) {}
      // Per §5.2.2 we should reply with INIT-ACK reflecting our existing
      // verification tags. For now we drop — peer's likely confused or
      // malicious; let our heartbeat / RTO machinery surface a real
      // path failure if peer actually restarted.
      return;
    }

    remoteVerificationTag = initiateTag;
    remoteTsn = initialTsn;
    lastCumulativeTsn = (initialTsn - 1) >>> 0;
    remoteRwnd = aRwnd; ssthresh = aRwnd; if (!peerInitialRwnd) peerInitialRwnd = remoteRwnd;

    // SCTP-6: detect PR-SCTP support. Params start after the fixed 16-byte
    // INIT prefix.
    detectSupportedExtensions(data.subarray(16));

    // Build cookie — contains association state, signed.
    //
    // SCTP-11: layout includes an embedded timestamp (epoch seconds) at
    // bytes 28-31, used by handleCookieEcho to enforce cookie lifetime
    // per RFC 4960 §5.1.5. Without this, a captured COOKIE-ECHO can be
    // replayed indefinitely. The timestamp is inside the HMAC, so an
    // attacker can't forward-date a captured cookie.
    var cookieData = Buffer.alloc(32);
    cookieData.writeUInt32BE(initiateTag, 0);
    cookieData.writeUInt32BE(localVerificationTag, 4);
    cookieData.writeUInt32BE(localTsn, 8);
    cookieData.writeUInt32BE(initialTsn, 12);
    cookieData.writeUInt32BE(aRwnd, 16);
    cookieData.writeUInt16BE(numOutbound, 20);
    cookieData.writeUInt16BE(numInbound, 22);
    cookieData.writeUInt32BE(localPort, 24);
    cookieData.writeUInt32BE(Math.floor(Date.now() / 1000), 28);

    var mac = crypto.createHmac('sha256', cookieSecret).update(cookieData).digest();
    var cookie = Buffer.concat([cookieData, mac]);

    // Send INIT-ACK
    var initAckBody = Buffer.alloc(20 + 4 + cookie.length);
    initAckBody.writeUInt32BE(localVerificationTag, 0);
    initAckBody.writeUInt32BE(maxReceiveBufferSize, 4);
    initAckBody.writeUInt16BE(DEFAULT_NUM_STREAMS, 8);
    initAckBody.writeUInt16BE(DEFAULT_NUM_STREAMS, 10);
    initAckBody.writeUInt32BE(localTsn, 12);

    // Supported Extensions parameter (RFC 5061 §4.2.7).
    // Format: type(2) + length(2) + chunk-type-bytes(N).
    // We list two: FORWARD-TSN (PR-SCTP, RFC 3758) and RECONFIG (stream
    // reset, RFC 6525). length = 4 (header) + 2 (bytes) = 6; padded to
    // 4-byte boundary so the next param starts aligned.
    initAckBody.writeUInt16BE(PARAM_SUPPORTED_EXTENSIONS, 16);
    initAckBody.writeUInt16BE(7, 18);
    initAckBody[20] = CHUNK_FORWARD_TSN;
    initAckBody[21] = CHUNK_RECONFIG;
    initAckBody[22] = CHUNK_I_DATA;   // RFC 8260 — see the note on INIT
    // bytes 22-23: padding (Buffer.alloc gives zeros)

    // Pad supported extensions to 4 bytes
    var padded = Buffer.alloc(24 + 4 + cookie.length);
    initAckBody.copy(padded, 0, 0, 22);

    // State Cookie parameter
    var cookieParamOff = 24;
    padded.writeUInt16BE(PARAM_STATE_COOKIE, cookieParamOff);
    padded.writeUInt16BE(4 + cookie.length, cookieParamOff + 2);
    cookie.copy(padded, cookieParamOff + 4);

    sendChunk(CHUNK_INIT_ACK, 0, padded, initiateTag);
  }


  /* ── INIT-ACK (we initiated, they respond) ── */

  function handleInitAck(data) {
    if (state !== STATE_COOKIE_WAIT) return;
    if (data.length < 16) return;

    remoteVerificationTag = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    var aRwnd      = (data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]) >>> 0;
    var initialTsn = (data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15]) >>> 0;

    remoteTsn = initialTsn;
    lastCumulativeTsn = (initialTsn - 1) >>> 0;
    remoteRwnd = aRwnd; ssthresh = aRwnd; if (!peerInitialRwnd) peerInitialRwnd = remoteRwnd;

    // SCTP-6: detect PR-SCTP support.
    detectSupportedExtensions(data.subarray(16));

    // Extract State Cookie
    var cookie = extractParam(data.subarray(16), PARAM_STATE_COOKIE);
    if (cookie) {
      state = STATE_COOKIE_ECHOED;
      sendChunk(CHUNK_COOKIE_ECHO, 0, Buffer.from(cookie), remoteVerificationTag);
    }
  }


  /* ── COOKIE-ECHO ── */

  function handleCookieEcho(data) {
    if (data.length < 64) {                                  // 32 cookie + 32 mac
      try { ev.emit('protocolViolation', { code: 'cookie-too-short', length: data.length }); } catch (e) {}
      return;
    }

    var cookieData = data.subarray(0, 32);
    var cookieMac  = data.subarray(32, 64);

    // Verify MAC. timingSafeEqual prevents timing-based key recovery.
    var expectedMac = crypto.createHmac('sha256', cookieSecret).update(cookieData).digest();
    if (!crypto.timingSafeEqual(Buffer.from(cookieMac), expectedMac)) {
      try { ev.emit('protocolViolation', { code: 'cookie-mac-invalid' }); } catch (e) {}
      return;
    }

    // SCTP-11: cookie lifetime check. RFC 4960 §5.1.5 — reject cookies
    // older than the configured lifetime to defend against replay. The
    // timestamp is inside the MAC so it can't have been altered.
    var cookieAgeS = Math.floor(Date.now() / 1000) - cookieData.readUInt32BE(28);
    if (cookieAgeS < 0 || cookieAgeS > cookieLifetimeS) {
      try { ev.emit('protocolViolation', { code: 'cookie-expired', ageSeconds: cookieAgeS }); } catch (e) {}
      // RFC 4960 §5.1.5 says to send ERROR(Stale Cookie) with the
      // measured staleness. We just drop — peer's INIT will retry.
      return;
    }

    // Restore state from cookie
    remoteVerificationTag = cookieData.readUInt32BE(0);
    localVerificationTag  = cookieData.readUInt32BE(4);
    localTsn              = cookieData.readUInt32BE(8);
    remoteTsn             = cookieData.readUInt32BE(12);
    lastCumulativeTsn     = (remoteTsn - 1) >>> 0;
    remoteRwnd = cookieData.readUInt32BE(16); ssthresh = remoteRwnd; if (!peerInitialRwnd) peerInitialRwnd = remoteRwnd;

    // Send COOKIE-ACK
    sendChunk(CHUNK_COOKIE_ACK, 0, Buffer.alloc(0), remoteVerificationTag);

    // Association established
    state = STATE_ESTABLISHED;
    onEstablished();
    ev.emit('open');
  }


  /* ── COOKIE-ACK ── */

  function handleCookieAck() {
    if (state !== STATE_COOKIE_ECHOED) return;
    state = STATE_ESTABLISHED;
    onEstablished();
    ev.emit('open');
  }


  /* ── DATA ── */

  /**
   * I-DATA (RFC 8260 2.1). Same job as handleData, different header:
   *
   *     DATA    TSN(4) SID(2) SSN(2)      PPID(4)          payload
   *     I-DATA  TSN(4) SID(2) reserved(2) MID(4) PPID/FSN(4) payload
   *
   * The fourth word is PPID on a first fragment (B flag set) and FSN on any
   * other — the two never coexist, because a continuation inherits the PPID
   * of the message it belongs to.
   *
   * Reassembly keys on SID+MID rather than a contiguous TSN run, which is the
   * whole point of the extension: fragments of different messages may be
   * interleaved on the wire.
   */
  function handleIData(flags, data) {
    if (state !== STATE_ESTABLISHED && state !== STATE_SHUTDOWN_RECEIVED) return;
    if (data.length < 16) return;

    var tsn      = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    var streamId = data[4] << 8 | data[5];
    // data[6..7] reserved
    var mid      = (data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11]) >>> 0;
    var fourth   = (data[12] << 24 | data[13] << 16 | data[14] << 8 | data[15]) >>> 0;
    var payload  = data.subarray(16);

    var isBegin = !!(flags & DATA_FLAG_BEGIN);
    var ppid    = isBegin ? fourth : 0;
    var fsn     = isBegin ? 0 : fourth;

    // Hand the PARSED fields to the shared path. Everything after the header
    // — TSN bookkeeping, SACK policy, the fragment store, delivery — is
    // identical for both chunk types, and duplicating it would leave two
    // copies of the most heavily-fixed code in this file.
    //
    // Passing fields rather than re-encoding a DATA-shaped buffer avoids
    // copying the payload a second time, which on the large messages this
    // extension exists for is the whole cost of the feature. It also keeps
    // the 32-bit MID intact; squeezing it into DATA's 16-bit SSN field would
    // alias two messages onto one identifier every 65536 messages.
    _acceptDataFields(flags, tsn, streamId, mid, ppid, payload, mid, fsn);
  }

  /**
   * @param iMid  RFC 8260 message identifier, when this arrived as I-DATA.
   *              Null for classic DATA, where the TSN run carries the
   *              ordering and there is no message id.
   * @param iFsn  fragment number within that message; null likewise.
   */
  function handleData(flags, data) {
    if (state !== STATE_ESTABLISHED && state !== STATE_SHUTDOWN_RECEIVED) return;
    if (data.length < 12) return;
    _acceptDataFields(
      flags,
      (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0,   // tsn
      data[4] << 8 | data[5],                                          // sid
      data[6] << 8 | data[7],                                          // ssn
      (data[8] << 24 | data[9] << 16 | data[10] << 8 | data[11]) >>> 0, // ppid
      data.subarray(12),
      null, null);                                                     // not interleaved
  }

  /**
   * The shared receive path, from parsed header fields onward.
   *
   * @param seq   ordering key: SSN for DATA, MID for I-DATA.
   * @param iMid  RFC 8260 message identifier, or null for classic DATA where
   *              the contiguous TSN run carries the ordering instead.
   * @param iFsn  fragment number within that message; null likewise.
   */
  function _acceptDataFields(flags, tsn, streamId, seq, ppid, payload, iMid, iFsn) {
    rateRxBytes += payload.length;   // SCTP-14: reverse-direction load
    // State gating and header parsing happen in the callers (handleData for
    // DATA, handleIData for I-DATA) — RFC 4960 §9.2 still applies: after
    // receiving SHUTDOWN we keep accepting and SACKing in-flight chunks, and
    // drop anything arriving once SHUTDOWN_ACK has been sent.
    var ssn = seq;

    var isBegin     = !!(flags & DATA_FLAG_BEGIN);
    var isEnd       = !!(flags & DATA_FLAG_END);
    var isUnordered = !!(flags & DATA_FLAG_UNORDERED);

    // Record the TSN. This handles cumulative-ack advance (fix for B2,
    // including the out-of-order case the old code couldn't handle) and
    // duplicate detection (fix for B4 — duplicates no longer cause double
    // reassembly + double delivery).
    var status = recordReceivedTsn(tsn);

    // SACK regardless of status — even for duplicates, the peer needs to
    // hear that we got it (otherwise they keep retransmitting). For overflow
    // we still SACK so the peer learns our cumTsn; they'll back off from
    // congestion control kicking in eventually.
    //
    // SCTP-13: instead of emitting a SACK per DATA chunk, mark the packet
    // as needing a SACK and let the handlePacket epilogue emit ONE SACK
    // covering all received TSNs. For a packet with N bundled DATA chunks
    // this is N→1 reduction in SACK traffic.
    //
    // SCTP-2 (delayed ACK / RFC 4960 §6.2): we MUST SACK immediately on:
    //   - duplicate ('too-old' or 'duplicate' status) — peer's retransmitting,
    //     they need to know we already have it
    //   - gap (receivedRanges non-empty after drain — we have TSNs above cum
    //     but missing ones in between, so peer should fast-retransmit)
    // Otherwise the epilogue defers to the every-other-packet / 200ms rule.
    sackPendingThisPacket = true;
    if (status === 'duplicate' || status === 'too-old' || receivedRanges.length > 0) {
      sackImmediateRequired = true;
    }
    if (packetDepth === 0) {
      // Outside handlePacket window (rare path) — flush right away.
      sendSackAndReset();
    }

    if (status !== 'new') {
      // Don't reassemble or deliver duplicates / overflowed chunks. The
      // SACK above already informed the peer.
      return;
    }

    // Stash this fragment in the per-stream fragment store. We don't try
    // to assemble in arrival order any more — fragments may arrive
    // reordered, and assembling-on-arrival was bug N3 (it produced
    // mangled bytes when MIDDLE arrived before BEGIN). tryAssemble walks
    // the store in TSN order looking for a complete BEGIN→END chain.
    //
    // SCTP-11 N4: per-stream fragment-store cap. Without it a malicious
    // peer could open a stream and send unlimited BEGIN-only fragments
    // (no END), filling our memory. The global MAX_RECEIVED_TSNS cap
    // implicitly bounds total receive memory but it doesn't stop a
    // single attacker stream from monopolising buffer until that limit
    // hits. We cap each stream at MAX_FRAGS_PER_STREAM entries; once
    // exceeded we drop the OLDEST entry (lowest TSN) and the now-orphaned
    // fragment becomes unrecoverable, but the association keeps running.
    if (!fragStore[streamId]) fragStore[streamId] = new Map();
    var streamFrags = fragStore[streamId];
    if (streamFrags.size >= MAX_FRAGS_PER_STREAM) {
      // Drop oldest. Map preserves insertion order; first key is oldest.
      var oldestKey = streamFrags.keys().next().value;
      streamFrags.delete(oldestKey);
      try { ev.emit('protocolViolation', { code: 'fragstore-overflow', streamId: streamId }); } catch (e) {}
    }
    streamFrags.set(tsn, {
      ssn: ssn, ppid: ppid,
      isBegin: isBegin, isEnd: isEnd, isUnordered: isUnordered,
      payload: Buffer.from(payload),
      // Interleaving identity (RFC 8260). Null on classic DATA, where the
      // TSN run itself carries the ordering; set on I-DATA, where fragments
      // of one message are found by mid and ordered by fsn no matter what
      // else sits between them in TSN space.
      mid: (typeof iMid === 'number') ? iMid : null,
      fsn: (typeof iFsn === 'number') ? iFsn : null,
    });

    // Try to extract any complete messages that are now assemblable.
    // One DATA chunk's arrival can complete one or more messages
    // (e.g., the long-awaited BEGIN of one message + a previously
    // already-assembled-but-pending one). Loop until exhausted.
    while (true) {
      var msg = tryAssemble(streamId);
      if (!msg) break;
      deliverAssembled(streamId, msg);
    }
  }


  /* ── SACK ──
   *
   * Pre-SCTP-1 this read cumTsn and a_rwnd then did nothing — the send
   * queue was a stub, so there was nothing to drop, no RTT to measure,
   * no gap analysis to drive fast retransmit. SCTP-1 makes SACK do its
   * actual job:
   *   1. Drop chunks ≤ cumTsn from sendQueue. For chunks that were never
   *      retransmitted (Karn's algorithm), update SRTT/RTTVAR/RTO.
   *   2. Walk gap blocks. Any chunk whose TSN sits in a gap (i.e., is
   *      below the highest-acked TSN but missing from the gap-block
   *      coverage) gets its missingReports counter bumped. At >= 3 we
   *      fast-retransmit (RFC 4960 §7.2.4); only the lowest such TSN
   *      retransmits per SACK to avoid bursts.
   *   3. Manage T3 lifecycle. Empty queue → clear timer; otherwise
   *      restart (covering the new oldest chunk).
   *   4. If we're in SHUTDOWN_PENDING and the queue just drained,
   *      transition to SHUTDOWN_SENT. (The drain-before-shutdown step
   *      that SCTP-12 deferred until SCTP-1's queue existed.)
   */
  function handleSack(data) {
    if (data.length < 12) return;
    var cumTsn       = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    remoteRwnd       = (data[4] << 24 | data[5] << 16 | data[6] << 8 | data[7]) >>> 0;
    var numGapBlocks = data[8] << 8 | data[9];
    // numDupTsns is informational (reported by peer for diagnostics).
    // We don't act on it: peer reports duplicates we caused (e.g.,
    // unnecessary retransmit due to lost SACK), and our retransmit
    // discipline is already governed by missingReports + RTO.
    // var numDupTsns   = data[10] << 8 | data[11];

    // Parse gap blocks. Each block: start(2) + end(2), as offsets from
    // cumTsn. Convert to absolute TSNs for downstream comparison via
    // tsnLeq (handles wrap correctly).
    var gaps = [];
    var off = 12;
    for (var g = 0; g < numGapBlocks; g++) {
      if (off + 4 > data.length) break;
      var gStart = data[off]     << 8 | data[off + 1];
      var gEnd   = data[off + 2] << 8 | data[off + 3];
      gaps.push({
        start: (cumTsn + gStart) >>> 0,
        end:   (cumTsn + gEnd)   >>> 0,
      });
      off += 4;
    }

    var now = Date.now();
    var ackedSomething = false;

    /* ── SCTP-14: forward-progress detection for the RTO backoff ──
     *
     * onT3Expire doubles rto every expiry, up to the 60s cap, and only a
     * cumulative-ack advance ever brings it back down. Under scattered loss
     * that is a trap the association cannot climb out of: the head chunk is
     * missing, so cumTsn is pinned, so the backoff keeps growing, so the
     * next retransmit attempt is further away, so cumTsn stays pinned.
     * Observed: rto reached exactly 60000 and the transfer sat idle for
     * minutes with a healthy window and 261 chunks queued.
     *
     * But a SACK carrying NEW gap blocks is proof the path is delivering,
     * even while cumTsn stands still — that is precisely the situation
     * interleaving produces, since a message's fragments no longer form one
     * contiguous run whose head gates everything behind it. So progress is
     * measured against the highest TSN the peer has reported receiving by
     * ANY means, cumulative or gap-acked.
     */
    var peerHighestThisSack = cumTsn;
    for (var pg = 0; pg < gaps.length; pg++) {
      if (tsnGt(gaps[pg].end, peerHighestThisSack)) peerHighestThisSack = gaps[pg].end;
    }
    var peerMadeProgress = (peerHighestSeen === null) ||
                           tsnGt(peerHighestThisSack, peerHighestSeen);
    if (peerMadeProgress) peerHighestSeen = peerHighestThisSack;

    // Drop cumulatively acked chunks. Use Karn's algorithm: only sample
    // RTT from chunks that haven't been retransmitted (otherwise we
    // can't tell which transmission was acked). Each drop fires a
    // 'chunkAcked' event so the upper layer can decrement its
    // bufferedAmount counter without polling sendQueue itself.
    //
    // Performance: instead of `Array.shift()` per chunk (each O(remaining)),
    // we count contiguous acked chunks first and splice once at the end.
    // Drains 1000 chunks: was 1M element-copies, now just 1K. Hot path.
    //
    // SCTP-8: only inFlight chunks contribute to outstandingBytes. The
    // cum-ack only acks TSNs we actually sent, so by definition the
    // dropped prefix is all inFlight=true.
    //
    // SCTP-9: track bytesAcked over the drain so we can update cwnd
    // (slow-start exponential / CA linear) at the end.
    var dropCount  = 0;
    var bytesAcked = 0;
    while (dropCount < sendQueue.length && tsnLeq(sendQueue[dropCount].tsn, cumTsn)) {
      var acked = sendQueue[dropCount];
      ackedSomething = true;
      if (acked.retransmits === 0) {
        updateRtt(now - acked.sentAt);
      }
      // SCTP-9: track bytesAcked BEFORE chunkRemoved decrements outstandingBytes,
      // so the cwnd-growth gate (computed below) sees the pre-drain values
      // implied by `outstandingBytes + bytesAcked`.
      if (acked.inFlight) bytesAcked += acked.payloadLen;
      chunkRemoved(acked);
      dropCount++;
    }
    if (dropCount > 0) sendQueue.splice(0, dropCount);

    // SCTP-9: cum-ack progressed → loss event recovered. Allow another
    // fast-retransmit halving on the next loss.
    // SCTP-14: forward progress also retires any T3 backoff still in effect.
    if (dropCount > 0) fastRetransmitCutThisRound = false;
    // SCTP-14: any evidence the peer is still receiving retires the backoff.
    // BOTH signals are needed and they are not the same event. A cum-ack
    // advance is the obvious one. Gap progress catches the case where the
    // head chunk is missing so cumTsn cannot move at all. And the reverse:
    // when a retransmit finally plugs a hole, cumTsn leaps forward over TSNs
    // the peer had already gap-acked — real progress, yet the HIGHEST TSN it
    // has seen does not change, so the gap test alone misses it. Gating on
    // only one of the two leaves the backoff stuck in the other case.
    if (dropCount > 0 || peerMadeProgress) collapseRtoBackoff();
    // SCTP-14: retire I-FORWARD-TSN skip entries the peer has provably
    // consumed — its cumulative ack has moved past every TSN of the
    // abandoned message, which can only happen after it processed the
    // I-FORWARD-TSN covering that hole.
    for (var akey in abandonedMidPerStream) {
      if (tsnGt(cumTsn, abandonedMidPerStream[akey].tsn)) {
        delete abandonedMidPerStream[akey];
      }
    }
    // A stream may have just gone quiet — release any reset waiting on it.
    _releaseReadyStreamResets();
    // SCTP-9: grow cwnd according to slow-start / CA rules.
    // RFC 4960 §7.2.1 gates growth on "cwnd was fully utilised". The
    // strict reading "outstandingBytes >= cwnd" is overly conservative
    // when chunks don't pack the window exactly: transmitPending stops
    // before exceeding cwnd, so outstanding is typically cwnd minus
    // one fragment's worth — never quite equal.
    //
    // Pragmatic interpretation (matches Linux / FreeBSD behaviour): the
    // window is "utilised" iff there's pending data the user wanted to
    // send but we held back. That is, sendQueue still has !inFlight
    // entries after this drain — the only reason they're sitting there
    // is the cwnd/rwnd budget. If the queue is empty (or all inFlight),
    // the user isn't pushing — don't reward them with extra cwnd.
    var hasPending = false;
    for (var pi = 0; pi < sendQueue.length; pi++) {
      if (!sendQueue[pi].inFlight) { hasPending = true; break; }
    }
    if (bytesAcked > 0 && hasPending) {
      var mtu = pmtu;
      if (cwnd < ssthresh) {
        // Slow start: cwnd += min(bytes, MTU). The min cap prevents one
        // huge cum-ack from doubling cwnd in a single step (jumbo SACK
        // shouldn't be a stronger signal than the smallest one).
        cwnd += Math.min(bytesAcked, mtu);
      } else {
        // Congestion avoidance: bytes accumulate in pba; when pba reaches
        // cwnd, bump cwnd by one MTU and carry the remainder.
        partialBytesAcked += bytesAcked;
        if (partialBytesAcked >= cwnd) {
          partialBytesAcked -= cwnd;
          cwnd += mtu;
        }
      }
    }

    // SCTP-6: maxLifetime sweep. Iterate sendQueue and collect messageSeqs
    // whose firstSentAt is past the deadline. We dedupe via a Set since
    // multiple fragments of one message all share the same messageSeq.
    // Mutating during iteration is unsafe — collect first, abandon after.
    var toAbandon = null;
    for (var lk = 0; lk < sendQueue.length; lk++) {
      var le = sendQueue[lk];
      if (le.maxLifetime != null && (now - le.firstSentAt) >= le.maxLifetime &&
          peerSupportsForwardTsn) {
        if (toAbandon === null) toAbandon = new Set();
        toAbandon.add(le.messageSeq);
      }
    }
    if (toAbandon !== null) {
      toAbandon.forEach(abandonMessage);
    }

    // Gap-ack handling: mark chunks below the highest-acked TSN that
    // weren't covered by any gap block as "missing"; fast retransmit on
    // the LOWEST such chunk that's hit FAST_RETRANSMIT_THRESHOLD reports.
    if (sendQueue.length > 0 && gaps.length > 0) {
      var highestAckedTsn = gaps[gaps.length - 1].end;
      var fastRetransmitIdx = -1;

      for (var k = 0; k < sendQueue.length; k++) {
        var entry = sendQueue[k];
        // Only chunks below the last gap-acked TSN are "passed over" —
        // chunks above it haven't been seen-as-missing by the peer yet,
        // so they don't count as gap-reported.
        if (!tsnLeq(entry.tsn, highestAckedTsn)) break;

        // Is this TSN inside any gap block (i.e., the peer DID receive it)?
        var inGap = false;
        for (var gi = 0; gi < gaps.length; gi++) {
          if (tsnLeq(gaps[gi].start, entry.tsn) &&
              tsnLeq(entry.tsn, gaps[gi].end)) {
            inGap = true;
            break;
          }
        }

        if (!inGap) {
          // Peer is missing this TSN despite acking higher ones.
          entry.missingReports++;
          if (entry.missingReports >= fastRetransmitThreshold &&
              fastRetransmitIdx === -1) {
            fastRetransmitIdx = k;
          }
        }
      }

      if (fastRetransmitIdx !== -1) {
        var fr = sendQueue[fastRetransmitIdx];
        // SCTP-6: abandon-before-retransmit. The retransmit budget check
        // is `>=` evaluated BEFORE the increment, so retransmits=N with
        // maxRetransmits=N means "next retransmit would be N+1 = over
        // budget". Abandon instead.
        if (shouldAbandon(fr, now)) {
          abandonMessage(fr.messageSeq);
        } else {
          fr.retransmits++;
          fr.missingReports = 0;
          fr.sentAt = now;
          // P2: re-emit the pre-built packet — no Buffer.alloc, no copy,
          // no CRC recomputation. Packet bytes are byte-identical to the
          // original send (vtag, ports, TSN, payload all unchanged).
          _sctpDiagPacket(fr.packet, 'retransmit');
          ev.emit('packet', fr.packet);
          sctpStats.fastRetransmits++;
          sctpStats.chunksRetransmitted++;

          // SCTP-9: fast retransmit signals moderate congestion (peer's
          // sending SACKs, path's not dead — just losing some chunks).
          // RFC 4960 §7.2.4:
          //   ssthresh = max(cwnd/2, 4*MTU)
          //   cwnd     = ssthresh   ← NOT 1*MTU; we go straight to CA
          //   pba      = 0
          // We only halve once per "loss event" — multiple gap-block
          // detections in the same SACK shouldn't keep cutting cwnd.
          // Track via a flag we reset when something gets cum-acked.
          if (!fastRetransmitCutThisRound) {
            var mtu = pmtu;
            ssthresh          = Math.max((cwnd / 2) | 0, 4 * mtu);
            cwnd              = ssthresh;
            partialBytesAcked = 0;
            fastRetransmitCutThisRound = true;
          }
        }
      }
    }

    // SCTP-8: rwnd may have opened up. Try to promote pending chunks
    // (queued but not transmitted because the previous rwnd budget was
    // full). The check is fast — early-returns if nothing pending or
    // rwnd still tight.
    var wasNoInFlight = (inFlightCount === 0);
    transmitPending();

    // T3 lifecycle. Empty in-flight count → cancel; non-empty AND we
    // either acked or just promoted pending → restart so the (possibly
    // new) oldest in-flight chunk gets a fresh budget. Otherwise leave
    // the existing timer alone (the oldest chunk hasn't changed;
    // resetting its timer would be a free pass to retransmit attackers
    // can exploit).
    if (inFlightCount === 0) {
      clearT3Timer();
    } else if (ackedSomething || wasNoInFlight || peerMadeProgress) {
      // SCTP-14: peerMadeProgress included. Without it a SACK that advances
      // only the gap blocks leaves the old, backed-off deadline in place —
      // so the timer that collapseRtoBackoff just shortened would still not
      // fire for another minute. Re-arming applies the new RTO immediately.
      startT3Timer();
    }

    // SCTP-6: peer's cumTsn (from this SACK) might be lagging behind our
    // advancedPeerAckPoint — happens when our previous FORWARD-TSN was
    // lost or this SACK was sent before peer received it. Re-emit if so.
    // maybeFwdTsn early-returns when nothing has been abandoned, so this
    // is free for fully-reliable workloads.
    if (peerSupportsForwardTsn && sctpStats.chunksAbandoned > 0) {
      // Peer's cumTsn from this SACK is the snapshot we want to compare against.
      var advPt;
      if (sendQueue.length === 0) {
        advPt = (localTsn - 1) >>> 0;
      } else {
        advPt = (sendQueue[0].tsn - 1) >>> 0;
      }
      if (tsnGt(advPt, cumTsn)) {
        // Peer is behind. Force a re-send by clearing the dedup cache;
        // sendForwardTsn updates lastForwardTsnSent.
        if (lastForwardTsnSent === undefined ||
            tsnGt(advPt, lastForwardTsnSent) ||
            advPt === lastForwardTsnSent /* identical: peer didn't get prior */) {
          sendForwardTsn(advPt);
        }
      }
    }

    // SCTP-12 follow-up: if we were waiting for the queue to drain
    // before sending SHUTDOWN, check now.
    attemptShutdownTransition();
  }


  // Single point of post-handshake initialization. Called from both
  // handleCookieEcho (server side) and handleCookieAck (client side)
  // immediately before emit('open'). Idempotent — if it ever runs
  // twice (it shouldn't) the timer-clear-and-restart pattern guards
  // against duplicate timers.
  function onEstablished() {
    hbLastActivityAt = Date.now();
    hbRetries = 0;
    hbOutstandingNonce = null;
    startHeartbeatTimer();
  }


  /* ── HEARTBEAT — RFC 4960 §8.3 ──
   *
   * Two roles:
   *   • Responder: reflect peer's HEARTBEAT body back as HEARTBEAT_ACK.
   *     Body is opaque to us — peer uses it for their own RTT/nonce
   *     check.
   *   • Initiator: every HEARTBEAT_INTERVAL_MS of receive idle, send
   *     a HEARTBEAT with our own 16-byte nonce. If the matching
   *     HEARTBEAT_ACK doesn't come back within RTO + interval, count
   *     a failure; at HEARTBEAT_MAX_RETRANS consecutive failures the
   *     path is declared dead and the association tears down. Any
   *     incoming chunk resets the activity counter (handleChunk).
   *
   * The nonce is 16 random bytes; we keep one outstanding at a time
   * (keeps state minimal). On HEARTBEAT_ACK, byte-compare the echoed
   * info against our outstanding nonce — anything else is a stale ACK
   * or a confused peer; ignore.
   */

  function handleHeartbeat(data) {
    // Reflect peer's heartbeat body verbatim. Per spec the data must be
    // wrapped in a Heartbeat Info parameter, which is exactly what they
    // sent us — we don't unwrap, just echo.
    sendChunk(CHUNK_HEARTBEAT_ACK, 0, Buffer.from(data), remoteVerificationTag);
  }

  function handleHeartbeatAck(data) {
    if (!hbOutstandingNonce) return;
    // Pull the Heartbeat Info parameter out of `data` and check the
    // nonce. Layout: paramType(2)=1 + paramLen(2) + body.
    if (data.length < 4) return;
    var pType = data[0] << 8 | data[1];
    if (pType !== 1) return;
    var pLen  = data[2] << 8 | data[3];
    if (pLen < 4 || 4 + (pLen - 4) > data.length) return;
    var body = data.subarray(4, pLen);
    if (body.length !== hbOutstandingNonce.length) return;
    // Constant-time-ish compare (we're not under crypto threat here, but
    // it's a habit worth keeping).
    for (var i = 0, diff = 0; i < body.length; i++) {
      diff |= body[i] ^ hbOutstandingNonce[i];
    }
    if (diff !== 0) return;

    // Match — peer is alive. Clear outstanding HB and reset the failure
    // counter. The next idle interval may emit a fresh HB.
    hbOutstandingNonce = null;
    hbRetries = 0;
  }

  function sendHeartbeat() {
    // Guard: if we already have one outstanding, count this as a miss
    // (the previous HB went unacked through a full interval).
    if (hbOutstandingNonce !== null) {
      hbRetries++;
      if (hbRetries >= heartbeatMaxRetrans) {
        // Path-down: too many consecutive HB failures. RFC 4960 §8.2:
        // declare destination unreachable and send ABORT (cause-code
        // 0x000A "User-Initiated Abort" closest match for our case)
        // so peer knows we're gone — without this they'd retransmit
        // for ~30s before T3 expiry tells them.
        sctpStats.pathFailures++;
        try { ev.emit('pathFailure', { reason: 'heartbeat', retries: hbRetries }); } catch (e) {}
        if (state === STATE_ESTABLISHED || state === STATE_SHUTDOWN_PENDING ||
            state === STATE_SHUTDOWN_SENT || state === STATE_SHUTDOWN_RECEIVED ||
            state === STATE_SHUTDOWN_ACK_SENT) {
          sendAbort();
        }
        finalizeClose();
        return;
      }
    }

    // Build a fresh nonce; remember it for the matching HB_ACK.
    var nonce = crypto.randomBytes(16);
    hbOutstandingNonce = nonce;

    // Heartbeat Info parameter: type(2)=1, length(2), body(N).
    var pad = nonce.length % 4 === 0 ? 0 : 4 - (nonce.length % 4);
    var body = Buffer.alloc(4 + nonce.length + pad);
    body.writeUInt16BE(1, 0);
    body.writeUInt16BE(4 + nonce.length, 2);
    nonce.copy(body, 4);
    sendChunk(CHUNK_HEARTBEAT, 0, body, remoteVerificationTag);
  }

  function startHeartbeatTimer() {
    clearHeartbeatTimer();
    hbTimer = setTimeout(onHeartbeatTick, heartbeatIntervalMs);
    if (hbTimer && typeof hbTimer.unref === 'function') hbTimer.unref();
  }

  function clearHeartbeatTimer() {
    if (hbTimer) {
      clearTimeout(hbTimer);
      hbTimer = null;
    }
  }

  function onHeartbeatTick() {
    hbTimer = null;
    if (state !== STATE_ESTABLISHED) return;
    var now = Date.now();
    // Only HB if the path's been idle for a full interval. Any incoming
    // chunk advances hbLastActivityAt, so a busy connection never HBs.
    if (now - hbLastActivityAt < heartbeatIntervalMs) {
      // Reschedule for the remainder.
      hbTimer = setTimeout(onHeartbeatTick,
                           heartbeatIntervalMs - (now - hbLastActivityAt));
      if (hbTimer && typeof hbTimer.unref === 'function') hbTimer.unref();
      return;
    }
    sendHeartbeat();
    if (state === STATE_ESTABLISHED) startHeartbeatTimer();
  }


  /* ── SHUTDOWN — RFC 4960 §9.2 ──
   *
   * The shutdown handshake is 3-way:
   *   close-initiator (e.g. peer A)        close-responder (peer B)
   *     ─────────────────────                 ─────────────────────
   *     close() called
   *     state → SHUTDOWN_PENDING
   *     (drain queue — no-op until SCTP-1)
   *     state → SHUTDOWN_SENT
   *     send SHUTDOWN(cumTsn)        ───►
   *                                          handleShutdown
   *                                          (read peer's cumTsn —
   *                                           ignored until SCTP-1)
   *                                          state → SHUTDOWN_RECEIVED
   *                                          (drain queue)
   *                                          state → SHUTDOWN_ACK_SENT
   *                                  ◄───   send SHUTDOWN_ACK
   *     handleShutdownAck
   *     state → CLOSED
   *     send SHUTDOWN_COMPLETE       ───►
   *                                          handleShutdownComplete
   *                                          state → CLOSED
   *     emit 'close'                          emit 'close'
   *
   * SHUTDOWN and SHUTDOWN_ACK are retransmitted on a T2-shutdown
   * timer (we use shutdownRtoMs, default 1s); after shutdownMaxRetries
   * we give up and force the close.
   */

  function handleShutdown(data) {
    if (data.length < 4) return;
    // Peer's cumulative TSN ack — what they've successfully received from
    // us. SCTP-1 wires this through: drop anything ≤ peerCumTsn from our
    // sendQueue (peer won't be sacking us further from this point —
    // they're closing). This avoids leaving "phantom" chunks queued for
    // retransmit after a clean close.
    var peerCumTsn = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    var now = Date.now();
    var dropCount = 0;
    while (dropCount < sendQueue.length && tsnLeq(sendQueue[dropCount].tsn, peerCumTsn)) {
      var acked = sendQueue[dropCount];
      if (acked.retransmits === 0) {
        updateRtt(now - acked.sentAt);
      }
      chunkRemoved(acked);
      dropCount++;
    }
    if (dropCount > 0) sendQueue.splice(0, dropCount);
    if (inFlightCount === 0) clearT3Timer();

    if (state === STATE_ESTABLISHED) {
      // Standard passive shutdown path.
      state = STATE_SHUTDOWN_RECEIVED;
      // (Drain send queue — no-op until SCTP-1.)
      state = STATE_SHUTDOWN_ACK_SENT;
      shutdownRetries = 0;
      sendShutdownAck();
      scheduleShutdownRetransmit();
    } else if (state === STATE_SHUTDOWN_PENDING ||
               state === STATE_SHUTDOWN_SENT) {
      // Simultaneous close — both sides issued SHUTDOWN. RFC 4960 §9.2
      // says continue and respond with SHUTDOWN_ACK. The first peer to
      // get the ACK wins the race; whoever receives SHUTDOWN_ACK first
      // sends SHUTDOWN_COMPLETE and finalizes.
      state = STATE_SHUTDOWN_ACK_SENT;
      shutdownRetries = 0;
      sendShutdownAck();
      scheduleShutdownRetransmit();
    } else if (state === STATE_SHUTDOWN_ACK_SENT) {
      // Peer retransmitted SHUTDOWN — they didn't get our SHUTDOWN_ACK.
      // Resend it (idempotent; doesn't reset our retry counter so we
      // still time-bound how long we hang around).
      sendShutdownAck();
    }
    // STATE_SHUTDOWN_RECEIVED: redundant SHUTDOWN, ignore (we'll send
    // SHUTDOWN_ACK shortly anyway). STATE_CLOSED / pre-established:
    // ignore.
  }

  function handleShutdownAck() {
    if (state === STATE_SHUTDOWN_SENT) {
      // Peer acknowledged our SHUTDOWN. Send SHUTDOWN_COMPLETE and
      // tear down. The COMPLETE chunk is fire-and-forget — peer's
      // T2 timer will retransmit their SHUTDOWN_ACK if the
      // SHUTDOWN_COMPLETE is lost, and they'll eventually time out
      // and close locally. Per RFC 4960 §8.5.1, even if the
      // verification tag in this packet is wrong, we should still
      // send a SHUTDOWN_COMPLETE with T-bit set. We're not that
      // defensive yet; the vtag check in handlePacket already gates.
      sendShutdownComplete();
      finalizeClose();
    }
    // In other states: peer sent unexpected SHUTDOWN_ACK. Per RFC
    // 4960 §8.5.1 we'd respond with SHUTDOWN_COMPLETE+T-bit; for
    // now just silently ignore.
  }

  function handleShutdownComplete() {
    if (state === STATE_SHUTDOWN_ACK_SENT) {
      // Three-way handshake complete from our side.
      finalizeClose();
    }
    // Other states: malformed exchange or duplicate. Silently ignore.
  }

  // Send the SHUTDOWN chunk. Body is the cumulative TSN ack — what we've
  // received and acked from peer. (Pre-Patch-1 this was 4 zero bytes; B6.)
  function sendShutdown() {
    var body = Buffer.alloc(4);
    body.writeUInt32BE(lastCumulativeTsn, 0);
    sendChunk(CHUNK_SHUTDOWN, 0, body, remoteVerificationTag);
  }

  // SCTP-12 follow-up (now unblocked by SCTP-1's queue): the
  // SHUTDOWN_PENDING → SHUTDOWN_SENT transition. Per RFC 4960 §9.2,
  // SHUTDOWN_PENDING is meant to give the local stack time to drain its
  // outstanding DATA before tearing the association down. Pre-SCTP-1
  // this was a no-op because there was no queue; now we actually wait
  // for sendQueue to empty (driven by handleSack as ACKs arrive) before
  // emitting SHUTDOWN. attemptShutdownTransition is the gate — it does
  // nothing if the queue is non-empty, so handleSack can call it
  // unconditionally on every ACK.
  function attemptShutdownTransition() {
    if (state !== STATE_SHUTDOWN_PENDING) return;
    if (sendQueue.length > 0) return;
    state = STATE_SHUTDOWN_SENT;
    shutdownRetries = 0;
    sendShutdown();
    scheduleShutdownRetransmit();
  }

  function sendShutdownAck() {
    sendChunk(CHUNK_SHUTDOWN_ACK, 0, Buffer.alloc(0), remoteVerificationTag);
  }

  function sendShutdownComplete() {
    sendChunk(CHUNK_SHUTDOWN_COMPLETE, 0, Buffer.alloc(0), remoteVerificationTag);
  }

  // T2-shutdown timer. Restart on every send of SHUTDOWN or SHUTDOWN_ACK,
  // clear on the corresponding response or on finalizeClose. After
  // shutdownMaxRetries failures, force close even if peer never responds
  // (RFC 4960 §9.2.2).
  function clearShutdownTimer() {
    if (shutdownTimer) {
      clearTimeout(shutdownTimer);
      shutdownTimer = null;
    }
  }

  function scheduleShutdownRetransmit() {
    clearShutdownTimer();
    // Exponential backoff capped at 32x — RFC 4960 §6.3.3 caps at 64
    // for DATA RTO, but for shutdown we want to give up sooner.
    var delay = shutdownRtoMs * Math.pow(2, Math.min(shutdownRetries, 5));
    shutdownTimer = setTimeout(function () {
      shutdownTimer = null;
      // Sanity: state may have advanced (e.g. SHUTDOWN_ACK arrived
      // during the timeout). If not in a state that needs retransmit,
      // bail.
      if (state !== STATE_SHUTDOWN_SENT && state !== STATE_SHUTDOWN_ACK_SENT) {
        return;
      }
      shutdownRetries++;
      if (shutdownRetries >= shutdownMaxRetries) {
        // Give up. Peer is unresponsive; force-close locally.
        finalizeClose();
        return;
      }
      // Resend the appropriate chunk and reschedule.
      if (state === STATE_SHUTDOWN_SENT) {
        sendShutdown();
      } else /* STATE_SHUTDOWN_ACK_SENT */ {
        sendShutdownAck();
      }
      scheduleShutdownRetransmit();
    }, delay);
    // Don't keep the Node.js event loop alive solely for this timer;
    // if the caller has nothing else pending, the process should be
    // free to exit. (handle.unref is a no-op on browser-targeted
    // builds but matters on Node for long-running test processes.)
    if (shutdownTimer && typeof shutdownTimer.unref === 'function') {
      shutdownTimer.unref();
    }
  }

  // Final teardown. Unconditional state reset + 'close' event fire.
  // This is the single point of "the association is done" in the new
  // design — pre-Patch-3 it was inline at the end of close() and
  // handleShutdown.
  //
  // Idempotency uses the `closed` flag rather than `state ===
  // STATE_CLOSED` because STATE_CLOSED is also the INITIAL state of
  // a brand-new association (pre-handshake). Using the state would
  // cause the "close before handshake" path to silently skip the
  // 'close' event, which broke a test in the first run.
  function finalizeClose() {
    if (closed) return;   // idempotent
    closed = true;
    // SCTP-14: drop any half-enqueued messages. The pump is unref'd and
    // guards on state, but clearing here means no work is even attempted.
    txJobs.length = 0;
    clearShutdownTimer();
    // SCTP-1: also clear retransmit + heartbeat timers, otherwise they
    // may fire after the association is supposedly gone, hitting
    // ev.emit('packet', ...) with stale verification tags or trying to
    // run logic on a torn-down state.
    clearT3Timer();
    clearHeartbeatTimer();
    // SCTP-2: cancel any in-flight delayed SACK — peer won't get one,
    // but we're closing anyway. Without this, the timer fires post-close
    // and tries to send through emit('packet') with our zeroed state.
    if (delayedSackTimer) {
      clearTimeout(delayedSackTimer);
      delayedSackTimer = null;
    }
    state = STATE_CLOSED;
    ev.emit('close');
    // Defer removeAllListeners so synchronous 'close' listeners
    // attached after construction can run. (ev.emit is synchronous;
    // listeners fire before this line.)
    ev.removeAllListeners();
  }


  /* ── FORWARD-TSN — RFC 3758 §3.2 ──
   *
   * Peer is telling us they've abandoned chunks below newCumTsn (PR-SCTP
   * abandon path). We accept their advance of cumTsn even though the TSNs
   * in between were never received.
   *
   * Pre-flat-ranges this only updated lastCumulativeTsn — leaving stale
   * entries below newCumTsn in receivedTsnsAboveCum. Those would later
   * confuse computeGapBlocks (reporting "gaps" for TSNs that the peer had
   * already given up on). That was bug N5 from the audit, slated for SCTP-6.
   *
   * The rebase model fixes it for free: rebaseBy drops everything ≤
   * newCumTsn from receivedRanges and shifts the rest, in one operation.
   */
  /* SCTP-14 / RFC 8260 §2.3.1 — I-FORWARD-TSN (0xC2).
   *
   * TSN semantics are identical to FORWARD-TSN: advance cumTsn, sweep
   * orphaned fragments. Only the skip entries differ — SID(2) Flags(2,
   * bit0 = U) MID(4) instead of SID(2) SSN(2) — because under interleaving
   * the receiver's in-order gate runs on 32-bit MIDs, and unordered
   * messages have their own MID space whose holes also need announcing
   * (their fragments may be parked in fragStore waiting for a middle piece
   * that was abandoned).
   *
   * Both handlers share advanceCumTsnForAbandon for the common part rather
   * than duplicating the fragment sweep — the sweep has wrap-around
   * subtleties that must not fork. */
  function handleIForwardTsn(data) {
    if (data.length < 4) return;
    var newCumTsn = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    if (!tsnGt(newCumTsn, lastCumulativeTsn)) return;
    /* CRITICAL DIFFERENCE from handleForwardTsn: NO blanket sweep of the
     * (oldCum, newCum] TSN window. Under classic DATA a message occupies one
     * contiguous TSN run, so every fragment inside an abandoned window
     * belongs to an abandoned message and sweeping the window is safe. Under
     * interleaving that is exactly false — a live message's fragments sit
     * BETWEEN the abandoned one's TSNs, inside the advanced window. The
     * sweep was deleting fragments of messages the peer fully delivered,
     * leaving them pinned half-assembled forever (audit 6: message 3 held at
     * 23984 bytes, never delivered, association otherwise idle).
     * Orphan cleanup under I-DATA is identity-based instead: the skip
     * entries below name the abandoned (SID, U, MID) exactly, and
     * dropFragsForMid removes precisely those. */
    advanceCumTsnKeepFrags(newCumTsn);

    var off = 4;
    while (off + 8 <= data.length) {
      var sid   = (data[off] << 8 | data[off + 1]);
      var flags = (data[off + 2] << 8 | data[off + 3]);
      var mid   = (data[off + 4] << 24 | data[off + 5] << 16 |
                   data[off + 6] << 8  | data[off + 7]) >>> 0;
      if (flags & 1) {
        dropFragsForMid(sid, mid, true);
      } else {
        dropFragsForMid(sid, mid, false);
        advanceRecvMidPastAbandoned(sid, mid);
      }
      off += 8;
    }

    // Mirror handleForwardTsn: the rebase may have exposed a contiguous
    // prefix (a TSN above the old cum-ack we had already received).
    drainPrefix();
  }

  // Identity-based orphan cleanup: drop stored fragments of the named
  // stream/space whose MID is at or below the abandoned one. Fragments of
  // other messages — even at TSNs inside the advanced window — are LIVE and
  // must be kept; their missing pieces may still arrive as retransmissions.
  function dropFragsForMid(streamId, abandonedMid, unordered) {
    var store = fragStore[streamId];
    if (!store) return;
    var toDel = null;
    store.forEach(function (frag, tsn) {
      if (frag.mid != null && frag.isUnordered === unordered &&
          (frag.mid === abandonedMid || tsnLt(frag.mid, abandonedMid))) {
        (toDel || (toDel = [])).push(tsn);
      }
    });
    if (toDel) {
      for (var i = 0; i < toDel.length; i++) store.delete(toDel[i]);
      if (store.size === 0) delete fragStore[streamId];
    }
  }

  /* 32-bit twin of advanceRecvSSNPastAbandoned. Not merged with it: the
   * two differ in every arithmetic step (mask, comparison, increment), and
   * a shared body parameterised on width would bury exactly the 16/32
   * distinction that already caused one delivery-stall bug here. */
  function advanceRecvMidPastAbandoned(streamId, abandonedMid) {
    var current = recvSSN[streamId] || 0;
    if (current === abandonedMid || tsnLt(current, abandonedMid)) {
      recvSSN[streamId] = (abandonedMid + 1) >>> 0;
    }
    var pending = pendingMsgs[streamId];
    if (pending) {
      var toDel = [];
      pending.forEach(function (_msg, mid) {
        if (mid === abandonedMid || tsnLt(mid, abandonedMid)) toDel.push(mid);
      });
      for (var di = 0; di < toDel.length; di++) pending.delete(toDel[di]);
      var expected = recvSSN[streamId];
      while (pending.has(expected)) {
        var nxt = pending.get(expected);
        pending.delete(expected);
        processMessage(streamId, nxt.ppid, nxt.payload);
        expected = (expected + 1) >>> 0;
      }
      recvSSN[streamId] = expected;
      if (pending.size === 0) delete pendingMsgs[streamId];
    }
  }

  /* Shared TSN-advance for both FORWARD-TSN flavours: rebase past the
   * abandoned window and sweep fragStore orphans inside it. Snapshot
   * oldCumTsn BEFORE the rebase — the abandoned window is
   * (oldCumTsn, newCumTsn], and fragments there (e.g. BEGIN+MIDDLE of a
   * message whose END was abandoned) would otherwise sit in memory forever
   * and confuse future tryAssemble walks. */
  function advanceCumTsnForAbandon(newCumTsn) {
    var oldCumTsn = lastCumulativeTsn;
    var delta     = (newCumTsn - oldCumTsn) >>> 0;

    rebaseBy(delta);

    // Two-pass sweep: Map iteration is safe but mutation during it isn't.
    for (var sidStr in fragStore) {
      var store = fragStore[sidStr];
      var toDel = null;
      var iter = store.keys();
      var step;
      while (!(step = iter.next()).done) {
        var fragTsn = step.value;
        if (tsnGt(fragTsn, oldCumTsn) && tsnLeq(fragTsn, newCumTsn)) {
          if (toDel === null) toDel = [];
          toDel.push(fragTsn);
        }
      }
      if (toDel !== null) {
        for (var di = 0; di < toDel.length; di++) store.delete(toDel[di]);
        if (store.size === 0) delete fragStore[sidStr];
      }
    }
  }

  // I-DATA variant of the cum-TSN advance: rebase the received-TSN ranges
  // but leave fragStore alone (see handleIForwardTsn for why).
  function advanceCumTsnKeepFrags(newCumTsn) {
    var delta = (newCumTsn - lastCumulativeTsn) >>> 0;
    rebaseBy(delta);
  }

  function handleForwardTsn(data) {
    if (data.length < 4) return;
    var newCumTsn = (data[0] << 24 | data[1] << 16 | data[2] << 8 | data[3]) >>> 0;
    if (!tsnGt(newCumTsn, lastCumulativeTsn)) return;
    advanceCumTsnForAbandon(newCumTsn);

    // Parse optional Stream/SSN pairs (RFC 3758 §3.2). Each pair tells us
    // "peer abandoned an ordered message on stream S with sequence N";
    // we advance our recvSSN[S] past N so any subsequent ordered messages
    // on that stream don't sit forever in pendingMsgs waiting for the
    // gap-SSN that will never arrive. Drain pendingMsgs[S] on the way.
    var off = 4;
    while (off + 4 <= data.length) {
      var sid = (data[off] << 8 | data[off + 1]);
      var ssn = (data[off + 2] << 8 | data[off + 3]);
      advanceRecvSSNPastAbandoned(sid, ssn);
      off += 4;
    }

    // After the rebase, offset 1 may now be filled (e.g., if we'd already
    // received TSN newCumTsn+1 before this FORWARD-TSN). Try to drain.
    drainPrefix();
  }

  // SCTP-6: advance recvSSN past an abandoned ordered SSN reported by
  // peer in FORWARD-TSN. Bumps recvSSN[sid] to (abandonedSsn + 1) iff
  // recvSSN was at-or-below abandonedSsn (mod-16 arithmetic), then
  // drains pendingMsgs[sid] in case the new recvSSN unlocks held messages.
  function advanceRecvSSNPastAbandoned(streamId, abandonedSsn) {
    var current = recvSSN[streamId] || 0;
    // ssnLeq: equivalent of "current is at or below abandonedSsn in
    // 16-bit serial arithmetic". Reuse ssnLt — current === abandonedSsn
    // OR current "before" abandonedSsn → both mean we should advance past.
    if (current === abandonedSsn || ssnLt(current, abandonedSsn)) {
      recvSSN[streamId] = (abandonedSsn + 1) & 0xFFFF;
    }
    // Drop pendingMsgs entries with SSN ≤ abandonedSsn — they're orphans.
    var pending = pendingMsgs[streamId];
    if (pending) {
      var toDel = [];
      pending.forEach(function (_msg, ssn) {
        if (ssn === abandonedSsn || ssnLt(ssn, abandonedSsn)) {
          toDel.push(ssn);
        }
      });
      for (var di = 0; di < toDel.length; di++) pending.delete(toDel[di]);

      // Drain in order: any held message at the new recvSSN gets delivered.
      var expected = recvSSN[streamId];
      while (pending.has(expected)) {
        var nxt = pending.get(expected);
        pending.delete(expected);
        processMessage(streamId, nxt.ppid, nxt.payload);
        expected = (expected + 1) & 0xFFFF;
      }
      recvSSN[streamId] = expected;
      if (pending.size === 0) delete pendingMsgs[streamId];
    }
  }


  /* ========================= SCTP-7: Stream Reset (RFC 6525) =========================
   *
   * The RECONFIG chunk (type 130) carries one or more "Re-configuration
   * Parameters". For our DataChannel needs we handle three:
   *
   *   • PARAM_OUTGOING_SSN_RESET (0x000D) — peer is asking us to reset our
   *     RECEIVE state for some streams (their outgoing → our incoming).
   *     We clear recvSSN/pendingMsgs/fragStore for those streams and reply
   *     with a Re-configuration Response. RFC 8831 §6.7 also expects the
   *     receiver to in turn close its OWN outgoing direction on the same
   *     streams, so we emit a 'streamReset' event the upper layer hooks
   *     to issue a matching reset back.
   *
   *   • PARAM_INCOMING_SSN_RESET (0x000E) — peer asks us to reset OUR
   *     outgoing on some streams. We clear sendSSN[sid] and reply.
   *     Our own buffered DATA on those streams is dropped (the peer
   *     won't deliver them).
   *
   *   • PARAM_RECONFIG_RESPONSE (0x0010) — peer's response to one of our
   *     prior outgoing-reset requests. Resolves the corresponding entry
   *     in pendingResetRequests, fires the user's callback.
   *
   * "Sender's Last Assigned TSN" in the outgoing-reset request is the
   * highest TSN we've assigned on the streams being reset. RFC 6525 §5
   * says the responder waits for cumulative ack to reach that TSN before
   * completing the reset, so any in-flight DATA on the stream gets through
   * first. Since we allocate TSNs globally (not per-stream), we send
   * (localTsn - 1) which is conservatively-correct: it's >= every TSN
   * we've actually used on those streams.
   */

  function handleReconfig(data) {
    // Walk parameters. Each: type(2) + length(2) + body((length-4) bytes),
    // padded to 4-byte boundary.
    var off = 0;
    while (off + 4 <= data.length) {
      var pType = data[off] << 8 | data[off + 1];
      var pLen  = data[off + 2] << 8 | data[off + 3];
      if (pLen < 4 || off + pLen > data.length) break;
      var pBody = data.subarray(off + 4, off + pLen);

      if (pType === PARAM_OUTGOING_SSN_RESET)        handleOutgoingResetRequest(pBody);
      else if (pType === PARAM_INCOMING_SSN_RESET)   handleIncomingResetRequest(pBody);
      else if (pType === PARAM_RECONFIG_RESPONSE)    handleReconfigResponse(pBody);
      // Other reconfig param types (ADD streams, etc.) silently ignored.

      off += pLen;
      if (off % 4 !== 0) off += 4 - (off % 4);
    }
  }

  // Peer is resetting THEIR outgoing → OUR incoming. Reset our recv state
  // and reply with success. Per RFC 6525 §5.2.1 we must guard against
  // duplicates: if peer's request seq matches the last we processed,
  // replay the previous response without redoing the reset (idempotent).
  function handleOutgoingResetRequest(body) {
    if (body.length < 12) return;
    var reqSeq      = (body[0] << 24 | body[1] << 16 | body[2] << 8  | body[3])  >>> 0;
    var respSeq     = (body[4] << 24 | body[5] << 16 | body[6] << 8  | body[7])  >>> 0;
    var senderLastTsn = (body[8] << 24 | body[9] << 16 | body[10] << 8 | body[11]) >>> 0;

    // Dup detection — peer retransmitted the same RECONFIG.
    if (lastReconfigPeerReqSeen !== undefined && reqSeq === lastReconfigPeerReqSeen) {
      sendReconfigResponse(reqSeq, lastReconfigResponseResult);
      return;
    }

    // Parse stream-id list (each 2 bytes; if empty list, all streams reset).
    var streams = [];
    for (var i = 12; i + 2 <= body.length; i += 2) {
      streams.push(body[i] << 8 | body[i + 1]);
    }

    // RFC 6525 §5.2.2: if peer's senderLastTsn is above our cumulative ack,
    // we'd be racing in-flight DATA. Defer with IN_PROGRESS — peer will
    // retry. (Simplification: we don't actually defer, we just respond
    // IN_PROGRESS once. Peer should resend if it cares; otherwise the
    // reset is moot anyway because peer already gave up on those TSNs.)
    if (tsnGt(senderLastTsn, lastCumulativeTsn)) {
      lastReconfigPeerReqSeen     = reqSeq;
      lastReconfigResponseResult  = RECONFIG_RESULT_IN_PROGRESS;
      sendReconfigResponse(reqSeq, RECONFIG_RESULT_IN_PROGRESS);
      return;
    }

    // Apply the reset to our recv state for each requested stream.
    for (var s = 0; s < streams.length; s++) {
      var sid = streams[s];
      // DELIVER BEFORE DISCARDING (RFC 6525 3.1 + RFC 8831 6.7): an
      // incoming stream reset closes the stream for FUTURE data — it does
      // not invalidate messages that already arrived and are sitting
      // complete in the reassembly buffers. Dropping them here is what
      // made "send(msg); close();" lose msg on the RECEIVING side: the
      // reset chunk cleaned up the very message it was meant to follow.
      // Only INCOMPLETE fragments are discarded; a complete message is
      // handed up first.
      var _pend = pendingMsgs[sid];
      if (_pend && _pend.size) {
        // deliver in SSN order, exactly as the normal drain does
        var _ssns = [];
        _pend.forEach(function (_m, _ssn) { _ssns.push(_ssn); });
        _ssns.sort(function (a, b) { return a - b; });
        for (var _pi = 0; _pi < _ssns.length; _pi++) {
          var _msg = _pend.get(_ssns[_pi]);
          try { processMessage(sid, _msg.ppid, _msg.payload); } catch (eD) {}
        }
      }
      delete recvSSN[sid];
      if (pendingMsgs[sid]) delete pendingMsgs[sid];
      if (fragStore[sid])   delete fragStore[sid];
    }

    lastReconfigPeerReqSeen     = reqSeq;
    lastReconfigResponseResult  = RECONFIG_RESULT_SUCCESS_PERFORMED;
    sendReconfigResponse(reqSeq, RECONFIG_RESULT_SUCCESS_PERFORMED);

    // Notify upper layer. RFC 8831 §6.7: peer reset its outgoing direction;
    // we should reset our outgoing direction on the same streams in
    // response, completing the bidirectional close. We emit and let cm.js
    // decide — usually it'll call resetStreams() back.
    try { ev.emit('streamReset', { streamIds: streams.slice(), incoming: true }); } catch (e) {}
  }

  // Peer asks US to reset OUR outgoing on some streams. We clear sendSSN
  // and drop any pending DATA on those streams from sendQueue (peer won't
  // accept it after the reset).
  function handleIncomingResetRequest(body) {
    if (body.length < 4) return;
    var reqSeq = (body[0] << 24 | body[1] << 16 | body[2] << 8 | body[3]) >>> 0;

    if (lastReconfigPeerReqSeen !== undefined && reqSeq === lastReconfigPeerReqSeen) {
      sendReconfigResponse(reqSeq, lastReconfigResponseResult);
      return;
    }

    var streams = [];
    for (var i = 4; i + 2 <= body.length; i += 2) {
      streams.push(body[i] << 8 | body[i + 1]);
    }

    var sidSet = new Set(streams);
    // SCTP-14: also drop the un-enqueued tail of any message still being
    // pumped onto a stream being reset — otherwise the pump would keep
    // appending DATA for a stream whose sequence numbering has just been
    // reset out from under it.
    dropTxJobs(function (j) { return sidSet.has(j.streamId); });
    // Drop unacked DATA for the requested streams from sendQueue. Each
    // dropped chunk fires chunkAcked so bufferedAmount stays correct.
    for (var qi = sendQueue.length - 1; qi >= 0; qi--) {
      if (sidSet.has(sendQueue[qi].streamId)) {
        var dropped = sendQueue.splice(qi, 1)[0];
        chunkRemoved(dropped);
      }
    }
    for (var s = 0; s < streams.length; s++) delete sendSSN[streams[s]];

    lastReconfigPeerReqSeen     = reqSeq;
    lastReconfigResponseResult  = RECONFIG_RESULT_SUCCESS_PERFORMED;
    sendReconfigResponse(reqSeq, RECONFIG_RESULT_SUCCESS_PERFORMED);

    try { ev.emit('streamReset', { streamIds: streams.slice(), incoming: false }); } catch (e) {}
  }

  // Peer's response to one of our outgoing-reset requests.
  function handleReconfigResponse(body) {
    if (body.length < 8) return;
    var respSeq = (body[0] << 24 | body[1] << 16 | body[2] << 8 | body[3]) >>> 0;
    var result  = (body[4] << 24 | body[5] << 16 | body[6] << 8 | body[7]) >>> 0;

    var pending = pendingResetRequests.get(respSeq);
    if (!pending) return;   // unknown — late dup, ignore

    if (result === RECONFIG_RESULT_IN_PROGRESS) {
      // Peer hasn't finished; they'll respond again. We just wait — no
      // explicit retry here because RECONFIG goes over reliable SCTP and
      // peer is responsible for re-responding.
      return;
    }

    pendingResetRequests.delete(respSeq);

    // For SUCCESS responses, also reset our local sendSSN for those
    // streams (we'd deferred this until peer confirmed).
    if (result === RECONFIG_RESULT_SUCCESS_PERFORMED ||
        result === RECONFIG_RESULT_SUCCESS_NOTHING_TO_DO) {
      for (var s = 0; s < pending.streamIds.length; s++) {
        delete sendSSN[pending.streamIds[s]];
      }
    }

    if (typeof pending.callback === 'function') {
      try { pending.callback(null, { result: result, streamIds: pending.streamIds.slice() }); }
      catch (e) {}
    }
  }

  // Build and send a RECONFIG chunk containing a Re-configuration Response
  // parameter. Used by handleOutgoingResetRequest / handleIncomingResetRequest.
  function sendReconfigResponse(reqSeq, result) {
    var body = Buffer.alloc(12);                      // param type+len + 8B body
    body.writeUInt16BE(PARAM_RECONFIG_RESPONSE, 0);
    body.writeUInt16BE(12, 2);                        // param length
    body.writeUInt32BE(reqSeq >>> 0, 4);
    body.writeUInt32BE(result >>> 0, 8);
    sendChunk(CHUNK_RECONFIG, 0, body, remoteVerificationTag);
  }

  // Public: ask peer to reset (close) the given streams. Returns the
  // request sequence number; the callback fires when peer responds.
  // Caller can pass an empty list to reset ALL streams (RFC 6525 §4.1).
  // If peer doesn't support RECONFIG, the callback fires immediately
  // with err='peer-no-reconfig' so cm.js can fall back to local-only
  // close (W3C-compatible degradation).
  /**
   * Stream resets that are WAITING for their data to be acknowledged.
   *   key: reqSeq   value: { streamIds, body, timer }
   * See _streamHasOutstanding for why they wait.
   */
  var pendingStreamResets = new Map();

  /**
   * Does this stream still have data we have not seen acknowledged?
   *
   * A stream reset tells the peer "everything up to senderLastTsn is
   * final, now close the stream". If chunks for that stream are still
   * sitting in sendQueue — unsent because rwnd is closed, or sent but
   * unacked — the peer receives the reset while those chunks are still
   * in flight and discards them (RFC 6525 3.1). That is exactly how the
   * common "send(msg); close();" idiom lost its last message.
   */
  function _streamHasOutstanding(sid) {
    for (var i = 0; i < sendQueue.length; i++) {
      if (sendQueue[i].streamId === sid) return true;
    }
    // SCTP-14: a message still being pumped is outstanding too, even when
    // the fragments enqueued so far have all been acked. Checking only
    // sendQueue would report the stream idle mid-message and let the
    // RECONFIG overtake the tail — the same "send(msg); close();" loss this
    // guard exists to prevent, just moved one layer down.
    for (var j = 0; j < txJobs.length; j++) {
      if (txJobs[j].streamId === sid) return true;
    }
    return false;
  }

  /**
   * Release any reset whose streams have gone quiet. Called from
   * handleSack (every acknowledgement is a chance for a stream to
   * drain) and from the safety timer below.
   */
  function _releaseReadyStreamResets() {
    if (pendingStreamResets.size === 0) return;
    pendingStreamResets.forEach(function (entry, reqSeq) {
      var stillBusy = entry.streamIds.some(_streamHasOutstanding);
      if (stillBusy) return;
      if (entry.timer) clearTimeout(entry.timer);
      pendingStreamResets.delete(reqSeq);
      entry.send();
    });
  }

  function resetStreams(streamIds, callback) {
    if (state !== STATE_ESTABLISHED) {
      if (typeof callback === 'function') {
        queueMicrotask(function() { callback(new Error('not established')); });
      }
      return null;
    }
    if (!Array.isArray(streamIds)) streamIds = [streamIds];
    if (!peerSupportsReconfig) {
      if (typeof callback === 'function') {
        queueMicrotask(function() { callback(new Error('peer-no-reconfig')); });
      }
      return null;
    }

    var reqSeq = reconfigReqSeq;
    reconfigReqSeq = (reconfigReqSeq + 1) >>> 0;

    pendingResetRequests.set(reqSeq, {
      streamIds: streamIds.slice(),
      callback:  callback || null,
    });

    // Build PARAM_OUTGOING_SSN_RESET:
    //   type(2) + len(2) + reqSeq(4) + respSeq(4) + senderLastTsn(4) + sids(2*N)
    var paramBodyLen = 12 + streamIds.length * 2;
    var paramLen     = 4 + paramBodyLen;
    var bodyLen      = paramLen;
    if (bodyLen % 4 !== 0) bodyLen += 4 - (bodyLen % 4);   // pad

    // BUILD LATE, SEND LATE — and WAIT FOR THE STREAM TO DRAIN.
    //
    // Two orderings must hold before a RECONFIG may leave:
    //   • it must not overtake data still queued behind the coalescing
    //     transmit microtask (RFC 4960 6.10 bundling);
    //   • senderLastTsn must cover that data, which means reading
    //     localTsn only after the data has been assigned its TSNs
    //     (RFC 6525 4.1).
    // Building the whole parameter inside the deferred sender gives both.
    // On top of that, if the stream still has UNACKNOWLEDGED chunks the
    // reset waits for them: the peer would otherwise apply the reset
    // while those chunks are in flight and drop them — the "send(msg);
    // close();" data loss. handleSack releases the reset as soon as the
    // stream goes quiet, and a safety timer releases it regardless so a
    // stalled queue can never keep a channel open forever.
    var _sendReset = function () {
    var body = Buffer.alloc(bodyLen);
    body.writeUInt16BE(PARAM_OUTGOING_SSN_RESET, 0);
    body.writeUInt16BE(paramLen, 2);
    body.writeUInt32BE(reqSeq, 4);
    // "Reconfig Response Sequence Number" — peer's last seen response seq.
    // RFC 6525 §4.1: this is "the next response sequence number expected".
    // We use the last we saw or 0; not strictly required for our flow.
    body.writeUInt32BE(lastReconfigPeerReqSeen || 0, 8);
    body.writeUInt32BE((localTsn - 1) >>> 0, 12);
    for (var i = 0; i < streamIds.length; i++) {
      body.writeUInt16BE(streamIds[i] & 0xFFFF, 16 + i * 2);
    }

    // ORDER WITH PENDING DATA (RFC 8831 6.7 / W3C 6.2.5): user data goes
    // out through sendQueue on a coalescing MICROTASK, while this
    // RECONFIG was written synchronously — so a stream reset OVERTOOK
    // data the application had just sent and the peer closed the stream
    // before the message arrived. "send(msg); close();" silently lost
    // msg. queueMicrotask preserves FIFO order and send() already
    // scheduled its transmit pass, so deferring the RECONFIG the same
    // way puts it strictly AFTER the data it must not overtake.
    sendChunk(CHUNK_RECONFIG, 0, body, remoteVerificationTag);
    };

    // STATUS (round 116): the wait itself works — traced busy=true, the
    // reset held, released on the SACK. But with an IMMEDIATE close the
    // peer's SCTP never emits the message at all, so the loss is EARLIER
    // than this layer: between dcc.send()'s enqueue and the transmit
    // pass, for that one timing. The two orderings fixed in round 115
    // and this drain-wait are all RFC-correct and stay; the remaining
    // piece is why that first chunk never leaves. Next probe: trace
    // transmitPending's selection for a stream whose channel entered
    // 'closing' in the same turn.
    // SCTP-14: W3C close() flushes what the application already sent, so
    // finish enqueuing any in-progress message on these streams rather than
    // dropping its tail. This also settles _streamHasOutstanding into its
    // sendQueue-only answer below.
    var _resetSids = new Set(streamIds);
    for (var _ji = txJobs.length - 1; _ji >= 0; _ji--) {
      if (!_resetSids.has(txJobs[_ji].streamId)) continue;
      var _fj = txJobs[_ji];
      while (emitFragment(_fj)) { /* drain this message fully */ }
      txJobs.splice(_ji, 1);
    }
    scheduleTransmit();

    var _busy = streamIds.some(_streamHasOutstanding);
    if (_busy) {
      var _entry = { streamIds: streamIds.slice(), send: _sendReset, timer: null };
      _entry.timer = setTimeout(function () {
        if (pendingStreamResets.has(reqSeq)) {
          pendingStreamResets.delete(reqSeq);
          _sendReset();   // safety net: never leave a channel unclosed
        }
      }, Math.max(200, (typeof rto === 'number' ? rto : 200) * 2));
      if (_entry.timer && _entry.timer.unref) _entry.timer.unref();
      pendingStreamResets.set(reqSeq, _entry);
    } else {
      queueMicrotask(_sendReset);
    }
    return reqSeq;
  }


  /* ========================= SCTP-10: ABORT / ERROR =========================
   *
   * ABORT (RFC 4960 §3.3.7) — peer ends the association abruptly. May carry
   * one or more error-cause parameters telling us why. Standard-conforming
   * action: tear down immediately, no SHUTDOWN-ACK exchange. We emit a
   * 'pathFailure' event with cause info so cm.js can react, then close.
   *
   * ERROR (RFC 4960 §3.3.10) — non-fatal protocol error report. Peer is
   * informing us they got a chunk they couldn't process (unknown chunk type,
   * stale cookie, etc.) but the association continues. We log and emit
   * for upper-layer telemetry.
   */
  function handleAbort(data) {
    var cause = parseFirstErrorCauseCode(data);
    sctpStats.pathFailures++;
    try { ev.emit('pathFailure', { source: 'abort', cause: cause }); } catch (e) {}
    // Don't reply with our own ABORT — peer just told us the association
    // is dead from their side. finalizeClose tears us down silently per
    // RFC 4960 §3.3.7.
    finalizeClose();
  }

  function handleError(data) {
    var cause = parseFirstErrorCauseCode(data);
    try { ev.emit('protocolError', { cause: cause }); } catch (e) {}
  }

  // Both ABORT and ERROR carry a list of "error cause" TLVs. We extract
  // the first one's cause-code for telemetry. Format per RFC 4960 §3.3.10:
  //   cause-code(2) + cause-length(2) + cause-info(variable)
  function parseFirstErrorCauseCode(data) {
    if (data.length < 4) return null;
    return data[0] << 8 | data[1];
  }

  /* sendAbort — emit ABORT chunk to peer.
   *
   * RFC 4960 §3.3.7:
   *   Type: 6, Flags: T-bit, Length, [Error Causes]
   *
   * The T-bit (flags & 0x01) when set means "verification tag is the
   * one I copied from your packet" — used pre-cookie when we don't have
   * a real vtag. Post-handshake we use our normal remoteVerificationTag
   * with T-bit clear.
   *
   * Per §6.10 rule 1, ABORT MAY be bundled with other chunks BUT once
   * peer sees ABORT they discard the rest of the packet. We send it
   * standalone for clarity.
   *
   * We don't include error causes in the body — the empty ABORT is
   * RFC-valid and matches libwebrtc's path-failure ABORT.
   */
  function sendAbort(causeCode) {
    var body = Buffer.alloc(0);
    if (causeCode != null) {
      body = Buffer.alloc(4);
      body.writeUInt16BE(causeCode, 0);
      body.writeUInt16BE(4, 2);    // length-only error cause (no info)
    }
    // Bypass the bundling path so ABORT goes out alone.
    if (pendingOutChunks.length > 0) flushOutChunks();
    emitOneChunk(CHUNK_ABORT, 0, body, remoteVerificationTag);
  }

  /* sendError — emit ERROR chunk for non-fatal protocol issues.
   *
   * RFC 4960 §3.3.10 — ERROR carries one or more "error cause" parameters.
   * Use this when the peer sent something we can't process but the
   * association should continue (unrecognized chunk type, invalid stream
   * ID on a DATA chunk, stale cookie before handshake completes).
   *
   * Currently only wired from optional callers — most peers ignore ERROR
   * since it's advisory. We send it bundled-by-default; control chunks
   * may share a packet with DATA per RFC §6.10 (only INIT/INIT_ACK/
   * SHUTDOWN_COMPLETE require sole-occupancy).
   */
  function sendError(causeCode, causeInfo) {
    var info = causeInfo ? Buffer.from(causeInfo) : Buffer.alloc(0);
    var causeLen = 4 + info.length;
    // Pad cause-info to 4-byte boundary per RFC §3.2.1
    var padded = (causeLen + 3) & ~3;
    var body = Buffer.alloc(padded);
    body.writeUInt16BE(causeCode, 0);
    body.writeUInt16BE(causeLen, 2);
    if (info.length) info.copy(body, 4);
    sendChunk(CHUNK_ERROR, 0, body, remoteVerificationTag);
  }


  /* ========================= Message delivery ========================= */

  // Queue of reassembled messages awaiting delivery, and the drain that hands
  // them up ONE PER TASK. See processMessage.
  var _deliverQueue = [];
  var _deliverScheduled = false;

  function _drainDeliveries() {
    _deliverScheduled = false;
    if (closed) { _deliverQueue.length = 0; return; }
    var item = _deliverQueue.shift();
    if (item) {
      try { ev.emit('data', item[0], item[1], item[2]); } catch (e) { /* a handler must not stall the queue */ }
    }
    if (_deliverQueue.length > 0) _scheduleDelivery();
  }

  function _scheduleDelivery() {
    if (_deliverScheduled) return;
    _deliverScheduled = true;
    var t = setTimeout(_drainDeliveries, 0);
    if (t.unref) t.unref();
  }

  /**
   * Hand a reassembled message to the application — ONE PER TASK.
   *
   * Messages arrive in bursts: a single SCTP packet can carry several, and the
   * reordering drain can release a whole run at once. Emitting them in a
   * synchronous loop delivered the entire burst before the application got a
   * chance to run, which breaks the ordinary pattern of consuming one message
   * at a time:
   *
   *     const {data} = await new Promise(r => channel.onmessage = r);
   *
   * The handler is only reattached after the await — a microtask — so every
   * message after the first in each burst landed on a handler that had already
   * been removed. Measured with 100 messages: 3 arrived, 97 were lost.
   *
   * Browsers deliver each message as its own task, which is why the pattern
   * works there. A macrotask per message matches that, and gives handlers,
   * promise continuations and reattached listeners a chance to run in between.
   * Ordering is preserved: the queue is FIFO and the drain takes one item.
   */
  function processMessage(streamId, ppid, payload) {
    _deliverQueue.push([streamId, ppid, payload]);
    _scheduleDelivery();
    return;
  }


  /* ========================= Sending ========================= */

  // send(streamId, payload, opts?)
  //
  //   streamId  integer in [0, 65535] — the SCTP stream to send on.
  //
  //   payload   Buffer — one complete user message. Auto-fragmented by
  //             PMTU (SCTP-3): payloads up to maxPerChunk go as one DATA
  //             chunk; larger ones are split into N chunks sharing one
  //             SSN/PPID/messageSeq with contiguous TSNs.
  //
  //   opts      optional object:
  //               ppid            Payload Protocol Identifier, u32. Default 0.
  //               unordered       boolean. Default false (ordered).
  //               maxRetransmits  integer ≥ 0 or null (default null/none).
  //                               When set, the message is abandoned if any
  //                               of its fragments has been retransmitted
  //                               this many times without ack. Mutually
  //                               exclusive with maxLifetime per W3C.
  //               maxLifetime     integer ≥ 0 ms or null (default null/none).
  //                               When set, the message is abandoned once
  //                               firstSentAt + maxLifetime has elapsed
  //                               without ack.
  //
  // PR-SCTP semantics (SCTP-6, RFC 3758):
  //   • If peer didn't advertise FORWARD-TSN in its INIT/INIT-ACK
  //     SUPPORTED_EXTENSIONS, opts.maxRetransmits/maxLifetime are silently
  //     ignored — the message is fully reliable. (RFC 8831 §6.6 mandates
  //     this graceful degradation.)
  //   • Abandonment is per-MESSAGE: when any fragment exceeds its limit,
  //     ALL fragments of the same message are dropped from sendQueue and
  //     a FORWARD-TSN is sent so the peer advances past the gap.
  //   • Abandoned bytes still emit a 'chunkAcked' event so the upper layer's
  //     bufferedAmount accounting drains correctly (the user's send is
  //     "complete" from their POV regardless of fate).
  //
  // Throws on bad state, bad arguments, or payload exceeding maxMessageSize.
  // Emits 'chunkSent' per FRAGMENT (so a 5KB user message produces multiple
  // events summing to 5KB). Counterpart 'chunkAcked' fires from handleSack
  // as cumTsn advances OR from abandonMessage on PR-SCTP drop.
  function sendData(streamId, payload, opts) {
    if (state !== STATE_ESTABLISHED) {
      throw new Error("SctpAssociation.send: requires state='established' (got '" +
                      STATE_NAMES[state] + "')");
    }
    if (typeof streamId !== 'number' || !Number.isInteger(streamId) ||
        streamId < 0 || streamId > 0xFFFF) {
      throw new TypeError('SctpAssociation.send: streamId must be integer in [0, 65535]');
    }
    if (!Buffer.isBuffer(payload)) {
      throw new TypeError('SctpAssociation.send: payload must be a Buffer');
    }

    var ppid           = (opts && opts.ppid != null) ? opts.ppid : 0;
    var unordered      = !!(opts && opts.unordered);
    // PR-SCTP per-message limits. null means "no limit" (fully reliable).
    var maxRetransmits = (opts && opts.maxRetransmits != null) ? opts.maxRetransmits : null;
    var maxLifetime    = (opts && opts.maxLifetime    != null) ? opts.maxLifetime    : null;

    if (typeof ppid !== 'number' || !Number.isInteger(ppid) ||
        ppid < 0 || ppid > 0xFFFFFFFF) {
      throw new TypeError('SctpAssociation.send: opts.ppid must be integer in [0, 4294967295]');
    }
    if (maxRetransmits !== null && (!Number.isInteger(maxRetransmits) || maxRetransmits < 0)) {
      throw new TypeError('SctpAssociation.send: opts.maxRetransmits must be a non-negative integer or null');
    }
    if (maxLifetime !== null && (!Number.isInteger(maxLifetime) || maxLifetime < 0)) {
      throw new TypeError('SctpAssociation.send: opts.maxLifetime must be a non-negative integer (ms) or null');
    }
    if (payload.length > maxMessageSize) {
      throw new RangeError('SctpAssociation.send: payload (' + payload.length +
                           ' bytes) exceeds maxMessageSize (' + maxMessageSize + ')');
    }

    // Silent degradation per RFC 8831 §6.6: if peer can't process FORWARD-
    // TSN we MUST send fully reliably regardless of caller's wish for
    // partial reliability. (Caller can detect this via assoc.peerSupports
    // ForwardTsn if they care.)
    if (!peerSupportsForwardTsn) {
      maxRetransmits = null;
      maxLifetime    = null;
    }

    // SSN is allocated ONCE per message (all fragments share it).
    var ssn;
    if (unordered) {
      ssn = 0;
    } else {
      ssn = sendSSN[streamId] || 0;
      sendSSN[streamId] = (ssn + 1) & 0xFFFF;
    }

    // RFC 8260 MID: one per message on this stream, always incremented.
    // Allocated even when not sending I-DATA — it costs a counter bump and
    // keeps the two paths from diverging if the peer's support changes.
    //
    // SCTP-14: ordered and unordered draw from SEPARATE per-stream spaces
    // (RFC 8260 §2.2.1). See the sendMIDOrdered/sendMIDUnordered comment.
    var midSpace = unordered ? sendMIDUnordered : sendMIDOrdered;
    var mid = midSpace[streamId] || 0;
    midSpace[streamId] = (mid + 1) >>> 0;

    // SCTP-6: messageSeq groups fragments for abandon/lookup. Distinct from
    // SSN (which is per-stream and on-the-wire); messageSeq is purely local.
    var messageSeq = nextMessageSeq;
    nextMessageSeq = (nextMessageSeq + 1) >>> 0;

    // RFC 8260: send I-DATA only when the peer ADVERTISED it. A peer that did
    // not has no parser for chunk type 0x40 and would treat the whole packet
    // as malformed — so this single flag is the difference between the new
    // wire format and the old one, and everything below keys off it.
    var useIData = (peerSupportsIData === true);
    var chunkOverhead = useIData ? I_DATA_CHUNK_OVERHEAD : DATA_CHUNK_OVERHEAD;
    var maxPerChunk = pmtu - SCTP_HEADER_OVERHEAD - chunkOverhead;
    var numFragments = payload.length === 0
                         ? 1
                         : Math.ceil(payload.length / maxPerChunk);

    // ── SCTP-14: enqueue policy ──────────────────────────────────────
    // Everything below builds fragments; the only question is WHEN. A
    // message small enough to not matter is built here and now, exactly as
    // before. A long one becomes a job that the pump feeds into sendQueue a
    // few fragments at a time, yielding in between, so a send() that happens
    // later still gets its TSNs interleaved between this message's.
    //
    // Interleaving REQUIRES I-DATA. Under classic DATA the receiver
    // reassembles by walking a contiguous TSN run (tryAssemble's
    // expectTsn = tsn + 1 walk), so any fragment of another message landing
    // in the middle breaks the chain — for messages on OTHER streams too,
    // since a gap in the run is a gap regardless of who filled it. So
    // without I-DATA we keep the old all-at-once behaviour, which is also
    // what a peer that never advertised the extension expects.
    var job = {
      streamId:       streamId,
      payload:        payload,
      ppid:           ppid,
      ssn:            ssn,
      mid:            mid,
      messageSeq:     messageSeq,
      unordered:      unordered,
      maxRetransmits: maxRetransmits,
      maxLifetime:    maxLifetime,
      useIData:       useIData,
      chunkOverhead:  chunkOverhead,
      maxPerChunk:    maxPerChunk,
      numFragments:   numFragments,
      cursor:         0,
      // PR-SCTP deadlines run from the send() call, not from the moment a
      // fragment happens to reach the queue — otherwise a message's later
      // fragments would each get a fresh lifetime and outlive their deadline.
      createdAt:      Date.now(),
    };

    sampleRates();
    if (!shouldSlice(useIData, numFragments)) {
      while (emitFragment(job)) { /* drain synchronously */ }
      // SCTP-13: coalesced transmit. Instead of transmitting inline on every
      // send(), schedule a single transmit pass on the microtask queue. A
      // burst of send() calls in the same tick therefore all land in
      // sendQueue *before* the one pass runs, so transmitPending() can bundle
      // them into full packets (RFC 4960 §6.10) — the whole point of adaptive
      // bundling. A microtask runs at the end of the current synchronous
      // stack, before any I/O or timers, so a lone send() still goes out this
      // same tick: zero real added latency, no Nagle-style waiting.
      scheduleTransmit();
      return;
    }

    // Long message: register the job. If the active set has room, push its
    // first quantum right now so the head of the message leaves in this same
    // tick (no added latency on the first bytes); otherwise it waits its turn
    // in FIFO order and the pump picks it up as earlier messages finish.
    txJobs.push(job);
    // Fill toward the window right now so the head of the message leaves in
    // this same tick; scheduleTransmit's pass will pick it up.
    fillTxQueue(TX_REFILL_BURST);
    scheduleTransmit();
    scheduleTxPump();
  }

  /* ── SCTP-14: fragment builder ───────────────────────────────────────
   *
   * Builds ONE fragment of `job` (the one at job.cursor), appends it to
   * sendQueue, and advances the cursor. Returns true while the job still
   * has fragments left.
   *
   * This is the body of what used to be sendData's `for (f...)` loop,
   * lifted out unchanged apart from reading its inputs off `job`. Lifting
   * it is the whole point: the loop can now be driven from sendData
   * (synchronously, for short messages) or from the pump (a few per tick,
   * for long ones) without the two paths diverging.
   *
   * TSN ORDER — the invariant everything downstream leans on — survives
   * because this function is the ONLY place a TSN is allocated, it always
   * allocates from localTsn, and it always push()es onto the TAIL. Queue
   * position therefore still tracks TSN order exactly, no matter how the
   * calls are interleaved between jobs or spread across ticks. Nothing
   * reorders the queue; handleSack's front-drain, forwardTsn's
   * sendQueue[0].tsn - 1, and T3's "sendQueue[0] is the oldest" all keep
   * holding. That is what makes this the safe place to interleave, and the
   * reason interleaving at drain time was not.
   */
  function emitFragment(job) {
    var f = job.cursor;
    if (f >= job.numFragments) return false;
    job.cursor++;

    var fragStart   = f * job.maxPerChunk;
    var fragEnd     = Math.min(fragStart + job.maxPerChunk, job.payload.length);
    var fragPayload = job.payload.subarray(fragStart, fragEnd);

    var tsn = localTsn;
    localTsn = (localTsn + 1) >>> 0;

    var flags = 0;
    if (f === 0)                      flags |= DATA_FLAG_BEGIN;
    if (f === job.numFragments - 1)   flags |= DATA_FLAG_END;
    if (job.unordered)                flags |= DATA_FLAG_UNORDERED;

    // Performance: single Buffer.alloc per fragment that holds the FULL
    // wire packet (SCTP common header + chunk header + DATA metadata +
    // payload + padding). Pre-optimization we allocated `body` and then
    // a separate packet inside sendChunk, copying body in. For a 100KB
    // user message that's 88 fragments x 2 allocs = 176; now it's 88.
    // We retain the packet in sendQueue so retransmit is just a re-emit
    // (no rebuild) — see onT3Expire / fast-retransmit. None of the
    // packet bytes change between transmissions: vtag, ports, flags,
    // TSN, payload, even the CRC are identical.
    var chunkLen    = job.chunkOverhead + fragPayload.length;
    var chunkPadded = chunkLen + ((chunkLen % 4) ? (4 - chunkLen % 4) : 0);
    var pktLen      = 12 + chunkPadded;
    var pkt = Buffer.alloc(pktLen);

    // Common header
    pkt.writeUInt16BE(localPort,             0);
    pkt.writeUInt16BE(remotePort,            2);
    pkt.writeUInt32BE(remoteVerificationTag, 4);
    // bytes 8-11: checksum (set after CRC; Buffer.alloc gives zeros)

    // Chunk header
    pkt[12] = job.useIData ? CHUNK_I_DATA : CHUNK_DATA;
    pkt[13] = flags;
    pkt.writeUInt16BE(chunkLen, 14);

    if (job.useIData) {
      // I-DATA metadata (RFC 8260 2.1):
      //
      //   TSN(4) SID(2) reserved(2) MID(4) PPID-or-FSN(4)
      //
      // The last word is the PPID on a first fragment and the FSN on any
      // other — a continuation inherits its message's PPID, so the two
      // never need to travel together. RFC 8260 §2.1: the first fragment's
      // FSN is implicit 0 (the field carries the PPID instead), so the
      // second fragment is FSN 1 — which is what `f` gives for f >= 1.
      pkt.writeUInt32BE(tsn,          16);
      pkt.writeUInt16BE(job.streamId, 20);
      pkt.writeUInt16BE(0,            22);   // reserved
      // MID must be UNIQUE per message on this stream — it is the key the
      // receiver groups fragments by (RFC 8260 2.1) — and it must come from
      // the right one of the stream's two MID spaces (ordered / unordered,
      // RFC 8260 §2.2.1), because for ordered messages the receiver also
      // uses it as the in-order delivery sequence.
      //
      // SSN cannot serve. Unordered messages all take ssn = 0, and data
      // channels are unordered, so every message would claim MID 0. Under
      // classic DATA that is harmless: reassembly follows a contiguous TSN
      // run and two runs cannot overlap. Under I-DATA it is fatal as soon
      // as two messages are in flight together — their fragments become
      // indistinguishable and neither reassembles.
      pkt.writeUInt32BE(job.mid, 24);   // MID
      pkt.writeUInt32BE((f === 0) ? job.ppid : f, 28);
      fragPayload.copy(pkt, 32);
    } else {
      // DATA metadata (RFC 4960 3.3.1)
      pkt.writeUInt32BE(tsn,          16);
      pkt.writeUInt16BE(job.streamId, 20);
      pkt.writeUInt16BE(job.ssn,      22);
      pkt.writeUInt32BE(job.ppid,     24);
      fragPayload.copy(pkt, 28);
    }

    // CRC32c — checksum field is currently zeros from Buffer.alloc.
    pkt.writeUInt32LE(crc32c(pkt), 8);

    var nowTs = Date.now();
    sendQueue.push({
      tsn:            tsn,
      streamId:       job.streamId,
      ppid:           job.ppid,
      ssn:            job.ssn,
      payloadLen:     fragPayload.length,
      flags:          flags,
      packet:         pkt,            // full pre-built wire packet, reused on retransmit
      firstSentAt:    job.createdAt,  // PR-SCTP deadline runs from send(), not from enqueue
      sentAt:         nowTs,
      retransmits:    0,
      missingReports: 0,
      needsRetx:      false,      // SCTP-14: set by T3 (RFC 4960 §6.3.3 E3)
      messageSeq:     job.messageSeq,
      mid:            job.mid,        // SCTP-14: needed for I-FORWARD-TSN skips
      maxRetransmits: job.maxRetransmits,
      maxLifetime:    job.maxLifetime,
      unordered:      job.unordered,
      inFlight:       false,          // SCTP-8: transmitPending flips this when rwnd allows
    });
    pendingBytes += fragPayload.length;
    rateTxBytes  += fragPayload.length;   // SCTP-14
    sctpStats.chunksSent++;

    // chunkSent fires for ALL queued chunks (in-flight or pending) so
    // bufferedAmount reflects user's intent. Counterpart chunkAcked
    // fires from handleSack on cum-ack OR from abandonMessage on PR-SCTP
    // drop OR from incoming-reset cleanup.
    try {
      ev.emit('chunkSent', {
        streamId: job.streamId,
        ppid:     job.ppid,
        bytes:    fragPayload.length,
      });
    } catch (e) {}

    return job.cursor < job.numFragments;
  }

  /* ── SCTP-14: the interleaving pump ──────────────────────────────────
   *
   * One round = one quantum of fragments from EVERY active job, in
   * round-robin order. Then we yield and let the event loop run: SACKs get
   * processed, timers fire, and — the point of the exercise — a send() that
   * arrives in the meantime gets its TSNs allocated between this message's
   * fragments instead of behind all of them.
   *
   * Round-robin rather than "finish one slice of message A, then a slice of
   * message B" because fairness must not depend on the order the yields
   * happen to resolve in. Every job gets the same quantum every round, so
   * N concurrent messages each progress at 1/N of the rate with no
   * per-message timers to coordinate and nothing that degrades as N grows.
   *
   * Why setImmediate and not setTimeout(0): setTimeout has a >=1ms clamp in
   * Node, which would cap a 220-fragment message at ~28 rounds/second. And
   * why not queueMicrotask: microtasks drain completely before the event
   * loop advances, so the pump would starve the very I/O it is yielding
   * for — no SACKs, no incoming data, and the yield buys nothing.
   * setImmediate runs in the check phase, after pending I/O, which is
   * exactly the "let the socket breathe, then continue" semantics wanted.
   *
   * SCHEDULING AFTER EVERY ROUND IS LOAD-BEARING. Each round appends to
   * sendQueue and those entries start life with inFlight = false; nothing
   * moves them until a transmitPending() pass runs. scheduleTransmit()'s
   * _transmitScheduled flag only coalesces callers within a single tick, so
   * a round that lands in a later tick needs its own call. Omit it and the
   * first quantum leaves, every later one accumulates in the queue unsent,
   * and the transfer stalls with a full send queue and an open window.
   */
  function scheduleTxPump() {
    if (_txPumpScheduled || txJobs.length === 0) return;
    _txPumpScheduled = true;
    var t = setImmediate(runTxPump);
    if (t && typeof t.unref === 'function') t.unref();
  }

  /* ── SCTP-14: window-driven refill ─────────────────────────────────
   *
   * Keep the PENDING region of sendQueue stocked to roughly one send window,
   * and no more. Both numbers matter, and getting either wrong shows up
   * immediately in production traffic.
   *
   * TOO LITTLE queued starves the congestion controller. handleSack grows
   * cwnd only when `hasPending` — when chunks are sitting in the queue that
   * the window would not let out. That is the standard "was the sender
   * cwnd-limited?" test, and it is how a sender avoids inflating its window
   * on traffic it never actually offered. A fixed-quantum pump feeding a
   * handful of fragments per event-loop turn empties the pending region
   * between SACKs, so the sender reports itself application-limited, cwnd
   * stops growing, and throughput plateaus far below the path capacity. This
   * is why the first version of the pump halved server-direction throughput
   * while fixing latency: the pacing was the ceiling, not the link.
   *
   * TOO MUCH queued destroys the latency win. Interleaving allocates TSNs at
   * enqueue time, so a small message can only overtake fragments that have
   * not been enqueued YET. Once a long message has dumped hundreds of
   * fragments into the queue, a control message enqueued afterwards sits
   * behind all of them no matter how small it is. An unbounded pump does
   * exactly that whenever the window is closed — it keeps appending while
   * nothing drains — which is how a short message ends up seconds late.
   *
   * One window's worth satisfies both: enough that cwnd growth never sees a
   * starved queue, little enough that a message arriving now waits at most
   * about one window ahead of it.
   *
   * The refill runs synchronously from transmitPending, so a SACK that opens
   * the window tops the queue back up in the same turn it arrived — no
   * event-loop round trip between "window opened" and "data available". The
   * setImmediate pump remains for the case where nothing is draining yet
   * (the initial burst) and to spread a very large refill over several turns.
   */
  /* Roll the rate window if it has elapsed and re-evaluate the latch.
   * Called from the send path, so it is driven by traffic rather than by a
   * timer — an idle association neither samples nor decides anything. */
  function sampleRates() {
    var now = Date.now();
    if (rateWindowStart === 0) { rateWindowStart = now; return; }
    var dt = now - rateWindowStart;
    if (dt < INTERLEAVE_RATE_WINDOW_MS) return;
    var rx = rateRxBytes * 1000 / dt;
    var tx = rateTxBytes * 1000 / dt;
    // EWMA so one quiet window does not flip the decision on its own.
    rateRxPerSec = rateRxPerSec === 0 ? rx : (rateRxPerSec * 0.7 + rx * 0.3);
    rateTxPerSec = rateTxPerSec === 0 ? tx : (rateTxPerSec * 0.7 + tx * 0.3);
    rateRxBytes = 0; rateTxBytes = 0; rateWindowStart = now;

    // "Heavy" needs an absolute floor as well as a ratio: a trickle of
    // control traffic in both directions satisfies any ratio test while
    // meaning nothing. One MTU per window is the smallest rate that could
    // plausibly be a bulk transfer.
    var floor = pmtu * 1000 / INTERLEAVE_RATE_WINDOW_MS;
    var heavy = (rateRxPerSec > floor) &&
                (rateRxPerSec >= rateTxPerSec * INTERLEAVE_BIDI_RATIO);

    if (heavy === bidirectionalLoad) { bidiStreak = 0; return; }
    if (++bidiStreak >= INTERLEAVE_BIDI_STREAK) {
      bidirectionalLoad = heavy;
      bidiStreak = 0;
      // Only report a change the mode actually acts on — under 'always' or
      // 'never' the latch is advisory and announcing a flip that changes
      // nothing is misleading telemetry.
      if (interleaveMode === 'adaptive') {
        try { ev.emit('interleaveMode', { slicing: !heavy, rxBytesPerSec: Math.round(rateRxPerSec), txBytesPerSec: Math.round(rateTxPerSec) }); } catch (e) {}
      }
    }
  }

  /* Should this message be sliced? */
  function shouldSlice(useIData, numFragments) {
    if (!useIData) return false;                        // classic DATA cannot interleave
    if (numFragments <= INTERLEAVE_SYNC_FRAGMENTS) return false;
    if (interleaveMode === 'never') return false;
    if (interleaveMode === 'adaptive' && bidirectionalLoad) return false;
    return true;
  }

  function txRefillTarget() {
    // Only what the window can absorb RIGHT NOW, plus a quantum of headroom.
    //
    // Queueing a whole window's worth was wrong: absent loss cwnd grows until
    // it hits rwnd, so the target became ~1MB and the pending region turned
    // into a multi-second standing buffer. Since interleaving hands out TSNs
    // at enqueue time, a control message enqueued behind that buffer waits
    // for all of it — measured 5.2s at p95 on a 2Mbit link. Textbook
    // bufferbloat, self-inflicted, in our own queue.
    //
    // The pending region has exactly two jobs: have data ready the instant
    // the window opens, and keep handleSack's hasPending test true so cwnd
    // still grows. Both need only the unfilled part of the window plus a
    // little headroom — not a second copy of the window.
    var w    = Math.min(cwnd, remoteRwnd);
    var room = Math.max(0, w - outstandingBytes);
    return room + INTERLEAVE_QUANTUM * pmtu;
  }

  /* Fill the pending region toward the target, round-robin across the active
   * jobs so their fragments stay interleaved. Returns true if work remains.
   * maxFragments bounds the synchronous burst — a large cwnd would otherwise
   * build hundreds of packets (alloc + CRC each) in one turn and stall the
   * event loop; the caller reschedules for the rest. */
  var _fillingTx = false;   // SCTP-14: reentrancy latch, see below
  function fillTxQueue(maxFragments) {
    if (txJobs.length === 0) return false;
    if (state !== STATE_ESTABLISHED) { txJobs.length = 0; return false; }
    /* REENTRANCY. This function is reachable from inside itself:
     * emitFragment fires 'chunkSent', a listener may call send(); and any
     * path that leads to handlePacket (delayed delivery inside the same
     * process, tests, loopback) can run handleSack -> transmitPending ->
     * fillTxQueue while an outer fill is mid-loop. The outer loop's `order`
     * array then holds stale job references whose cursors the inner call
     * has already advanced — the two interleave their quantum loops on the
     * SAME job and the accounting (built, pendingBytes vs target) splits
     * across two frames. Audit finding: ~11 fragments of a live message
     * silently never emitted (sent=68992 of 81920) when an abandon ran
     * re-entrantly under an active fill. One latch, not a queue of deferred
     * fills: the outer call resumes its own loop with fresh state on the
     * next iteration, and the pump reschedules anyway. */
    if (_fillingTx) return txJobs.length > 0;
    _fillingTx = true;
    try {
      return _fillTxQueueInner(maxFragments);
    } finally {
      _fillingTx = false;
    }
  }

  function _fillTxQueueInner(maxFragments) {
    var target = txRefillTarget();
    var built  = 0;
    var order  = selectActiveJobs();
    while (pendingBytes < target && built < maxFragments && txJobs.length > 0) {
      var progressed = false;
      for (var i = order.length - 1; i >= 0; i--) {
        var job = order[i];
        if (txJobs.indexOf(job) === -1) continue;   // finished earlier this pass
        var more = true;
        for (var q = 0; q < INTERLEAVE_QUANTUM && more; q++) {
          more = emitFragment(job);
          built++;
          progressed = true;
        }
        if (!more) {
          var idx = txJobs.indexOf(job);
          if (idx !== -1) txJobs.splice(idx, 1);
          if (txJobs.length === 0) { order = []; break; }
          order = selectActiveJobs();   // a slot freed — promote a waiter
        }
      }
      if (!progressed) break;
    }
    // "DID WE BUILD ANYTHING", not "is there work left".
    //
    // These are different questions, and returning the second one spun the
    // pump. When the window or the queue is full the while loop above exits
    // without a single iteration, so nothing was built — but txJobs is still
    // non-empty, so the caller re-armed setImmediate and arrived at the same
    // blocked state again, forever.
    //
    // Measured in a live 4-participant demo: Immediate and TickObject at
    // ~214,000/second with PROMISE flat. The check phase is starved, so every
    // await in the process stops progressing and even SIGINT goes unanswered,
    // while timers and UDP keep running — which is why it presents as a hang
    // rather than a busy loop.
    //
    // Nothing is lost by not re-arming: when the window opens, handleSack →
    // transmitPending → refill runs this synchronously.
    return built > 0;
  }

  /* Which jobs get to run this pass. Shortest REMAINING work first, not
   * arrival order.
   *
   * FIFO admission recreated head-of-line blocking one level up. A 40KB
   * summary is 35 fragments — over INTERLEAVE_SYNC_FRAGMENTS, so it becomes a
   * job — and behind a dozen 256KB bulk jobs it waited for all of them:
   * measured 11.2 seconds. The fragment-level interleaving was working
   * perfectly; the message never reached it, because it was still queued.
   *
   * Shortest-remaining-first is the right rule here (it minimises mean
   * completion time), and it is the rule that matches what people expect: the
   * small thing does not wait for the big thing. To stop a steady drip of
   * small messages from starving a large transfer, the OLDEST job always
   * holds one slot regardless of size, so the bulk transfer keeps draining.
   */
  function selectActiveJobs() {
    // Total on an empty list. fillTxQueue re-selects every time a job
    // finishes, and the job that finishes may have been the last one — which
    // is the normal end of every transfer, not an edge case.
    if (txJobs.length === 0) return [];
    var oldest = txJobs[0];
    var pool   = txJobs.slice(1).sort(function (x, y) {
      return (x.numFragments - x.cursor) - (y.numFragments - y.cursor);
    });

    /* ── Byte budget, not just a message count ──
     *
     * Every message being interleaved is a message the RECEIVER cannot
     * deliver yet, so it holds all of its fragments in the reassembly store
     * until the last one lands. Held bytes therefore scale with how many
     * messages we interleave times how big they are — and the peer advertises
     * (its buffer minus what it is holding), so we are spending its receive
     * window to buy our own latency.
     *
     * A fixed count of 4 is fine for 40KB messages and ruinous for 256KB
     * ones: four of those is ~1MB against a 1MB default buffer, and the
     * advertised window collapses. Measured on a saturating transfer, rwnd
     * spiked down to 37KB and throughput halved, while the identical workload
     * on the serial path held a steady ~900KB window. The interleaving was
     * not costing CPU or pacing — it was eating the receiver's buffer.
     *
     * So the active set is capped by both: at most INTERLEAVE_MAX_ACTIVE
     * messages, and at most a fraction of the peer's advertised buffer in
     * total outstanding message bytes. Half leaves the other half as working
     * room so the window never approaches zero. One job is always admitted
     * regardless — a single message larger than the whole budget must still
     * be able to make progress, exactly as it did before interleaving.
     */
    var budget = peerInitialRwnd > 0 ? (peerInitialRwnd >> 1) : (64 * pmtu);
    var chosen = [oldest];
    var used   = oldest.payload.length;
    for (var i = 0; i < pool.length && chosen.length < INTERLEAVE_MAX_ACTIVE; i++) {
      var cand = pool[i];
      if (used + cand.payload.length > budget) break;   // sorted: rest are bigger
      chosen.push(cand);
      used += cand.payload.length;
    }
    return chosen;
  }

  function runTxPump() {
    _txPumpScheduled = false;
    if (txJobs.length === 0) return;
    // The pump outlives the tick that started it, so the association may
    // have gone away underneath us. Queueing DATA after ESTABLISHED means
    // emitting packets with a torn-down verification tag.
    if (state !== STATE_ESTABLISHED) { txJobs.length = 0; return; }

    // Only the first INTERLEAVE_MAX_ACTIVE jobs run (inside fillTxQueue).
    // txJobs is FIFO, so a waiting message is promoted automatically the
    // moment an earlier one finishes and is spliced out — no separate queue,
    // no starvation.
    var _progressed = fillTxQueue(TX_REFILL_BURST);

    scheduleTransmit();   // see note above — required every round
    // Re-arm ONLY on progress. A round that built nothing — window full,
    // queue full — would otherwise reschedule itself into the same blocked
    // state on every check phase, starving the event loop while appearing to
    // do work. The refill resumes from handleSack the moment the window
    // opens, so there is nothing to wait for here.
    if (_progressed) scheduleTxPump();
  }

  /* SCTP-14: drain every outstanding job into sendQueue synchronously.
   * Used by close(), which must get all user data into the queue before
   * SHUTDOWN_PENDING — attemptShutdownTransition gates on sendQueue being
   * EMPTY, so a job still holding fragments would either be lost or, worse,
   * be enqueued after the shutdown drain had already decided it was done. */
  function flushTxJobs() {
    for (var i = 0; i < txJobs.length; i++) {
      var job = txJobs[i];
      while (emitFragment(job)) { /* drain */ }
    }
    txJobs.length = 0;
  }

  /* SCTP-14: drop the un-enqueued remainder of jobs matching a predicate.
   * Fragments already in sendQueue are handled by the existing splice
   * paths; this is only about the tail that never made it there. */
  function dropTxJobs(pred) {
    for (var i = txJobs.length - 1; i >= 0; i--) {
      if (pred(txJobs[i])) txJobs.splice(i, 1);
    }
  }

  // SCTP-13: microtask-coalesced transmit trigger. Collapses a same-tick
  // burst of sendData() calls into one transmitPending() pass so chunks
  // bundle. Idempotent within a tick via the _transmitScheduled flag.
  function scheduleTransmit() {
    if (_transmitScheduled) return;
    _transmitScheduled = true;
    queueMicrotask(flushTransmit);
  }

  // Run the pending transmit pass now (also called synchronously by close()
  // so queued data leaves before SHUTDOWN). Safe to call when nothing is
  // scheduled — it just runs a transmitPending() pass.
  /**
   * Interleave at SEND time, not in the queue (RFC 8260 head-of-line
   * blocking).
   *
   * WHAT THE FIRST ATTEMPT GOT WRONG, because it is the thing to know before
   * touching this again: it reordered the pending region of sendQueue so
   * fragments of different messages alternated. Control latency p95 fell from
   * 585ms to 27ms — and throughput went to ZERO. Only 9 of ~240 messages
   * arrived.
   *
   * sendQueue is required to be in ascending TSN order. At least four places
   * depend on it, and they are all hot:
   *
   *   handleSack    drains acknowledged entries from the FRONT and stops at
   *                 the first TSN above the cumulative ack (twice, lines
   *                 ~1199 and ~1563)
   *   forwardTsn    computes advancedPeerAckPoint as sendQueue[0].tsn - 1
   *   T3 timeout    treats sendQueue[0] as the oldest outstanding chunk
   *
   * TSNs are allocated in send() as fragments are built, so reordering the
   * queue divorces queue position from TSN order: the drain loop hits an
   * out-of-order TSN, stops early, and the queue never empties. Everything
   * downstream stalls behind it.
   *
   * THE FIX IS TO SCHEDULE EARLIER. Interleaving has to happen where TSNs are
   * assigned, so the wire order and the queue order stay the same thing. That
   * means send() must be able to emit a message's fragments in more than one
   * pass, yielding between them — a change to how a message is enqueued, not
   * to how the queue is drained.
   *
   * Deliberately not attempted here: it restructures the send path, and the
   * measurement above shows exactly how a plausible-looking change to this
   * area fails. Stages 1-2b stand on their own — the wire format is
   * negotiated and working against Firefox — and this is the remaining piece.
   */

  function flushTransmit() {
    _transmitScheduled = false;
    var wasNoInFlight = (inFlightCount === 0);
    transmitPending();
    if (wasNoInFlight && inFlightCount > 0) startT3Timer();
  }

  /* SCTP-8 + SCTP-9: walk sendQueue, promote pending entries to in-flight
   * while outstandingBytes + entry.payloadLen <= effectiveWindow, where
   * effectiveWindow = min(cwnd, remoteRwnd). cwnd governs congestion
   * (our rate); rwnd governs flow control (peer's buffer). Whichever is
   * tighter wins.
   *
   * Special case: per RFC 4960 §6.1, the sender MAY transmit one full
   * MTU even when the offered window is zero, to probe for window
   * re-opening. We honour this when outstandingBytes === 0 (nothing in
   * flight) and the effective window is 0 — send ONE chunk so peer's
   * next SACK tells us whether the window has opened.
   *
   * Performance: queue invariant says sendQueue[0..inFlightCount-1] are
   * all in-flight and sendQueue[inFlightCount..] are all pending. So we
   * skip directly to the first pending — no per-entry inFlight check,
   * no wasted iterations over the (potentially long) in-flight prefix.
   * Hot path: gets called from sendData and handleSack, both per-message.
   */
  function transmitPending() {
    // SCTP-14: top the queue up FIRST, in this same turn. A SACK that opened
    // the window must find data ready to go, and handleSack's cwnd-growth
    // test must find a non-empty pending region.
    if (txJobs.length > 0) fillTxQueue(TX_REFILL_BURST);
    if (inFlightCount === sendQueue.length) return;   // nothing pending
    var effectiveWindow = Math.min(cwnd, remoteRwnd);
    // ── SCTP-14: window-probe condition (RFC 4960 §6.1) ──
    //
    // The probe must fire whenever nothing is in flight and the next chunk
    // does not fit — NOT only when the window is exactly zero. A window that
    // is non-zero but smaller than one fragment (say 880 bytes against a
    // 1168-byte fragment) failed the old `effectiveWindow === 0` test, so no
    // chunk was sent, so no SACK came back, so the window was never updated:
    // a permanent deadlock with a full send queue, an idle link, and no
    // retransmit timer running because nothing was ever in flight.
    //
    // It is reachable without interleaving but interleaving walks straight
    // into it. The receiver advertises (maxReceiveBufferSize − bytes held in
    // reassembly), and interleaving is precisely the feature that keeps N
    // messages PARTIALLY assembled at once instead of completing them one at
    // a time. Held bytes therefore scale with concurrency, the advertised
    // window shrinks toward zero, and it passes through "smaller than one
    // fragment" on the way — where the old condition left it stuck. That is
    // the sharp "works at 4 messages, dead at 8" threshold: it is not a
    // count, it is the point where N partial messages fill the peer's
    // receive buffer.
    //
    // Sending one chunk into a too-small window is what the RFC allows and
    // what usrsctp and the Linux stack do: the peer buffers or drops it, but
    // either way it SACKs, and that SACK carries the current a_rwnd.
    var probeAllowed    = (outstandingBytes === 0 && inFlightCount === 0);
    var now = Date.now();

    // ── Opportunistic chunk bundling (RFC 4960 §6.10) ──
    // Rather than emit one UDP datagram per DATA chunk, we pack as many
    // window-eligible chunks as fit under the PMTU into a single packet,
    // then emit that. This is what usrsctp/libwebrtc do at output time.
    //
    // It is NOT Nagle: we never *wait* for more data. We bundle only what
    // is already queued at this instant — so a lone send() still goes out
    // immediately (one chunk, one packet, zero added latency), while a
    // burst that has piled up in sendQueue (same-tick sends coalesced via
    // scheduleTransmit(), or a backlog released when a SACK opens the
    // window) rides out in full packets. Adaptivity is intrinsic to "how
    // much is queued right now", with no timer and no mode switch.
    //
    // Mechanics (option-b): each entry.packet is a complete standalone wire
    // packet [common header(12) | chunk(padded to 4)]. entry.packet stays
    // intact (retransmit re-emits it as-is). To bundle we take each chunk's
    // bytes = entry.packet.subarray(12) — already 4-byte padded, so chunks
    // concatenate with correct alignment — under ONE fresh common header,
    // and recompute the CRC32C over the whole datagram.
    //
    // maxChunksBytes = pmtu - 12 (common header). We flush the current
    // bundle when the next chunk wouldn't fit, then start a new bundle.
    var maxChunksBytes = pmtu - SCTP_HEADER_OVERHEAD;
    var bundle    = [];     // entries pending flush into one packet
    var bundleLen = 0;      // bytes of chunk-data currently bundled

    function flushBundle() {
      if (bundle.length === 0) return;
      if (bundle.length === 1) {
        // Single chunk — emit its standalone packet untouched (byte-for-
        // byte identical to the non-bundled path; no concat, no CRC redo).
        _sctpDiagPacket(bundle[0].packet, 'bundle');
        ev.emit('packet', bundle[0].packet);
      } else {
        var parts = new Array(bundle.length + 1);
        var header = Buffer.allocUnsafe(SCTP_HEADER_OVERHEAD);
        header.writeUInt16BE(localPort,              0);
        header.writeUInt16BE(remotePort,             2);
        header.writeUInt32BE(remoteVerificationTag,  4);
        header.writeUInt32LE(0,                      8);   // checksum placeholder
        parts[0] = header;
        for (var b = 0; b < bundle.length; b++) {
          // chunk bytes = everything past the common header; already
          // 4-byte padded, so chunks concatenate correctly aligned.
          parts[b + 1] = bundle[b].packet.subarray(SCTP_HEADER_OVERHEAD);
        }
        var pkt = Buffer.concat(parts);
        pkt.writeUInt32LE(crc32c(pkt), 8);                 // CRC over whole datagram
        ev.emit('packet', pkt);
        sctpStats.chunksBundled += bundle.length;
        sctpStats.bundledPackets++;
      }
      bundle    = [];
      bundleLen = 0;
    }

    for (var i = inFlightCount; i < sendQueue.length; i++) {
      var entry = sendQueue[i];
      // Invariant: entry.inFlight === false here.
      if ((outstandingBytes + entry.payloadLen) > effectiveWindow && !probeAllowed) {
        break;   // stop at the first non-fitting entry
      }
      probeAllowed = false;   // probe is one-shot: only the first chunk of a
                              // pass may exceed the window, and only when the
                              // link is otherwise idle
      // SCTP-14: a chunk released by T3 (RFC 4960 §6.3.3 E3) is going back out
      // as a RETRANSMISSION, not a first transmission. Counting it as one
      // keeps Karn's algorithm honest — sampling RTT off a resent chunk is
      // how an RTO collapses toward the minimum during exactly the loss burst
      // that needs it long — and keeps the PR-SCTP retransmit budget real.
      if (entry.needsRetx) {
        entry.needsRetx = false;
        entry.retransmits++;
        sctpStats.chunksRetransmitted++;
      }
      entry.inFlight    = true;
      entry.sentAt      = now;     // first-transmit timestamp (RTT via Karn)
      outstandingBytes += entry.payloadLen;
      pendingBytes     -= entry.payloadLen;
      inFlightCount++;

      var chunkLen = entry.packet.length - SCTP_HEADER_OVERHEAD;
      // An already-MTU-sized fragment can't share a packet: flush the
      // current bundle, then emit it solo (its own standalone packet).
      if (chunkLen > maxChunksBytes) {
        flushBundle();
        ev.emit('packet', entry.packet);
        continue;
      }
      // Won't fit alongside the current bundle → flush and start fresh.
      if (bundleLen + chunkLen > maxChunksBytes) flushBundle();
      bundle.push(entry);
      bundleLen += chunkLen;
    }
    flushBundle();   // emit the final partial bundle
  }

  /* SCTP-8: pion-style receive-window credit (getMyReceiverWindowCredit).
   *
   * We advertise (maxReceiveBufferSize − bytesHeldInReassembly) instead of
   * a fixed window, so the peer is told to slow down when our reassembly /
   * reorder buffers fill and to resume as they drain. This is the exact
   * shape pion uses, and mirrors usrsctp/Linux (minus Linux's optional
   * >>1 halving — we advertise the full remaining space like pion).
   *
   * CRITICAL SAFETY PROPERTY: this is recomputed from the LIVE buffer
   * contents on every SACK, NOT tracked as a running counter. A running
   * counter that mis-decrements is the classic a_rwnd bug (window stuck at
   * 0 forever → total receive stall) that the Linux kernel fixed in
   * ef2820a7. Deriving from ground truth each time makes that class of bug
   * structurally impossible: if the buffers are empty, the window is full,
   * period.
   *
   * Because this stack delivers messages synchronously (the 'data' event),
   * assembled messages don't linger — held bytes are normally ~0, so the
   * window sits near maxReceiveBufferSize and throughput is unconstrained.
   * It only shrinks during active fragmentation or SSN-reordering, which is
   * exactly when flow control should engage. A useful side effect: the
   * pendingMsgs / fragStore overflow paths become effectively unreachable
   * with a compliant peer, because the advertised window closes before the
   * reorder buffer can fill (fixing the silent-drop-on-overflow hazard).
   *
   * Cost: O(total buffered fragments/messages), which is bounded
   * (MAX_FRAGS_PER_STREAM / MAX_PENDING_MSGS_PER_STREAM) and normally zero.
   * Called once per SACK (delayed-ACK batched), not per chunk.
   */
  function myReceiverWindowCredit() {
    var held = 0;
    var fk = Object.keys(fragStore);
    for (var i = 0; i < fk.length; i++) {
      fragStore[fk[i]].forEach(function (f) { held += f.payload.length; });
    }
    var pk = Object.keys(pendingMsgs);
    for (var j = 0; j < pk.length; j++) {
      pendingMsgs[pk[j]].forEach(function (m) { held += m.payload.length; });
    }
    if (held >= maxReceiveBufferSize) return 0;
    return maxReceiveBufferSize - held;
  }

  function sendSack() {
    // RFC 4960 §3.3.4 SACK chunk:
    //   Cumulative TSN Ack       (4)
    //   Advertised Receiver Window Credit a_rwnd (4)
    //   Number of Gap Ack Blocks (2)
    //   Number of Duplicate TSNs (2)
    //   For each gap block: Start (2) + End (2)  — offsets from cumTsn
    //   For each dup TSN: TSN (4)
    //
    // Pre-fix this always emitted zero gap blocks and zero dup TSNs (bug
    // B5), which meant fast retransmit never fired on the peer side and
    // the peer couldn't tell that some TSNs had reached us twice.
    var gaps = computeGapBlocks();
    var dups = dupTsns;

    // ── SCTP-14: bound the SACK to one packet ──
    // computeGapBlocks emits one block per received range with no ceiling.
    // Under loss the range count grows without limit and the SACK chunk
    // grows past the PMTU: the packet is then fragmented or dropped by the
    // path, so the sender gets NO acknowledgement at all — exactly when it
    // most needs one — and recovery falls back to T3 timeouts.
    //
    // Interleaving makes this reachable much sooner. Serial sending loses a
    // contiguous run of TSNs (one gap block); interleaving spreads a
    // message's fragments across the TSN space, so the same loss rate
    // produces many small scattered gaps instead of a few large ones.
    //
    // Truncate to what fits, keeping the LOWEST blocks: those sit just above
    // the cumulative ack, they are the ones that drive fast retransmit, and
    // the sender re-learns the rest from the next SACK as cumTsn advances.
    // Duplicates are the first thing sacrificed — they are diagnostic, while
    // gap blocks are what actually drives recovery.
    var sackCapacity = pmtu - SCTP_HEADER_OVERHEAD - 4 /* chunk header */ - 12 /* SACK fixed fields */;
    var maxEntries   = Math.max(1, Math.floor(sackCapacity / 4));
    if (gaps.length > maxEntries) gaps = gaps.slice(0, maxEntries);
    if (gaps.length + dups.length > maxEntries) {
      dups = dups.slice(0, Math.max(0, maxEntries - gaps.length));
    }

    var bodyLen = 12 + gaps.length * 4 + dups.length * 4;
    var body = Buffer.alloc(bodyLen);

    body.writeUInt32BE(lastCumulativeTsn, 0);
    // Advertised receive window: maxReceiveBufferSize minus what we're
    // currently holding un-delivered (pion getMyReceiverWindowCredit).
    // Dynamic, so it shrinks under reassembly/reorder pressure and the
    // peer applies real flow control. Was a fixed DEFAULT_A_RWND (64 KB).
    body.writeUInt32BE(myReceiverWindowCredit(), 4);
    body.writeUInt16BE(gaps.length, 8);
    body.writeUInt16BE(dups.length, 10);

    var off = 12;
    for (var i = 0; i < gaps.length; i++) {
      body.writeUInt16BE(gaps[i].start, off);
      body.writeUInt16BE(gaps[i].end,   off + 2);
      off += 4;
    }
    for (var j = 0; j < dups.length; j++) {
      body.writeUInt32BE(dups[j], off);
      off += 4;
    }

    sendChunk(CHUNK_SACK, 0, body, remoteVerificationTag);

    // Reset the dup list — peer's been told once, we don't want to keep
    // re-reporting the same dups in every SACK. (RFC 4960 §6.7.1: each
    // SACK is a snapshot; dups reset between SACKs.)
    if (dupTsns.length > 0) dupTsns = [];
  }

  /* SCTP-13: chunk bundling (RFC 4960 §6.10).
   *
   * One UDP datagram can carry multiple SCTP chunks under the shared
   * common header. Pre-SCTP-13 every sendChunk emitted its own packet,
   * so an incoming packet with 5 DATA chunks produced 5 separate SACKs
   * instead of one bundled into a single reply, and any HEARTBEAT_ACK
   * + SACK pair went out as two packets.
   *
   * We bundle reactively: when sendChunk is called while inside
   * handlePacket (i.e., as a reaction to incoming chunks), it queues
   * into pendingOutChunks instead of emitting. handlePacket flushes
   * at the end, building one packet from the queue.
   *
   * DATA chunks bypass this path entirely (they go through sendData
   * with their own pre-built packets — see P2). So bundling here is
   * for control/ack traffic only, which is exactly the workload that
   * benefits most from coalescing.
   *
   * vtag is the peer's verification tag — same for every chunk in a
   * given handlePacket window post-handshake. We assert that all
   * queued chunks share a vtag; if not (e.g., racy state transition),
   * we flush before queueing the differing one.
   */
  var packetDepth      = 0;
  var pendingOutChunks = [];
  var sackPendingThisPacket = false;

  /* SCTP-2: delayed ACK (RFC 4960 §6.2).
   *
   * Pre-SCTP-2 we sent one SACK per incoming SCTP packet that contained
   * DATA. RFC says we MAY defer:
   *   - SACK at least every SECOND packet (not chunk).
   *   - SACK within 200ms of any unacknowledged DATA.
   *   - SACK IMMEDIATELY on duplicate or out-of-order DATA.
   *
   * Result on quiet bursty workloads: ~50% fewer SACKs on the wire.
   *
   *   sackUnackedPackets    — count of packets with DATA that haven't
   *                          generated a SACK yet. Reset on emit.
   *   sackImmediateRequired — true iff this packet contained a duplicate
   *                          or created a gap; forces a SACK at epilogue.
   *   delayedSackTimer      — timer for the 200ms deadline. Started when
   *                          a packet defers SACK and the timer isn't
   *                          already running. Cleared on emit.
   */
  var sackUnackedPackets    = 0;
  var sackImmediateRequired = false;
  var delayedSackTimer      = null;

  function sendChunk(chunkType, chunkFlags, chunkBody, vtag) {
    // RFC 4960 §6.10 forbids bundling of INIT (rule 1), INIT-ACK (rule 2),
    // and SHUTDOWN-COMPLETE (rule 3): they MUST be the only chunk in the
    // SCTP packet. Force emit-without-bundling regardless of packetDepth.
    // (INIT itself is always sent from outside handlePacket so it'd hit
    // emitOneChunk anyway, but we guard explicitly for safety.)
    if (chunkType === CHUNK_INIT ||
        chunkType === CHUNK_INIT_ACK ||
        chunkType === CHUNK_SHUTDOWN_COMPLETE) {
      // Flush whatever's queued before us so it doesn't ride alongside.
      if (pendingOutChunks.length > 0) flushOutChunks();
      emitOneChunk(chunkType, chunkFlags, chunkBody, vtag);
      return;
    }

    if (packetDepth > 0) {
      // Inside handlePacket — queue for bundle.
      // Different vtag forces an early flush (rare; only at handshake
      // boundaries where peer's vtag changes).
      if (pendingOutChunks.length > 0 && pendingOutChunks[0].vtag !== vtag) {
        flushOutChunks();
      }
      pendingOutChunks.push({ chunkType: chunkType, chunkFlags: chunkFlags, chunkBody: chunkBody, vtag: vtag });
      return;
    }
    // Direct emit path (timer-driven sends, sendData fast path doesn't
    // come here, etc.).
    emitOneChunk(chunkType, chunkFlags, chunkBody, vtag);
  }

  /**
   * Describe an OUTGOING SCTP packet (LEMON_DEBUG=1 / WEBRTC_DEBUG=1).
   *
   * A peer that rejects a packet at the DTLS layer with decode_error has
   * already decrypted it successfully and failed to make sense of what was
   * inside — so the question is which chunk we sent, not how it was
   * protected. This walks the packet the way the peer does: every chunk
   * type, its length, and for DATA the stream, sequence and PPID, which is
   * what identifies a DCEP control message versus user data.
   */
  function _sctpDiagPacket(pkt, where) {
    try {
      if (typeof process === 'undefined' || !process.env ||
          (process.env.LEMON_DEBUG !== '1' && process.env.WEBRTC_DEBUG !== '1')) return;
      var NAMES = { 0:'DATA', 1:'INIT', 2:'INIT_ACK', 3:'SACK', 4:'HEARTBEAT',
                    5:'HEARTBEAT_ACK', 6:'ABORT', 7:'SHUTDOWN', 8:'SHUTDOWN_ACK',
                    9:'ERROR', 10:'COOKIE_ECHO', 11:'COOKIE_ACK', 14:'SHUTDOWN_COMPLETE',
                    15:'AUTH', 64:'I_DATA', 128:'ASCONF_ACK', 130:'RE_CONFIG',
                    131:'PAD', 192:'FORWARD_TSN', 193:'ASCONF', 194:'I_FORWARD_TSN' };
      var PPIDS = { 50:'DCEP', 51:'STRING', 52:'BINARY_PARTIAL', 53:'BINARY',
                    56:'STRING_PARTIAL', 57:'STRING_EMPTY', 58:'BINARY_EMPTY' };
      var parts = [];
      var off = 12;
      while (off + 4 <= pkt.length) {
        var ct = pkt[off];
        var clen = pkt.readUInt16BE(off + 2);
        if (clen < 4) { parts.push('MALFORMED(len=' + clen + ')'); break; }
        var desc = (NAMES[ct] || ('type' + ct)) + '(' + clen + ')';
        if (ct === 0 && off + 16 <= pkt.length) {
          var tsn = pkt.readUInt32BE(off + 4);
          var sid = pkt.readUInt16BE(off + 8);
          var ssn = pkt.readUInt16BE(off + 10);
          var ppid = pkt.readUInt32BE(off + 12);
          desc += ' tsn=' + tsn + ' sid=' + sid + ' ssn=' + ssn +
                  ' ppid=' + ppid + (PPIDS[ppid] ? '/' + PPIDS[ppid] : '') +
                  ' flags=0x' + pkt[off + 1].toString(16);
          if (ppid === 50 && off + 17 <= pkt.length) {
            var dcep = pkt[off + 16];
            desc += ' dcep=' + (dcep === 3 ? 'OPEN' : dcep === 2 ? 'ACK' : dcep);
          }
        }
        parts.push(desc);
        var padded = clen + ((clen % 4) ? 4 - (clen % 4) : 0);
        off += padded;
      }
      console.log('[sctp-tx] len=' + pkt.length + ' ' + parts.join(' + ') +
                  (where ? '  <' + where + '>' : ''));
    } catch (e) {}
  }

  function emitOneChunk(chunkType, chunkFlags, chunkBody, vtag) {
    var chunkLen = 4 + chunkBody.length;
    var chunkPadded = chunkLen;
    if (chunkPadded % 4 !== 0) chunkPadded += 4 - (chunkPadded % 4);

    var pktLen = 12 + chunkPadded;
    var pkt = Buffer.alloc(pktLen);

    pkt.writeUInt16BE(localPort, 0);
    pkt.writeUInt16BE(remotePort, 2);
    pkt.writeUInt32BE(vtag, 4);
    // bytes 8-11 checksum, filled after CRC

    pkt[12] = chunkType;
    pkt[13] = chunkFlags;
    pkt.writeUInt16BE(chunkLen, 14);
    chunkBody.copy(pkt, 16);

    pkt.writeUInt32LE(crc32c(pkt), 8);
    _sctpDiagPacket(pkt, 'emitOneChunk');
    ev.emit('packet', pkt);
  }

  function flushOutChunks() {
    if (pendingOutChunks.length === 0) return;
    if (pendingOutChunks.length === 1) {
      // Common case: just one queued chunk. Skip the bundling overhead.
      var c = pendingOutChunks[0];
      pendingOutChunks.length = 0;
      emitOneChunk(c.chunkType, c.chunkFlags, c.chunkBody, c.vtag);
      return;
    }

    // Compute total packet size (each chunk header 4 + body, padded).
    var total = 12;   // common header
    var sizes = new Array(pendingOutChunks.length);
    for (var i = 0; i < pendingOutChunks.length; i++) {
      var len = 4 + pendingOutChunks[i].chunkBody.length;
      var padded = len + ((len % 4) ? (4 - len % 4) : 0);
      sizes[i] = { len: len, padded: padded };
      total += padded;
    }

    var pkt = Buffer.alloc(total);
    var vtag = pendingOutChunks[0].vtag;
    pkt.writeUInt16BE(localPort, 0);
    pkt.writeUInt16BE(remotePort, 2);
    pkt.writeUInt32BE(vtag, 4);
    // bytes 8-11 checksum, filled after CRC

    var off = 12;
    for (var j = 0; j < pendingOutChunks.length; j++) {
      var c = pendingOutChunks[j];
      pkt[off]     = c.chunkType;
      pkt[off + 1] = c.chunkFlags;
      pkt.writeUInt16BE(sizes[j].len, off + 2);
      c.chunkBody.copy(pkt, off + 4);
      // bytes after len-end up to padded boundary stay zero from alloc
      off += sizes[j].padded;
    }

    pkt.writeUInt32LE(crc32c(pkt), 8);
    pendingOutChunks.length = 0;
    ev.emit('packet', pkt);
  }



  /* ========================= SCTP-1: reliability ========================= */

  /* The T3-rtx timer + retransmit machinery + RTT estimation. Three
   * pieces, lock-stepped:
   *
   *   1. T3-rtx timer (RFC 4960 §6.3.2). One per association, covering
   *      the OLDEST unacked chunk. Started when sendQueue goes from
   *      empty to non-empty; restarted whenever the oldest entry rotates
   *      (handleSack drained some entries, the new sendQueue[0] is a
   *      different chunk); cleared when the queue empties.
   *
   *   2. Retransmit on T3 expiry. Bump retransmits, refresh sentAt, re-
   *      emit the chunk, double the RTO (capped at RTO_MAX_MS), and
   *      restart the timer. After ASSOC_MAX_RETRANS expiries on the same
   *      chunk we declare path failure and tear down — the peer is
   *      provably unreachable.
   *
   *   3. RTT estimation (RFC 4960 §6.3.1). Karn's algorithm: only
   *      sample RTT from chunks that were never retransmitted. SRTT and
   *      RTTVAR are updated exponentially (α=1/8, β=1/4). RTO is then
   *      SRTT + max(G, 4*RTTVAR), bounded to [RTO_MIN_MS, RTO_MAX_MS].
   *      Pre-first-sample we use RTO_INITIAL_MS verbatim.
   *
   * Fast retransmit is in handleSack — it doesn't touch this timer
   * directly, just bumps a missingReports counter and re-emits when it
   * crosses FAST_RETRANSMIT_THRESHOLD.
   */

  function startT3Timer() {
    clearT3Timer();
    if (sendQueue.length === 0) return;
    t3Timer = setTimeout(onT3Expire, rto);
    if (t3Timer && typeof t3Timer.unref === 'function') t3Timer.unref();
  }

  function clearT3Timer() {
    if (t3Timer) {
      clearTimeout(t3Timer);
      t3Timer = null;
    }
  }

  function onT3Expire() {
    t3Timer = null;
    // State guard: the association may have torn down between when the
    // timer was scheduled and when it fired (e.g., close() during the
    // timeout window). Don't retransmit on a closed/closing channel.
    if (state !== STATE_ESTABLISHED &&
        state !== STATE_SHUTDOWN_PENDING &&
        state !== STATE_SHUTDOWN_SENT) {
      return;
    }
    // SCTP-8: nothing in flight → no T3 work. Pending entries don't get
    // covered by T3 (they were never transmitted; rwnd-deferred).
    if (inFlightCount === 0) return;

    sctpStats.rtoExpiries++;

    // Queue invariant: sendQueue[0..inFlightCount-1] are all in-flight,
    // and we got here only when inFlightCount > 0. So sendQueue[0] is
    // always the oldest in-flight entry — no search needed.
    var oldest = sendQueue[0];
    var now    = Date.now();

    // SCTP-6: PR-SCTP abandon check. If the user marked this message with
    // a maxRetransmits/maxLifetime that's now exceeded, drop the whole
    // message instead of retransmitting. RFC 3758 §3.4.4 says we SHOULD
    // NOT increase RTO on abandon (path isn't necessarily slow — we just
    // chose to give up on this chunk).
    if (shouldAbandon(oldest, now)) {
      abandonMessage(oldest.messageSeq);
      if (inFlightCount > 0) startT3Timer();   // current rto, no doubling
      return;
    }

    // Per RFC 4960 §6.3.3: retransmit the oldest unacked chunk and double
    // the RTO. (Some implementations retransmit all chunks below cwnd; we
    // keep it minimal here. SCTP-9's congestion control will revisit.)
    oldest.retransmits++;

    if (oldest.retransmits > assocMaxRetrans) {
      // Path is dead. RFC 4960 §8.2: declare unreachable and send ABORT.
      // sendAbort uses our remoteVerificationTag (T-bit clear); peer
      // tears down on receipt without acking, completing the implicit
      // close. Without this peer keeps retransmitting until their own
      // T3 budget exhausts.
      sctpStats.pathFailures++;
      try { ev.emit('pathFailure', { retransmits: oldest.retransmits }); } catch (e) {}
      sendAbort();
      finalizeClose();
      return;
    }

    // ── SCTP-14: RFC 4960 §6.3.3 E3 — release the whole outstanding window ──
    //
    // The old code retransmitted sendQueue[0] and left every OTHER in-flight
    // chunk marked inFlight = true. Those chunks were presumed lost, yet they
    // kept their share of outstandingBytes forever, so transmitPending's
    //
    //     (outstandingBytes + entry.payloadLen) > effectiveWindow  ->  break
    //
    // test could never pass again: cwnd had just been cut to one MTU while
    // outstandingBytes still counted the entire pre-loss window. From that
    // point the association advanced only by one T3 retransmit per RTO, with
    // the RTO doubling each time — and because only one chunk was ever in
    // flight, the peer's SACKs carried no gap blocks, so fast retransmit
    // could not fire either. Measured: 10 retransmits in 80 seconds, all T3,
    // zero fast retransmits, cwnd pinned at 1200.
    //
    // E3 says to mark all outstanding data for retransmission and then send
    // what cwnd allows. Clearing inFlight puts them back in the pending
    // region, where transmitPending re-sends them in TSN order as the window
    // reopens. needsRetx keeps two things honest on the way back out: the
    // chunk must count as a retransmission, and it must not produce an RTT
    // sample (Karn's algorithm — sendQueue's retransmits === 0 test is what
    // gates that).
    //
    // Interleaving is what made this pre-existing bug load-bearing. Serial
    // sending lays a message's fragments in one contiguous TSN run, so when a
    // T3 finally pushes sendQueue[0] through, the cumulative ack sweeps the
    // whole already-received run behind it and frees a large block of
    // outstandingBytes in one go — the association claws its way out.
    // Interleaved, the holes are scattered among four messages, each cum-ack
    // advance stops at the next hole a few chunks later, and the recovery
    // never gets going.
    for (var ri = 0; ri < inFlightCount; ri++) {
      var re = sendQueue[ri];
      re.inFlight  = false;
      re.needsRetx = true;
      pendingBytes += re.payloadLen;   // SCTP-14: moved in-flight -> pending
    }
    outstandingBytes = 0;
    inFlightCount    = 0;

    oldest.sentAt = now;
    oldest.missingReports = 0;   // expiry supersedes any in-flight gap reporting
    // Retransmit the oldest chunk here and now; the rest go out through
    // transmitPending as cwnd (one MTU, then slow start) permits.
    oldest.needsRetx = false;    // already counted via oldest.retransmits++ above
    oldest.inFlight  = true;
    outstandingBytes = oldest.payloadLen;
    pendingBytes    -= oldest.payloadLen;
    inFlightCount    = 1;
    // P2: re-emit pre-built packet (zero-alloc retransmit path).
    ev.emit('packet', oldest.packet);
    sctpStats.chunksRetransmitted++;

    // SCTP-9: T3 expiry signals heavy congestion. Per RFC 4960 §7.2.3:
    //   ssthresh = max(cwnd/2, 4*MTU)
    //   cwnd     = 1*MTU
    //   pba      = 0
    // This is the most aggressive backoff (full slow-start restart).
    // We also leave fast-retransmit untouched for in-flight chunks —
    // they already had their chance.
    var mtu = pmtu;
    ssthresh          = Math.max((cwnd / 2) | 0, 4 * mtu);
    cwnd              = mtu;
    partialBytesAcked = 0;

    rto = Math.min(rto * 2, rtoMaxMs);
    startT3Timer();
  }

  /* ─── SCTP-6: PR-SCTP abandon helpers ───
   *
   * shouldAbandon — gate: returns true iff this entry should NOT be
   * retransmitted again, per its per-message limits. Two ways to qualify:
   *
   *   1. retransmits >= maxRetransmits — we've hit the budget. Note the
   *      comparison is `>=`, evaluated BEFORE incrementing retransmits.
   *      maxRetransmits=0 means "send once, never resend" (matches W3C).
   *
   *   2. firstSentAt + maxLifetime <= now — the message is past its
   *      deadline. firstSentAt is fixed at sendData time and never
   *      updated by retransmit (sentAt is the one that updates).
   *
   * If peer didn't advertise FORWARD-TSN we never abandon. (sendData
   * already nulls maxRetransmits/maxLifetime in that case, but we
   * defend in depth: the test runs anyway.)
   */
  function shouldAbandon(entry, now) {
    if (!peerSupportsForwardTsn) return false;
    if (entry.maxRetransmits != null && entry.retransmits >= entry.maxRetransmits) return true;
    if (entry.maxLifetime    != null && (now - entry.firstSentAt) >= entry.maxLifetime) return true;
    return false;
  }

  /* abandonMessage — removes ALL fragments of a message from sendQueue.
   *
   * PR-SCTP abandonment is per-MESSAGE not per-fragment: leaving fragments
   * F1, F3 in the queue while abandoning F2 produces an unreassemblable
   * orphan at the peer (BEGIN+END fragments arrive but middle is missing
   * forever). So we splice every entry with the same messageSeq.
   *
   * For each abandoned fragment we emit 'chunkAcked' so the upper layer's
   * bufferedAmount accounting drains the bytes — from the user's POV the
   * send is "complete" regardless of fate. Then maybeFwdTsn pushes a
   * FORWARD-TSN to the peer to advance their cumulative TSN past the
   * gap we've just opened up at the head of sendQueue.
   */

  /* Helper: decrement SCTP-8 counters for an in-flight entry that's
   * being removed from sendQueue, and fire chunkAcked so bufferedAmount
   * stays in sync. The entry is the splice/drained chunk (still has its
   * payloadLen/streamId/ppid/inFlight fields populated).
   *
   * Called from four sites (handleSack drain, handleShutdown drain,
   * handleIncomingResetRequest splice, abandonMessage splice) — each
   * was previously inlining the same five-line dance.
   */
  function chunkRemoved(entry) {
    if (entry.inFlight) {
      outstandingBytes -= entry.payloadLen;
      inFlightCount--;
    } else {
      pendingBytes -= entry.payloadLen;   // SCTP-14
    }
    try {
      ev.emit('chunkAcked', {
        streamId: entry.streamId,
        ppid:     entry.ppid,
        bytes:    entry.payloadLen,
      });
    } catch (e) { /* listener errors don't break protocol processing */ }
  }

  function abandonMessage(messageSeq) {
    var anyAbandoned = false;
    // SCTP-14: a message can be abandoned while the pump is still feeding
    // it. Kill the job first, or the fragments it goes on to enqueue would
    // re-open a hole we just told the peer to skip past with FORWARD-TSN.
    dropTxJobs(function (j) { return j.messageSeq === messageSeq; });
    for (var i = sendQueue.length - 1; i >= 0; i--) {
      if (sendQueue[i].messageSeq === messageSeq) {
        var entry = sendQueue.splice(i, 1)[0];
        sctpStats.chunksAbandoned++;

        // SCTP-6 (Stream/SSN pairs): for ordered abandoned messages,
        // remember the highest SSN we've abandoned per stream. Sent in
        // the FORWARD-TSN body so peer's recvSSN can jump past the gap
        // — without this, peer holds the stream waiting for a message
        // that will never arrive (until the MAX_PENDING_MSGS_PER_STREAM
        // safety cap kicks in, which is a coarse fallback).
        if (peerSupportsIData) {
          // SCTP-14 / RFC 8260 §2.3.1: under interleaving the skip list
          // carries 32-bit MIDs, and — unlike classic FORWARD-TSN — entries
          // exist for UNORDERED messages too (their MID space also has a
          // hole the receiver must be told to not wait on). Keyed by
          // sid + U-bit, since the two MID spaces are independent.
          var iKey = entry.streamId + (entry.unordered ? 'u' : 'o');
          var iPrev = abandonedMidPerStream[iKey];
          if (iPrev === undefined || tsnGt(entry.mid, iPrev.mid)) {
            abandonedMidPerStream[iKey] = { mid: entry.mid, tsn: entry.tsn };
          } else if (entry.mid === iPrev.mid && tsnGt(entry.tsn, iPrev.tsn)) {
            iPrev.tsn = entry.tsn;   // same message, later fragment: track its highest TSN
          }
        } else if (!entry.unordered) {
          var prev = abandonedSSNPerStream[entry.streamId];
          if (prev === undefined || ssnGt(entry.ssn, prev)) {
            abandonedSSNPerStream[entry.streamId] = entry.ssn;
          }
        }

        chunkRemoved(entry);
        anyAbandoned = true;
      }
    }
    if (anyAbandoned) {
      maybeFwdTsn();
      // SCTP-14: lost wakeup. Abandoning frees in-flight window space, but
      // nothing here restarted the sender. If the abandoned chunks were the
      // last ones in flight, the association is left with inFlightCount = 0,
      // outstandingBytes = 0, a queue full of PENDING chunks, and no timer:
      // T3 is cleared precisely because nothing is in flight, and the only
      // other trigger — handleSack — needs a SACK that will never come,
      // because nothing is being sent. Measured: 151 chunks frozen
      // indefinitely with an idle link and a wide-open window.
      //
      // Reachable from the T3 abandon branch too, which returns without any
      // transmit pass. Scheduling one here covers every abandon path at once.
      scheduleTransmit();
    }
  }

  /* maybeFwdTsn — emit a FORWARD-TSN if the head of sendQueue indicates
   * we've abandoned chunks below it.
   *
   * advancedPeerAckPoint is (sendQueue[0].tsn - 1) when non-empty, else
   * (localTsn - 1). It represents the highest TSN such that everything
   * ≤ it is either acked or abandoned — the value peer's cumTsn is
   * ALLOWED to advance to.
   *
   * We only send when advPt strictly increases (`tsnGt`) — same value
   * as last FORWARD-TSN means peer either already got our previous
   * FORWARD-TSN (good) or didn't but resending the identical chunk
   * is wasted bandwidth (we'll retry on the NEXT abandonment).
   *
   * Optimization: if no chunk has EVER been abandoned, advPt naturally
   * tracks what peer's regular SACK already knows — no FORWARD-TSN
   * needed. We use sctpStats.chunksAbandoned as the cheap "ever
   * abandoned anything?" flag.
   *
   * Note: optional Stream/SSN pairs in FORWARD-TSN (RFC 3758 §3.2) are
   * deferred. Without them, peer's per-stream recvSSN doesn't auto-skip
   * past abandoned ordered messages — receive side falls back to the
   * MAX_PENDING_MSGS_PER_STREAM cap (Patch 2 / SCTP-5) which eventually
   * unsticks the stream by dropping its pending buffer wholesale. We
   * accept this trade for now.
   */
  function maybeFwdTsn() {
    if (!peerSupportsForwardTsn) return;
    if (sctpStats.chunksAbandoned === 0) return;

    var advPt;
    if (sendQueue.length === 0) {
      advPt = (localTsn - 1) >>> 0;
    } else {
      advPt = (sendQueue[0].tsn - 1) >>> 0;
    }

    if (lastForwardTsnSent !== undefined && !tsnGt(advPt, lastForwardTsnSent)) return;

    sendForwardTsn(advPt);
  }

  function sendForwardTsn(newCumTsn) {
    // RFC 3758 §3.2 FORWARD-TSN chunk:
    //   header: type=0xC0 flags=0 length
    //   body:   newCumulativeTsn(4) + [stream(2) + ssn(2)]*N
    //
    // SCTP-6 follow-up: Stream/SSN pairs let peer advance recvSSN past
    // abandoned ordered messages. Without them peer waits for a message
    // that never arrives (until MAX_PENDING_MSGS_PER_STREAM trips). We
    // emit one pair per stream with abandoned ordered chunks since the
    // last FORWARD-TSN.
    if (peerSupportsIData) {
      // SCTP-14 / RFC 8260 §2.3.1: with interleaving negotiated the
      // I-FORWARD-TSN chunk (0xC2) MUST be used instead of FORWARD-TSN.
      // Entry layout per §2.3.1: SID(2) + Flags(2, bit0 = U) + MID(4).
      // Sending the classic chunk here would hand the peer a 16-bit SSN
      // where it expects a 32-bit MID — a silent interop break with any
      // compliant receiver (and our own receive side, once it complies).
      var iKeys   = Object.keys(abandonedMidPerStream);
      var iBody   = Buffer.alloc(4 + iKeys.length * 8);
      iBody.writeUInt32BE(newCumTsn, 0);
      for (var k = 0; k < iKeys.length; k++) {
        var key   = iKeys[k];
        var isU   = key.charAt(key.length - 1) === 'u';
        var sidN  = parseInt(key.slice(0, -1), 10);
        var off   = 4 + k * 8;
        iBody.writeUInt16BE(sidN & 0xFFFF, off);
        iBody.writeUInt16BE(isU ? 1 : 0,   off + 2);
        iBody.writeUInt32BE(abandonedMidPerStream[key].mid >>> 0, off + 4);
      }
      sendChunk(CHUNK_I_FORWARD_TSN, 0, iBody, remoteVerificationTag);
      lastForwardTsnSent = newCumTsn;
      /* The tracker is NOT cleared here. Two ways a one-shot tracker loses
       * skip entries for good, both observed:
       *   1. maybeFwdTsn's dedup can decline to send at all when the advance
       *      point hasn't moved (live fragments of another message still
       *      hold the queue head) — the entry recorded just before is then
       *      dropped without ever reaching the wire;
       *   2. the handleSack re-emit path resends when the peer looks behind,
       *      and a cleared tracker makes that resend carry ZERO entries, so
       *      a peer that missed the first chunk never learns the skips.
       * Entries are pruned in handleSack once the peer's cumulative ack
       * proves the hole has been passed. Until then, repeating a skip the
       * peer already applied is harmless — advanceRecvMidPastAbandoned is
       * idempotent (serial-arithmetic ≤ checks throughout). */
      return;
    }

    var streams = Object.keys(abandonedSSNPerStream);
    var bodyLen = 4 + streams.length * 4;
    var body    = Buffer.alloc(bodyLen);
    body.writeUInt32BE(newCumTsn, 0);
    for (var i = 0; i < streams.length; i++) {
      var sid = streams[i] | 0;
      body.writeUInt16BE(sid, 4 + i * 4);
      body.writeUInt16BE(abandonedSSNPerStream[sid] & 0xFFFF, 4 + i * 4 + 2);
    }
    sendChunk(CHUNK_FORWARD_TSN, 0, body, remoteVerificationTag);
    lastForwardTsnSent = newCumTsn;
    // Clear the per-stream tracker — peer's been told. New abandons
    // beyond this point will accumulate fresh entries.
    abandonedSSNPerStream = {};
  }

  /* SCTP-14: undo the T3 exponential backoff once the peer proves the path
   * is alive again.
   *
   * onT3Expire doubles rto on every expiry, and the ONLY thing that ever
   * lowers it is updateRtt — which Karn's algorithm gates on
   * retransmits === 0. During a loss burst practically every outstanding
   * chunk has been retransmitted, so no sample is admissible, so the doubling
   * is a one-way ratchet: 150ms -> 300 -> 600 -> ... -> the 60s cap, and the
   * association is left waiting a minute between retransmits long after the
   * link has recovered. Measured at 15% loss: RTO climbed until forward
   * progress stopped entirely while the path was still perfectly usable.
   *
   * Karn's algorithm is about not MEASURING off an ambiguous chunk. It does
   * not say the backoff must persist once new data is acknowledged — RFC 6298
   * §5.7 is explicit that the sender should recompute RTO from the smoothed
   * estimators at that point. Cumulative-ack progress is unambiguous
   * evidence, so that is the trigger here. With no SRTT yet (no clean sample
   * has ever been taken) there is nothing to recompute from and the backed-off
   * value stands.
   */
  function collapseRtoBackoff() {
    if (srtt === null) return;
    var newRto = Math.round(srtt + Math.max(1, 4 * rttvar));
    rto = Math.max(rtoMinMs, Math.min(rtoMaxMs, newRto));
  }

  // RFC 4960 §6.3.1 RTO calculation.
  function updateRtt(R) {
    // Defensive: a clock-skew or 0-ms loopback can produce R=0 or R<0.
    // RFC 4960 specifies subsecond clock granularity G; we treat R<1 as
    // 1ms to avoid SRTT/RTTVAR collapsing to 0 (which would push RTO to
    // exactly RTO_MIN_MS forever — aggressive but not catastrophic).
    if (R < 1) R = 1;
    sctpStats.rttSamples++;
    if (srtt === null) {
      srtt   = R;
      rttvar = R / 2;
    } else {
      rttvar = (1 - 1/4) * rttvar + (1/4) * Math.abs(srtt - R);
      srtt   = (1 - 1/8) * srtt   + (1/8) * R;
    }
    var newRto = Math.round(srtt + Math.max(1, 4 * rttvar));
    rto = Math.max(rtoMinMs, Math.min(rtoMaxMs, newRto));
  }


  /* ── connect() — public handshake entry point ──
   *
   * Symmetric for both roles. The intent is "tell me when ready", and
   * the function tolerates whatever state the association is in:
   *
   *   • 'closed' (initial)         — registers the callback and sends
   *                                   INIT (both roles — RFC 8841
   *                                   requires both endpoints to
   *                                   initiate the association).
   *   • 'cookie-wait'/'cookie-echoed' — handshake already in progress;
   *                                   registers the callback to fire
   *                                   when 'open' or 'close' settles.
   *                                   No double-INIT is sent.
   *   • 'established'              — we're already up; fires cb(null)
   *                                   on the next microtask. (Async to
   *                                   avoid Zalgo: the callback never
   *                                   runs synchronously from inside
   *                                   the connect() call.)
   *   • shutdown states            — throws; we're closing down, no point.
   *   • torn-down (`closed` flag)  — throws; instance is unusable. Make
   *                                   a new SctpAssociation.
   *
   * The callback fires exactly once per call:
   *   cb(null)    — handshake reached 'established'
   *   cb(Error)   — association closed before reaching 'established'
   *
   * 'open' and 'close' EventEmitter events still fire for any other
   * listeners attached via assoc.on(). connect() is purely additive.
   *
   * connect() is safe to call multiple times; each call gets its own
   * one-shot callback. (No double-INIT; the second call just registers
   * another listener.)
   */
  function connect(callback) {
    if (closed) {
      throw new Error('SctpAssociation.connect: association is torn down; create a new instance');
    }
    if (state === STATE_SHUTDOWN_PENDING ||
        state === STATE_SHUTDOWN_SENT ||
        state === STATE_SHUTDOWN_RECEIVED ||
        state === STATE_SHUTDOWN_ACK_SENT) {
      throw new Error("SctpAssociation.connect: association is shutting down (state='" +
                      STATE_NAMES[state] + "')");
    }
    if (callback != null && typeof callback !== 'function') {
      throw new TypeError('SctpAssociation.connect: callback must be a function');
    }

    // Fast path: already established. Fire the callback async (next
    // microtask) so it never runs synchronously from inside connect()
    // itself — that "sometimes-sync, sometimes-async" pattern is the
    // classic Zalgo hazard.
    if (state === STATE_ESTABLISHED) {
      if (callback) {
        queueMicrotask(function () {
          try { callback(null); } catch (e) { /* swallow */ }
        });
      }
      return;
    }

    // Closed or mid-handshake — register the callback to fire on the
    // next state transition. One-shot semantics via the `done` flag
    // ensure the second of (open/close) doesn't re-fire.
    if (callback) {
      var done = false;
      var onOpen, onClose;
      var settle = function (err) {
        if (done) return;
        done = true;
        ev.off('open',  onOpen);
        ev.off('close', onClose);
        try { callback(err || null); } catch (e) { /* swallow */ }
      };
      onOpen  = function () { settle(null); };
      onClose = function () {
        settle(new Error('association closed before handshake completed'));
      };
      ev.on('open',  onOpen);
      ev.on('close', onClose);
    }

    // Initiate regardless of role. RFC 8841 (SCTP over DTLS in SDP):
    //
    //   "When an SCTP association is established, both SCTP endpoints
    //    MUST initiate the SCTP association (i.e., both SCTP endpoints
    //    take the 'active' role). ... As both SCTP endpoints take the
    //    'active' role, the SDP 'setup' attribute does not apply to
    //    SCTP association establishment."
    //
    // The previous guard sent INIT only for role='client' (mirroring
    // the DTLS setup role). Stacks that make the symmetric mistake in
    // the opposite direction — SIPSorcery and werift both wait for the
    // peer's INIT even as DTLS client — then deadlocked with us: DTLS
    // completed, nobody sent INIT, and the DataChannel never opened.
    // (libdatachannel/pion masked it by always initiating, exactly as
    // the RFC requires.)
    //
    // The DTLS role retains exactly one SCTP-adjacent duty — DCEP
    // stream-id parity (RFC 8832 §6: DTLS client uses even stream ids,
    // server odd) — and plays no part in association establishment.
    // Simultaneous INITs from both ends are ordinary SCTP (RFC 4960
    // §5.2.1) and are already handled by handleInit's collision path.
    // (Mid-handshake calls just attach the callback.)
    if (state === STATE_CLOSED) {
      sendInit();
    }
  }

  // Internal: emit the INIT chunk that starts the 4-way handshake from
  // the client side. Pre-rename this was the public `initiate()` method.
  function sendInit() {
    state = STATE_COOKIE_WAIT;

    var body = Buffer.alloc(20);
    body.writeUInt32BE(localVerificationTag, 0);
    body.writeUInt32BE(maxReceiveBufferSize, 4);
    body.writeUInt16BE(DEFAULT_NUM_STREAMS, 8);
    body.writeUInt16BE(DEFAULT_NUM_STREAMS, 10);
    body.writeUInt32BE(localTsn, 12);

    // Supported Extensions: FORWARD-TSN (PR-SCTP), RECONFIG (stream reset),
    // and I-DATA (RFC 8260 user message interleaving).
    //
    // Advertising I-DATA is a statement that we can RECEIVE it — the receive
    // path landed in stage 1. It does not commit us to sending it: a peer
    // that also advertises it may start sending I-DATA to us, which is
    // exactly what we want to exercise, while our own send path stays on
    // classic DATA until stage 2b.
    //
    // Both directions of an association negotiate this independently in the
    // sense that each side advertises what it can receive, so this is safe
    // asymmetrically (RFC 8260 3.1).
    body.writeUInt16BE(PARAM_SUPPORTED_EXTENSIONS, 16);
    body.writeUInt16BE(7, 18);

    var padded = Buffer.alloc(24);
    body.copy(padded, 0, 0, 20);
    padded[20] = CHUNK_FORWARD_TSN;
    padded[21] = CHUNK_RECONFIG;
    padded[22] = CHUNK_I_DATA;

    sendChunk(CHUNK_INIT, 0, padded, 0);  // INIT always has vtag=0
  }


  /* ========================= Helpers ========================= */

  // TSN comparison (handles wraparound). RFC 1982 serial-number arithmetic.
  //
  // SUBTLE: the obvious-looking expression `(a - b) & 0xFFFFFFFF` is wrong
  // in JavaScript because the bitwise & operator coerces its result to a
  // SIGNED 32-bit integer. So `(-1) & 0xFFFFFFFF` returns -1, not
  // 0xFFFFFFFF (4294967295). That made tsnGt(smaller, larger) return true
  // for adjacent TSNs (diff=1 reverses to diff=-1, signed-extension makes
  // it less than 0x80000000, returns true). The original code in this
  // file had this bug; it was latent because tsnGt was only called from
  // handleForwardTsn where the typical case (diff small positive) works.
  // Once we wired tsnLeq into the new recordReceivedTsn it surfaced
  // immediately as "every DATA chunk reported as 'too-old'".
  //
  // The fix is `>>> 0` which is JavaScript's unsigned-32-bit-conversion
  // operator: -1 >>> 0 === 4294967295.
  function tsnGt(a, b) {
    var diff = ((a - b) >>> 0);   // unsigned 0 .. 0xFFFFFFFF
    return diff !== 0 && diff < 0x80000000;
  }

  // tsnLt — strict less-than in TSN-arithmetic order.
  function tsnLt(a, b) {
    return tsnGt(b, a);
  }

  // tsnLeq — less-than-or-equal in TSN-arithmetic order.
  function tsnLeq(a, b) {
    return a === b || tsnGt(b, a);
  }

  // Add a TSN to the duplicate-report list, bounded by MAX_DUP_TSNS to
  // cap SACK chunk size. dupTsns is reset between SACKs (sendSack clears).
  function recordDupTsn(tsn) {
    if (dupTsns.length < MAX_DUP_TSNS && dupTsns.indexOf(tsn) === -1) {
      dupTsns.push(tsn);
    }
  }

  // Rebase: advance lastCumulativeTsn by `delta` and adjust all stored
  // offsets to remain relative to the new cumTsn. This is the operation
  // that lets flat-ranges' purely-numeric comparison work safely on what
  // is fundamentally modular-32-bit data — by the time wraparound would
  // matter, the relevant offsets have long since been rebased away.
  //
  // Used for two distinct reasons:
  //   1. Prefix drain (drainPrefix below) — when a contiguous run of
  //      offsets starting at 1 is filled in, we advance cumTsn through
  //      the run.
  //   2. FORWARD-TSN — peer abandoned chunks; we accept their advance of
  //      our cumTsn even though the TSNs in between were never received.
  //
  // After `rebaseBy(Δ)`:
  //   • lastCumulativeTsn += Δ  (modular)
  //   • Any range covering offsets [a, b) where a < Δ+1 has its
  //     pre-Δ portion dropped (those offsets are now ≤ new cumTsn,
  //     i.e. cumulatively acked).
  //   • All surviving range endpoints decrease by Δ.
  function rebaseBy(delta) {
    if (delta <= 0) return;
    lastCumulativeTsn = (lastCumulativeTsn + delta) >>> 0;
    // Drop offsets [0, delta+1) — those are at-or-below the new cumTsn.
    // (Half-open: offset==delta means TSN==newCumTsn, which is acked.)
    flatRanges.remove(receivedRanges, [0, delta + 1]);
    // Shift remaining ranges down so they remain offsets from new cumTsn.
    for (var i = 0; i < receivedRanges.length; i++) {
      receivedRanges[i] -= delta;
    }
  }

  // If receivedRanges starts at offset 1 (i.e. cumTsn+1 has been received),
  // advance cumTsn through the contiguous prefix. Returns true if cumTsn
  // moved. Single call drains as far as the first range goes; subsequent
  // arrivals will keep extending.
  function drainPrefix() {
    if (receivedRanges.length < 2 || receivedRanges[0] !== 1) return false;
    // First range covers offsets [1, end), inclusive count = end-1 TSNs.
    var delta = receivedRanges[1] - 1;
    rebaseBy(delta);
    return true;
  }

  // Record a TSN we just received from the peer. Returns:
  //   'new'        — first time seen, was inserted into tracking
  //   'duplicate'  — TSN already received (logged in dupTsns for next SACK)
  //   'too-old'    — TSN is at or below cumulative ack (peer retransmitted
  //                  a chunk we'd already acked cumulatively; counts as dup)
  //   'overflow'   — receiver buffer full; chunk dropped silently (peer
  //                  will eventually retransmit when their RTO expires)
  function recordReceivedTsn(tsn) {
    if (tsnLeq(tsn, lastCumulativeTsn)) {
      // Peer retransmitted something already cumulatively acked, or this
      // is a stale arrival from before cumTsn advanced over it. Either way,
      // it's a duplicate. Tell the peer in our next SACK so they can stop
      // retransmitting it.
      recordDupTsn(tsn);
      return 'too-old';
    }

    var offset = (tsn - lastCumulativeTsn) >>> 0;

    // Try to add. flat-ranges.add returns false if the offset was already
    // covered by an existing range — that's our duplicate detection.
    var changed = flatRanges.add(receivedRanges, [offset, offset + 1]);
    if (!changed) {
      recordDupTsn(tsn);
      return 'duplicate';
    }

    // Defensive cap. Only one new range can have been created by a single
    // add (worst case: a TSN that doesn't merge with either neighbour).
    // If we just blew the cap, undo and report overflow. In normal
    // operation receivedRanges holds 1-5 ranges; hitting 2048 means a
    // peer pathology or attack.
    if (receivedRanges.length > MAX_RECEIVED_RANGES * 2) {
      flatRanges.remove(receivedRanges, [offset, offset + 1]);
      return 'overflow';
    }

    drainPrefix();
    return 'new';
  }

  // Build the gap-block list for a SACK. Pre-flat-ranges this scanned
  // a TSN array grouping contiguous runs; with the rebased range model
  // it's purely a format conversion:
  //   • flat-ranges format: half-open [from, to), offsets from cumTsn.
  //   • SCTP SACK format:  {start, end}, both 16-bit offsets from cumTsn,
  //                        with `end` INCLUSIVE per RFC 4960 §3.3.4.
  // So the i-th gap block is { receivedRanges[2i], receivedRanges[2i+1]-1 }.
  // Both fields are masked to 16 bits per the SACK chunk wire format —
  // SCTP's SACK can't represent gap offsets > 65535. In practice
  // receivedRanges never gets near that bound because cumTsn advances
  // continually as data arrives, keeping offsets small.
  function computeGapBlocks() {
    var n = receivedRanges.length / 2;
    if (n === 0) return [];
    var out = new Array(n);
    for (var i = 0; i < n; i++) {
      out[i] = {
        start:  receivedRanges[i * 2]      & 0xFFFF,
        end:   (receivedRanges[i * 2 + 1] - 1) & 0xFFFF,
      };
    }
    return out;
  }


  /* ========================= SSN ordering helpers ========================= */

  // SSN is 16-bit and wraps at 2^16. Comparison uses serial-number arithmetic
  // (RFC 1982) just like TSN, but the unsigned-vs-signed concern from
  // Finding 9 doesn't apply at 16 bits: `& 0xFFFF` produces a value in
  // [0, 0xFFFF] that fits in a positive signed 32-bit int, so the bitwise
  // AND is safe even though it's a "signed" operation in JavaScript.
  function ssnGt(a, b) {
    var diff = (a - b) & 0xFFFF;
    return diff !== 0 && diff < 0x8000;
  }
  function ssnLt(a, b) { return ssnGt(b, a); }

  /* ========================= Fragment store ========================= */

  // Try to extract a complete user message from this stream's fragment store.
  // Returns { ssn, ppid, payload, unordered } if a complete BEGIN→END chain
  // is found with consistent SSN/PPID/U-bit, otherwise null. On success,
  // the consumed fragments are removed from the store.
  //
  // We iterate over the store's TSNs in tsn-arithmetic order (so wraparound
  // works), looking for a BEGIN, then walking forward while the next TSN
  // is contiguous AND the SSN/PPID/U-bit match the BEGIN's. A complete
  // chain is BEGIN..(MIDDLE..)END.
  //
  // tryAssemble may need to be called repeatedly — after one message comes
  // out, another might also be ready. handleData's caller loops.
  function tryAssemble(streamId) {
    var store = fragStore[streamId];
    if (!store || store.size === 0) return null;

    // Sort keys in tsn-arithmetic order. This is rare-path; O(n log n) on
    // a small store is fine.
    var tsns = Array.from(store.keys());
    tsns.sort(function (a, b) {
      if (a === b) return 0;
      return tsnLt(a, b) ? -1 : 1;
    });

    for (var i = 0; i < tsns.length; i++) {
      var head = store.get(tsns[i]);
      if (!head.isBegin) continue;

      // Single-fragment message — BEGIN+END together is the common path
      // and we want it fast.
      if (head.isEnd) {
        store.delete(tsns[i]);
        if (store.size === 0) delete fragStore[streamId];
        return {
          ssn: head.ssn, ppid: head.ppid, unordered: head.isUnordered,
          payload: head.payload,
          wide: (head.mid != null),   // SCTP-14: I-DATA -> ssn holds a 32-bit MID
        };
      }

      // INTERLEAVED (RFC 8260): fragments of this message are found by mid
      // and ordered by fsn, wherever they sit in TSN space. That is the
      // entire point of the extension — another stream's fragments may be
      // interleaved between them — so the contiguous-TSN walk below cannot
      // be used.
      if (head.mid != null) {
        // Index this message's fragments by fsn in ONE pass, then walk them.
        //
        // The obvious shape — rescan the store for each fsn in turn — is
        // O(n^2), and n here is the fragment count of a large message: a
        // 256KB payload at a 1200-byte MTU is ~218 fragments, so ~47,000
        // comparisons per assembly. This code path exists precisely for large
        // messages, so that is the wrong cost to carry.
        var byFsn = new Map();
        for (var ik = 0; ik < tsns.length; ik++) {
          var cand = store.get(tsns[ik]);
          if (!cand || cand.mid !== head.mid) continue;
          // Same consistency rules the contiguous path enforces: a fragment
          // claiming this message must agree about what the message is.
          if (cand.ppid !== head.ppid && cand.ppid !== 0) continue;   // N2
          if (cand.isUnordered !== head.isUnordered) continue;        // N15
          if (!byFsn.has(cand.fsn)) byFsn.set(cand.fsn, [cand, tsns[ik]]);
        }

        var iParts = [head.payload];
        var iConsumed = [tsns[i]];
        var iDone = false;
        for (var want = 1; ; want++) {
          var hit = byFsn.get(want);
          if (!hit) break;                         // chain incomplete — wait
          iParts.push(hit[0].payload);
          iConsumed.push(hit[1]);
          if (hit[0].isEnd) { iDone = true; break; }
        }
        if (iDone) {
          for (var ic = 0; ic < iConsumed.length; ic++) store.delete(iConsumed[ic]);
          if (store.size === 0) delete fragStore[streamId];
          return {
            ssn: head.ssn, ppid: head.ppid, unordered: head.isUnordered,
            payload: Buffer.concat(iParts),
            // SCTP-14: ssn here is a 32-bit MID, not a 16-bit SSN. The
            // ordered-delivery gate needs to know which, because the two
            // wrap at different points.
            wide: true,
          };
        }
        continue;   // not yet complete; try the next BEGIN
      }

      // Multi-fragment: walk forward from BEGIN.
      var parts = [head.payload];
      var consumed = [tsns[i]];
      var expectTsn = (tsns[i] + 1) >>> 0;
      var ssn = head.ssn, ppid = head.ppid, unordered = head.isUnordered;
      var assembled = null;

      for (var j = i + 1; j < tsns.length; j++) {
        if (tsns[j] !== expectTsn) break;             // gap in chain
        var f = store.get(tsns[j]);
        if (f.isBegin) break;                          // unexpected BEGIN — abort
        if (f.ssn !== ssn) break;                      // N1: SSN mismatch
        if (f.ppid !== ppid) break;                    // N2: PPID mismatch
        if (f.isUnordered !== unordered) break;        // N15: U-bit mismatch
        parts.push(f.payload);
        consumed.push(tsns[j]);
        if (f.isEnd) {
          assembled = {
            ssn: ssn, ppid: ppid, unordered: unordered,
            payload: Buffer.concat(parts),
          };
          break;
        }
        expectTsn = (tsns[j] + 1) >>> 0;
      }

      if (assembled) {
        for (var k = 0; k < consumed.length; k++) store.delete(consumed[k]);
        if (store.size === 0) delete fragStore[streamId];
        return assembled;
      }
      // BEGIN found but chain incomplete — try the next BEGIN, if any.
      // (Two BEGINs can coexist if the peer has interleaved fragments
      // from two different messages, which RFC 4960 forbids per stream
      // but we should be defensive about.)
    }
    return null;
  }


  /* ========================= Ordered delivery ========================= */

  // Deliver an assembled message respecting ordered/unordered semantics.
  //   • Unordered (U-bit set): emit immediately, don't touch SSN state.
  //     This is the fix for B7 — pre-Patch-2 the U-bit was parsed but
  //     ignored, so unordered messages got SSN-checked anyway (which
  //     happened to work only because no SSN check existed at all).
  //   • Ordered: if msg.ssn === recvSSN[streamId], deliver and advance,
  //     then drain pendingMsgs while the next SSN is buffered. If
  //     msg.ssn > recvSSN, hold in pendingMsgs. If msg.ssn < recvSSN,
  //     drop silently — already delivered (or skipped via FORWARD-TSN
  //     when peer abandoned the message under PR-SCTP).
  // This is the fix for B3.
  function deliverAssembled(streamId, msg) {
    if (msg.unordered) {
      processMessage(streamId, msg.ppid, msg.payload);
      return;
    }

    // SCTP-14: DATA's ordering key is a 16-bit SSN; I-DATA's is a 32-bit
    // MID (RFC 8260 §2.1). Both arrive here as msg.ssn, so the modular
    // arithmetic has to follow the width of whichever it is. Advancing a
    // MID with `& 0xFFFF` pins the local counter at 65535 while the peer's
    // MIDs keep climbing past it: every later message on the stream is
    // filed as "future", held in pendingMsgs, and never delivered. On a
    // busy stream that is a permanent stall, and one that only shows up
    // after 64K messages — long after any test would have stopped looking.
    var wide = (msg.wide === true);
    var step = wide ? function (v) { return (v + 1) >>> 0; }
                    : function (v) { return (v + 1) & 0xFFFF; };
    var gt   = wide ? tsnGt : ssnGt;   // tsnGt is the same serial comparison, 32-bit

    var expected = recvSSN[streamId] || 0;

    if (msg.ssn === expected) {
      processMessage(streamId, msg.ppid, msg.payload);
      expected = step(expected);
      // Drain any held messages whose SSN is now next.
      var held = pendingMsgs[streamId];
      while (held && held.has(expected)) {
        var nxt = held.get(expected);
        held.delete(expected);
        processMessage(streamId, nxt.ppid, nxt.payload);
        expected = step(expected);
      }
      recvSSN[streamId] = expected;
      if (held && held.size === 0) delete pendingMsgs[streamId];
      return;
    }

    if (gt(msg.ssn, expected)) {
      // Future SSN — hold it.
      if (!pendingMsgs[streamId]) pendingMsgs[streamId] = new Map();
      var pending = pendingMsgs[streamId];
      if (pending.size >= MAX_PENDING_MSGS_PER_STREAM) {
        // Defensive: peer has held back delivery too long. Drop the
        // entire stream's pending buffer and let the application handle
        // the gap. (This matches libwebrtc behavior and SCTP-5's DoR.)
        pending.clear();
        delete pendingMsgs[streamId];
        return;
      }
      pending.set(msg.ssn, { ppid: msg.ppid, payload: msg.payload });
      return;
    }

    // ssn < expected — already delivered or skipped. Drop silently.
    // (recordReceivedTsn already filtered TSN-level dups; this case
    // means the peer sent a fresh TSN with a stale SSN, which is a
    // peer-side bug.)
  }

  // Extract parameter from INIT/INIT-ACK optional data
  /* extractParam — find a TLV parameter of the given type in data.
   *
   * SCTP-11 N12 hardening: bound-check pLen against remaining buffer.
   * A malicious peer could send pLen=0xFFFF in an INIT param to trick
   * us into returning a subarray that promises more bytes than exist.
   * subarray clamps silently, so callers might read uninitialised bytes
   * from later in the parsing flow. We clamp pLen explicitly and refuse
   * to recurse if pLen exceeds the remaining buffer.
   */
  function extractParam(data, paramType) {
    var off = 0;
    while (off + 4 <= data.length) {
      var pType = data[off] << 8 | data[off + 1];
      var pLen  = data[off + 2] << 8 | data[off + 3];
      if (pLen < 4) break;
      if (off + pLen > data.length) break;   // N12: param claims to extend past buffer

      if (pType === paramType) {
        return data.subarray(off + 4, off + pLen);
      }

      off += pLen;
      if (off % 4 !== 0) off += 4 - (off % 4);
    }
    return null;
  }

  // RFC 5061 §4.2.7 — PARAM_SUPPORTED_EXTENSIONS carries a list of chunk-type
  // bytes the peer supports. We're interested in two extensions:
  //
  //   • CHUNK_FORWARD_TSN (0xC0) — enables PR-SCTP send-side abandonment
  //     (RFC 3758). Without it we silently keep all sends fully reliable
  //     per RFC 8831 §6.6.
  //   • CHUNK_RECONFIG (130 / 0x82) — enables stream-reset (RFC 6525) so
  //     dc.close() actually tears the stream down at the peer. Without it
  //     resetStreams() is a no-op and dc.close() leaves the peer's view
  //     of the channel open.
  function detectSupportedExtensions(paramsBuf) {
    var ext = extractParam(paramsBuf, PARAM_SUPPORTED_EXTENSIONS);
    if (!ext) return;
    for (var i = 0; i < ext.length; i++) {
      if (ext[i] === CHUNK_FORWARD_TSN) peerSupportsForwardTsn = true;
      if (ext[i] === CHUNK_RECONFIG)    peerSupportsReconfig    = true;
      // RFC 8260: the peer telling us it can RECEIVE I-DATA. Recorded now so
      // stage 2b can gate sending on it — a peer that did not advertise must
      // never be sent I-DATA, since it has no parser for the chunk type.
      if (ext[i] === CHUNK_I_DATA)      peerSupportsIData       = true;
    }
  }


  /* ========================= close ========================= */

  function close() {
    if (closed) return;

    // Pre-established or already-closing states: nothing to negotiate,
    // just tear down. (Closing during handshake is a graceful give-up.)
    if (state !== STATE_ESTABLISHED) {
      finalizeClose();
      return;
    }

    // SCTP-14: a long message may still be half-enqueued in a txJob. Push
    // the remainder into sendQueue FIRST — W3C close() semantics flush what
    // the application already handed us, and attemptShutdownTransition gates
    // on sendQueue being empty, so a job left holding fragments would either
    // vanish or arrive after shutdown had concluded the queue was drained.
    flushTxJobs();

    // SCTP-13: flush any microtask-coalesced transmit NOW, so data queued
    // in this same tick is actually in-flight before we begin the SHUTDOWN
    // drain (attemptShutdownTransition only advances once the queue is
    // empty; unsent-but-queued data would otherwise wait a microtask that
    // races the shutdown path).
    flushTransmit();

    // Active close. Per RFC 4960 §9.2 we transition through
    // SHUTDOWN_PENDING (drain) then SHUTDOWN_SENT (awaiting ack). With
    // SCTP-1's send queue in place, the drain is real:
    // attemptShutdownTransition advances PENDING → SENT only when the
    // queue is empty. If it isn't, handleSack calls back into
    // attemptShutdownTransition each time the queue shortens, and the
    // SHUTDOWN goes out the moment we hit zero outstanding.
    state = STATE_SHUTDOWN_PENDING;
    attemptShutdownTransition();
  }


  /* ========================= abort ========================= */

  /**
   * Tear the association down ABRUPTLY (RFC 4960 3.3.7).
   *
   * close() is the graceful path — SHUTDOWN, drain, await SHUTDOWN_ACK — and
   * it is right when a channel is closing while the connection lives on.
   *
   * pc.close() is not that case. The peer connection is being destroyed, so
   * nothing survives to complete the handshake: the SHUTDOWN may not even
   * reach the wire, and the remote peer is left holding channels that stay
   * 'open' forever with no event to tell it otherwise.
   *
   * ABORT is one packet and needs no reply, which is what a terminal close
   * can actually guarantee. Cause code 12 is User-Initiated Abort, which the
   * remote side reports as sctpCauseCode.
   */
  function abort(causeCode) {
    if (closed) return;
    try {
      if (state === STATE_ESTABLISHED) sendAbort(causeCode == null ? 12 : causeCode);
    } catch (e) { /* a failed ABORT must never block teardown */ }
    finalizeClose();
  }

  /* ========================= Public API ========================= */

  this.abort = abort;

  // Did the peer advertise RFC 8260 interleaving? Useful for diagnostics and
  // for the interop harness, which reports whether it was negotiated.
  Object.defineProperty(this, 'interleavingNegotiated', {
    get: function () { return peerSupportsIData === true; },
  });

  Object.defineProperty(this, 'state', { get: function() { return STATE_NAMES[state]; } });
  Object.defineProperty(this, 'established', { get: function() { return state === STATE_ESTABLISHED; } });
  Object.defineProperty(this, 'role', { get: function() { return role; } });
  Object.defineProperty(this, 'pmtu',           { get: function() { return pmtu; } });
  Object.defineProperty(this, 'maxMessageSize', { get: function() { return maxMessageSize; } });
  Object.defineProperty(this, 'maxReceiveBufferSize', { get: function() { return maxReceiveBufferSize; } });
  // SCTP-6: lets the upper layer probe whether PR-SCTP options will take
  // effect. False until INIT/INIT-ACK exchange completes; consult after 'open'.
  Object.defineProperty(this, 'peerSupportsForwardTsn', { get: function() { return peerSupportsForwardTsn; } });
  // SCTP-7: like peerSupportsForwardTsn but for stream reset. False until
  // handshake completes; cm.js checks this before issuing dc.close() resets.
  Object.defineProperty(this, 'peerSupportsReconfig',   { get: function() { return peerSupportsReconfig; } });
  // SCTP-1 stats. Returns a snapshot copy — consumer can't mutate
  // internal counters. Field set will grow as SCTP-8/9/11 land
  // (rwnd accounting, congestion stats, byte counts).
  Object.defineProperty(this, 'stats', { get: function() {
    return {
      chunksSent:          sctpStats.chunksSent,
      chunksRetransmitted: sctpStats.chunksRetransmitted,
      chunksAbandoned:     sctpStats.chunksAbandoned,
      chunksBundled:       sctpStats.chunksBundled,
      bundledPackets:      sctpStats.bundledPackets,
      fastRetransmits:     sctpStats.fastRetransmits,
      rtoExpiries:         sctpStats.rtoExpiries,
      pathFailures:        sctpStats.pathFailures,
      rttSamples:          sctpStats.rttSamples,
      srtt:                srtt,
      rttvar:              rttvar,
      rto:                 rto,
      sendQueueDepth:      sendQueue.length,
      /* SCTP-14: bytes accepted by send() that are NOT yet fragmented into
       * sendQueue. Without this the queue looks empty while megabytes sit in
       * txJobs, and anything pacing on sendQueueDepth over-sends badly. */
      unfragmentedBytes:   (function () {
        var n = 0;
        for (var ji = 0; ji < txJobs.length; ji++) {
          n += txJobs[ji].payload.length -
               txJobs[ji].cursor * txJobs[ji].maxPerChunk;
        }
        return n > 0 ? n : 0;
      })(),
      pendingMessages:     txJobs.length,
      // SCTP-14: bidirectional-load view, for tuning interleaveMode.
      slicing:             interleaveMode === 'never' ? false
                            : (interleaveMode === 'adaptive' ? !bidirectionalLoad : true),
      rxBytesPerSec:       Math.round(rateRxPerSec),
      txBytesPerSec:       Math.round(rateTxPerSec),
      // SCTP-8 visibility: in-flight bytes vs rwnd lets the upper layer
      // see when we're rwnd-bound (outstandingBytes near remoteRwnd).
      inFlightCount:       inFlightCount,
      outstandingBytes:    outstandingBytes,
      remoteRwnd:          remoteRwnd,
      // SCTP-9 visibility: cwnd governs our send rate; comparing to
      // ssthresh tells you if we're in slow start (cwnd<ssthresh) or
      // congestion avoidance.
      cwnd:                cwnd,
      ssthresh:            ssthresh,
      partialBytesAcked:   partialBytesAcked,
      receivedRangesCount: receivedRanges.length / 2,
      lastCumulativeTsn:   lastCumulativeTsn,
    };
  } });

  // SCTP-14 test hook: snapshot of sendQueue TSNs, for asserting the
  // ascending-order invariant from outside. Read-only; no protocol effect.
  this._debugSendQueue = function () {
    var out = new Array(sendQueue.length);
    for (var i = 0; i < sendQueue.length; i++) out[i] = sendQueue[i].tsn;
    return out;
  };
  this._debugRecv = function (sid) {
    var frags=[]; var st=fragStore[sid];
    if(st) st.forEach(function(f,tsn){frags.push({mid:f.mid,fsn:f.fsn,B:f.isBegin,E:f.isEnd});});
    var pend=[]; var pm=pendingMsgs[sid];
    if(pm) pm.forEach(function(m,k){pend.push(k);});
    return { recvSSN: recvSSN[sid], frags: frags, pending: pend };
  };
  this._debugState = function () {
    return {
      q: sendQueue.length, inFlight: inFlightCount, outBytes: outstandingBytes,
      cwnd: cwnd, ssthresh: ssthresh, rwnd: remoteRwnd, rto: rto, srtt: srtt,
      t3Armed: !!t3Timer, jobs: txJobs.length,
      head: sendQueue.length ? {
        tsn: sendQueue[0].tsn, inFlight: sendQueue[0].inFlight,
        retx: sendQueue[0].retransmits, miss: sendQueue[0].missingReports,
        needsRetx: sendQueue[0].needsRetx, sid: sendQueue[0].streamId,
      } : null,
      lastCumTsn: lastCumulativeTsn, localTsn: localTsn,
    };
  };

  this.handlePacket = handlePacket;
  this.connect      = connect;       // connect([cb])  — symmetric for both roles
  this.send         = sendData;      // send(streamId, payload, ppid, opts?)
  this.close        = close;         // close()        — graceful 3-way SHUTDOWN
  this.resetStreams = resetStreams;  // SCTP-7: dc.close() backing primitive

  // SCTP-8: current advertised receive-window credit (bytes). Exposed for
  // diagnostics — lets the upper layer / tests observe flow-control state.
  this.getReceiverWindowCredit = myReceiverWindowCredit;

  this.on   = function(name, fn) { ev.on(name, fn); };
  this.off  = function(name, fn) { ev.off(name, fn); };
  this.once = function(name, fn) { ev.once(name, fn); };

  return this;
}


/* ========================= Static exports ========================= */

// Symbolic state constants for callers that prefer named comparisons:
//   if (assoc.state === SctpAssociation.STATES.ESTABLISHED) { ... }
// over string-literal comparisons. Both work; this is the typo-resistant
// version. The set matches RFC 4960 §4 verbatim.
SctpAssociation.STATES = Object.freeze({
  CLOSED:             'closed',
  COOKIE_WAIT:        'cookie-wait',
  COOKIE_ECHOED:      'cookie-echoed',
  ESTABLISHED:        'established',
  SHUTDOWN_PENDING:   'shutdown-pending',
  SHUTDOWN_SENT:      'shutdown-sent',
  SHUTDOWN_RECEIVED:  'shutdown-received',
  SHUTDOWN_ACK_SENT:  'shutdown-ack-sent',
});


/* ========================= Exports ========================= */

export { SctpAssociation };
export default SctpAssociation;
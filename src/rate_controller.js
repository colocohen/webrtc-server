// src/rate_controller.js
//
// Media rate adaptation (RFC 8834 §7) — the pure parts: what the peer's
// description allows (b=CT / b=TIAS / b=AS, JSEP RFC 8829 §5.10), how one
// connection's target send rate is split across its senders and their
// simulcast layers, the hysteresis that keeps an encoder from being
// reconfigured on every feedback, and the RTP circuit breaker (RFC 8083).
//
// No I/O, no clock of its own: every time is an argument. media_transport.js
// owns the state and calls these (updateRates, the circuit breakers);
// api.js registers each RTCRtpSender with it and applies what comes out.
//
// What the RFCs leave open, and what this file chose:
//
//   - The congestion controller itself (RFC 8834 §7: "will have to be
//     proprietary"): rtp-packet's BandwidthEstimator, delay and loss based
//     (draft-ietf-rmcat-gcc's two rules, simplified). Its estimate covers
//     every RTP byte; MEDIA_SHARE of it goes to the encoders, the rest is
//     headroom for headers, RTX and RTCP.
//   - Audio first: each audio sender gets its own ceiling (40 kbps Opus by
//     default, its maxBitrate if set) before video gets anything; only a
//     budget too small for the audio itself scales audio down (never below
//     AUDIO_MIN_BPS). RFC 8835 §4.1 makes priority independent of media
//     type; audio's need is small and inelastic, so it is served first and
//     the priorities share what is left between the video senders.
//   - Video senders share the rest by RTCRtpEncodingParameters.priority
//     (the first encoding's: W3C webrtc-priority), each level twice the one
//     below (RFC 8835 §4.1: very-low 1, low 2, medium 4, high 8), each
//     capped at its own ceiling, the surplus redistributed (water-filling).
//     networkPriority is DSCP only (RFC 8837) and plays no part.
//   - Simulcast: layers are served from the lowest resolution up (the
//     largest scaleResolutionDownBy first); each lower layer gets its whole
//     ceiling before the next is considered, a layer is turned on only when
//     what is left reaches its minimum (LAYER_MIN_FRACTION of its ceiling,
//     at least VIDEO_MIN_BPS; LAYER_ENABLE_MARGIN times that to turn a layer
//     that is off back on), and a layer that is off turns off every layer
//     above it — libwebrtc's rule of dropping the top layers first. The
//     lowest layer is always on while its sender has any budget.
//   - A layer's ceiling: its maxBitrate (never exceeded), else 1 Mbps (the
//     pipeline's default) divided by scaleResolutionDownBy², never below
//     VIDEO_MIN_BPS; then the TMMBR limit of its SSRC and the circuit
//     breaker's reduced rate, when there is one. A section's b=TIAS (or
//     b=AS converted) caps its sender's total; the session's b=CT caps the
//     connection's total.
//   - Hysteresis (RateHysteresis): a decrease of DECREASE_STEP or more at
//     most every DECREASE_INTERVAL_MS (URGENT_DECREASE at once), an increase
//     of INCREASE_STEP or more at most every INCREASE_INTERVAL_MS; whatever
//     a SIGNALED limit (maxBitrate, TIAS / AS, CT, TMMBR, the circuit
//     breaker) requires is applied at once — those are MUSTs, the estimate
//     is not. media-processing's configure() starts a new encoder run (a
//     key frame) even for a bitrate-only change, so every update costs one.

import { tmmbrNetBitrate } from 'rtp-packet';


var MEDIA_SHARE          = 0.95;
var AUDIO_DEFAULT_BPS    = 40000;      // media_pipeline.js's Opus default
var AUDIO_MIN_BPS        = 6000;       // Opus' lowest useful rate
var VIDEO_DEFAULT_BPS    = 1000000;    // media_pipeline.js DEFAULT_BITRATE
var VIDEO_MIN_BPS        = 30000;
var LAYER_MIN_FRACTION   = 0.25;
var LAYER_ENABLE_MARGIN  = 1.25;
// JSEP (RFC 8829 §5.10): TIAS = AS * 1000 * 0.95 - (50 * 40 * 8).
var JSEP_RTCP_SHARE      = 0.95;
var JSEP_OVERHEAD_BPS    = 50 * 40 * 8;
// RFC 8835 §4.1: "approximately twice the transmission capacity ... of the
// level below".
var PRIORITY_WEIGHT = { 'very-low': 1, 'low': 2, 'medium': 4, 'high': 8 };

var DECREASE_STEP        = 0.10;
var DECREASE_INTERVAL_MS = 1000;
var URGENT_DECREASE      = 0.30;
var INCREASE_STEP        = 0.20;
var INCREASE_INTERVAL_MS = 5000;


/**
 * The weight of an RTCPriorityType (W3C webrtc-priority; RFC 8835 §4.1).
 * Anything else is 'low', the default.
 */
function priorityWeight(priority) {
  return Object.prototype.hasOwnProperty.call(PRIORITY_WEIGHT, priority)
    ? PRIORITY_WEIGHT[priority] : PRIORITY_WEIGHT.low;
}

function _bwValue(list, type) {
  if (!list) return null;
  for (var i = 0; i < list.length; i++) {
    if (String(list[i].type).toUpperCase() === type && typeof list[i].limit === 'number') return list[i].limit;
  }
  return null;
}

/**
 * The sending limits a remote description sets, by JSEP (RFC 8829 §5.10):
 *   - session level: b=CT is the limit for the total of every m= section
 *     (kbps); b=AS there "MUST be ignored";
 *   - media level: b=TIAS (bps, RFC 3890: the RTP payload rate) is the
 *     limit when sending that section's media; without it, b=AS (kbps) is
 *     converted, TIAS = AS * 1000 * 0.95 - (50 * 40 * 8); b=CT there "MUST
 *     be ignored".
 *
 * @param {object} parsed  a parsed remote description (sdp.js parseRemoteSdp)
 * @returns {{ctBps: number|null, tiasByMid: Object<string, number>}}
 *          ctBps is CT * 1000 as written (the overhead is taken off in
 *          allocateRates, where the number of sending sections is known).
 */
function remoteBandwidthLimits(parsed) {
  var out = { ctBps: null, tiasByMid: {} };
  if (!parsed) return out;
  var ct = _bwValue(parsed.bandwidth, 'CT');
  if (ct !== null) out.ctBps = ct * 1000;
  var media = parsed.media || [];
  for (var i = 0; i < media.length; i++) {
    var m = media[i];
    if (!m || m.type === 'application' || m.mid == null) continue;
    var tias = _bwValue(m.bandwidth, 'TIAS');
    if (tias === null) {
      var as = _bwValue(m.bandwidth, 'AS');
      if (as !== null) tias = Math.max(0, as * 1000 * JSEP_RTCP_SHARE - JSEP_OVERHEAD_BPS);
    }
    if (tias !== null) out.tiasByMid[String(m.mid)] = tias;
  }
  return out;
}

/**
 * The most a layer may be given: its maxBitrate when the application set
 * one (> 0), else the kind's default (video: VIDEO_DEFAULT_BPS / scale², at
 * least VIDEO_MIN_BPS), then its signaled cap (TMMBR, circuit breaker).
 */
function layerCeiling(kind, layer) {
  var c;
  if (layer.maxBitrate > 0) c = layer.maxBitrate;
  else if (kind === 'audio') c = AUDIO_DEFAULT_BPS;
  else {
    var s = layer.scale > 1 ? layer.scale : 1;
    c = Math.max(VIDEO_MIN_BPS, VIDEO_DEFAULT_BPS / (s * s));
  }
  if (typeof layer.capBps === 'number' && layer.capBps >= 0 && layer.capBps < c) c = layer.capBps;
  return c;
}

/**
 * Split one connection's budget across its senders and their layers.
 *
 * @param {object} input
 * @param {number} input.estimateBps   the congestion controller's estimate
 *                                     (Infinity: signaled limits only)
 * @param {number|null} input.ctBps    the peer's b=CT, in bps
 * @param {Array} input.senders        [{ id, kind, mid, priority,
 *        sectionCapBps (the section's TIAS, or null),
 *        layers: [{ key, maxBitrate, scale, active (the application's),
 *                   capBps (TMMBR / circuit breaker, or null),
 *                   enabled (what the controller set last; undefined: new) }] }]
 * @returns {{budgetBps: number, layers: Object<string, {bitrate, enabled}>,
 *            senders: Object<string, {allocatedBps, droppedLayer}>}}
 */
function allocateRates(input) {
  var senders = input.senders || [];
  var out = { budgetBps: 0, layers: {}, senders: {} };

  // Per sender: its live layers, their ceilings, its own ceiling.
  var info = [];
  var mids = [];
  for (var i = 0; i < senders.length; i++) {
    var s = senders[i];
    var live = [];
    var sum = 0;
    for (var l = 0; l < s.layers.length; l++) {
      var ly = s.layers[l];
      out.layers[ly.key] = { bitrate: 0, enabled: false };
      if (!ly.active) continue;
      var c = layerCeiling(s.kind, ly);
      live.push({ idx: l, layer: ly, ceiling: c });
      sum += c;
    }
    var ceiling = sum;
    if (typeof s.sectionCapBps === 'number' && s.sectionCapBps < ceiling) ceiling = Math.max(0, s.sectionCapBps);
    info.push({ s: s, live: live, ceiling: ceiling, alloc: 0 });
    if (live.length && s.mid != null && mids.indexOf(String(s.mid)) < 0) mids.push(String(s.mid));
  }

  var budget = input.estimateBps * MEDIA_SHARE;
  if (typeof input.ctBps === 'number') {
    // b=CT is a total with its overheads; JSEP's AS→TIAS conversion, once
    // per sending section.
    budget = Math.min(budget, Math.max(0, input.ctBps * JSEP_RTCP_SHARE - JSEP_OVERHEAD_BPS * mids.length));
  }
  if (!(budget > 0)) budget = 0;
  out.budgetBps = budget;

  // Audio first, at its ceiling; scaled down only when the budget cannot
  // carry even that.
  var audioNeed = 0;
  for (var a = 0; a < info.length; a++) if (info[a].s.kind === 'audio') audioNeed += info[a].ceiling;
  var audioTotal = 0;
  for (var a2 = 0; a2 < info.length; a2++) {
    var ia = info[a2];
    if (ia.s.kind !== 'audio' || ia.ceiling <= 0) continue;
    var give = ia.ceiling;
    if (audioNeed > budget) give = Math.max(Math.min(AUDIO_MIN_BPS, ia.ceiling), ia.ceiling * budget / audioNeed);
    ia.alloc = give;
    audioTotal += give;
  }

  // Video: weighted water-filling over what audio left.
  var rest = Math.max(0, budget - audioTotal);
  var open = [];
  for (var v = 0; v < info.length; v++) {
    if (info[v].s.kind !== 'audio' && info[v].ceiling > 0) open.push(info[v]);
  }
  while (open.length && rest > 0) {
    var wsum = 0;
    for (var w = 0; w < open.length; w++) wsum += priorityWeight(open[w].s.priority);
    var full = [];
    for (var w2 = 0; w2 < open.length; w2++) {
      if (rest * priorityWeight(open[w2].s.priority) / wsum >= open[w2].ceiling) full.push(open[w2]);
    }
    if (!full.length) {
      for (var w3 = 0; w3 < open.length; w3++) open[w3].alloc = rest * priorityWeight(open[w3].s.priority) / wsum;
      rest = 0;
      break;
    }
    for (var w4 = 0; w4 < full.length; w4++) {
      full[w4].alloc = full[w4].ceiling;
      rest -= full[w4].ceiling;
      open.splice(open.indexOf(full[w4]), 1);
    }
  }

  // Each sender's allocation across its layers.
  for (var k = 0; k < info.length; k++) {
    var it = info[k];
    var given = 0;
    var droppedLayer = false;
    if (it.s.kind === 'audio') {
      for (var al = 0; al < it.live.length; al++) {
        // One layer per audio sender; more would share it in order.
        var ab = Math.min(it.live[al].ceiling, it.alloc - given);
        if (ab > 0) { out.layers[it.live[al].layer.key] = { bitrate: Math.round(ab), enabled: true }; given += ab; }
        else droppedLayer = true;
      }
    } else {
      var order = it.live.slice().sort(function (x, y) {
        var sx = x.layer.scale > 1 ? x.layer.scale : 1, sy = y.layer.scale > 1 ? y.layer.scale : 1;
        return (sy - sx) || (x.idx - y.idx);
      });
      var left = it.alloc;
      var chain = true;
      for (var o = 0; o < order.length; o++) {
        var e = order[o];
        var on;
        if (o === 0) on = left > 0;
        else {
          var min = Math.min(e.ceiling, Math.max(VIDEO_MIN_BPS, e.ceiling * LAYER_MIN_FRACTION));
          var need = e.layer.enabled === false ? min * LAYER_ENABLE_MARGIN : min;
          on = chain && left >= need;
        }
        if (on) {
          var b = Math.min(e.ceiling, left);
          out.layers[e.layer.key] = { bitrate: Math.round(b), enabled: true };
          left -= b;
          given += b;
        } else {
          chain = false;
          droppedLayer = true;
        }
      }
    }
    out.senders[it.s.id] = { allocatedBps: Math.round(given), droppedLayer: droppedLayer };
  }
  return out;
}

/**
 * Whether the congestion controller holds a sender below what the signaled
 * limits alone would let it send (W3C webrtc-stats qualityLimitationReason
 * 'bandwidth': "limited due to congestion cues during bandwidth
 * estimation"): one of its layers gets less, or is off, in `want` (the
 * allocation with the estimate) than in `hard` (estimate Infinity).
 */
function estimateLimited(sender, want, hard) {
  for (var i = 0; i < sender.layers.length; i++) {
    var k = sender.layers[i].key;
    var w = want.layers[k], h = hard.layers[k];
    if (!w || !h || !h.enabled) continue;
    if (!w.enabled || w.bitrate < h.bitrate) return true;
  }
  return false;
}


/**
 * RateHysteresis — decides which of an allocation's per-layer rates are
 * worth an encoder reconfigure now (see the header for the rule).
 *
 * @param {object} [opts]  decreaseStep, decreaseIntervalMs, urgentDecrease,
 *                         increaseStep, increaseIntervalMs
 */
function RateHysteresis(opts) {
  opts = opts || {};
  this._decStep  = opts.decreaseStep       != null ? opts.decreaseStep       : DECREASE_STEP;
  this._decMs    = opts.decreaseIntervalMs != null ? opts.decreaseIntervalMs : DECREASE_INTERVAL_MS;
  this._urgent   = opts.urgentDecrease     != null ? opts.urgentDecrease     : URGENT_DECREASE;
  this._incStep  = opts.increaseStep       != null ? opts.increaseStep       : INCREASE_STEP;
  this._incMs    = opts.increaseIntervalMs != null ? opts.increaseIntervalMs : INCREASE_INTERVAL_MS;
  this._applied  = Object.create(null);   // key -> { bitrate, enabled, at }
}

/**
 * @param {Object<string, {bitrate, enabled}>} want  allocateRates' layers
 *        (with the estimate)
 * @param {Object<string, {bitrate, enabled}>} hard  allocateRates' layers
 *        under the signaled limits alone (estimate Infinity): a rate above
 *        it is lowered at once
 * @param {number} nowMs
 * @returns {Array<{key, bitrate, enabled}>}  the changes to apply, by key
 */
RateHysteresis.prototype.decide = function (want, hard, nowMs) {
  var changes = [];
  var keys = Object.keys(want).sort();
  for (var i = 0; i < keys.length; i++) {
    var key = keys[i];
    var w = want[key];
    var prev = this._applied[key];
    if (!prev) {
      this._applied[key] = { bitrate: w.bitrate, enabled: w.enabled, at: nowMs };
      changes.push({ key: key, bitrate: w.bitrate, enabled: w.enabled });
      continue;
    }
    var hb = hard && hard[key];
    var overHard = !!hb && (!hb.enabled ? prev.enabled : prev.bitrate > hb.bitrate);
    if (!w.enabled) {
      if (prev.enabled) {
        prev.enabled = false; prev.at = nowMs;
        changes.push({ key: key, bitrate: prev.bitrate, enabled: false });
      }
      continue;
    }
    var apply = !prev.enabled || overHard;
    if (!apply && w.bitrate !== prev.bitrate) {
      var dt = nowMs - prev.at;
      if (w.bitrate < prev.bitrate) {
        var dr = (prev.bitrate - w.bitrate) / prev.bitrate;
        apply = dr >= this._urgent || (dr >= this._decStep && dt >= this._decMs);
      } else {
        var ir = prev.bitrate > 0 ? (w.bitrate - prev.bitrate) / prev.bitrate : Infinity;
        apply = ir >= this._incStep && dt >= this._incMs;
      }
    }
    if (!apply) continue;
    prev.bitrate = w.bitrate; prev.enabled = true; prev.at = nowMs;
    changes.push({ key: key, bitrate: w.bitrate, enabled: true });
  }
  return changes;
};

/** What was last applied to a layer, or null. */
RateHysteresis.prototype.applied = function (key) {
  var a = this._applied[key];
  return a ? { bitrate: a.bitrate, enabled: a.enabled } : null;
};

/** Forget a layer (its sender went away). */
RateHysteresis.prototype.forget = function (key) {
  delete this._applied[key];
};


// ═══════════════════════════════════════════════════════════════════
//  RTP circuit breaker (RFC 8083)
// ═══════════════════════════════════════════════════════════════════

var CB_K               = 5;       // §4.2: the RECOMMENDED non-reporting threshold
var CB_TMIN_MS         = 5000;    // §4.1: Td with the fixed minimum Tmin = 5 s
var CB_USABILITY_LOSS  = 0.5;     // §4.4: application dependent (ours)
var CB_USABILITY_MS    = 10000;   //       "on the order of seconds, or tens of seconds"
var CB_RECOVERY_MS     = 30000;   // §4.3: "after a reasonable amount of time"
var CB_WINDOW_MAX      = 64;

/**
 * The TCP throughput a Reno flow would get on the path, in bytes/s
 * (RFC 8083 §4.3, the simplified equation [Mathis], b = 1):
 *   X = s / (Tr * sqrt(2 * b * p / 3))
 * @param {number} s     packet size, bytes
 * @param {number} trSec round-trip time, s
 * @param {number} p     loss event rate (here the average fraction lost)
 */
function tcpThroughput(s, trSec, p) {
  if (!(p > 0) || !(trSec > 0)) return Infinity;
  return s / (trSec * Math.sqrt(2 * p / 3));
}

/**
 * CB_INTERVAL (RFC 8083 §4.3), in reports:
 *   ceil(3 * min(max(10*G*Tf, 10*Tr, 3*Tdr), max(15, 3*Td)) / (3*Tdr))
 * times in seconds.
 */
function cbInterval(G, tfSec, trSec, tdrSec, tdSec) {
  var inner = Math.min(Math.max(10 * G * tfSec, 10 * trSec, 3 * tdrSec), Math.max(15, 3 * tdSec));
  return Math.ceil(3 * inner / (3 * tdrSec));
}

/**
 * MEDIA_TIMEOUT (RFC 8083 §4.2), in reports: ceil(k * max(Tf, Tr, Tdr) / Tdr).
 */
function mediaTimeout(k, tfSec, trSec, tdrSec) {
  return Math.ceil(k * Math.max(tfSec, trSec, tdrSec) / tdrSec);
}

/**
 * The RTCP timeout circuit breaker (RFC 8083 §4.1): media sent and no RTCP
 * reporting on it for three deterministic intervals Td, Td with the fixed
 * minimum Tmin = 5 s.
 *
 * @param {number} nowMs
 * @param {number|null} lastRtcpAtMs  the last report (any SSRC of ours on
 *                                    this 5-tuple), or null
 * @param {number|null} sendingSinceMs when sending began, or null (not sending)
 * @param {number} tdMs               our deterministic interval
 */
function rtcpTimedOut(nowMs, lastRtcpAtMs, sendingSinceMs, tdMs) {
  if (sendingSinceMs == null) return false;
  var since = lastRtcpAtMs != null && lastRtcpAtMs > sendingSinceMs ? lastRtcpAtMs : sendingSinceMs;
  return nowMs - since >= 3 * Math.max(CB_TMIN_MS, tdMs);
}

/**
 * RtpCircuitBreaker — the media timeout (§4.2), congestion (§4.3) and
 * media usability (§4.4) circuit breakers of one RTP stream we send,
 * driven by the report blocks the peer returns for its SSRC. The RTCP
 * timeout (§4.1) is the connection's (rtcpTimedOut), as every SSRC rides
 * one 5-tuple; it trips the breakers with trip().
 *
 * States: 'ok'; 'reduced' (the congestion breaker fired once on a stream
 * whose encoder can cut its rate tenfold: §4.3 "MAY first reduce its
 * sending rate by this factor"; reducedCapBps holds the cap); 'tripped'
 * (cease transmission, §4.5: until reset()).
 *
 * @param {object} [opts]
 * @param {number}  [opts.frameIntervalMs=20]  Tf
 * @param {number}  [opts.groupSize=1]         G
 * @param {number}  [opts.ownIntervalMs=1000]  our Td
 * @param {boolean} [opts.canReduce=false]     the stream's rate can be cut
 */
function RtpCircuitBreaker(opts) {
  opts = opts || {};
  this.frameIntervalMs = opts.frameIntervalMs > 0 ? opts.frameIntervalMs : 20;
  this.groupSize       = opts.groupSize > 0 ? opts.groupSize : 1;
  this.ownIntervalMs   = opts.ownIntervalMs > 0 ? opts.ownIntervalMs : 1000;
  this.canReduce       = !!opts.canReduce;
  this.state           = 'ok';
  this.reason          = null;
  this.trippedAt       = null;
  this.holdMs          = 0;
  this.reducedCapBps   = null;
  this._reducedAt      = null;
  this._rttMs          = null;      // Tr, smoothed (§3)
  this._tdrMs          = null;      // Tdr, from the reports' spacing
  this._last           = null;      // { at, highestSeq, packets, bytes }
  this._misses         = 0;
  this._timeout        = null;      // MEDIA_TIMEOUT in force
  this._window         = [];        // { f, d, bytes, packets }
  this._badSince       = null;
}

/** A new RTT sample (RFC 8083 §3: Tr = 0.8 Tr + 0.2 Tr_new). */
RtpCircuitBreaker.prototype.updateRtt = function (rttMs) {
  if (!(rttMs >= 0)) return;
  this._rttMs = this._rttMs == null ? rttMs : 0.8 * this._rttMs + 0.2 * rttMs;
};

RtpCircuitBreaker.prototype.trip = function (reason, nowMs, holdMs) {
  if (this.state === 'tripped') return;
  this.state = 'tripped';
  this.reason = reason;
  this.trippedAt = nowMs;
  this.holdMs = holdMs > 0 ? holdMs : 0;
  this.reducedCapBps = null;
};

/**
 * Clear a tripped (or reduced) breaker — the application asked to send
 * again (§4.5). Refused (false) until the reaction has lasted the interval
 * that triggered it ("MUST rate limit attempts to restart a flow").
 */
RtpCircuitBreaker.prototype.reset = function (nowMs) {
  if (this.state === 'tripped' && nowMs - this.trippedAt < this.holdMs) return false;
  this.state = 'ok';
  this.reason = null;
  this.trippedAt = null;
  this.holdMs = 0;
  this.reducedCapBps = null;
  this._reducedAt = null;
  this._last = null;
  this._misses = 0;
  this._timeout = null;
  this._window = [];
  this._badSince = null;
  return true;
};

/**
 * A report block on this stream's SSRC (an RR or SR of the peer).
 *
 * @param {{fractionLost: number, highestSeq: number}} rep  the block (the
 *        fraction an 8-bit fixed point number, the extended highest
 *        sequence number received)
 * @param {{packets: number, bytes: number}} sent  our cumulative counters
 *        for the SSRC now
 * @param {number} nowMs
 * @returns {string|null}  'reduce' | 'recover' | 'cease' when the state
 *          changed, else null
 */
RtpCircuitBreaker.prototype.onReport = function (rep, sent, nowMs) {
  if (this.state === 'tripped') return null;
  var last = this._last;
  this._last = { at: nowMs, highestSeq: rep.highestSeq >>> 0, packets: sent.packets, bytes: sent.bytes };
  // The first block: the receiver has our media (it reports on the SSRC).
  if (!last) return null;
  var d = nowMs - last.at;
  if (!(d > 0)) return null;   // a second block on the same instant
  this._tdrMs = this._tdrMs == null ? d : 0.8 * this._tdrMs + 0.2 * d;
  var tdr = this._tdrMs / 1000, tr = this._rttMs == null ? 0 : this._rttMs / 1000;
  var tf = this.frameIntervalMs / 1000;
  var dPackets = sent.packets - last.packets, dBytes = sent.bytes - last.bytes;

  // §4.2 media timeout: an extended highest sequence number that did not
  // move while we sent.
  var moved = (((rep.highestSeq >>> 0) - last.highestSeq) >>> 0);
  var increased = moved > 0 && moved < 0x80000000;
  if (increased) {
    this._misses = 0;
    this._timeout = mediaTimeout(CB_K, tf, tr, tdr);
  } else if (dPackets > 0) {
    var mt = mediaTimeout(CB_K, tf, tr, tdr);
    if (this._timeout == null || mt > this._timeout) this._timeout = mt;
    this._misses++;
    if (this._misses >= this._timeout) {
      this.trip('media-timeout', nowMs, this._misses * this._tdrMs);
      return 'cease';
    }
  }

  // §4.3 congestion: only while sending at least one packet every
  // max(Tdr, Tr).
  if (dPackets > 0 && dPackets * Math.max(this._tdrMs, this._rttMs || 0) >= d) {
    this._window.push({ f: Math.min(rep.fractionLost, 255) / 256, d: d, bytes: dBytes, packets: dPackets });
    if (this._window.length > CB_WINDOW_MAX) this._window.shift();
  }
  var n = cbInterval(this.groupSize, tf, tr, tdr, this.ownIntervalMs / 1000);
  if (this._window.length === 0) return null;
  var span = this._window.slice(-n);
  var fd = 0, dd = 0, bb = 0, pp = 0;
  for (var i = 0; i < span.length; i++) { fd += span[i].f * span[i].d; dd += span[i].d; bb += span[i].bytes; pp += span[i].packets; }
  var p = dd > 0 ? fd / dd : 0;

  // §4.4 media usability: loss this high for this long.
  if (p >= CB_USABILITY_LOSS) {
    if (this._badSince == null) this._badSince = nowMs - dd;
    if (nowMs - this._badSince >= CB_USABILITY_MS) {
      this.trip('media-usability', nowMs, nowMs - this._badSince);
      return 'cease';
    }
  } else this._badSince = null;

  // "If more than CB_INTERVAL report blocks have been received".
  if (this._rttMs == null || this._window.length <= n || pp <= 0 || dd <= 0) {
    return this._maybeRecover(nowMs);
  }
  var s = bb / pp;
  var rate = bb / (dd / 1000);   // bytes/s
  var x = tcpThroughput(s, this._rttMs / 1000, p);
  if (rate > 10 * x) {
    if (this.state === 'ok' && this.canReduce) {
      this.state = 'reduced';
      this.reason = 'congestion';
      this.reducedCapBps = rate * 8 / 10;
      this._reducedAt = nowMs;
      this._window = [];   // the next CB_INTERVAL reports judge the reduction
      return 'reduce';
    }
    this.trip('congestion', nowMs, dd);
    return 'cease';
  }
  return this._maybeRecover(nowMs);
};

RtpCircuitBreaker.prototype._maybeRecover = function (nowMs) {
  if (this.state === 'reduced' && nowMs - this._reducedAt >= CB_RECOVERY_MS) {
    this.state = 'ok';
    this.reason = null;
    this.reducedCapBps = null;
    this._reducedAt = null;
    return 'recover';
  }
  return null;
};


/**
 * The TMMBR limit of one SSRC at a packet rate: tmmbrNetBitrate over its
 * effective bounding set (rtp-packet), Infinity when none.
 */
function tmmbrLimit(entry, packetRate) {
  if (!entry || !entry.effective || !entry.effective.length) return Infinity;
  return tmmbrNetBitrate(entry.effective, packetRate);
}


export {
  MEDIA_SHARE, AUDIO_DEFAULT_BPS, AUDIO_MIN_BPS, VIDEO_DEFAULT_BPS, VIDEO_MIN_BPS,
  LAYER_MIN_FRACTION, LAYER_ENABLE_MARGIN, PRIORITY_WEIGHT,
  priorityWeight, remoteBandwidthLimits, layerCeiling, allocateRates, estimateLimited,
  RateHysteresis,
  tcpThroughput, cbInterval, mediaTimeout, rtcpTimedOut, RtpCircuitBreaker,
  tmmbrLimit,
};

// src/media_transport.js
//
// MediaTransport — the data plane orchestrator. Owns RTP/RTCP send and
// receive paths, SRTP encrypt/decrypt, NACK/RTX, BWE, and per-stream stats.
//
// Architectural position (libwebrtc terms):
//
//   ConnectionManager (composition root)
//     ├── SdpOfferAnswer          (signaling state machine)
//     ├── DataChannelController   (DCEP + SCTP)
//     └── MediaTransport          ← THIS FILE
//          • RTP/RTCP send + receive
//          • SRTP encrypt/decrypt
//          • NACK + RTX retransmit
//          • RTCP scheduling (SR, RR, REMB, TWCC, NACK feedback)
//          • Bandwidth estimation
//
//   media_pipeline.js (above MediaTransport — its consumer):
//     • Encoders, decoders, packetize, depacketize, jitter buffer
//     • Talks to MediaTransport via manager.sendRtp() / manager.ev.on('rtp', …)
//
// Style: callbacks + events, no Promises. Promises live ONLY in api.js.
//
// State strategy: like SdpOfferAnswer and DataChannelController, this class
// is incrementally built. Today (8a) it owns the RTCP layer:
//   - sendRtcp, handleIncomingRtcp, requestKeyframe
//   - startRtcpTimer (1s SR/RR/REMB cadence)
//   - startTccFeedbackTimer (100ms TCC feedback)
//   - startNackFeedbackTimer (100ms NACK feedback + PLI escalation)
// Subsequent milestones move RTP receive (8b), RTP send + NACK retransmit
// (8c), and BWE/jitter integration (8d) into this class.
//
// Until then, much of the data-plane state (rtpStats, outboundStats,
// nackGenerators, tccFeedbackGenerators, bandwidthEstimator, etc.) lives in
// sharedState and is read through deps.sharedState. cm.js still owns
// handleNack (RTX retransmit) and setRtxMapping; this class calls them
// through deps.handleNack.

import { EventEmitter } from 'node:events';
import {
  parse as parseRtp,
  parseRtxPacket,
  NackGenerator,
  TransportCCFeedbackGenerator,
  RtxStream,
  buildPLI, buildRR, buildSR, buildNACK, buildREMB,
  parseRTCPCompound,
  parseTransportCC, parseREMB,
} from 'rtp-packet';


// Synthetic packet-loss simulation (off by default). Enable with the
// DROP_RTP_PCT environment variable (e.g. DROP_RTP_PCT=5 = 5% loss). Only
// useful for exercising NACK/RTX retransmission paths over a reliable
// loopback. Never drops the first 30 packets — Chrome needs a clean
// initial keyframe to stand up the decoder pipeline. RTX retransmissions
// themselves are exempt so we don't cascade losses.
var _DROP_RTP_PCT = (typeof process !== 'undefined' && process.env && parseFloat(process.env.DROP_RTP_PCT)) || 0;
if (_DROP_RTP_PCT > 0 && typeof console !== 'undefined' && console.warn) {
  console.warn('[mt-diag] SYNTHETIC PACKET LOSS ENABLED: ' + _DROP_RTP_PCT + '% — for testing NACK/RTX only');
}


class MediaTransport extends EventEmitter {
  /**
   * @param {Object} deps
   * @param {Function} deps.getClosed                () => boolean
   * @param {Object}   deps.sharedState              cm.js state object (read/write)
   * @param {Function} deps.getIceAgent              () => IceAgent | null
   *   ICE agent is the wire-out. Created lazily by cm.js; we look it up at
   *   send time (not constructor time) so we don't hold a stale reference.
   * @param {Function} deps.getSrtpSession           () => SrtpSession | null
   *   SRTP session for encrypt/decrypt. Same lazy-lookup rationale.
   * @param {Function} deps.findRemoteSsrcForMid     (mid) => number | null
   *   Used by requestKeyframe and NACK→PLI escalation.
   * @param {Function} deps.findPrimaryForRtx        (mapping) => number | null
   *   Resolve which primary SSRC an RTX SSRC repairs. Used by the RTP
   *   receive pipeline to unwrap RFC 4588 RTX packets.
   * @param {Function} deps.resolvePeekKeyframeFn    (codecName) => Function|null
   *   Look up a per-codec keyframe-detection function. Used for NACK
   *   eviction (skip gaps that resolve at a keyframe).
   * @param {Function} [deps.diag]                   (msg) => void  (logging)
   * @param {boolean}  [deps.debug]                  enable diagnostic logs
   */
  constructor(deps) {
    super();

    if (!deps || typeof deps.getClosed !== 'function') {
      throw new TypeError('MediaTransport: deps.getClosed required');
    }
    if (!deps.sharedState || typeof deps.sharedState !== 'object') {
      throw new TypeError('MediaTransport: deps.sharedState required');
    }
    if (typeof deps.getIceAgent !== 'function') {
      throw new TypeError('MediaTransport: deps.getIceAgent required');
    }
    if (typeof deps.getSrtpSession !== 'function') {
      throw new TypeError('MediaTransport: deps.getSrtpSession required');
    }
    if (typeof deps.findRemoteSsrcForMid !== 'function') {
      throw new TypeError('MediaTransport: deps.findRemoteSsrcForMid required');
    }
    if (typeof deps.findPrimaryForRtx !== 'function') {
      throw new TypeError('MediaTransport: deps.findPrimaryForRtx required');
    }
    if (typeof deps.resolvePeekKeyframeFn !== 'function') {
      throw new TypeError('MediaTransport: deps.resolvePeekKeyframeFn required');
    }

    this._deps  = deps;
    this._state = deps.sharedState;
    this._diag  = deps.diag || function () {};
    this._debug = !!deps.debug;

    // Timer handles. null = not running. close() clears them.
    this._rtcpTimer        = null;
    this._tccFeedbackTimer = null;
    this._nackFeedbackTimer = null;
  }


  /* ====================== Outgoing RTP ====================== */

  /**
   * Bare-bones packet send — no encryption, no stamping, no stats. Used
   * by callers that handle their own framing (ICE consent checks, etc.).
   * Most code should go through sendRtp/sendRtcp instead.
   */
  sendPacket(buf) {
    var ice = this._deps.getIceAgent();
    if (ice) ice.send(buf);
  }

  /**
   * Send a single RTP packet:
   *   1. Stamp outgoing header extensions (transport-cc seq, abs-send-time).
   *   2. Save plaintext copy in the senderBuffer for potential RTX retransmit.
   *   3. Record send timing in the bandwidth estimator.
   *   4. (Optional) synthetic packet drop for testing NACK/RTX paths.
   *   5. SRTP-encrypt and send via ICE.
   *   6. Update outboundStats.
   *
   * Caller (media_pipeline.js) is responsible for packet framing — we treat
   * the buffer as a complete RTP packet and only modify the extension area.
   */
  sendRtp(rtpPacket) {
    var state = this._state;
    var srtp = this._deps.getSrtpSession();
    var ice = this._deps.getIceAgent();
    if (!srtp || !ice) {
      if (!state._diagSendRtpSkipLogged) {
        this._diag('[cm-diag] sendRtp SKIPPED — srtpSession=' + !!srtp + ' iceAgent=' + !!ice);
        state._diagSendRtpSkipLogged = true;
      }
      return;
    }

    // Apply outgoing header extensions (transport-cc seq, abs-send-time).
    // The stamper owns the per-session counter state and centralizes all
    // RTP-protocol knowledge in one place (libwebrtc's RTPSenderEgress
    // does the same).
    rtpPacket = state.headerStamper.stamp(rtpPacket);

    // Save a copy of the plaintext RTP for potential NACK retransmission.
    // We store the packet as it will go on the wire (transport-cc extension
    // already applied) so an RTX retransmit carries the same original
    // transport-wide seq — that's what the remote expects.
    state.senderBuffer.store(rtpPacket);

    // Bandwidth estimator: record send time so future transport-cc feedback
    // can compute delay gradients against our send times. Pair the recorded
    // seq with what the stamper just stamped.
    state.bandwidthEstimator.recordSend(
      state.headerStamper.lastTransportCcSeq(),
      Date.now(),
      rtpPacket.length
    );

    // Synthetic packet drop (DROP_RTP_PCT env var). Skips the first 30
    // packets so Chrome's decoder bootstraps cleanly. RTX packets exempt.
    if (_DROP_RTP_PCT > 0) {
      if (!state._sendRtpTotal) state._sendRtpTotal = 0;
      state._sendRtpTotal++;
      var ssrcPeek = rtpPacket.readUInt32BE(8);
      var isRtxPacket = state.rtxStreams[Object.keys(state.rtxStreams)[0]] &&
                        Object.values(state.rtxStreams).some(function (r) { return r.ssrc() === ssrcPeek; });
      if (state._sendRtpTotal > 30 && !isRtxPacket && (Math.random() * 100) < _DROP_RTP_PCT) {
        if (!state._droppedRtpTotal) state._droppedRtpTotal = 0;
        state._droppedRtpTotal++;
        if (state._droppedRtpTotal <= 3 || state._droppedRtpTotal % 50 === 0) {
          var seqPeek = rtpPacket.readUInt16BE(2);
          this._diag('[cm-diag] SYNTHETIC DROP #' + state._droppedRtpTotal +
            ' ssrc=' + ssrcPeek + ' seq=' + seqPeek +
            ' (total sent=' + state._sendRtpTotal + ')');
        }
        return;   // "drop" — skip encryption/send but keep the buffer entry
      }
    }

    var enc = srtp.encryptRtp(rtpPacket);
    if (!enc) {
      if (!state._diagSendRtpNullLogged) {
        this._diag('[cm-diag] sendRtp — encryptRtp returned NULL, rtp.length=' + rtpPacket.length);
        state._diagSendRtpNullLogged = true;
      }
      return;
    }

    var ssrc = rtpPacket.readUInt32BE(8);

    // Outbound RTP stats — per-SSRC, cumulative (mirrors state.rtpStats for
    // inbound). Used by RTCRtpSender.getStats() to build 'outbound-rtp'
    // entries and by RTCP SR generation.
    var o = state.outboundStats[ssrc];
    if (!o) {
      o = state.outboundStats[ssrc] = {
        packets:       0,
        bytes:         0,
        payloadType:   rtpPacket[1] & 0x7F,
        firstPacketAt: Date.now(),
        lastPacketAt:  Date.now(),
      };
    }
    o.packets++;
    o.bytes += rtpPacket.length;
    o.lastPacketAt = Date.now();
    // Most recent sent RTP seq — diagnostic aid for NACK gap analysis.
    o.lastSentSeq = (rtpPacket[2] << 8) | rtpPacket[3];

    if (!state._diagSendRtpCount) state._diagSendRtpCount = 0;
    state._diagSendRtpCount++;
    if (state._diagSendRtpCount <= 3 || state._diagSendRtpCount % 300 === 0) {
      this._diag('[cm-diag] sendRtp #' + state._diagSendRtpCount +
        ' rtp.length=' + rtpPacket.length +
        ' srtp.length=' + enc.length +
        ' ssrc=' + ssrc +
        ' selectedPair=' + (state.selectedPair ? 'yes' : 'NO'));
    }
    ice.send(enc);
  }

  /**
   * Handle an incoming NACK (RFC 4585 §6.2.1). For each lost sequence
   * number the remote is asking for, look it up in the sender buffer and
   * re-send wrapped in an RTX (RFC 4588) packet.
   *
   * Buffer + RTX construction + throttling all live in rtp-packet's
   * retransmit module. We orchestrate: look up, encrypt, send.
   */
  handleNack(senderSsrc, mediaSsrc, lostSeqs) {
    if (!lostSeqs || lostSeqs.length === 0) return;

    var state = this._state;
    var rtx = state.rtxStreams[mediaSsrc];
    if (!rtx) return;   // no RTX negotiated for this stream

    var srtp = this._deps.getSrtpSession();
    var ice = this._deps.getIceAgent();
    if (!srtp || !ice) return;

    // Pull the current outbound head to compute "how far behind" the NACK
    // is from what we most recently sent. Few packets = real-time loss.
    // Hundreds = packet long gone.
    var o = state.outboundStats[mediaSsrc];
    var currentSeq = (o && o.lastSentSeq != null) ? o.lastSentSeq : null;

    var sent = 0, missing = 0, throttled = 0;
    for (var i = 0; i < lostSeqs.length; i++) {
      var lostSeq = lostSeqs[i];

      // Throttle: don't retransmit the same (ssrc, seq) pair faster than
      // once per 100ms. Protects against NACK storms doubling our upstream.
      if (!state.nackThrottle.shouldSend(mediaSsrc, lostSeq)) {
        throttled++;
        continue;
      }

      var origPkt = state.senderBuffer.get(mediaSsrc, lostSeq);
      if (!origPkt) {
        // Packet evicted from the ring buffer (too old) — can't help.
        missing++;
        continue;
      }

      var rtxPacket = rtx.wrap(origPkt);
      if (!rtxPacket) continue;

      var rtxSrtp = srtp.encryptRtp(rtxPacket);
      if (!rtxSrtp) continue;
      ice.send(rtxSrtp);
      sent++;

      // Surface retransmission in outbound-rtp stats.
      if (o) {
        o.retransmittedPacketsSent = (o.retransmittedPacketsSent || 0) + 1;
        o.retransmittedBytesSent   = (o.retransmittedBytesSent   || 0) + rtxPacket.length;
        o.nackCount                = (o.nackCount || 0) + 1;
      }
    }

    // Diag pattern: every NACK for the first 20, then every 50th. Shows
    // bursts vs steady-state loss without flooding logs.
    if (!state._diagNackCount) state._diagNackCount = 0;
    state._diagNackCount++;
    if (state._diagNackCount <= 20 || state._diagNackCount % 50 === 0) {
      // Gap between oldest NACKed seq and current outbound head shows
      // whether we're chasing stale packets or near-real-time feedback.
      var minNacked = lostSeqs[0];
      var maxNacked = lostSeqs[0];
      for (var k = 1; k < lostSeqs.length; k++) {
        if (lostSeqs[k] < minNacked) minNacked = lostSeqs[k];
        if (lostSeqs[k] > maxNacked) maxNacked = lostSeqs[k];
      }
      var gap = (currentSeq != null) ? ((currentSeq - maxNacked) & 0xFFFF) : '?';
      this._diag('[cm-diag] NACK#' + state._diagNackCount +
        ' ssrc=' + mediaSsrc +
        ' seqs=[' + minNacked + '..' + maxNacked + '] (' + lostSeqs.length + ')' +
        ' currentSeq=' + currentSeq +
        ' gap=' + gap +
        ' resent=' + sent +
        ' throttled=' + throttled +
        ' missing=' + missing);
    }
  }

  /**
   * Register the RTX association between a primary SSRC and its RTX SSRC.
   * Called when a transceiver with RTX support is created (cm.js's
   * addTransceiverInternal). Each call sets up a fresh RtxStream (fresh
   * random initial seq) in rtp-packet.
   */
  setRtxMapping(primarySsrc, rtxSsrc, rtxPt) {
    this._state.rtxStreams[primarySsrc] = new RtxStream({
      rtxSsrc: rtxSsrc,
      rtxPt:   rtxPt,
    });
  }

  /**
   * Register codec metadata for an outbound RTP stream BEFORE the first
   * packet flows. Pre-populates state.outboundStats[ssrc] with the codec
   * metadata that downstream RTCP generation needs to build correct
   * sender reports.
   *
   * Why this exists:
   *   The RTCP SR's rtpTimestamp field (RFC 3550 §6.4.1) must correspond
   *   to the same wall-clock instant as ntpTimestamp, so receivers can
   *   align media streams (lipsync). Computing it requires extrapolating
   *   the most recent sent rtpTimestamp forward by elapsed wall-clock
   *   time × clockRate. Without clockRate, the SR builder falls back to
   *   the unextrapolated last-sent timestamp (one frame off) or 0 (no
   *   sync at all). This API plumbs clockRate from where it's known
   *   (api.js's _startPipeline, after SDP negotiation) to where it's
   *   needed (the SR builder, in the periodic RTCP timer).
   *
   * Idempotent: if the entry already exists, codec fields are merged in
   * without disturbing packet/byte counters. Safe to call multiple times
   * for the same SSRC across replaceTrack flows. Safe to call before OR
   * after the first sendRtp — sendRtp's lazy-init handles either order.
   *
   * @param {number} ssrc
   * @param {Object} info     {clockRate, codecName?, payloadType?}
   *   clockRate     — RTP timebase tick rate (Hz). VP8/VP9/H264: 90000.
   *                   Opus: 48000. G.711: 8000. Required for SR sync.
   *   codecName     — informational, e.g. 'VP8'. Currently unused but
   *                   reserved for richer outbound-rtp stats reporting.
   *   payloadType   — declared PT for the stream. If absent, sendRtp
   *                   reads it from the first packet's header instead.
   */
  registerOutboundStream(ssrc, info) {
    if (ssrc == null || !info) return;
    var state = this._state;
    var o = state.outboundStats[ssrc];
    if (!o) {
      // Pre-create the entry. Counters start at 0 and firstPacketAt
      // stays 0 — sendRtp's lazy-init branch sets it to the actual
      // first-send timestamp when the first packet arrives. payloadType
      // gets a placeholder if not provided here (sendRtp will overwrite
      // only when creating an entry from scratch, so we explicitly set
      // it here too if known).
      o = state.outboundStats[ssrc] = {
        packets:       0,
        bytes:         0,
        payloadType:   (info.payloadType != null) ? info.payloadType : 0,
        firstPacketAt: 0,
        lastPacketAt:  0,
      };
    }
    if (typeof info.clockRate === 'number' && info.clockRate > 0) {
      o.clockRate = info.clockRate;
    }
    if (info.codecName) {
      o.codecName = info.codecName;
    }
    if (info.payloadType != null) {
      o.payloadType = info.payloadType;
    }
  }


  /* ====================== Outgoing RTCP ====================== */

  /**
   * Encrypt and send a single RTCP packet (or compound). No-op if SRTP
   * isn't ready or ICE agent isn't up. Compound RTCP must already be
   * assembled by the caller (we don't wrap into compound here).
   */
  sendRtcp(rtcpPacket) {
    var srtp = this._deps.getSrtpSession();
    var ice  = this._deps.getIceAgent();
    if (!srtp || !ice) return;
    var srtcp = srtp.encryptRtcp(rtcpPacket);
    if (srtcp) ice.send(srtcp);
  }

  /**
   * Send a PLI (Picture Loss Indication, RFC 4585 §6.3) for a remote SSRC.
   *
   * Per-SSRC by design — matches libwebrtc's RTCPSender::BuildPLI which
   * uses a per-instance `remote_ssrc_` set via SetRemoteSSRC():
   *
   *   void RTCPSender::BuildPLI(...) {
   *     rtcp::Pli pli;
   *     pli.SetSenderSsrc(ssrc_);          // local_media_ssrc
   *     pli.SetMediaSsrc(remote_ssrc_);    // bound at construction
   *   }
   *
   * For simulcast, libwebrtc instantiates ONE RtpRtcp module per layer,
   * each with its own (local_media_ssrc, remote_ssrc) pair. The right
   * primitive is therefore "send PLI to a specific SSRC", not "send PLI
   * for a mid" — multiple SSRCs can share a mid (3 simulcast layers all
   * carry the same mid), and a per-mid API silently picks one layer's
   * SSRC and leaves the other two without their requested keyframe.
   *
   * Callers in this codebase that have an SSRC in scope:
   *   - first-sink-attach hook in media_pipeline.js (per-receiver SSRC)
   *   - first-round PLI burst (iterates remoteSsrcList — per-SSRC)
   *   - NACK→PLI escalation (the per-stream NackGenerator's bound SSRC)
   * All three already had the SSRC available; the previous mid-based
   * indirection threw it away and re-resolved (incorrectly) via
   * findRemoteSsrcForMid.
   *
   * Defensive checks:
   *   - skip RTX SSRCs (RFC 4588 retransmission streams don't carry
   *     primary frames, have no keyframes of their own; sending PLI is
   *     a protocol error)
   *   - localSsrc resolved via the mapping's mid (for buildPLI's
   *     senderSsrc field). Falls back to 1 if no mapping (consistent
   *     with prior behavior).
   *
   * @param {number} remoteSsrc  SSRC of the primary stream to ask for
   *                             a keyframe on.
   */
  requestKeyframe(remoteSsrc) {
    if (!Number.isFinite(remoteSsrc) || remoteSsrc < 0) return;
    var state = this._state;
    var mapping = state.remoteSsrcMap[remoteSsrc];
    if (mapping && mapping.isRtx) return;   // PLI to RTX is invalid
    var localSsrc = 1;
    if (mapping && state.localSsrcs[mapping.mid]) {
      localSsrc = state.localSsrcs[mapping.mid].id;
    }
    this.sendRtcp(buildPLI(localSsrc, remoteSsrc));
  }


  /* ====================== Incoming RTCP ====================== */

  /**
   * Handle an incoming SRTCP packet. Decrypts, parses (compound), and
   * dispatches each sub-packet by type. No-op if SRTP isn't up.
   */
  handleIncomingRtcp(buf, rinfo) {
    var srtp = this._deps.getSrtpSession();
    if (!srtp) return;

    var rtcp = srtp.decryptRtcp(buf);
    if (!rtcp) return;

    // RTCP is almost always compound (RFC 3550 §6.1) — e.g. RR+SDES, or
    // SR+RR+SDES. Parse every sub-packet, then process each individually.
    var parsedList = parseRTCPCompound(rtcp);

    for (var pi = 0; pi < parsedList.length; pi++) {
      var parsed = parsedList[pi];
      if (!parsed) continue;

      this._handleRtcpSubpacket(parsed);

      // Forward every parsed RTCP packet to whoever is listening
      // ('rtcp' is mostly a debug/observability event).
      this.emit('rtcp', rtcp, rinfo, parsed);
    }
  }

  _handleRtcpSubpacket(parsed) {
    var state = this._state;

    // SR: remote-outbound stats + DLSR bookkeeping for our outgoing RR.
    if (parsed.name === 'SR' && state.rtpStats[parsed.ssrc]) {
      this._handleSr(parsed);
    }

    // RR/SR report blocks: remote's view of the streams WE send.
    if ((parsed.name === 'RR' || parsed.name === 'SR') && parsed.reports) {
      this._handleReportBlocks(parsed);
    }

    // NACK: retransmit via RTX. Logic is now on this class (handleNack
    // method below).
    if (parsed.name === 'NACK' && parsed.lostSequenceNumbers && parsed.mediaSsrc) {
      this.handleNack(parsed.senderSsrc, parsed.mediaSsrc, parsed.lostSequenceNumbers);
    }

    // PLI / FIR: peer asks for a keyframe. Bump stats and emit so the
    // media pipeline (encoder) can produce one.
    if (parsed.name === 'PLI' && parsed.mediaSsrc) {
      if (state.outboundStats[parsed.mediaSsrc]) {
        state.outboundStats[parsed.mediaSsrc].pliCount =
          (state.outboundStats[parsed.mediaSsrc].pliCount || 0) + 1;
      }
      this.emit('pli', parsed.mediaSsrc);
    }
    if (parsed.name === 'FIR' && parsed.mediaSsrc) {
      if (state.outboundStats[parsed.mediaSsrc]) {
        state.outboundStats[parsed.mediaSsrc].firCount =
          (state.outboundStats[parsed.mediaSsrc].firCount || 0) + 1;
      }
      this.emit('pli', parsed.mediaSsrc);
    }

    // Transport-wide congestion control feedback (RTPFB PT=205 FMT=15).
    // Feed delay-variation info to the bandwidth estimator.
    if (parsed.name === 'TransportCC' && parsed.fci) {
      var tccReport = parseTransportCC(parsed.fci);
      if (tccReport) {
        state.bandwidthEstimator.observeTransportCC(tccReport);
        if (!state._diagTccCount) state._diagTccCount = 0;
        state._diagTccCount++;
        if (state._diagTccCount <= 3 || state._diagTccCount % 50 === 0) {
          this._diag('[cm-diag] TransportCC #' + state._diagTccCount +
            ' baseSeq=' + tccReport.baseSeq +
            ' pkts=' + tccReport.packetCount +
            ' estimate=' + state.bandwidthEstimator.getEstimate() + ' bps');
        }
      }
    }

    // REMB (PSFB PT=206 FMT=15) — remote's bitrate estimate.
    if (parsed.name === 'REMB' && parsed.fci) {
      var rembReport = parseREMB(parsed.fci);
      if (rembReport) {
        state.bandwidthEstimator.observeRemb(rembReport.bitrate);
        if (!state._diagRembCount) state._diagRembCount = 0;
        state._diagRembCount++;
        if (state._diagRembCount <= 3 || state._diagRembCount % 20 === 0) {
          this._diag('[cm-diag] REMB #' + state._diagRembCount +
            ' remoteBps=' + rembReport.bitrate +
            ' estimate=' + state.bandwidthEstimator.getEstimate() + ' bps');
        }
      }
    }
  }

  _handleSr(parsed) {
    // SR sender-info tracks what the REMOTE peer is sending to US.
    // Maps to W3C 'remote-outbound-rtp' (their outbound == our inbound).
    var state = this._state;
    var remoteOut = state.remoteOutboundStats[parsed.ssrc];
    if (!remoteOut) {
      remoteOut = state.remoteOutboundStats[parsed.ssrc] = {
        packetsSent:                0,
        bytesSent:                  0,
        reportsSent:                0,
        ntpTimestampMsw:            0,
        ntpTimestampLsw:            0,
        rtpTimestamp:               0,
        remoteTimestampMs:          0,
        roundTripTime:              0,
        totalRoundTripTime:         0,
        roundTripTimeMeasurements:  0,
        updatedAt:                  0,
      };
    }
    // RFC 3550 SR header: packet count + octet count are accumulators
    // from the beginning of the stream. Don't sum them — just record.
    remoteOut.packetsSent      = parsed.packetCount >>> 0;
    remoteOut.bytesSent        = parsed.octetCount  >>> 0;
    remoteOut.ntpTimestampMsw  = parsed.ntpTimestampMsw >>> 0;
    remoteOut.ntpTimestampLsw  = parsed.ntpTimestampLsw >>> 0;
    remoteOut.rtpTimestamp     = parsed.rtpTimestamp >>> 0;
    // Convert NTP (seconds since 1900) to Unix-epoch ms.
    // NTP epoch = 1900-01-01; Unix epoch = 1970-01-01; diff = 2208988800 sec.
    var ntpSecUnix = (parsed.ntpTimestampMsw >>> 0) - 2208988800;
    var ntpFracMs  = (parsed.ntpTimestampLsw >>> 0) / 4294967296 * 1000;
    remoteOut.remoteTimestampMs = ntpSecUnix * 1000 + ntpFracMs;
    remoteOut.reportsSent++;
    remoteOut.updatedAt = Date.now();

    // Cache the remote's SR middle32 so our outgoing RR's "DLSR" field
    // can report the correct delay-since-last-SR for the remote peer.
    // lastSR is the middle 32 bits of the NTP timestamp — upper 16 of
    // msw concatenated with upper 16 of lsw.
    var stats_ = state.rtpStats[parsed.ssrc];
    stats_.lastSR =
      (((parsed.ntpTimestampMsw & 0xFFFF) << 16) |
       ((parsed.ntpTimestampLsw >>> 16) & 0xFFFF)) >>> 0;
    stats_.lastSRTime = Date.now();
  }

  _handleReportBlocks(parsed) {
    // RR/SR report blocks describe packets the remote peer has RECEIVED
    // from us. For each block, mediaSsrc identifies one of OUR outbound
    // streams. We ignore blocks whose mediaSsrc isn't in outboundStats.
    var state = this._state;
    for (var ri = 0; ri < parsed.reports.length; ri++) {
      var rep = parsed.reports[ri];
      var targetSsrc = rep.mediaSsrc;
      if (!state.outboundStats[targetSsrc]) continue;

      var rs = state.rtcpStats[targetSsrc];
      if (!rs) rs = state.rtcpStats[targetSsrc] = {};
      rs.fractionLost     = rep.fractionLost || 0;
      rs.totalLost        = rep.totalLost    || 0;
      rs.highestSeq       = rep.highestSeq   || 0;
      rs.jitter           = rep.jitter       || 0;
      rs.lastSR           = rep.lastSR       || 0;
      rs.delaySinceLastSR = rep.delaySinceLastSR || 0;
      rs.updatedAt        = Date.now();

      // RTT estimate (RFC 3550 §6.4.1): if we sent SR at time T with
      // middle32(NTP)=M, and the remote's RR reports lastSR=M with a
      // delay-since-last-SR of D (1/65536 s ticks), then:
      //   RTT = now - T - D * 1000 / 65536   [ms]
      if (rs.lastSR && state.lastOwnSR && state.lastOwnSR.middle32 === rs.lastSR) {
        var now = Date.now();
        var dlsrMs = (rs.delaySinceLastSR * 1000) / 65536;
        var rttMs = now - state.lastOwnSR.at - dlsrMs;
        if (rttMs >= 0) {
          rs.roundTripTime    = rttMs;
          rs.totalRoundTripTime = (rs.totalRoundTripTime || 0) + rttMs;
          rs.rttMeasurements  = (rs.rttMeasurements || 0) + 1;

          // Propagate RTT to all NACK generators. RTT is symmetric over
          // the same network path, so a measurement from the remote about
          // our outbound is equally valid for retry timing on their inbound
          // streams to us.
          var ngKeys = Object.keys(state.nackGenerators);
          for (var ng = 0; ng < ngKeys.length; ng++) {
            state.nackGenerators[ngKeys[ng]].updateRtt(rttMs);
          }

          // Notify external subscribers (typically media-pipeline jitter
          // buffers) that a fresh RTT is in. The jitter buffer uses RTT
          // to extend its loss-declaration wait window so RTX-recovered
          // packets have time to slot back into order.
          this.emit('rtt:update', rttMs);
        }
      }
    }
  }


  /* ====================== Incoming RTP ====================== */

  /**
   * Outer entry point: handles SRTP decryption only. The body of the
   * receive pipeline lives in _handleIncomingRtpInner so that we can
   * recurse into it cleanly when an RTX packet (RFC 4588) is unwrapped:
   * the recursion takes a *plaintext* RTP packet, so it must not pass
   * through decryption a second time.
   */
  handleIncomingRtp(buf, rinfo) {
    var srtp = this._deps.getSrtpSession();
    if (!srtp) return;

    var rtp = srtp.decryptRtp(buf);
    if (!rtp) {
      var state = this._state;
      if (!state._diagDecryptFailLogged) {
        this._diag('[cm-diag] handleIncomingRtp: decryptRtp returned NULL (len=' + buf.length + ')');
        state._diagDecryptFailLogged = true;
      }
      return;
    }

    this._handleIncomingRtpInner(rtp, rinfo, /*isRecovered=*/false, buf.length);
  }

  /**
   * Inner receive pipeline: receives a plaintext RTP packet and runs through
   * the full inbound media flow. May be called recursively (with
   * isRecovered=true) when an RTX packet is unwrapped into its primary.
   *
   * @param {Buffer}  rtp          decrypted RTP packet
   * @param {Object}  rinfo        UDP rinfo for diagnostics
   * @param {boolean} isRecovered  true iff this is a primary packet
   *                               reconstructed from an RTX wrapper.
   *                               Forwarded to NackGenerator so it doesn't
   *                               count this as natural reordering.
   * @param {number}  byteLen      encrypted byte length (for bytesReceived
   *                               stats). On RTX recursion we re-use the
   *                               outer RTX packet's byteLen so the primary
   *                               stream's bytes counter reflects the actual
   *                               cost of receipt (RTX wrapping overhead included).
   */
  _handleIncomingRtpInner(rtp, rinfo, isRecovered, byteLen) {
    var state = this._state;

    // Parse once, use the result everywhere. parseRtp now returns the
    // extension map too — no need to re-parse the header manually.
    var parsed = parseRtp(rtp);
    if (!parsed) return;
    var pt   = parsed.payloadType;
    var seq  = parsed.sequenceNumber;
    var ts   = parsed.timestamp;
    var ssrc = parsed.ssrc;

    // ── RID/repaired-RID runtime learning (RFC 8852 §3.1) ──
    //
    // On simulcast offers where we don't yet know which SSRC corresponds to
    // which rid, the SENDER tags each packet with a sdes:rtp-stream-id header
    // extension carrying the rid as an ASCII string. For RTX streams, they
    // use sdes:repaired-rtp-stream-id to name the primary rid being repaired.
    //
    // Senders STOP emitting these extensions once the binding is established
    // to save bytes. So we latch on first sighting — inspecting every packet
    // is wasteful once the mapping is known for that SSRC.
    //
    // Two sub-cases:
    //   a) remoteSsrcMap[ssrc] ALREADY exists (SDP declared a=ssrc for this
    //      ssrc — e.g. Firefox) but rid is missing (no a=ssrc-group:SIM):
    //      update the existing entry's .rid.
    //   b) remoteSsrcMap[ssrc] does NOT exist (Chrome-style — SSRCs chosen at
    //      send time, never declared in SDP): create a new entry, linking it
    //      to the simulcast m-section in the remote SDP (the one that has
    //      this rid in its a=rid:X send list).
    //
    // ORDERING NOTE: this block runs BEFORE rtpStats init and BEFORE the RTX
    // branch, on purpose — the RTX branch needs an up-to-date mapping to know
    // whether this SSRC repairs another. Without that, a stream's very first
    // RTX packet would be misclassified as primary.
    var _mapping = state.remoteSsrcMap[ssrc];
    var _alreadyLearned = _mapping && _mapping._ridLearned;
    if (!_alreadyLearned && parsed.extensions) {
      var _ridBuf          = state.remoteRidExtId         != null ? parsed.extensions[state.remoteRidExtId]         : null;
      var _repairedRidBuf  = state.remoteRepairedRidExtId != null ? parsed.extensions[state.remoteRepairedRidExtId] : null;
      // The SDES extensions use "two-byte header form" variable-length strings.
      // The value is the ASCII bytes of the rid, no null terminator (per RFC
      // 8852 §4.1: "restricted to letters, digits, underscore and hyphen").
      var _rid         = _ridBuf         && _ridBuf.length         > 0 ? _ridBuf.toString('ascii')         : null;
      var _repairedRid = _repairedRidBuf && _repairedRidBuf.length > 0 ? _repairedRidBuf.toString('ascii') : null;
      var _learnedRid  = _repairedRid || _rid;
      var _isRtx       = !!_repairedRid;

      if (_learnedRid) {
        // If mapping doesn't exist, create it. Find the owning mid by
        // scanning the remote SDP for the m-section that advertises this
        // rid in its simulcast send list.
        if (!_mapping) {
          var _ownerMid = null;
          if (state.parsedRemoteSdp && state.parsedRemoteSdp.media) {
            for (var _rmi = 0; _rmi < state.parsedRemoteSdp.media.length; _rmi++) {
              var _rm = state.parsedRemoteSdp.media[_rmi];
              if (_rm.type !== 'video' && _rm.type !== 'audio') continue;
              if (!_rm.rids) continue;
              for (var _rdi = 0; _rdi < _rm.rids.length; _rdi++) {
                var _rd = _rm.rids[_rdi];
                if (_rd.direction === 'send' && _rd.id === _learnedRid) {
                  _ownerMid = _rm.mid;
                  break;
                }
              }
              if (_ownerMid != null) break;
            }
          }
          if (_ownerMid == null) {
            // Shouldn't happen with a well-formed offer, but if it does,
            // fall back to the first video m-section.
            if (state.parsedRemoteSdp && state.parsedRemoteSdp.media) {
              for (var _rmi2 = 0; _rmi2 < state.parsedRemoteSdp.media.length; _rmi2++) {
                if (state.parsedRemoteSdp.media[_rmi2].type === 'video') {
                  _ownerMid = state.parsedRemoteSdp.media[_rmi2].mid;
                  break;
                }
              }
            }
          }
          _mapping = state.remoteSsrcMap[ssrc] = {
            mid:   _ownerMid,
            rid:   null,
            isRtx: false,
          };
        }

        _mapping.rid         = _learnedRid;
        _mapping.isRtx       = _isRtx;
        _mapping._ridLearned = true;

        this._diag('[cm-diag] learned SSRC→rid via ' +
          (_isRtx ? 'repaired-rid' : 'rtp-stream-id') +
          ' ext: ssrc=' + ssrc + ' rid=' + _learnedRid +
          (_isRtx ? ' (RTX)' : '') + ' mid=' + _mapping.mid);

        this.emit('ssrc:rid-learned', {
          ssrc:  ssrc,
          rid:   _learnedRid,
          isRtx: _isRtx,
          mid:   _mapping.mid,
        });
      }
    }

    // ── RTX consumption (RFC 4588) ──
    //
    // If this SSRC is the RTX pair of a primary stream, the packet's
    // payload begins with a 2-byte OSN (original seq) followed by the
    // original RTP payload. parseRtxPacket reverses RFC 4588's wrap:
    // it reconstructs the primary RTP packet (correct SSRC, seq, PT),
    // and we re-process it through this same function with isRecovered=true
    // so the NackGenerator knows not to count it as natural reordering.
    //
    // The mapping.primarySsrc lookup is cached on the mapping itself
    // after the first successful resolve — RTX packets can be 5-10% of
    // traffic, so we avoid a fresh O(n) scan per packet.
    //
    // Defensive: refuse to recurse if isRecovered is already set, in
    // case a sender ever wraps RTX inside RTX.
    if (_mapping && _mapping.isRtx && !isRecovered) {
      if (_mapping.primarySsrc == null) {
        _mapping.primarySsrc = this._deps.findPrimaryForRtx(_mapping);
      }
      var primaryStats = _mapping.primarySsrc != null
                         ? state.rtpStats[_mapping.primarySsrc]
                         : null;
      if (_mapping.primarySsrc != null && primaryStats) {
        var primaryPkt = parseRtxPacket(rtp, {
          primarySsrc: _mapping.primarySsrc,
          primaryPt:   primaryStats.payloadType,
        });
        if (primaryPkt) {
          this._handleIncomingRtpInner(primaryPkt, rinfo, /*isRecovered=*/true, byteLen);
        }
      }
      // RTX packets stop here — they have no value beyond carrying the
      // primary. Drop without populating rtpStats[rtxSsrc].
      return;
    }

    // Inbound RTP stats — per-SSRC, cumulative (WebRTC-spec style).
    var s = state.rtpStats[ssrc];
    if (!s) {
      s = state.rtpStats[ssrc] = {
        packets:        0,
        bytes:          0,
        packetsLost:    0,
        highestSeq:     seq,
        baseSeq:        seq,
        cycles:         0,
        jitter:         0,
        lastArrival:    0,
        lastTs:         0,
        payloadType:    pt,
        firstPacketAt:  Date.now(),
        lastPacketAt:   Date.now(),
        lastSR:         0,
        lastSRTime:     0,
        nackCount:      0,
        retransmittedPacketsReceived: 0,
        packetsRepaired:              0,
        peekKeyframeFn: undefined,
      };
      this._diag('[cm-diag] handleIncomingRtp: first RTP from ssrc=' + ssrc + ' pt=' + pt);
    }

    // First-time peek-function resolution for this SSRC. We don't do this
    // in the rtpStats init block above because the SSRC↔mid mapping or the
    // codec table for the mid may not have been populated yet. Checking
    // `=== undefined` keeps retrying until we get a definitive answer
    // (function or null), then stops.
    if (s.peekKeyframeFn === undefined) {
      var _mapForCodec = state.remoteSsrcMap[ssrc];
      var _midForCodec = _mapForCodec ? _mapForCodec.mid : null;
      var _recvForCodec = _midForCodec != null ? state.mediaReceivers[_midForCodec] : null;
      var _codecName = _recvForCodec && _recvForCodec.codec ? _recvForCodec.codec.name : null;
      if (_codecName) {
        s.peekKeyframeFn = this._deps.resolvePeekKeyframeFn(_codecName);
      }
    }

    s.packets++;
    s.bytes += byteLen;
    s.lastPacketAt = Date.now();

    // RTX recovery accounting. isRecovered=true means this call is the
    // recursive re-entry from the RTX-unwrap branch above.
    if (isRecovered) {
      s.retransmittedPacketsReceived++;
      s.packetsRepaired++;
    }

    // Sequence number wrap detection. Ignore late arrivals (they don't
    // advance highest) but count wraps so highest + cycles*65536 is
    // monotonically increasing.
    var seqDiff = seq - s.highestSeq;
    if (seqDiff > 32768)  seqDiff -= 65536;
    else if (seqDiff < -32768) seqDiff += 65536;
    if (seqDiff > 0) {
      if (seq < s.highestSeq) s.cycles++;
      s.highestSeq = seq;
      var expected = (s.cycles * 65536 + s.highestSeq) - s.baseSeq + 1;
      s.packetsLost = Math.max(0, expected - s.packets);
    }

    // Interarrival jitter (RFC 3550 §A.8).
    var arrival = Date.now();
    if (s.lastArrival !== 0) {
      // Both arrival and ts converted to RTP clock. For 90kHz video:
      // 1 ms local time == 90 RTP ticks. Generic 90k clock here is fine
      // for stats display.
      var arrivalTicks = arrival * 90;
      var lastArrivalTicks = s.lastArrival * 90;
      var d = Math.abs((arrivalTicks - lastArrivalTicks) - (ts - s.lastTs));
      s.jitter += (d - s.jitter) / 16;
    }
    s.lastArrival = arrival;
    s.lastTs = ts;

    // ── NACK generation (RFC 4585) ──
    //
    // Lazy per-SSRC instance. Each observePacket call updates the generator's
    // internal state (received-set, missing-list, reordering histogram); the
    // actual NACK send happens on a fixed cadence in the nackFeedbackTimer.
    //
    // extSeq is the 32-bit monotonic seq (cycles * 65536 + 16-bit seq). The
    // generator works in extSeq internally for wrap-safe arithmetic but emits
    // 16-bit seqs externally.
    //
    // isKeyframe is populated via the per-codec peekKeyframe primitive. When
    // true, NackGenerator skips adding the gap below this packet to its
    // missing list and evicts existing missing entries below it — both because
    // the decoder will reset from this keyframe.
    var nackGen = state.nackGenerators[ssrc];
    if (!nackGen) {
      nackGen = state.nackGenerators[ssrc] = new NackGenerator({});
    }
    var extSeq = s.cycles * 65536 + s.highestSeq;
    var isKeyframe = s.peekKeyframeFn ? s.peekKeyframeFn(parsed.payload) : false;
    nackGen.observePacket(extSeq, isKeyframe, isRecovered);

    // Transport-CC feedback generation.
    //
    // If the remote negotiated a transport-cc header extension on this media
    // section (state.remoteTransportCcExtId is set from SDP), every incoming
    // RTP packet carries a 16-bit transport-wide seq in that extension. We
    // capture (seq, arrivalTime) pairs now; the tccFeedbackTimer drains them
    // into an RTCP feedback packet every tccFeedbackIntervalMs.
    var tccExtId = state.remoteTransportCcExtId;
    if (tccExtId != null && parsed.extensions && parsed.extensions[tccExtId]) {
      var tccBuf = parsed.extensions[tccExtId];
      if (tccBuf.length >= 2) {
        var tccSeq = tccBuf.readUInt16BE(0);
        var gen = state.tccFeedbackGenerators[ssrc];
        if (!gen) {
          // Lazily create one generator per incoming media SSRC. The
          // senderSsrc field on outgoing feedback is our local SSRC on
          // the matching m= section if we know it, else 1.
          var localSenderSsrc = 1;
          var mapping = state.remoteSsrcMap[ssrc];
          if (mapping && state.localSsrcs[mapping.mid]) {
            localSenderSsrc = state.localSsrcs[mapping.mid].id;
          }
          gen = new TransportCCFeedbackGenerator({
            senderSsrc: localSenderSsrc,
            mediaSsrc:  ssrc,
          });
          state.tccFeedbackGenerators[ssrc] = gen;
        }
        gen.recordArrival(tccSeq, arrival);
      }
    }

    // ── Per-receiver source tracking (W3C webrtc-pc §5.3.4) ──
    //
    // For incoming primary (non-RTX) packets that map to a known transceiver,
    // we track CSRC entries (RFC 3550 §6.1, append-list with 10s freshness
    // window) and SSRC entries (latest-wins per SSRC). RTX packets are skipped
    // (retransmissions, not new source activity); SSRCs that map to nothing
    // are skipped too.
    if (_mapping && !_mapping.isRtx && _mapping.transceiver) {
      var receiver = _mapping.transceiver.receiver;
      var nowWall = (typeof performance !== 'undefined' && performance.now)
                    ? performance.now()
                    : Date.now();

      if (parsed.csrc && parsed.csrc.length) {
        if (!receiver._csrcEntries) receiver._csrcEntries = [];
        for (var ci = 0; ci < parsed.csrc.length; ci++) {
          receiver._csrcEntries.push({
            source:       parsed.csrc[ci],
            timestamp:    nowWall,
            rtpTimestamp: parsed.timestamp,
          });
        }
        // Lazy trim every 16th append — bounds memory growth.
        // getContributingSources filters at read time anyway.
        if ((receiver._csrcEntries.length & 0x0F) === 0) {
          var cutoff = nowWall - 10000;
          var kept = [];
          for (var ki = 0; ki < receiver._csrcEntries.length; ki++) {
            if (receiver._csrcEntries[ki].timestamp >= cutoff) {
              kept.push(receiver._csrcEntries[ki]);
            }
          }
          receiver._csrcEntries = kept;
        }
      }

      if (!receiver._ssrcEntries) receiver._ssrcEntries = {};
      receiver._ssrcEntries[ssrc] = {
        source:       ssrc,
        timestamp:    nowWall,
        rtpTimestamp: parsed.timestamp,
      };
    }

    var info = { payloadType: pt, sequenceNumber: seq, ssrc: ssrc };
    this.emit('rtp', rtp, rinfo, info);
  }


  /* ====================== Periodic RTCP ====================== */

  /**
   * Start the 1-second SR/RR/REMB timer. Idempotent — repeated calls are
   * no-ops while the timer is already running.
   *
   * Also starts TCC and NACK feedback timers (separate cadences). Until
   * each layer's full extraction lands, all three timers are owned by
   * MediaTransport so they share the same lifecycle gate.
   */
  startRtcpTimer() {
    if (this._rtcpTimer) return;
    var self = this;
    var state = this._state;
    var rtcpRound = 0;

    this._rtcpTimer = setInterval(function () {
      if (state.closed || !self._deps.getSrtpSession()) {
        clearInterval(self._rtcpTimer);
        self._rtcpTimer = null;
        return;
      }
      rtcpRound++;

      var ssrcs = Object.keys(state.rtpStats);
      var remoteSsrcList = [];

      for (var i = 0; i < ssrcs.length; i++) {
        var remoteSsrc = parseInt(ssrcs[i], 10);
        var stats = state.rtpStats[remoteSsrc];
        var mapping = state.remoteSsrcMap[remoteSsrc];
        var localSsrc = 1;
        if (mapping && state.localSsrcs[mapping.mid]) {
          localSsrc = state.localSsrcs[mapping.mid].id;
        }
        remoteSsrcList.push(remoteSsrc);

        // Compute fractionLost over the last RR interval (RFC 3550 §6.4.1):
        //   fraction = (expectedInterval - receivedInterval) / expectedInterval * 256
        var expected = (stats.cycles * 65536 + stats.highestSeq) - stats.baseSeq + 1;
        var expectedInterval = expected - (stats._lastReportedExpected || 0);
        var receivedInterval = stats.packets - (stats._lastReportedReceived || 0);
        var lostInterval = expectedInterval - receivedInterval;
        var fractionLost = 0;
        if (expectedInterval > 0 && lostInterval > 0) {
          fractionLost = Math.min(255, Math.floor((lostInterval << 8) / expectedInterval));
        }
        stats._lastReportedExpected = expected;
        stats._lastReportedReceived = stats.packets;

        // DLSR (Delay since Last SR) — RFC 3550 §6.4.1, in 1/65536 s units.
        var dlsr = 0;
        if (stats.lastSRTime) {
          var elapsedMs = Date.now() - stats.lastSRTime;
          if (elapsedMs < 0) elapsedMs = 0;
          dlsr = Math.min(0xFFFFFFFF, Math.floor(elapsedMs * 65.536));
        }

        self.sendRtcp(buildRR({
          ssrc: localSsrc, mediaSsrc: remoteSsrc,
          fractionLost: fractionLost,
          totalLost: stats.packetsLost,
          highestSeq: stats.highestSeq + (stats.cycles << 16),
          jitter: Math.floor(stats.jitter),
          lastSR: stats.lastSR,
          delaySinceLastSR: dlsr,
        }));
      }

      // Single REMB covers all known remote SSRCs in one shot.
      if (remoteSsrcList.length > 0) {
        var localSsrc2 = 1;
        var firstMapping = state.remoteSsrcMap[remoteSsrcList[0]];
        if (firstMapping && state.localSsrcs[firstMapping.mid]) {
          localSsrc2 = state.localSsrcs[firstMapping.mid].id;
        }
        self.sendRtcp(buildREMB(localSsrc2, remoteSsrcList, 2000000));
      }

      // SR (Sender Report) for every outbound stream. Lets the remote
      // match RR blocks back to our send time, so they can include DLSR
      // and we compute RTT per RFC 3550.
      var outSsrcs = Object.keys(state.outboundStats);
      for (var os = 0; os < outSsrcs.length; os++) {
        var oSsrc = parseInt(outSsrcs[os], 10);
        var oSt = state.outboundStats[oSsrc];
        if (!oSt || oSt.packets === 0) continue;

        var sent = Date.now();
        var ntpSec  = Math.floor(sent / 1000) + 2208988800;
        var ntpFrac = Math.floor(((sent % 1000) / 1000) * 0x100000000);
        var srBuf = buildSR({
          ssrc:         oSsrc,
          ntpTimestamp: [ntpSec, ntpFrac],
          rtpTimestamp: 0,
          packetCount:  oSt.packets,
          octetCount:   oSt.bytes,
        });
        self.sendRtcp(srBuf);

        // Cache middle32 so we can match DLSR from incoming RR.
        // The `>>> 0` is essential — JavaScript bitwise produces signed
        // 32-bit ints; without unsigned coercion the === check against
        // the remote's RR (read as unsigned) fails for top-bit-set values
        // (NTP sec from 2028+). See pre-cleanup comment for details.
        if (!state.lastOwnSR) state.lastOwnSR = {};
        state.lastOwnSR.middle32 = (((ntpSec & 0xFFFF) << 16) | ((ntpFrac >>> 16) & 0xFFFF)) >>> 0;
        state.lastOwnSR.at       = sent;
      }

      // First-round PLI burst — kick the encoder on the remote side so
      // we get a keyframe early instead of waiting for natural cadence.
      // Per-SSRC: iterate every primary stream we're receiving and send
      // a PLI to each. For simulcast this means N PLIs (one per layer),
      // which is exactly what we need to bring up all decoders cleanly.
      // RTX SSRCs are skipped — requestKeyframe handles the filter
      // defensively but doing it here too saves the RTCP packet.
      if (rtcpRound === 1) {
        for (var j = 0; j < remoteSsrcList.length; j++) {
          var remoteSsrcJ = remoteSsrcList[j];
          var mappingJ = state.remoteSsrcMap[remoteSsrcJ];
          if (mappingJ && !mappingJ.isRtx) self.requestKeyframe(remoteSsrcJ);
        }
      }
    }, 1000);

    if (this._rtcpTimer.unref) this._rtcpTimer.unref();

    // Transport-CC and NACK feedback run on faster cadences (default
    // 100ms each) — they're per-packet-precise and want low latency to
    // be useful. Separate timers so cadences and gating evolve independently.
    this.startTccFeedbackTimer();
    this.startNackFeedbackTimer();
  }

  startTccFeedbackTimer() {
    if (this._tccFeedbackTimer) return;
    var self = this;
    var state = this._state;
    var _tccDiagCount = 0;

    this._tccFeedbackTimer = setInterval(function () {
      if (state.closed || !self._deps.getSrtpSession()) {
        clearInterval(self._tccFeedbackTimer);
        self._tccFeedbackTimer = null;
        return;
      }
      var gens = state.tccFeedbackGenerators;
      var keys = Object.keys(gens);
      for (var i = 0; i < keys.length; i++) {
        var gen = gens[keys[i]];
        if (!gen || gen.pending() === 0) continue;
        var pendingCount = gen.pending();
        var fbPacket = gen.buildFeedback();
        if (fbPacket) {
          self.sendRtcp(fbPacket);
          _tccDiagCount++;
          if (_tccDiagCount <= 3 || _tccDiagCount % 50 === 0) {
            self._diag('[cm-diag] TCC feedback #' + _tccDiagCount +
              ' ssrc=' + keys[i] +
              ' packets=' + pendingCount +
              ' bytes=' + fbPacket.length);
          }
        }
      }
    }, state.tccFeedbackIntervalMs);

    if (this._tccFeedbackTimer.unref) this._tccFeedbackTimer.unref();
  }

  /**
   * NACK feedback timer.
   *
   * Drains every per-SSRC NackGenerator on a fixed cadence (default 100ms,
   * same as transport-cc). For each generator with pending gaps, calls
   * buildFeedback() to get a 16-bit seq list, wraps it in an RFC 4585
   * generic NACK RTCP packet, and sends it.
   *
   * Also handles PLI escalation: if the generator's missing list overflowed
   * beyond what keyframe-aware eviction can recover, fire a PLI for that
   * mid and acknowledge so the flag clears for the next interval.
   *
   * Cadence rationale: 100ms is a compromise. Lower (20-50ms) gives faster
   * recovery but more RTCP and CPU; higher (200ms+) delays recovery to the
   * point of being noticeable. libwebrtc uses ~20ms; mediasoup uses 25ms.
   * We err toward less RTCP because the NackGenerator does its own
   * retry-after-RTT throttling, so a slower drain doesn't double-NACK.
   */
  startNackFeedbackTimer() {
    if (this._nackFeedbackTimer) return;
    var self = this;
    var state = this._state;
    var _nackOutDiagCount = 0;
    var _nackPliDiagCount = 0;

    this._nackFeedbackTimer = setInterval(function () {
      if (state.closed || !self._deps.getSrtpSession()) {
        clearInterval(self._nackFeedbackTimer);
        self._nackFeedbackTimer = null;
        return;
      }
      var gens = state.nackGenerators;
      var keys = Object.keys(gens);
      for (var i = 0; i < keys.length; i++) {
        var ssrc = parseInt(keys[i], 10);
        var gen = gens[ssrc];
        if (!gen) continue;

        // Drain the generator. seqs is already 16-bit wire-format.
        var seqs = gen.buildFeedback(Date.now());
        if (seqs.length > 0) {
          // RFC 4585: NACK feedback's senderSsrc names the entity emitting
          // the feedback. Pick the one bound to the matching m-section;
          // fallback to 1 if no mapping exists yet.
          var mapping = state.remoteSsrcMap[ssrc];
          var localSenderSsrc = 1;
          if (mapping && state.localSsrcs[mapping.mid]) {
            localSenderSsrc = state.localSsrcs[mapping.mid].id;
          }
          self.sendRtcp(buildNACK(localSenderSsrc, ssrc, seqs));

          var st = state.rtpStats[ssrc];
          if (st) st.nackCount = (st.nackCount || 0) + 1;

          _nackOutDiagCount++;
          if (_nackOutDiagCount <= 3 || _nackOutDiagCount % 50 === 0) {
            self._diag('[cm-diag] NACK out #' + _nackOutDiagCount +
              ' ssrc=' + ssrc +
              ' seqs=[' + seqs[0] + '..' + seqs[seqs.length - 1] + ']' +
              ' (' + seqs.length + ')');
          }
        }

        // PLI escalation: NACK list overflowed past what we can recover
        // by keyframe-aware eviction. Generator asks for a fresh keyframe.
        // The `ssrc` here is the per-stream SSRC the NackGenerator is
        // bound to (one generator per inbound primary stream — see
        // _handleIncomingRtpInner above where state.nackGenerators[ssrc]
        // is created). Send PLI directly to it; this matches libwebrtc's
        // model of one RtpRtcp module per stream, each driving its own
        // PLI feedback to its own remote_ssrc_.
        if (gen.needKeyframe()) {
          self.requestKeyframe(ssrc);
          gen.acknowledgeKeyframeRequested();
          _nackPliDiagCount++;
          if (_nackPliDiagCount <= 5 || _nackPliDiagCount % 20 === 0) {
            self._diag('[cm-diag] NACK→PLI escalation #' + _nackPliDiagCount +
              ' ssrc=' + ssrc +
              ' (NACK list overflow, requesting keyframe)');
          }
        }
      }
    }, state.nackFeedbackIntervalMs);

    if (this._nackFeedbackTimer.unref) this._nackFeedbackTimer.unref();
  }


  /* ====================== Stats / setup API ====================== */

  /**
   * Register a transceiver layer with the header-extension stamper.
   * Called by cm.js's addTransceiverInternal for every layer that has a
   * non-null RID (simulcast layers and their RTX pair). Non-simulcast
   * layers (rid=null) skip this — there's nothing to stamp.
   *
   * For simulcast layers:
   *   - primary SSRC is stamped with rtp-stream-id (RFC 8852).
   *   - RTX SSRC is stamped with both rtp-stream-id (mirror) and
   *     repaired-rtp-stream-id (pointer back to the source layer) — this
   *     is how the peer/SFU correlates retransmissions to the layer
   *     being repaired.
   */
  registerTransceiverLayer(layer) {
    if (!layer || !layer.rid) return;
    var stamper = this._state.headerStamper;
    if (layer.ssrc != null)    stamper.setRidForSsrc(layer.ssrc, layer.rid);
    if (layer.rtxSsrc != null) stamper.setRtxRids(layer.rtxSsrc, layer.rid, layer.rid);
  }

  /**
   * Reverse of registerTransceiverLayer. Called by api.js when a transceiver
   * is stopped — clears the stamper's per-SSRC mapping so a future
   * transceiver reusing one of these SSRCs (rare) starts clean.
   */
  unregisterTransceiverLayer(layer) {
    if (!layer) return;
    var stamper = this._state.headerStamper;
    if (!stamper) return;
    if (layer.ssrc != null)    stamper.clearSsrc(layer.ssrc);
    if (layer.rtxSsrc != null) stamper.clearSsrc(layer.rtxSsrc);
  }

  /**
   * Sync the header-extension stamper's extMap to whatever the local SDP
   * negotiated. Called by SdpOfferAnswer's deps after every successful
   * setLocalDescription (so the stamper stamps with the IDs the peer
   * actually agreed to, not the hardcoded defaults).
   *
   * Any extension URI declared in the SDP but absent from the URI→name
   * map below is ignored (stamper wouldn't stamp it anyway).
   */
  syncExtMap(parsedLocal) {
    var stamper = this._state.headerStamper;
    if (!stamper || !parsedLocal || !parsedLocal.media) return;
    var URI_TO_NAME = {
      'http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time':              'abs-send-time',
      'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01': 'transport-cc',
      'urn:ietf:params:rtp-hdrext:sdes:mid':                                     'mid',
      'urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id':                           'rtp-stream-id',
      'urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id':                  'repaired-rtp-stream-id',
    };
    // Merge across all video m-sections. Across BUNDLE-grouped media, the
    // same extension URI SHOULD map to the same ID (BUNDLE requires extmap
    // consistency) — last-write-wins is benign.
    var newMap = {};
    for (var mi = 0; mi < parsedLocal.media.length; mi++) {
      var mm = parsedLocal.media[mi];
      if (!mm.extensions) continue;
      for (var ei = 0; ei < mm.extensions.length; ei++) {
        var e = mm.extensions[ei];
        var name = URI_TO_NAME[e.uri];
        if (name) newMap[name] = e.id;
      }
    }
    if (Object.keys(newMap).length) {
      stamper.setExtMap(newMap);
    }
  }

  /**
   * Snapshot of all per-SSRC counters owned by MediaTransport. Returned as
   * shared references (no copy) — callers must treat the maps as read-only.
   * api.js's getStats() consumes this to build RTCStatsReport entries.
   */
  getRawStats() {
    var state = this._state;
    return {
      inbound:               state.rtpStats,
      outbound:              state.outboundStats,
      rtcp:                  state.rtcpStats,
      remoteOutbound:        state.remoteOutboundStats,
      estimatedBandwidthBps: state.bandwidthEstimator.getEstimate(),
      remoteRembBps:         state.bandwidthEstimator.getRemoteRembEstimate(),
    };
  }

  /**
   * Current sender-side bandwidth estimate in bps, derived from transport-cc
   * delay-gradient analysis and REMB feedback.
   */
  getEstimatedBandwidth() {
    return this._state.bandwidthEstimator.getEstimate();
  }


  /* ====================== Lifecycle ====================== */

  /**
   * Stop all timers. Called by cm.js's close().
   */
  close() {
    if (this._rtcpTimer)        { clearInterval(this._rtcpTimer);        this._rtcpTimer = null; }
    if (this._tccFeedbackTimer) { clearInterval(this._tccFeedbackTimer); this._tccFeedbackTimer = null; }
    if (this._nackFeedbackTimer){ clearInterval(this._nackFeedbackTimer); this._nackFeedbackTimer = null; }
  }
}


export { MediaTransport };

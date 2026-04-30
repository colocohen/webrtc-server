// src/rtp_transmission_manager.js
//
// Transceiver / sender / receiver management — the W3C control plane.
//
// Owns the algorithms for:
//   - creating a fresh transceiver with sender layers and SSRCs (W3C
//     RTCRtpTransceiver creation flow + RFC 8852 RIDs for simulcast)
//   - allocating a fresh mid that doesn't collide with existing
//     transceivers, the previous local SDP, or the previous remote SDP
//   - finding a transceiver by mid
//   - applying answer-side direction updates per W3C §4.4.1.6 step 11.1.7.4
//   - SSRC↔mid lookup (and RTX-primary lookup) for the data plane
//   - the W3C §4.7.3 check-if-negotiation-is-needed algorithm
//
// What this module does NOT own:
//   - RTP I/O (handleIncomingRtp, sendRtp) — that's connection_manager.js
//   - the operations chain or signalingstatechange — sdp_offer_answer.js
//     (currently still in cm.js until milestone 5)
//   - DTLS/ICE/SCTP plumbing — transport_controller.js
//   - building or parsing SDP — sdp.js / webrtc_sdp.js
//   - encoder/decoder pipelines — media_pipeline.js
//
// The functions here all take the cm.js `state` object as their first
// parameter and read/mutate it in place. There is no separate state
// container — same model as transport_controller.js.
//
// Part of the SDP-layer refactor; see SDP_REFACTOR_PLAN.md, milestone 3.

import * as SDP from './sdp.js';


/* ========================= Mid allocation ========================= */

/**
 * Allocate the next free mid as a string.
 *
 * Avoids collisions against:
 *   - mids of existing transceivers
 *   - mids in the cached parsedLocalSdp (covers DCs and rejected slots)
 *   - mids in the cached parsedRemoteSdp
 *
 * Reads from the cached parsed structures rather than re-parsing the SDP
 * string each time. parsedLocalSdp/parsedRemoteSdp are kept in sync by
 * setLocalDescription/setRemoteDescription.
 *
 * @param {Object} state
 * @returns {number}  the next free mid (caller stringifies if needed)
 */
function getNextMid(state) {
  var usedMids = {};
  for (var i = 0; i < state.transceivers.length; i++) {
    usedMids[state.transceivers[i].mid] = true;
  }
  if (state.parsedLocalSdp && state.parsedLocalSdp.media) {
    for (var j = 0; j < state.parsedLocalSdp.media.length; j++) {
      usedMids[state.parsedLocalSdp.media[j].mid] = true;
    }
  }
  if (state.parsedRemoteSdp && state.parsedRemoteSdp.media) {
    for (var k = 0; k < state.parsedRemoteSdp.media.length; k++) {
      usedMids[state.parsedRemoteSdp.media[k].mid] = true;
    }
  }
  var next = 0;
  while (usedMids[String(next)]) next++;
  return next;
}


/* ========================= Transceiver creation ========================= */

/**
 * Create a fresh transceiver and append it to state.transceivers.
 *
 * This function is the "pure" part of W3C addTransceiver — it builds the
 * transceiver object, allocates SSRCs (per layer for simulcast), and
 * populates state.localSsrcs[mid]. It does NOT perform side effects that
 * belong to the runtime (registering RTX mappings, header-stamper RID
 * registration, firing negotiationneeded). The caller (cm.js's
 * addTransceiverInternal wrapper) is responsible for those.
 *
 * Validation matches W3C §5.2 + RFC 8852 §10:
 *   - simulcast (sendEncodings.length > 1) requires rid on every encoding
 *   - rid must match /^[A-Za-z0-9_-]{1,32}$/
 *   - rids must be unique within the transceiver
 *
 * Throws TypeError on invalid input.
 *
 * @param {Object} state
 * @param {'audio'|'video'} kind
 * @param {Object} [init]   { direction, sendEncodings }
 * @returns {Object} the newly created transceiver
 */
function createTransceiver(state, kind, init) {
  init = init || {};
  var mid = String(getNextMid(state));

  var reqEncodings = Array.isArray(init.sendEncodings) ? init.sendEncodings : null;
  var isSimulcast = reqEncodings && reqEncodings.length > 1;

  // RID format validation (RFC 8852 §3.1):
  //   "Restricted to letters, digits, underscore and hyphen, 1-32 chars."
  // The format restriction applies to ANY rid that the application provides,
  // not just simulcast. A single-encoding configuration with
  //   { rid: 'invalid space' }
  // would bypass the simulcast-only validation and silently propagate an
  // invalid string into the rtp-stream-id header extension on the wire,
  // where the peer's parser may reject it. Validate format unconditionally;
  // require non-empty + uniqueness only when simulcast (rid is required for
  // simulcast per RFC 8852 §3.1, but optional for single encoding).
  if (reqEncodings) {
    var seenRids = {};
    for (var ei = 0; ei < reqEncodings.length; ei++) {
      var enc = reqEncodings[ei] || {};
      if (isSimulcast && !enc.rid) {
        throw new TypeError('sendEncodings: rid required on every encoding when simulcast');
      }
      if (enc.rid != null && !/^[A-Za-z0-9_-]{1,32}$/.test(enc.rid)) {
        throw new TypeError('sendEncodings: invalid rid "' + enc.rid + '"');
      }
      if (isSimulcast) {
        if (seenRids[enc.rid]) {
          throw new TypeError('sendEncodings: duplicate rid "' + enc.rid + '"');
        }
        seenRids[enc.rid] = true;
      }
    }
  }

  var layers = [];
  var encodings = [];
  if (reqEncodings && reqEncodings.length) {
    for (var li = 0; li < reqEncodings.length; li++) {
      var e = reqEncodings[li] || {};
      var ls = SDP.generateSsrc();
      var lrtx = SDP.generateSsrc();
      layers.push({ rid: e.rid || null, ssrc: ls, rtxSsrc: lrtx });
      encodings.push({
        rid:                   e.rid || null,
        active:                e.active !== false,
        maxBitrate:            typeof e.maxBitrate === 'number' ? e.maxBitrate : 0,
        maxFramerate:          typeof e.maxFramerate === 'number' ? e.maxFramerate : 0,
        scaleResolutionDownBy: typeof e.scaleResolutionDownBy === 'number'
                                 ? e.scaleResolutionDownBy : 1,
        scalabilityMode:       e.scalabilityMode || null,
      });
    }
  } else {
    var ssrc = SDP.generateSsrc();
    var rtxSsrc = SDP.generateSsrc();
    layers.push({ rid: null, ssrc: ssrc, rtxSsrc: rtxSsrc });
    encodings.push({
      rid:                   null,
      active:                true,
      maxBitrate:            0,
      maxFramerate:          0,
      scaleResolutionDownBy: 1,
      scalabilityMode:       null,
    });
  }

  var transceiver = {
    mid: mid,
    sender: {
      track:     null,
      ssrc:      layers[0].ssrc,
      rtxSsrc:   layers[0].rtxSsrc,
      layers:    layers,
      encodings: encodings,
    },
    receiver: { track: null },
    direction: init.direction || 'sendrecv',
    currentDirection: null,
    kind: kind,
  };

  state.transceivers.push(transceiver);
  state.localSsrcs[mid] = {
    id:     layers[0].ssrc,
    rtxId:  layers[0].rtxSsrc,
    msid:   'stream0 ' + kind + mid,
    layers: layers.slice(),
  };

  return transceiver;
}


/* ========================= Lookups ========================= */

/**
 * Find a transceiver by its mid (string compare; numeric mids OK).
 *
 * @param {Object} state
 * @param {string|number} mid
 * @returns {Object|null}
 */
function findByMid(state, mid) {
  for (var i = 0; i < state.transceivers.length; i++) {
    if (state.transceivers[i].mid === String(mid)) return state.transceivers[i];
  }
  return null;
}

/**
 * Find a remote primary SSRC for a given mid by scanning state.remoteSsrcMap.
 *
 * Skips RTX entries (isRtx:true) — RTX SSRCs are retransmission carriers
 * (RFC 4588) and don't carry primary media frames. Sending a PLI to an
 * RTX SSRC is a protocol error: the RTX stream has no keyframes of its
 * own to produce. The single caller that uses this result is
 * MediaTransport.requestKeyframe → buildPLI(localSsrc, remoteSsrc),
 * so the filter is essential for correctness.
 *
 * remoteSsrcMap is populated by connection_manager.js's processRemoteMedia
 * from the parsed remote SDP — every SSRC declared in `a=ssrc` lines gets
 * `isRtx:false` initially, then FID groups overwrite the second SSRC of
 * each FID group to `isRtx:true`. So both primary and RTX SSRCs share the
 * same mid; without this filter, Object.keys() ordering decides whether
 * we'd grab a valid primary or an RTX (numeric-string keys sort
 * numerically in V8 — primary < RTX or primary > RTX is unpredictable
 * because both are 32-bit randoms from generateSsrc()).
 *
 * Note: this returns the FIRST primary SSRC for the mid. For simulcast
 * (3 layers, 3 primary SSRCs sharing a mid), this is incomplete — see
 * ROADMAP for the planned per-SSRC requestKeyframe API.
 *
 * @param {Object} state
 * @param {string} mid
 * @returns {number|null}
 */
function findRemoteSsrcForMid(state, mid) {
  var keys = Object.keys(state.remoteSsrcMap);
  for (var k = 0; k < keys.length; k++) {
    var entry = state.remoteSsrcMap[keys[k]];
    if (entry.mid === mid && !entry.isRtx) return parseInt(keys[k], 10);
  }
  return null;
}

/**
 * Find the primary SSRC that an RTX SSRC repairs.
 *
 * Used by RTX consumption in the data plane: when an RTX packet arrives,
 * media_transport.js needs the primary stream's SSRC to recurse through
 * the receive pipeline with the recovered packet. Two paths feed into
 * this function:
 *
 *   1. Pre-cached primarySsrc from SDP processing.
 *      connection_manager.js's processRemoteMedia walks the FID groups
 *      and stamps `primarySsrc = group.ssrcs[0]` on each RTX entry. The
 *      data plane checks `_mapping.primarySsrc` first and only calls
 *      findPrimaryForRtx if it's null — so the SDP-driven path normally
 *      bypasses this function entirely.
 *
 *   2. Runtime RID-learning fallback. Some senders (Chrome simulcast)
 *      don't declare ssrc-group:FID for RTX in the offer; the RTX↔primary
 *      binding is communicated via the sdes:repaired-rtp-stream-id RTP
 *      header extension on the wire. media_transport.js learns these
 *      bindings on first sighting and creates remoteSsrcMap entries with
 *      rid populated. THIS function then resolves primary by matching
 *      (mid, rid) against existing primary entries.
 *
 * Behavior:
 *   - rid != null (simulcast or RID-learned): match by (mid, rid).
 *   - rid == null (non-simulcast where primarySsrc didn't get pre-cached
 *     from SDP for any reason — e.g. ssrc-group:FID was malformed, or the
 *     remote SDP didn't declare a=ssrc lines): fall back to "the one
 *     primary on this mid". Only safe if exactly one primary exists for
 *     the mid; if zero or multiple, return null and let the caller deal
 *     (the RTX packet will be dropped, no recovery possible).
 *
 * @param {Object} state
 * @param {Object} rtxMapping  the RTX entry from remoteSsrcMap
 * @returns {number|null}
 */
function findPrimaryForRtx(state, rtxMapping) {
  if (!rtxMapping) return null;
  var keys = Object.keys(state.remoteSsrcMap);

  if (rtxMapping.rid != null) {
    // Simulcast / RID-learned path: match by (mid, rid). Multiple
    // primaries may share the mid (one per simulcast layer); the rid
    // disambiguates.
    for (var i = 0; i < keys.length; i++) {
      var entry = state.remoteSsrcMap[keys[i]];
      if (!entry.isRtx &&
          entry.mid === rtxMapping.mid &&
          entry.rid === rtxMapping.rid) {
        return parseInt(keys[i], 10);
      }
    }
    return null;
  }

  // Non-simulcast fallback: rid is null on both sides. Match by mid alone,
  // but only if exactly one primary exists for that mid. Multiple primaries
  // with rid:null all sharing a mid would be ambiguous — bail rather than
  // guess.
  var matches = [];
  for (var j = 0; j < keys.length; j++) {
    var e2 = state.remoteSsrcMap[keys[j]];
    if (!e2.isRtx && e2.mid === rtxMapping.mid && e2.rid == null) {
      matches.push(parseInt(keys[j], 10));
      if (matches.length > 1) return null;   // ambiguous, give up
    }
  }
  return matches.length === 1 ? matches[0] : null;
}


/* ========================= Direction commit (W3C §4.4.1.6) ========================= */

/**
 * Commit negotiated direction onto each transceiver's [[CurrentDirection]]
 * slot. Per W3C §4.4.1.6 step 11.1.7.4, runs when an answer / pranswer is
 * applied — both setLocalDescription(answer) and setRemoteDescription(answer).
 *
 * Direction perspective:
 *   - isLocalAnswer=true  → we authored this answer; the m-section
 *                            direction is in OUR perspective. Use as-is.
 *   - isLocalAnswer=false → this is the remote peer's answer; their
 *                            m-section direction is in THEIR perspective.
 *                            Flip via SDP.REVERSE_DIRECTION.
 *
 * Rejected m-section (port=0) marks the transceiver as stopped:
 * currentDirection becomes 'stopped'. m=application sections are skipped.
 *
 * @param {Object} state
 * @param {Object} parsed         parsedSdp from SDP.parseOffer/Answer
 * @param {boolean} isLocalAnswer
 */
function applyDirectionsFromAnswer(state, parsed, isLocalAnswer) {
  if (!parsed || !parsed.media) return;
  for (var i = 0; i < parsed.media.length; i++) {
    var m = parsed.media[i];
    if (!m || m.type === 'application') continue;
    var t = findByMid(state, m.mid);
    if (!t) continue;

    if (m.port === 0) {
      t.currentDirection = 'stopped';
      continue;
    }

    var dir = m.direction || 'sendrecv';
    if (!isLocalAnswer) {
      dir = SDP.REVERSE_DIRECTION[dir] || dir;
    }
    t.currentDirection = dir;
  }
}


/* ========================= W3C §4.7.3 negotiation-needed check ========================= */

/**
 * True if a DataChannel exists in state but the current local description
 * has no non-rejected m=application section.
 *
 * @param {Object} state
 * @returns {boolean}
 */
function hasApplicationMediaInLocalDescription(state) {
  if (!state.currentLocalDescription) return false;
  if (!state.parsedLocalSdp || !state.parsedLocalSdp.media) return false;
  for (var i = 0; i < state.parsedLocalSdp.media.length; i++) {
    var m = state.parsedLocalSdp.media[i];
    if (m.type === 'application' && m.port !== 0) return true;
  }
  return false;
}

/**
 * Run the transceiver/data-channel portion of the
 * "check if negotiation is needed" algorithm of W3C §4.7.3.
 *
 * Returns true when any of:
 *   - DataChannel exists but no m=application in current local description
 *   - some transceiver is unassociated (mid == null)
 *   - some transceiver's direction != currentDirection (app-side change)
 *
 * Does NOT check `needsIceRestart` — that's a signaling-layer concern
 * owned by SdpOfferAnswer. The caller (SdpOfferAnswer.updateNegotiationNeededFlag)
 * combines this result with its own ICE-restart check.
 *
 * Stopped transceivers are conservatively skipped (full transceiver.stop()
 * semantics will be a follow-up; see ROADMAP SDP-6).
 *
 * @param {Object} state
 * @returns {boolean}
 */
function checkIfNegotiationIsNeeded(state) {
  if (state.dataChannels && state.dataChannels.length > 0) {
    if (!hasApplicationMediaInLocalDescription(state)) return true;
  }

  for (var i = 0; i < state.transceivers.length; i++) {
    var t = state.transceivers[i];
    if (t.currentDirection === 'stopped') continue;
    if (t.mid == null) return true;
    if (t.direction !== t.currentDirection) return true;
  }

  return false;
}


/* ========================= Exports ========================= */

export {
  // Mid allocation
  getNextMid,

  // Transceiver creation
  createTransceiver,

  // Lookups
  findByMid,
  findRemoteSsrcForMid,
  findPrimaryForRtx,

  // Direction commit
  applyDirectionsFromAnswer,

  // Negotiation-needed
  hasApplicationMediaInLocalDescription,
  checkIfNegotiationIsNeeded,
};

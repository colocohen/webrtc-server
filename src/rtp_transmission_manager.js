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
/**
 * Give a send-capable SSRC to a transceiver that does not have one.
 *
 * createTransceiver() allocates SSRCs, but it only ever runs for LOCALLY
 * created transceivers. One created by setRemoteDescription — the remote
 * offered a section and we adopted it — is born with ssrc: null, because at
 * that moment it is receive-only and has nothing to send.
 *
 * An application is entitled to turn such a transceiver into a sender:
 *
 *     const [tc] = pc.getTransceivers();   // created by setRemoteDescription
 *     tc.direction = 'sendonly';
 *     tc.sender.replaceTrack(track);
 *
 * That is the ordinary answerer flow — the remote offers recvonly, we answer
 * by sending — and it is exactly what WPT's addTransceiver-renegotiation
 * tests do. Without this, the SSRC stayed null forever: no a=ssrc line in the
 * answer, nothing for the packetiser to stamp, and zero packets sent while
 * the SDP still said a=sendonly.
 *
 * Idempotent and safe to call on every direction change; returns true only
 * when it actually allocated.
 */
function ensureSendSsrc(state, transceiver) {
  if (!transceiver || !transceiver.sender) return false;
  if (transceiver.sender.ssrc != null) return false;

  var ssrc    = SDP.generateSsrc();
  var rtxSsrc = SDP.generateSsrc();

  transceiver.sender.ssrc    = ssrc;
  transceiver.sender.rtxSsrc = rtxSsrc;
  if (transceiver.sender.layers && transceiver.sender.layers.length) {
    transceiver.sender.layers[0].ssrc    = ssrc;
    transceiver.sender.layers[0].rtxSsrc = rtxSsrc;
  } else {
    transceiver.sender.layers = [{ rid: null, ssrc: ssrc, rtxSsrc: rtxSsrc, fecSsrc: null }];
  }

  // Mirror the routing slot createTransceiver would have written, so the SDP
  // builder emits a=ssrc for this section. Keyed by mid, which a remotely
  // created transceiver always has.
  if (transceiver.mid != null) {
    var trackId = (transceiver.sender.track && transceiver.sender.track.id) ||
                  (transceiver.kind + transceiver.mid);
    var streamIds = transceiver.streamIds;
    state.localSsrcs = state.localSsrcs || {};
    state.localSsrcs[transceiver.mid] = {
      id:     ssrc,
      rtxId:  rtxSsrc,
      fecId:  null,
      msid:   ((streamIds && streamIds[0]) || '-') + ' ' + trackId,
      msids:  (streamIds && streamIds.length > 1)
                ? streamIds.map(function (id) { return id + ' ' + trackId; })
                : null,
      layers: transceiver.sender.layers,
    };
  }
  return true;
}


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
  // AUDIO SHORT-CIRCUIT (W3C 5.2): an audio sender takes ONE encoding and
  // only `active` survives — video-only members are DROPPED SILENTLY, so
  // none of the video validation below may run for audio (an invalid
  // scaleResolutionDownBy on audio is removed, never an error).
  if (kind === 'audio' && reqEncodings && reqEncodings.length) {
    var _a0 = reqEncodings[0] || {};
    // AUDIO keeps `active` AND `maxBitrate` — only rid,
    // scaleResolutionDownBy and maxFramerate are video-only members.
    reqEncodings = [typeof _a0.maxBitrate === 'number'
      ? { active: _a0.active !== false, maxBitrate: _a0.maxBitrate }
      : { active: _a0.active !== false }];
  }

  // Truncate to the implementation ceiling FIRST: a caller passing a
  // ridiculous list gets a truncated one, never an error — and the
  // simulcast rules below then apply to the surviving layers only.
  if (reqEncodings && reqEncodings.length > MAX_SIMULCAST_ENCODINGS) {
    reqEncodings = reqEncodings.slice(0, MAX_SIMULCAST_ENCODINGS);
  }
  if (reqEncodings) {
    var seenRids = {};
    for (var ei = 0; ei < reqEncodings.length; ei++) {
      var enc = reqEncodings[ei] || {};
      // RFC 8852 requires a rid per simulcast layer ON THE WIRE, but the
      // W3C API does NOT require the app to supply one — a multi-encoding
      // addTransceiver with no rids is legal (the ladder test does
      // exactly this) and the rids are synthesised below.
      if (isSimulcast && !enc.rid) {
        enc = Object.assign({}, enc, { rid: 'r' + ei });
        reqEncodings[ei] = enc;
      }
      // RFC 8852 rid-syntax: alphanumerics ONLY (no '-' or '_' — those
      // are rid *separators* in SDP). Audio drops rid entirely later, so
      // validation applies where rid is meaningful.
      if (enc.rid != null && !/^[A-Za-z0-9]{1,32}$/.test(enc.rid)) {
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
  // WPT: absurd sendEncodings lists are TRUNCATED (UA cap), not rejected.
  if (reqEncodings && reqEncodings.length > 16) reqEncodings = reqEncodings.slice(0, 16);
  if (reqEncodings) {
    for (var _ri16 = 0; _ri16 < reqEncodings.length; _ri16++) {
      var _rid = reqEncodings[_ri16] && reqEncodings[_ri16].rid;
      if (_rid != null && String(_rid).length > 16) {
        throw new TypeError('sendEncodings: rid must be at most 16 characters');
      }
    }
  }
  if (reqEncodings && reqEncodings.length) {
    // W3C 5.2 addTransceiver, in order:
    //  1. AUDIO takes ONE encoding, and only `active` survives on it —
    //     video-shaped members (rid, scaleResolutionDownBy, maxBitrate…)
    //     are dropped rather than rejected.
    //  2. The list is TRUNCATED to the implementation maximum before any
    //     per-encoding work (a "ridiculous" list must not throw).
    //  3. VIDEO: when SOME encodings carry scaleResolutionDownBy, the
    //     others default to 1 — and a SINGLE encoding never keeps it.
    if (kind === 'audio') {
      var _a1 = reqEncodings[0] || {};
      // keeps active AND maxBitrate (see the collapse above)
      reqEncodings = [typeof _a1.maxBitrate === 'number'
        ? { active: _a1.active !== false, maxBitrate: _a1.maxBitrate }
        : { active: _a1.active !== false }];
    } else {
      if (reqEncodings.length > MAX_SIMULCAST_ENCODINGS) {
        reqEncodings = reqEncodings.slice(0, MAX_SIMULCAST_ENCODINGS);
      }
      var _anyScale = reqEncodings.some(function (e) { return e && e.scaleResolutionDownBy != null; });
      if (_anyScale) {
        // some set it => the rest default to 1
        reqEncodings = reqEncodings.map(function (e) {
          e = e || {};
          return e.scaleResolutionDownBy == null
            ? Object.assign({}, e, { scaleResolutionDownBy: 1 }) : e;
        });
      } else if (reqEncodings.length > 1) {
        // NONE set it => the spec's descending ladder: the FIRST layer is
        // full resolution and each subsequent one halves (1, 2, 4 …).
        // W3C: the auto-filled ladder DESCENDS — [2, 1] for two layers,
        // [4, 2, 1] for three: the LAST encoding is full resolution and
        // earlier ones are progressively scaled down. (We had it the
        // other way round, which inverted every simulcast ladder an app
        // did not configure explicitly.)
        var _n = reqEncodings.length;
        reqEncodings = reqEncodings.map(function (e, i) {
          return Object.assign({}, e || {}, { scaleResolutionDownBy: Math.pow(2, _n - 1 - i) });
        });
      }
    }
  }
  if (reqEncodings && reqEncodings.length) {
    for (var li = 0; li < reqEncodings.length; li++) {
      var e = reqEncodings[li] || {};
      var ls = SDP.generateSsrc();
      var lrtx = SDP.generateSsrc();
      layers.push({ rid: e.rid || null, ssrc: ls, rtxSsrc: lrtx });
      // A SINGLE encoding carries neither rid nor scaleResolutionDownBy
      // (both are simulcast-only concepts) — getParameters must not
      // report them. Audio never carries them at all.
      var _single = reqEncodings.length === 1;
      var _vid = kind === 'video';
      encodings.push({
        rid:                   (_single || !_vid) ? undefined : (e.rid || null),
        active:                e.active !== false,
        // maxBitrate applies to BOTH kinds (only rid/scale/framerate are video-only)
        maxBitrate:            (typeof e.maxBitrate === 'number') ? e.maxBitrate : undefined,
        maxFramerate:          (_vid && typeof e.maxFramerate === 'number') ? e.maxFramerate : undefined,
        // video reports it always (defaulting to 1); audio never does
        scaleResolutionDownBy: _vid
          ? (typeof e.scaleResolutionDownBy === 'number' ? e.scaleResolutionDownBy : 1)
          : undefined,
        scalabilityMode:       e.scalabilityMode || null,
        // WPT harvest: the per-encoding codec-selection member (W3C §5.2)
        // rides through to getParameters verbatim.
        codec:                 e.codec ? Object.assign({}, e.codec) : null,
      });
    }
  } else {
    var ssrc = SDP.generateSsrc();
    var rtxSsrc = SDP.generateSsrc();
    // FlexFEC: video streams get a FEC SSRC alongside (RFC 8627 model —
    // FEC rides its own SSRC, paired via a=ssrc-group:FEC-FR). Allocated
    // unconditionally like rtxSsrc; only EMITTED when flexfec is
    // negotiated (mirrors the rtxNegotiated gating in sdp.js).
    var fecSsrc = (kind === 'video') ? SDP.generateSsrc() : null;
    layers.push({ rid: null, ssrc: ssrc, rtxSsrc: rtxSsrc, fecSsrc: fecSsrc });
    encodings.push({
      rid:                   null,
      active:                true,
      // A DEFAULT encoding is exactly { active: true } — these members
      // are UNSET, not zero. Storing 0/1 here leaked into getParameters
      // the moment the projection stopped filtering falsy values.
      maxBitrate:            undefined,
      maxFramerate:          undefined,
      // VIDEO always carries scaleResolutionDownBy (default 1); AUDIO
      // never does — it is a video-only member.
      scaleResolutionDownBy: (kind === 'video') ? 1 : undefined,
      scalabilityMode:       null,
    });
  }

  // Stream association (subset of W3C init.streams / QUICK-1+2):
  // which MediaStream(s) this sender's track belongs to, surfaced to the
  // peer via a=msid. Previously EVERY transceiver hardcoded 'stream0' —
  // so a session forwarding several participants told the remote that
  // ALL tracks share one stream, and the browser grouped everyone into a
  // single MediaStream (one <video> ever renders). Accepts W3C
  // MediaStream objects (init.streams) or plain ids (init.streamIds —
  // the Node-stack convenience, no stream object needed server-side).
  var streamIds = null;
  if (Array.isArray(init.streamIds) && init.streamIds.length) {
    streamIds = init.streamIds.map(String);
  } else if (Array.isArray(init.streams) && init.streams.length) {
    streamIds = [];
    for (var sti = 0; sti < init.streams.length; sti++) {
      var st = init.streams[sti];
      if (st && st.id) streamIds.push(String(st.id));
    }
    if (!streamIds.length) streamIds = null;
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
    streamIds: streamIds,
  };

  state.transceivers.push(transceiver);
  state.localSsrcs[mid] = {
    id:     layers[0].ssrc,
    rtxId:  layers[0].rtxSsrc,
    fecId:  layers[0].fecSsrc || null,
    // WPT harvest: msid must carry the REAL stream id + track id — the
    // receiver reconstructs shared MediaStreams by these tokens, and
    // tests compare event.streams[0].id to the sender's stream.id.
    msid:   ((streamIds && streamIds[0]) || '-') + ' ' + ((init && init.track && init.track.id) || (kind + mid)),
    // MULTI-STREAM: a sender can belong to several MediaStreams
    // (addTrack(track, s1, s2)); each needs its own msid token or the
    // receiver can only ever rebuild one stream. Null for the common
    // single-stream case so nothing changes there.
    msids:  (streamIds && streamIds.length > 1)
      ? streamIds.map(function (sid) {
          return sid + ' ' + ((init && init.track && init.track.id) || (kind + mid));
        })
      : null,
    layers: layers.slice(),
  };
  // Data-plane lookup: media SSRC → its FEC SSRC (media_transport.sendRtp
  // uses this to know which outgoing streams get FlexFEC protection).
  if (layers[0].fecSsrc) {
    if (!state.localFecSsrcs) state.localFecSsrcs = {};
    state.localFecSsrcs[layers[0].ssrc] = layers[0].fecSsrc;
  }

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
/**
 * Rebind a transceiver to a new mid, moving its send-side state with it.
 * The ssrc allocation lives in state.localSsrcs keyed BY MID, so a mid
 * change without this re-key silently orphans the sender (no a=ssrc in
 * the offer, no RTP on the wire — the field bug of rounds 68-69). Four
 * call sites need this exact pair, so it lives here once.
 */
function rebindMid(state, t, newMid) {
  var oldMid = String(t.mid);
  var next = String(newMid);
  t.mid = next;
  if (oldMid !== next && state.localSsrcs && state.localSsrcs[oldMid]) {
    state.localSsrcs[next] = state.localSsrcs[oldMid];
    delete state.localSsrcs[oldMid];
  }
  return t;
}


/**
 * Is this transceiver stopped? The stopped state lives in its OWN flag,
 * not in currentDirection: W3C 5.4 says stop() sets direction to
 * 'stopped' while currentDirection stays null until a negotiation
 * actually retires the m-section. Encoding it in currentDirection made
 * the two observable values disagree with the spec and forced every
 * guard in the codebase to test two fields. One predicate, one truth.
 */
function isStopped(t) {
  if (!t) return false;
  return !!(t._stopped || t.direction === 'stopped' ||
            t.currentDirection === 'stopped');
}

/**
 * Is this transceiver FULLY stopped, as opposed to merely stopping?
 *
 * W3C 5.4 has two states and they behave differently:
 *
 *   [[Stopping]] — stop() has been called. direction reads 'stopped', but the
 *                  m-section is still live and MEDIA STILL FLOWS until a
 *                  negotiation retires it.
 *   [[Stopped]]  — that negotiation has happened. Nothing flows.
 *
 * isStopped() above deliberately answers "stopping or stopped" — it guards
 * things that must not touch a transceiver on its way out. But a few places
 * need the stricter question, because a stopping transceiver is still
 * negotiating: applyDirectionsFromAnswer must record the direction the answer
 * agreed on, or currentDirection stays null on a transceiver that is actively
 * carrying media. WPT reads {currentDirection: 'sendrecv', direction:
 * 'stopped'} on exactly that pair.
 */
function isFullyStopped(t) {
  if (!t) return false;
  return !!(t._stopped || t.currentDirection === 'stopped');
}


/**
 * JSEP legitimate-owner test — the single source of truth for "may this
 * transceiver own/steer an m-line?". Association is earned three ways:
 * created by a remote description, adopted during offer processing, or
 * bound by the local-offer binding step. A RAW MID MATCH IS NEVER ENOUGH
 * (birth mids live in an internal namespace and collide with the peer's).
 * Every selector in the codebase routes through this — cm's association
 * walk, the answer builder, and the directions committer.
 */
function isLegitimateOwner(t) {
  if (!t) return false;
  if (process.env.WSRV_LEGACY_ASSOC === '1') return true;   // pre-JSEP escape hatch
  return !!(t._associated || t._srdCreated || t._adopted);
}


// W3C: implementations cap the simulcast layer count; extra encodings
// are TRUNCATED (not an error). Three layers matches the common browser
// ceiling and our SFU's rid handling.
var MAX_SIMULCAST_ENCODINGS = 3;


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
    // THE FIFTH SELECTOR (same disease, last carrier): committing a
    // negotiated direction onto a transceiver whose only claim is a raw
    // birth-mid collision is the grab itself — legitimate owners only.
    if (t && !isLegitimateOwner(t)) t = null;
    if (!t) continue;
    // A FULLY STOPPED transceiver is final: applying a negotiated direction
    // over it resurrected it (direction came back as recvonly), which
    // also defeated the retirement sweep — a stopped transceiver could
    // never be retired and the list grew forever.
    //
    // A merely STOPPING one is not final. Its m-section is still live and
    // media still flows until a negotiation retires it, so the direction the
    // answer agreed on must be recorded. Skipping those left currentDirection
    // null on a transceiver that was actively carrying media.
    if (isFullyStopped(t)) continue;

    if (m.port === 0) {
      // TWO STEPS. Retiring an m-section spans a full offer/answer, and W3C
      // 5.4 gives the midpoint its own observable state:
      //
      //   our own OFFER carries the rejection   currentDirection = 'inactive'
      //   the ANSWER confirms it                currentDirection = 'stopped'
      //
      // The transceiver is on its way out either way, but until the answer
      // lands the negotiation is not finished and the spec does not call it
      // stopped yet. Committing 'stopped' at offer time skipped that state
      // and made the retirement sweep — which keys on it — run a round early.
      //
      // isLocalAnswer is true when WE are answering — the negotiation is
      // complete from our side and the section is retired. False means a
      // remote description is being applied to our own offer, i.e. the
      // midpoint, which only reaches 'inactive'.
      t.currentDirection = isLocalAnswer ? 'stopped' : 'inactive';
      continue;
    }

    var dir = m.direction || 'sendrecv';
    if (!isLocalAnswer) {
      dir = SDP.REVERSE_DIRECTION[dir] || dir;
    }
    t.currentDirection = dir;
    // "HAS THIS SENDER EVER SENT?" — recorded HERE, at the moment a
    // negotiation actually puts the transceiver into a sending
    // direction. W3C 5.1: addTrack may reuse a transceiver whose sender
    // is idle, but NOT one that has sent before — a peer that already
    // saw media on that m-line must be told about the new track through
    // a new section. The flag existed but was only set inside the
    // receive-side mute pass, which never runs for a send-only peer, so
    // a used sender was silently recycled.
    if ((dir === 'sendrecv' || dir === 'sendonly') && t.sender) {
      t.sender._everSentDir = true;
    }
  }
  // FIELD DIAG: one line naming exactly what the answer committed —
  // if the sender is silent, this says whether the direction landed.
  try {
    if (typeof console !== 'undefined' &&
        (process.env.WEBRTC_DEBUG === '1' || process.env.WEBRTC_DEBUG === 'true')) {
      console.log('[rtp-diag] post-answer table: ' + JSON.stringify(state.transceivers.map(function (x) {
        return (x.mid == null ? '?' : x.mid) + ':' + (x._associated ? 'A' : 'u') +
               (x.sender && x.sender.track ? 'T' : '-') + '/' + (x.currentDirection || '-');
      })));
    }
  } catch (eD) {}
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

/**
 * What direction did our own most recent local description declare for this
 * m-section? Null when we have not described it. See the note in
 * checkIfNegotiationIsNeeded on why this, and not currentDirection, is the
 * thing to compare a transceiver's direction against.
 */
/**
 * Have we already PROPOSED this transceiver's direction to the peer?
 *
 * The question exists because `direction` and `currentDirection` legally
 * differ: direction is what the application asked for, currentDirection is
 * what the peer agreed to, and a peer that declines half of a request leaves
 * them apart permanently and correctly:
 *
 *     direction        sendrecv     we are willing to send and receive
 *     currentDirection sendonly     they are not sending
 *
 * Renegotiating there would produce the identical offer and get the identical
 * answer, so the difference alone must not mean "negotiation needed". What
 * decides is whether the peer has SEEN our request.
 *
 * Only an OFFER states a request. An answer states the agreed direction — the
 * same value currentDirection already holds — so it can never tell us
 * anything, and reading it as a proposal makes this check compare a value with
 * itself.
 *
 * Three cases:
 *
 *   our local description is an offer   → compare the direction it carries
 *   we have only ever answered          → we have proposed nothing; the
 *                                         request is unsent, so NEEDED
 *   no local description yet            → nothing proposed, NEEDED
 */
function _proposedDirection(state, mid) {
  var pend = state.pendingLocalDescription;
  var curr = state.currentLocalDescription;
  // pendingLocalDescription wins while a round is in flight; otherwise the
  // completed one stands.
  var live = pend || curr;
  if (!live || live.type !== 'offer') return null;   // we proposed nothing
  var d = state.parsedLocalSdp;
  if (!d || !d.media) return null;
  for (var i = 0; i < d.media.length; i++) {
    var m = d.media[i];
    if (!m || String(m.mid) !== String(mid)) continue;
    return m.direction || null;
  }
  return null;
}


/**
 * Has the msid for this transceiver's m-section drifted from what our last
 * local description declared? setStreams() is the way that happens.
 */


/** Sorted, de-duplicated copy — the set form of a stream-id list. */
function _uniqueSorted(ids) {
  var seen = {}, out = [];
  for (var i = 0; i < ids.length; i++) {
    if (Object.prototype.hasOwnProperty.call(seen, ids[i])) continue;
    seen[ids[i]] = true;
    out.push(ids[i]);
  }
  return out.sort();
}

/** Stream ids an m-section declares, from either msid form. Null when it
 *  declares none — a section that never carried an msid is not out of date,
 *  it simply predates any. */
function _streamIdsFromSection(m) {
  var out = [];
  if (m.msids && m.msids.length) {
    for (var i = 0; i < m.msids.length; i++) {
      var sid = String(m.msids[i]).trim().split(/\s+/)[0];
      if (sid && sid !== '-') out.push(sid);
    }
    return out;
  }
  if (m.msid) {
    var one = String(m.msid).trim().split(/\s+/)[0];
    if (one && one !== '-') out.push(one);
    return out;
  }
  return null;
}

/** The same, from the local SSRC slot the application's setStreams wrote. */
function _streamIdsFromMsid(slot) {
  var out = [];
  var list = (slot.msids && slot.msids.length) ? slot.msids
           : (slot.msid ? [slot.msid] : null);
  if (!list) return null;
  for (var i = 0; i < list.length; i++) {
    var sid = String(list[i]).trim().split(/\s+/)[0];
    if (sid && sid !== '-') out.push(sid);
  }
  return out;
}

function _msidOutOfDate(state, t) {
  if (!t || t.mid == null) return false;
  var slot = state.localSsrcs && state.localSsrcs[t.mid];
  if (!slot || !slot.msid) return false;
  var d = state.parsedLocalSdp;
  if (!d || !d.media) return false;
  for (var i = 0; i < d.media.length; i++) {
    var m = d.media[i];
    if (!m || String(m.mid) !== String(t.mid)) continue;
    // Only compare when the description actually carried an msid; a section
    // that never had one is not "out of date", it simply predates any.
    // COMPARE THE SET OF STREAM IDS, NOT THE MSID TEXT.
    //
    // A track's membership is a SET: the same streams in a different order are
    // the same membership, and re-assigning the streams a track already
    // belongs to changes nothing the peer needs to hear about. W3C 5.2 says
    // negotiation is needed when the streams DIFFER, not whenever setStreams
    // is called.
    //
    // Comparing the rendered msid text made both of those look like changes —
    // setStreams(s1, s2) followed by setStreams(s2, s1), or even the identical
    // call twice, each fired negotiationneeded and produced an offer whose SDP
    // said the same thing. An application that re-asserts its streams (a
    // common way to keep state in sync) renegotiated on every assertion.
    var declaredIds = _streamIdsFromSection(m);
    if (declaredIds == null) return false;
    var currentIds = _streamIdsFromMsid(slot);
    if (currentIds == null) return false;
    // A SET IGNORES DUPLICATES TOO. setStreams(s1, s1, s2) assigns the same
    // membership as setStreams(s1, s2) — the track belongs to s1 and s2
    // either way, and the SDP that results is identical. Counting the repeat
    // as a change fired negotiationneeded for an assignment that changed
    // nothing.
    var a = _uniqueSorted(declaredIds), b = _uniqueSorted(currentIds);
    if (a.length !== b.length) return true;
    for (var k = 0; k < a.length; k++) {
      if (a[k] !== b[k]) return true;
    }
    return false;
  }
  return false;
}

function checkIfNegotiationIsNeeded(state) {
  if (state.dataChannels && state.dataChannels.length > 0) {
    if (!hasApplicationMediaInLocalDescription(state)) return true;
  }

  for (var i = 0; i < state.transceivers.length; i++) {
    var t = state.transceivers[i];

    // A STOPPING transceiver needs negotiation — that is the whole point of
    // the state. W3C 4.7.3: stop() marks [[Stopping]], and only a subsequent
    // negotiation retires the m-section and moves it to [[Stopped]]. Until
    // that happens the connection is out of sync with what the application
    // asked for, so negotiationneeded must fire.
    //
    // Lumping stopping in with stopped and skipping both meant the event
    // never fired: the application called stop(), nothing prompted it to
    // renegotiate, and the m-section stayed live forever. Anything awaiting
    // negotiationneeded after a stop() waited indefinitely.
    if (isFullyStopped(t)) continue;
    if (isStopped(t)) return true;      // stopping, not yet retired

    if (t.mid == null) return true;

    // W3C 4.7.3 compares the transceiver's direction against what the LAST
    // OFFER/ANSWER ACTUALLY OFFERED — not against currentDirection.
    //
    // currentDirection is the direction that was AGREED, and the two legally
    // differ whenever the peer declines half of what we asked for:
    //
    //   direction        sendrecv     we are willing to send and receive
    //   currentDirection sendonly     they are not sending, so we only send
    //
    // That is a settled, correct outcome — offering again would produce the
    // identical SDP and the peer would give the identical answer. Treating it
    // as a mismatch made negotiationneeded fire forever after any asymmetric
    // call: one side adds a track, the other does not, and the connection
    // never stops asking to renegotiate.
    //
    // The check that belongs here is whether the description we last sent
    // still describes what the application has asked for. If our own
    // description already carries this direction, there is nothing to
    // renegotiate.
    if (t.direction !== t.currentDirection) {
      var _proposed = _proposedDirection(state, t.mid);
      if (_proposed !== t.direction) return true;
    }

    // The msid in our last description must still match the streams the
    // application has assigned. sender.setStreams() changes which
    // MediaStreams a track belongs to, and that is carried in the SDP as
    // a=msid — so the peer only learns of it through a new offer.
    //
    // Nothing compared it, so setStreams() updated the internal state and
    // then reported no negotiation needed: the event never fired and the
    // remote side went on grouping the track under its old stream forever.
    if (_msidOutOfDate(state, t)) return true;
  }

  return false;
}


/* ========================= Exports ========================= */

export {
  // Mid allocation
  getNextMid,

  // Transceiver creation
  createTransceiver,
  ensureSendSsrc,
  isFullyStopped,

  // Lookups
  findByMid,
  findRemoteSsrcForMid,
  findPrimaryForRtx,

  // Direction commit
  applyDirectionsFromAnswer,
  isLegitimateOwner,
  isStopped,
  rebindMid,

  // Negotiation-needed
  hasApplicationMediaInLocalDescription,
  checkIfNegotiationIsNeeded,
};
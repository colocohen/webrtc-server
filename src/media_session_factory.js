// src/media_session_factory.js
//
// Build offers and answers from the current state.
//
// The factory turns the cm.js state (transceivers, dataChannels, codec
// preferences, current local description for renegotiation) into a fresh
// SDP string by feeding sdp.js's createOffer / createAnswer the right
// per-section specs.
//
// What the factory OWNS:
//   - building the m-section list for an offer (including renegotiation:
//     preserving extmap IDs, codecs, mids from the previous local SDP)
//   - building the m-section list for an answer (mapping each remote
//     m-section to a transceiver via mid)
//   - per-transceiver spec construction: codecs, codec preferences,
//     direction, SSRC + per-layer simulcast layers
//   - extmap ID assignment that doesn't collide within a BUNDLE
//
// What the factory does NOT own:
//   - ensuring local ICE creds / DTLS fingerprint exist — that's
//     transport_controller.js, called by cm.js BEFORE we run
//   - computing the DTLS setup attribute fallback (offer→actpass,
//     answer→resolveSetup of peer's setup) — cm.js computes that and
//     passes it in
//   - bringing up the ICE agent / gathering — that's cm.js's
//     prepareIceForSdp(), which runs BEFORE we run, and the resulting
//     local candidate list is passed in
//   - storing the resulting SDP as a description, advancing the
//     signaling state, firing events — that's the orchestrator
//
// All functions take state as their first parameter (no shadow state,
// matching transport_controller.js / rtp_transmission_manager.js).
//
// Part of the SDP-layer refactor; see SDP_REFACTOR_PLAN.md, milestone 4.

import * as SDP from './sdp.js';
import * as RtpManager from './rtp_transmission_manager.js';


/* ========================= Per-transceiver spec ========================= */

/**
 * Build the per-m-section spec for one transceiver. The result is fed to
 * sdp.js's createOffer / createAnswer as one entry in `media[]`.
 *
 * Codecs are seeded from DEFAULT_AUDIO_CODECS / DEFAULT_VIDEO_CODECS
 * with PTs assigned by position (audio: 111+idx, video: 96+idx*2 with
 * RTX at idx*2+1). If the transceiver has _codecPreferences set, the
 * codec list is reordered + filtered per W3C §5.4.3.8.
 *
 * Senders without an SSRC (auto-created by processRemoteMedia for tracks
 * the peer added that we have no matching sender for) cannot advertise
 * sendrecv/sendonly — they go recvonly with no a=ssrc, mirroring
 * computeAnswerDirection().
 *
 * @param {Object} state
 * @param {Object} t           transceiver
 * @returns {Object}           media-section spec
 */
function buildMediaForTransceiver(state, t) {
  var codecs;
  if (t.kind === 'audio') {
    codecs = SDP.DEFAULT_AUDIO_CODECS.map(function(c, idx) {
      return {
        payloadType: 111 + idx,
        name:        c.name,
        clockRate:   c.clockRate,
        channels:    c.channels,
        fmtp:        c.fmtp,
        feedback:    c.feedback,
      };
    });
  } else {
    codecs = SDP.DEFAULT_VIDEO_CODECS.map(function(c, idx) {
      return {
        payloadType:    96 + idx * 2,
        name:           c.name,
        clockRate:      c.clockRate,
        fmtp:           c.fmtp,
        feedback:       c.feedback,
        rtxPayloadType: c.rtx ? (97 + idx * 2) : undefined,
      };
    });
  }

  // W3C §5.4.3.8 — transceiver.setCodecPreferences. When the app provides
  // an ordered codec list, the m-section MUST be reordered to match, and
  // any codec absent from preferences MUST be excluded.
  //   • Preference mimeType format: "video/VP8", "audio/opus"
  //   • Match on codec name + clockRate (+ channels for audio)
  //   • PTs stay stable (keep the assignment above); reorder happens by
  //     reshuffling the codecs array before PT-dependent code sees it.
  // Empty array means "reset" per spec (api.js setCodecPreferences).
  if (t._codecPreferences && t._codecPreferences.length) {
    var reordered = [];
    for (var pi = 0; pi < t._codecPreferences.length; pi++) {
      var pref = t._codecPreferences[pi];
      if (!pref || !pref.mimeType) continue;
      var slash = pref.mimeType.indexOf('/');
      var prefName = (slash >= 0 ? pref.mimeType.slice(slash + 1) : pref.mimeType);
      for (var ci = 0; ci < codecs.length; ci++) {
        var c = codecs[ci];
        if (c.name.toLowerCase() !== prefName.toLowerCase()) continue;
        if (pref.clockRate && pref.clockRate !== c.clockRate) continue;
        if (t.kind === 'audio' && pref.channels && pref.channels !== c.channels) continue;
        reordered.push(c);
        codecs.splice(ci, 1);
        break;
      }
    }
    codecs = reordered;
  }

  // Transceivers without a sender SSRC (auto-created from peer-added
  // tracks) advertise recvonly without a=ssrc to keep Chrome happy.
  var hasLocalSsrc = (t.sender.ssrc != null);

  // Direction resolution: respect the user's direction setting, but
  // clamp send-side directions when there's nothing to send.
  //
  // W3C §5.4.4 RTCRtpTransceiver.direction is one of:
  //   sendrecv | sendonly | recvonly | inactive | stopped
  //
  // The previous code unconditionally forced `recvonly` whenever
  // hasLocalSsrc was false. That's wrong for `inactive`: if the user
  // explicitly set `transceiver.direction = 'inactive'` (e.g., to
  // pause receive temporarily on an auto-created receive transceiver),
  // we'd silently override their intent to `recvonly`, which keeps
  // the peer sending. `inactive` and `recvonly` are both legitimate
  // no-send states and must pass through unchanged.
  //
  // Only `sendonly`/`sendrecv` need clamping, since we have no SSRC
  // to actually send from. `sendonly` → `inactive` (we can neither
  // send nor receive), `sendrecv` → `recvonly` (we can still receive).
  var requestedDir = t.direction || 'sendrecv';
  var resolvedDir;
  if (hasLocalSsrc) {
    resolvedDir = requestedDir;
  } else if (requestedDir === 'inactive' || requestedDir === 'recvonly') {
    resolvedDir = requestedDir;
  } else if (requestedDir === 'sendonly') {
    resolvedDir = 'inactive';
  } else {
    // sendrecv (or unknown — defensively clamped)
    resolvedDir = 'recvonly';
  }

  var spec = {
    type:      t.kind,
    mid:       t.mid,
    direction: resolvedDir,
    codecs:    codecs,
  };

  if (hasLocalSsrc) {
    spec.ssrc = {
      id:    t.sender.ssrc,
      rtxId: t.sender.rtxSsrc,
      cname: state.localCname,
      msid:  'stream0 ' + t.kind + t.mid,
      layers: (t.sender.layers || []).map(function (L) {
        return { rid: L.rid, ssrc: L.ssrc, rtxSsrc: L.rtxSsrc };
      }),
    };
  }

  return spec;
}


/* ========================= Offer ========================= */

/**
 * Build an offer SDP string.
 *
 * Renegotiation handling: if state.currentLocalDescription is non-null,
 * the previous local SDP is parsed and used to PIN extmap IDs, codecs,
 * and mids per m-section. RFC 8285 technically allows reassignment, but
 * Chrome enforces a stricter "once bound, always bound" invariant —
 * changing an extmap ID across renegotiation triggers
 *   "RTP extension ID reassignment from <old-uri> to <new-uri> for ID N"
 * Same applies to codec PTs.
 *
 * Caller responsibilities BEFORE calling:
 *   - state.localIceUfrag / localIcePwd present
 *   - state.localFingerprint present
 *   - if iceRestart: agent.restart() already called by cm.js
 *   - in lite mode: agent created and gather() done; pass localCandidates
 *
 * @param {Object} state
 * @param {Object} options
 * @param {string} options.setup            DTLS setup attribute ('actpass' or pinned role)
 * @param {Object[]|null} options.liteCandidates  iceAgent.localCandidates in lite mode, else null
 * @returns {string}                       the offer SDP
 */
function buildOffer(state, options) {
  options = options || {};

  var mediaSections = [];
  var existingMids = {};
  // id → uri map of extmap claims already in this BUNDLE. Seeded from
  // the previous local SDP and extended for each new m-section, fed to
  // assignExtensionIds() so new sections pick non-colliding IDs.
  var bundleExtmap = {};

  // Renegotiation: preserve existing m-sections.
  // We pin from state.parsedCurrentLocalSdp (the parsed view of the most
  // recently *completed* round). Using state.parsedLocalSdp here would be
  // wrong during 'have-local-offer' — that points to the in-flight pending
  // offer rather than the previous completed offer. The class maintains
  // parsedCurrentLocalSdp on every answer application, so by the time
  // createOffer fires it reflects the current local description faithfully.
  //
  // For each previous m-section, we have three cases:
  //   1. mapped to an active (non-stopped) transceiver → emit normally,
  //      preserving mid, extensions, codecs.
  //   2. mapped to a stopped transceiver (or no transceiver at all) →
  //      try to recycle the slot for a new transceiver of matching kind.
  //      If found: assign that transceiver to this slot. If not: emit
  //      with port=0 per JSEP §5.2.2 ("rejected" m-section).
  //   3. m=application (DataChannel) → preserve unconditionally.
  if (state.parsedCurrentLocalSdp && Array.isArray(state.parsedCurrentLocalSdp.media)) {
    var existingParsed = state.parsedCurrentLocalSdp;
    for (var ei = 0; ei < existingParsed.media.length; ei++) {
      var em = existingParsed.media[ei];

      if (em.type === 'application') {
        existingMids[em.mid] = true;
        mediaSections.push({
          type: 'application', mid: em.mid,
          sctpPort: state.sctpPort, maxMessageSize: state.maxMessageSize,
        });
        continue;
      }

      var tr = RtpManager.findByMid(state, em.mid);
      var trStopped = !tr || tr.currentDirection === 'stopped' ||
                      tr.direction === 'stopped';

      if (tr && !trStopped) {
        // Active transceiver — emit normally, preserving extmap/codecs.
        existingMids[em.mid] = true;
        var spec = buildMediaForTransceiver(state, tr);
        if (em.extensions && em.extensions.length) spec.extensions = em.extensions;
        if (em.codecs     && em.codecs.length)     spec.codecs     = em.codecs;
        mediaSections.push(spec);
        if (em.extensions) {
          for (var ex = 0; ex < em.extensions.length; ex++) {
            bundleExtmap[em.extensions[ex].id] = em.extensions[ex].uri;
          }
        }
        continue;
      }

      // Stopped (or missing) transceiver — try to recycle this slot.
      // JSEP §5.2.2 / RFC 8829 §5.5.3: a new transceiver of matching kind
      // MAY take over a stopped m-section's slot rather than appending a
      // fresh one, keeping the m-section count bounded across many
      // add/stop cycles.
      var recycle = null;
      for (var ti2 = 0; ti2 < state.transceivers.length; ti2++) {
        var cand = state.transceivers[ti2];
        if (cand.currentDirection === 'stopped' || cand.direction === 'stopped') continue;
        if (existingMids[cand.mid]) continue;     // already placed
        if (cand.kind !== em.type) continue;
        recycle = cand;
        break;
      }

      if (recycle) {
        existingMids[recycle.mid] = true;
        var rspec = buildMediaForTransceiver(state, recycle);
        // Pin extmap/codecs to the slot's previous values so the peer
        // side has no extension-ID/codec-PT churn across the recycle —
        // Chrome rejects extmap reassignment.
        if (em.extensions && em.extensions.length) rspec.extensions = em.extensions;
        if (em.codecs     && em.codecs.length)     rspec.codecs     = em.codecs;
        mediaSections.push(rspec);
        if (em.extensions) {
          for (var ex2 = 0; ex2 < em.extensions.length; ex2++) {
            bundleExtmap[em.extensions[ex2].id] = em.extensions[ex2].uri;
          }
        }
      } else {
        // No new transceiver to recycle into — emit a rejected (port=0)
        // m-section preserving the original mid + media type + codec list.
        // The peer must keep the slot but receive no media on it.
        existingMids[em.mid] = true;
        mediaSections.push({
          type:      em.type,
          mid:       em.mid,
          port:      0,
          direction: 'inactive',
          codecs:    em.codecs || [],
          extensions: em.extensions || [],
        });
        if (em.extensions) {
          for (var ex3 = 0; ex3 < em.extensions.length; ex3++) {
            bundleExtmap[em.extensions[ex3].id] = em.extensions[ex3].uri;
          }
        }
      }
    }
  } else {
    // First offer: if there are DCs, allocate an m=application slot
    // with a mid that doesn't collide with any transceiver's mid.
    if (state.dataChannels.length > 0) {
      var dcMid = String(RtpManager.getNextMid(state));
      mediaSections.push({
        type: 'application', mid: dcMid,
        sctpPort: state.sctpPort, maxMessageSize: state.maxMessageSize,
      });
      existingMids[dcMid] = true;
    }
  }

  // New transceivers — pick extmap IDs that don't collide with the
  // BUNDLE so far. Chrome's extmap ordering varies by context (audio-only
  // vs audio+video), so any static default table will collide somewhere.
  for (var i = 0; i < state.transceivers.length; i++) {
    var t = state.transceivers[i];
    if (t.currentDirection === 'stopped' || t.direction === 'stopped') continue;
    if (!existingMids[t.mid]) {
      var newSpec = buildMediaForTransceiver(state, t);
      var defaults = (t.kind === 'audio')
        ? SDP.DEFAULT_AUDIO_EXTENSIONS
        : SDP.DEFAULT_VIDEO_EXTENSIONS;
      newSpec.extensions = SDP.assignExtensionIds(defaults, bundleExtmap);
      for (var ne = 0; ne < newSpec.extensions.length; ne++) {
        bundleExtmap[newSpec.extensions[ne].id] = newSpec.extensions[ne].uri;
      }
      mediaSections.push(newSpec);
    }
  }

  return SDP.createOffer({
    sessionId:       state.localSessionId,
    ice:             { ufrag: state.localIceUfrag, pwd: state.localIcePwd },
    dtls:            { fingerprint: state.localFingerprint, setup: options.setup },
    media:           mediaSections,
    cname:           state.localCname,
    mode:            state.mode,
    candidates:      options.liteCandidates,
    endOfCandidates: (state.mode === 'lite'),
  });
}


/* ========================= Answer ========================= */

/**
 * Build an answer SDP string.
 *
 * Iterates remote m-sections in order. For each (audio|video) m-section
 * that maps to a transceiver in state.localSsrcs (i.e. one we explicitly
 * added), the answer carries the SSRC. Sections we have no transceiver
 * for go recvonly/inactive with no a=ssrc — matches Chrome's behavior.
 *
 * Caller responsibilities BEFORE calling:
 *   - state.parsedRemoteSdp present (no remote offer = error before us)
 *   - state.localIceUfrag / localIcePwd present
 *   - state.localFingerprint present
 *   - in lite mode: agent created and gather() done; pass localCandidates
 *
 * @param {Object} state
 * @param {Object} options
 * @param {string} options.setup            DTLS setup attribute (pinned or echoed peer's setup)
 * @param {Object[]|null} options.liteCandidates  iceAgent.localCandidates in lite mode, else null
 * @returns {string}                       the answer SDP
 */
function buildAnswer(state, options) {
  options = options || {};

  // SSRCs come ONLY from transceivers the user added explicitly
  // (state.localSsrcs is populated by RtpManager.createTransceiver).
  // m-sections in the remote offer with no matching transceiver → no
  // SSRCs in the answer; sdp.js will emit recvonly/inactive accordingly.
  //
  // Directions: per-mid map of the user's preferred transceiver.direction
  // — passed to sdp.js's createAnswer so computeAnswerDirection can
  // intersect with user pref (W3C §5.5 step 2). Without this, the answer
  // would ignore `direction='inactive'` set on a transceiver after
  // negotiation and emit recvonly/sendrecv based purely on offer dir +
  // SSRC presence — same conceptual gap as MSF item 23 (a) but on the
  // answer path. Fixed in coordination with sdp.js item 24 (a).
  var ssrcs = {};
  var directions = {};
  for (var i = 0; i < state.parsedRemoteSdp.media.length; i++) {
    var m = state.parsedRemoteSdp.media[i];
    if (m.type !== 'audio' && m.type !== 'video') continue;
    if (state.localSsrcs[m.mid]) {
      ssrcs[m.mid] = state.localSsrcs[m.mid];
    }
    var tr = RtpManager.findByMid(state, m.mid);
    if (tr && tr.direction) {
      directions[m.mid] = tr.direction;
    }
  }

  return SDP.createAnswer(state.parsedRemoteSdp, {
    ice:             { ufrag: state.localIceUfrag, pwd: state.localIcePwd },
    dtls:            { fingerprint: state.localFingerprint, setup: options.setup },
    ssrcs:           ssrcs,
    directions:      directions,
    cname:           state.localCname,
    candidates:      options.liteCandidates,
    endOfCandidates: (state.mode === 'lite'),
    mode:            state.mode,
  });
}


/* ========================= Exports ========================= */

export {
  buildMediaForTransceiver,
  buildOffer,
  buildAnswer,
};

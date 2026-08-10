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
        // STATIC payload types win (RFC 3551: PCMU=0, PCMA=8, G722=9).
        // They are not ours to allocate — a peer that sees PCMA on a
        // dynamic PT may still decode it, but any endpoint following the
        // static table (SIP gateways, PSTN bridges) will not.
        payloadType: (c.pt != null) ? c.pt : (111 + idx),
        name:        c.name,
        clockRate:   c.clockRate,
        channels:    c.channels,
        fmtp:        c.fmtp,
        feedback:    c.feedback,
        // RED (RFC 2198): offered alongside opus at PT 63, mirroring
        // Chrome's default audio offer. The answer side attaches this
        // from the remote offer instead (extractCodecs pass 2b).
        redPayloadType: (c.name === 'opus') ? 63 : undefined,
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
        // FlexFEC (flexfec-03): offered once per video m-section, on the
        // first codec entry, at PT 118 (outside the 96..10x primary/rtx
        // range). Send path lives in media_transport.sendRtp; receive
        // path in _handleIncomingRtpInner.
        flexfecPayloadType: (idx === 0) ? 118 : undefined,
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
  // A TRACK counts as "something to send" even before an SSRC has been
  // allocated. An SRD-created transceiver that addTrack() has just
  // promoted to sendrecv has a track but no ssrc yet, so the clamp below
  // downgraded our ANSWER to recvonly — the peer was told we would not
  // send, and the offerer's currentDirection settled at sendonly instead
  // of sendrecv. The SSRC is assigned as part of building this very
  // description, so keying the clamp on it alone was a chicken-and-egg.
  var hasLocalSsrc = (t.sender.ssrc != null) || !!(t.sender && t.sender.track);

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
    // setCodecPreferences (W3C 5.4): the application ordering wins in the
    // m-section. Nothing consumed _codecPreferences here before — the API
    // accepted the call and silently ignored it. NOTE the deeper gap this
    // exposed: getCapabilities() advertises codecs (PCMA, PCMU, G722...)
    // that are NOT in SDP.DEFAULT_AUDIO_CODECS, so preferring one of them
    // still cannot change the wire until the two tables are reconciled.
    // The ranking below is correct and takes effect for any codec we do
    // offer; aligning the tables is its own piece of work.
    codecs:    (function () {
      var prefs = t._codecPreferences;
      if (!prefs || !prefs.length) return codecs;
      var ranked = [], seen = {};
      for (var pi = 0; pi < prefs.length; pi++) {
        var want = String(prefs[pi] && prefs[pi].mimeType || '').toLowerCase();
        for (var ci = 0; ci < codecs.length; ci++) {
          // internal entries carry a bare `name` ("opus"); capabilities
          // use the IDL mimeType ("audio/opus") — compare on the name.
          var haveName = String(codecs[ci] && codecs[ci].name || '').toLowerCase();
          var wantName = want.indexOf('/') >= 0 ? want.split('/')[1] : want;
          if (haveName && haveName === wantName && !seen[ci]) {
            ranked.push(codecs[ci]); seen[ci] = true;
          }
        }
      }
      // codecs the app did not mention keep their relative order at the end
      for (var ri = 0; ri < codecs.length; ri++) if (!seen[ri]) ranked.push(codecs[ri]);
      return ranked.length ? ranked : codecs;
    })(),
  };

  if (hasLocalSsrc) {
    spec.ssrc = {
      id:    t.sender.ssrc,
      rtxId: t.sender.rtxSsrc,
      cname: state.localCname,
      msid:  (((t.streamIds && t.streamIds[0]) || '-')) + ' ' +
             ((t.track && t.track.id) || (t.kind + t.mid)),
      // MULTI-STREAM (W3C: addTrack(track, s1, s2)): a sender may belong
      // to SEVERAL MediaStreams, and each one needs its own msid token —
      // we only ever emitted the first, so the receiving side could never
      // reconstruct more than one stream. Carried as a list; the SDP
      // writer emits one a=msid line per entry.
      msids: (t.streamIds && t.streamIds.length > 1)
        ? t.streamIds.map(function (sid) {
            return sid + ' ' + ((t.track && t.track.id) || (t.kind + t.mid));
          })
        : null,
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

  // SESSION-STICKY EXTMAP (M2 finding): claims made by the REMOTE side
  // must be honored too. In a session where BOTH endpoints add m-lines
  // (a browser adds its camera, the SFU adds consumer streams), the peer
  // has already bound extension IDs to URIs on ITS m-lines — Chrome, for
  // example, binds id 3 to video-orientation while our default table
  // binds id 3 to transport-cc. Allocating from our table alone produced
  // one BUNDLE where id 3 meant two different things; Chrome hard-fails
  // ("RTP extension ID reassignment not supported") and the session is
  // poisoned. Seed the remote's id→uri claims FIRST; the local-pin loop
  // below may overwrite (re-emitted local lines must stay self-
  // consistent), and assignExtensionIds() then steers every NEW section
  // around the union of both worlds.
  var _remoteParsedForExt = state.parsedRemoteSdp;
  if (_remoteParsedForExt && Array.isArray(_remoteParsedForExt.media)) {
    for (var _rmi = 0; _rmi < _remoteParsedForExt.media.length; _rmi++) {
      var _rm = _remoteParsedForExt.media[_rmi];
      if (_rm && _rm.extensions) {
        for (var _rei = 0; _rei < _rm.extensions.length; _rei++) {
          var _re = _rm.extensions[_rei];
          if (_re && _re.id != null && bundleExtmap[_re.id] == null) {
            bundleExtmap[_re.id] = _re.uri;
          }
        }
      }
    }
  }

  // Which transceivers have already been given a section, by IDENTITY.
  // Their internal mids are not reliable keys — see the note in the recycle
  // loop below.
  var _placedTransceivers = [];

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
      var trStopped = !tr || RtpManager.isStopped(tr) ||
                      tr.direction === 'stopped';

      // A STOPPING TRANSCEIVER STILL OWNS ITS SLOT. W3C 5.4 / JSEP: stop()
      // marks [[Stopping]], and the slot only becomes free once a
      // negotiation has RETIRED it — this very offer is that negotiation, and
      // it must still carry the section (rejected, port 0) so the peer learns
      // the transceiver is going away.
      //
      //   stop() then addTrack, then createOffer  →  2 m-lines
      //     one rejected section for the stopping transceiver,
      //     one new section for the new track
      //   after the retiring round completes    →  the slot is reusable
      //
      // Recycling on [[Stopping]] reused the slot in the same offer that was
      // supposed to retire it, so the peer never saw the rejection and the
      // two sides disagreed about what that m-line meant.
      var trRetired = !tr || RtpManager.isFullyStopped(tr);

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

      // Stopped (or missing) transceiver — try to recycle this slot,
      // but only once it is RETIRED, not merely stopping (see above).
      // JSEP §5.2.2 / RFC 8829 §5.5.3: a new transceiver of matching kind
      // MAY take over a stopped m-section's slot rather than appending a
      // fresh one, keeping the m-section count bounded across many
      // add/stop cycles.
      var recycle = null;
      if (trRetired) for (var ti2 = 0; ti2 < state.transceivers.length; ti2++) {
        var cand = state.transceivers[ti2];
        if (RtpManager.isStopped(cand)) continue;
        if (cand.kind !== em.type) continue;
        // "Already placed" is about the SECTION, not the transceiver's
        // internal mid. A transceiver is born with an internal mid of its
        // own and only means anything once ASSOCIATED — an unassociated one
        // carrying mid "1" is not occupying section 1, it is occupying
        // nothing, and it is exactly the candidate this recycle exists for.
        //
        // Keying the skip on existingMids[cand.mid] read that birth mid as a
        // placement: the transceiver was passed over here and then appended
        // its own section further down, so an offer that should have reused
        // one slot emitted two. Every add/stop cycle then grew the SDP by a
        // section that never went away.
        if (cand._associated && existingMids[cand.mid]) continue;
        if (_placedTransceivers.indexOf(cand) !== -1) continue;
        recycle = cand;
        break;
      }

      if (recycle) {
        // THE SLOT KEEPS ITS MID. An m-section's mid belongs to the SECTION,
        // not to whatever transceiver currently occupies it (RFC 5888): the
        // peer has already seen this section at this mid, and every m-line
        // after it is positioned by it.
        //
        // buildMediaForTransceiver emits the TRANSCEIVER's mid, so recycling
        // a transceiver into a stopped transceiver's slot moved its mid with
        // it — and the slot it came from was emitted again later with the
        // same value:
        //
        //   a=mid:1   ← the recycled transceiver, in slot 0
        //   a=mid:1   ← its own slot, emitted again
        //   a=mid:0
        //
        // Two sections claiming one mid is malformed, and it took the msid
        // with it (both sections then read the same localSsrcs entry), so the
        // peer rejected the whole description and negotiation failed.
        //
        // Re-key the transceiver onto the slot it is moving into, which keeps
        // its SSRC bookkeeping aligned too — the same re-key the adoption
        // path does.
        // THE POSITION IS REUSED; THE MID IS NOT.
        //
        // JSEP 5.2.2 / RFC 8829: recycling a rejected m-section reuses its
        // PLACE in the m-line ordering — which must never shift, or every
        // mid after it stops lining up with the peer's — but the section
        // gets a FRESH mid. The peer has already seen the old mid rejected;
        // reviving it would make one identifier mean two different things
        // across the session.
        //
        //   assert_not_equals(pc.getTransceivers()[0].mid, stoppedMid0)
        //
        // Keeping the slot's mid also revived the very value the rejection
        // retired, and it was what let two sections claim one mid: the
        // recycled transceiver brought the slot's mid with it while its own
        // section was emitted later with the same value.
        var _slotMid = String(RtpManager.getNextMid(state));
        while (existingMids[_slotMid]) {
          _slotMid = String(parseInt(_slotMid, 10) + 1);
        }
        var _oldMid = recycle.mid;
        if (String(_oldMid) !== _slotMid) {
          RtpManager.rebindMid(state, recycle, _slotMid);
        }
        existingMids[_slotMid] = true;
        _placedTransceivers.push(recycle);
        var rspec = buildMediaForTransceiver(state, recycle);
        rspec.mid = String(_slotMid);
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
    if (RtpManager.isStopped(t)) {
      // JSEP 5.2.2: a STOPPED transceiver that was already associated
      // with an m-section must still be OFFERED — as a REJECTED section
      // (port 0). Dropping the section outright renumbers every m-line
      // after it, so the peer's mids no longer line up with ours. The
      // section is emitted here and the transceiver is retired once the
      // negotiation completes (see cm's post-stable sweep).
      if (t._associated && t.mid != null && !existingMids[t.mid]) {
        existingMids[t.mid] = true;
        mediaSections.push({
          type: t.kind, mid: String(t.mid), port: 0,
          direction: 'inactive', rejected: true,
          codecs: [], extensions: [],
        });
      }
      continue;
    }
    // BIRTH-MID COLLISION (the last link of the bidi saga): an
    // UNASSOCIATED transceiver whose internal birth mid happens to equal
    // an m-line already placed for someone else was silently skipped —
    // the sender never got an m-line and stayed silent forever. Give it
    // a FRESH mid outside the used space and emit its section.
    if (existingMids[t.mid] && !RtpManager.isLegitimateOwner(t)) {
      var _fresh = 0;
      while (existingMids[String(_fresh)]) _fresh++;
      RtpManager.rebindMid(state, t, _fresh);
    }
    // Already given a section by the recycle pass? Its mid was rebound to
    // the slot it moved into, so the mid lookup below would find it placed —
    // but only because of that rebind. Check identity so the rule holds
    // whether or not a rebind happened.
    if (_placedTransceivers.indexOf(t) !== -1) continue;
    if (!existingMids[t.mid]) {
      existingMids[t.mid] = true;
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

  // RFC 3264 §8: bump o= session version on every generated description.
  // Counter lives on state so it survives renegotiations; starts at 2
  // (Chrome's visual convention) and increments monotonically.
  state.localSdpVersion = (state.localSdpVersion || 1) + 1;

  return SDP.createOffer({
    sessionId:       state.localSessionId,
    sessionVersion:  state.localSdpVersion,
    ice:             { ufrag: state.localIceUfrag, pwd: state.localIcePwd },
    dtls:            { fingerprint: state.localFingerprint, fingerprints: state.localFingerprints, setup: options.setup },
    media:           mediaSections,
    cname:           state.localCname,
    mode:            state.mode,
    candidates:      options.liteCandidates,
    // Lite: all candidates known at build time — always terminal.
    // Full: terminal only when the current gathering phase has actually
    // completed AND produced the roster we're embedding (JSEP §5.2.2).
    // The roster-length guard keeps a post-ICE-restart offer (stale
    // iceGatheringState 'complete', roster just reset) from claiming
    // end-of-candidates over an empty list.
    endOfCandidates: (state.mode === 'lite') ||
                     (state.iceGatheringState === 'complete' &&
                      !!(state.localGatheredCandidates &&
                         state.localGatheredCandidates.length > 0)),
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
  var hasTrack = {};
  for (var i = 0; i < state.parsedRemoteSdp.media.length; i++) {
    var m = state.parsedRemoteSdp.media[i];
    if (m.type !== 'audio' && m.type !== 'video') continue;
    // THE FOURTH SELECTOR (the bidi grab): this builder used the RAW
    // findByMid — a birth-mid collision handed the server's SEND
    // transceiver (and its localSsrcs slot!) to the browser's own
    // m-line, committing recvonly onto it and killing server-to-browser
    // video. Only legitimate owners may steer an answer m-line.
    var tr = RtpManager.findByMid(state, m.mid);
    if (tr && !RtpManager.isLegitimateOwner(tr)) tr = null;
    if (state.localSsrcs[m.mid] && tr) {
      ssrcs[m.mid] = state.localSsrcs[m.mid];
    }
    if (tr && tr.direction) {
      directions[m.mid] = tr.direction;
    }
    // Does this transceiver have something to send RIGHT NOW? See the
    // note at computeAnswerDirection: a track counts even before its
    // SSRC exists.
    if (tr && tr.sender && tr.sender.track) {
      hasTrack[m.mid] = true;
    }
  }

  // RFC 3264 §8 — same counter as buildOffer.
  state.localSdpVersion = (state.localSdpVersion || 1) + 1;

  return SDP.createAnswer(state.parsedRemoteSdp, {
    // JSEP §5.3.2: across subsequent answers "the fields of the o= line
    // MUST stay the same" except <session-version>. Without threading the
    // PC's stable session id here, sdp.js's createAnswer fell back to
    // String(Date.now()) — a FRESH sess-id on every generated answer,
    // changing the o= identity mid-session (and disagreeing with the
    // sess-id our own offers use via buildOffer).
    sessionId:       state.localSessionId,
    sessionVersion: state.localSdpVersion,
    hasTracks:       hasTrack,
    // per-mid preference lists, for the answer's codec filtering
    codecPreferences: (function () {
      var out = {};
      for (var _ci = 0; _ci < state.transceivers.length; _ci++) {
        var _t = state.transceivers[_ci];
        if (_t && _t.mid != null && _t._codecPreferences && _t._codecPreferences.length) {
          out[String(_t.mid)] = _t._codecPreferences;
        }
      }
      return out;
    })(),
    ice:             { ufrag: state.localIceUfrag, pwd: state.localIcePwd },
    dtls:            { fingerprint: state.localFingerprint, fingerprints: state.localFingerprints, setup: options.setup },
    ssrcs:           ssrcs,
    directions:      directions,
    cname:           state.localCname,
    candidates:      options.liteCandidates,
    // Same rule as buildOffer — see comment there.
    endOfCandidates: (state.mode === 'lite') ||
                     (state.iceGatheringState === 'complete' &&
                      !!(state.localGatheredCandidates &&
                         state.localGatheredCandidates.length > 0)),
    mode:            state.mode,
  });
}


/* ========================= Exports ========================= */

export {
  buildMediaForTransceiver,
  buildOffer,
  buildAnswer,
};
// src/transport_controller.js
//
// ICE / DTLS / SCTP-from-SDP plumbing.
//
// This module owns the "translation between SDP and the transport stack":
// - what local ICE creds to advertise
// - what local DTLS fingerprint to advertise
// - what remote ICE creds, fingerprint, candidates, SCTP params,
//   and RTP header-extension IDs to extract from a peer's SDP
//
// It does NOT own the runtime DTLS/ICE/SCTP machines — those live in
// connection_manager.js (turn-server's IceAgent, lemon-tls's DTLSSession,
// our SctpAssociation). This module just feeds them.
//
// The functions here all take the cm.js `state` object as their first
// parameter and mutate it in place. There is no separate state container;
// the state lives where it lived before, we just gathered the operations
// that read/write the SDP-related slice into one file.
//
// This is part of the SDP-layer refactor (see SDP_REFACTOR_PLAN.md,
// milestone 2). Subsequent milestones may further isolate the state, but
// for now the goal is a tight, safe code-move with zero behavior change.

import { sha256_sync } from 'cryptographic-primitives/sha2.js';
import { createSecureContext } from 'lemon-tls';
import { generateCertificate, certificateFingerprints } from './cert.js';
import * as SDP from './sdp.js';

// Debug logging gate (mirrors api.js / connection_manager.js). '[tc]'
// lines trace DTLS-role / setup decisions. Off by default — set
// WEBRTC_DEBUG=1 to enable.
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

// RTP header extension URIs we latch from remote SDP.
var TCC_URI          = 'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01';
var RID_URI          = 'urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id';
var REPAIRED_RID_URI = 'urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id';


/* ========================= Local creds + fingerprint ========================= */

/**
 * Ensure state has local ICE ufrag/pwd. If `forceNew` is true OR creds are
 * missing, generate fresh creds. Idempotent otherwise.
 *
 * Used by:
 *   - createOffer / createAnswer  (need local creds to put in the SDP)
 *   - restartIce()                (forceNew=true to rotate)
 *   - the setState ICE cascade    (idempotent fill on first transition)
 *
 * @param {Object} state
 * @param {boolean} [forceNew]
 */
function ensureLocalIceCreds(state, forceNew) {
  // Check both ufrag AND pwd. State corruption (e.g. partial restoration
  // from a snapshot, race during teardown) could leave one without the
  // other; the previous "ufrag-only" check would silently keep half-creds
  // alive until the next forceNew, producing SDP with a missing pwd.
  if (forceNew || !state.localIceUfrag || !state.localIcePwd) {
    var creds = SDP.generateIceCredentials();
    state.localIceUfrag = creds.ufrag;
    state.localIcePwd   = creds.pwd;
  }
}

/**
 * Ensure state has a local DTLS fingerprint derived from cert/key. If
 * neither is set, generate a new self-signed cert+key. If both are set
 * but no fingerprint, derive one. Idempotent if fingerprint already exists.
 *
 * Used by:
 *   - createOffer / createAnswer  (need fingerprint to put in the SDP)
 *
 * @param {Object} state
 */
function ensureLocalFingerprint(state) {
  if (state.localFingerprint) return;
  if (!state.cert || !state.key) {
    // The library's own certificate: ECDSA P-256, named explicitly (a
    // bare { name: 'ECDSA' } is refused, as WebCrypto refuses it).
    var generated = generateCertificate({ keygenAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' } });
    state.cert = generated.cert;
    state.key = generated.key;
    state.localFingerprint = { algorithm: 'sha-256', value: generated.fingerprint };
    _setLocalFingerprints(state, generated.fingerprints);
    return;
  }
  try {
    var sctx = createSecureContext({
      key:  typeof state.key  === 'string' ? state.key  : state.key.toString(),
      cert: typeof state.cert === 'string' ? state.cert : state.cert.toString(),
    });
    var certDer = sctx.certificateChain[0].cert;
    var fpHash = sha256_sync(certDer);
    state.localFingerprint = {
      algorithm: 'sha-256',
      value: Array.from(new Uint8Array(fpHash)).map(function(b) {
        return b.toString(16).padStart(2, '0').toUpperCase();
      }).join(':'),
    };
    // RFC 8122 §5.1: the signature's own hash too (a P-384 certificate's
    // SHA-384), when it is another.
    _setLocalFingerprints(state, certificateFingerprints(certDer));
  } catch (e) {
    // The user-supplied cert/key couldn't be loaded into a TLS context —
    // most commonly a key/cert mismatch, an encrypted PEM without the
    // passphrase, or a malformed file. Replacing silently with a self-
    // signed pair was the prior behavior; that hid the real problem from
    // the user (their PC starts but DTLS uses the wrong identity, peers
    // pin against the wrong fingerprint, etc.). Surface a warning so the
    // configuration error is visible while keeping the fallback so the
    // PC isn't stuck without a fingerprint.
    if (typeof console !== 'undefined' && console.warn) {
      console.warn('[transport_controller] could not derive fingerprint from ' +
        'supplied cert/key (' + (e && e.message || e) + '); falling back to ' +
        'a freshly-generated self-signed certificate. The supplied cert/key ' +
        'will not be used.');
    }
    var fallback = generateCertificate({ keygenAlgorithm: { name: 'ECDSA', namedCurve: 'P-256' } });
    state.cert = fallback.cert;
    state.key  = fallback.key;
    state.localFingerprint = { algorithm: 'sha-256', value: fallback.fingerprint };
    _setLocalFingerprints(state, fallback.fingerprints);
  }
}

// Every fingerprint of the one certificate (RFC 8122 §5.1), for the SDP,
// when there is more than its SHA-256 — unless the configuration's
// certificates already set the list (api.js: every certificate's
// fingerprints). The SHA-256 one first: sdp.js writes it last.
function _setLocalFingerprints(state, fps) {
  if (state.localFingerprints && state.localFingerprints.length) return;
  if (!fps || fps.length < 2) return;
  state.localFingerprints = fps.slice();
}

/**
 * What a=setup value to put in a freshly built ANSWER.
 *
 * Returns 'active' / 'passive' if our DTLS role has already been decided
 * (because we set a remote description first and learned it from the
 * peer's a=setup). Returns null if the role is not yet decided — the
 * caller echoes the peer's offer for answer-side resolution.
 *
 * A continued association keeps its roles in every answer (RFC 9429 5.3.2:
 * "Each a=setup line MUST use an active or passive role value consistent
 * with the existing DTLS association"; RFC 8842 §5.3: "a value that does
 * not change the previously negotiated DTLS roles"). An OFFER is always
 * actpass (JSEP 5.2.1 / 5.2.2, RFC 8842 §5.5), whatever the role.
 *
 * @param {Object} state
 * @returns {'active'|'passive'|null}
 */
function dtlsRoleForSdp(state) {
  if (state.dtlsRole === 'client') return 'active';
  if (state.dtlsRole === 'server') return 'passive';
  return null;
}


/* ========================= Remote-description extraction ========================= */

/**
 * Read the SDP-derived facts out of a parsed remote description into state.
 *
 * Consumes:
 *   - parsed.iceLite                  (session level)
 *   - parsed.media[*].iceUfrag/icePwd  (first non-empty wins; matches BUNDLE)
 *   - parsed.media[*].fingerprint
 *   - parsed.media[*].setup
 *   - parsed.media[*].candidates
 *   - parsed.media[*].sctpPort/maxMessageSize  (from m=application)
 *   - parsed.media[*].extensions       (TCC/RID/repaired-RID URIs)
 *
 * Mutates state:
 *   - state.remoteIceLite
 *   - state.remoteIceUfrag, state.remoteIcePwd
 *   - state.remoteFingerprint
 *   - state.dtlsRole          (only if currently null — first wins)
 *   - state.remoteCandidates  (appended)
 *   - state.remoteSctpPort, state.remoteMaxMessageSize, state.sendMaxMessageSize
 *   - state.remoteTransportCcExtId, state.remoteRidExtId,
 *     state.remoteRepairedRidExtId  (BUNDLE: same id across m-sections)
 *
 * Caller is responsible for:
 *   - parsing the SDP (state.parsedRemoteSdp = SDP.parseOffer/Answer(...))
 *   - updating state.signalingState
 *   - calling setState() to fire cascades (ICE remote params push, etc.)
 *   - feeding the candidates to the iceAgent (we collect; we don't push)
 *
 * @param {Object} state
 * @param {Object} parsed   parsedSdp from SDP.parseOffer/Answer
 */
function applyRemoteDescription(state, parsed) {
  // Session-level ice-lite flag. Forwarded to IceAgent via the cascade
  // when setState() runs.
  state.remoteIceLite = !!parsed.iceLite;

  // ── Reset SCTP-derived fields. ──
  // If the peer dropped m=application in this renegotiation (recycled
  // the slot), stale SCTP params from a prior round would otherwise
  // persist — and any later code that reads them (e.g. attempting to
  // send a DC message) would see ghost values pointing at a peer that
  // can no longer accept them. Reset to "no DC negotiated"; the m=
  // application loop below repopulates if the new SDP has one.
  state.remoteSctpPort       = null;
  state.remoteMaxMessageSize = null;
  // sendMaxMessageSize starts at our local cap (no peer cap to apply).
  // The m=application branch below tightens it to min(local, peer) once
  // the new SDP's a=max-message-size is read.
  state.sendMaxMessageSize   = state.maxMessageSize;

  // ── RTP header extension IDs. ──
  // Per BUNDLE (RFC 8843 §9.2) the same id MUST refer to the same URI
  // across all bundled m-sections. We latch the first id we see per URI
  // and warn if a subsequent m-section uses a different id for the same
  // URI — that indicates a peer-side BUNDLE violation that would lead
  // to extension-parsing corruption on whichever m-section is wrong.
  // m=application is skipped (it's not RTP, has no extmap).
  state.remoteTransportCcExtId = null;
  state.remoteRidExtId         = null;
  state.remoteRepairedRidExtId = null;
  state.remoteAudioLevelExtId  = null;
  // Every negotiated id → uri of the peer's, for a consumer that needs more
  // than the ids latched above: the FlexFEC decoder zeroes the peer's MUTABLE
  // extensions (transport-cc, abs-send-time, …) before its XOR, as the
  // peer's sender protected them while they were still zero.
  state.remoteExtensions       = {};
  var AUDIO_LEVEL_URI = 'urn:ietf:params:rtp-hdrext:ssrc-audio-level';

  function _latchExtId(uri, id, msMid) {
    if (uri === AUDIO_LEVEL_URI) {
      if (state.remoteAudioLevelExtId == null) state.remoteAudioLevelExtId = id;
      return;
    }
    if (uri === TCC_URI) {
      if (state.remoteTransportCcExtId == null) state.remoteTransportCcExtId = id;
      else if (state.remoteTransportCcExtId !== id && typeof console !== 'undefined' && console.warn) {
        console.warn('[transport_controller] BUNDLE violation: TCC ext id ' +
          state.remoteTransportCcExtId + ' (latched) vs ' + id + ' in m-section mid=' +
          msMid + '. Per RFC 8843 §9.2 the same id must refer to the same URI ' +
          'across all bundled sections. Using latched value.');
      }
    } else if (uri === RID_URI) {
      if (state.remoteRidExtId == null) state.remoteRidExtId = id;
      else if (state.remoteRidExtId !== id && typeof console !== 'undefined' && console.warn) {
        console.warn('[transport_controller] BUNDLE violation: RID ext id ' +
          state.remoteRidExtId + ' (latched) vs ' + id + ' in m-section mid=' +
          msMid + '. Using latched value.');
      }
    } else if (uri === REPAIRED_RID_URI) {
      if (state.remoteRepairedRidExtId == null) state.remoteRepairedRidExtId = id;
      else if (state.remoteRepairedRidExtId !== id && typeof console !== 'undefined' && console.warn) {
        console.warn('[transport_controller] BUNDLE violation: repaired-RID ext id ' +
          state.remoteRepairedRidExtId + ' (latched) vs ' + id + ' in m-section mid=' +
          msMid + '. Using latched value.');
      }
    }
  }
  for (var i = 0; i < parsed.media.length; i++) {
    var ms = parsed.media[i];
    if (ms.type === 'application' || !ms.extensions) continue;
    for (var ei = 0; ei < ms.extensions.length; ei++) {
      _latchExtId(ms.extensions[ei].uri, ms.extensions[ei].id, ms.mid);
      if (state.remoteExtensions[ms.extensions[ei].id] == null) {
        state.remoteExtensions[ms.extensions[ei].id] = ms.extensions[ei].uri;
      }
    }
  }

  // ── ICE creds + DTLS fingerprint + role. ──
  // From the m-section that owns the transport — see transportSection.
  var tSec = transportSection(parsed);
  // Reduced-size RTCP (RFC 5506 §5) only when the peer's description says
  // a=rtcp-rsize. RFC 8859 puts it in the IDENTICAL category: under BUNDLE
  // one value for the transport, read from the transport's section; a
  // transport section that is not RTP (m=application) has no RTCP to say
  // it for, so then the first live RTP section. Without it every RTCP
  // packet we send is compound (media_transport, RFC 3550 §6.1).
  state.remoteRtcpRsize = _rtcpRsizeOf(parsed, tSec);
  if (tSec) {
    // Detect ICE restart: peer ufrag (or pwd) changed since the last
    // applied remote description. Per RFC 8839 §5, an ICE restart is
    // signaled by changing ufrag and/or pwd. The previously-collected
    // remote candidates were authenticated against the OLD creds — STUN
    // checks against them with the new creds would fail MESSAGE-INTEGRITY.
    // Drop them; the new SDP's candidates + future trickled candidates
    // will populate cleanly. (iceAgent's own restart handling is driven
    // separately via the cascade in cm.js.)
    var iceRestart = state.remoteIceUfrag != null &&
                     (tSec.iceUfrag !== state.remoteIceUfrag ||
                      (tSec.icePwd && tSec.icePwd !== state.remoteIcePwd));
    if (iceRestart) {
      state.remoteCandidates.length = 0;
    }
    state.remoteIceUfrag = tSec.iceUfrag;
    if (tSec.icePwd)      state.remoteIcePwd      = tSec.icePwd;
    if (tSec.fingerprint) {
      state.remoteFingerprint = tSec.fingerprint;
      // Every a=fingerprint of the section (RFC 8122 §5.1): the DTLS check
      // matches the peer's certificate against the set, not the last line.
      state.remoteFingerprints = (tSec.fingerprints && tSec.fingerprints.length)
        ? tSec.fingerprints : [tSec.fingerprint];
    }
    // A NEW DTLS ASSOCIATION NEGOTIATES ITS ROLES AGAIN (RFC 8842 §5.4: the
    // offerer becomes client or server "based on the value of the SDP setup
    // attribute" of the answer that establishes it). Otherwise the first
    // description's role is kept: a continued association keeps its roles
    // (JSEP 5.3.2), and an actpass re-offer decides nothing.
    var _renewRole = !!(state.dtlsRenewPending && state.dtlsRole && tSec.setup &&
                        tSec.setup !== 'actpass');
    if (tSec.setup && (!state.dtlsRole || _renewRole)) {
      _diag('[tc] setup decision — mode:', state.mode, 'remote setup:', tSec.setup);
      // An ICE-lite peer is always the ICE-controlled agent: it never
      // initiates connectivity checks, it only responds. It must therefore
      // also be the DTLS *server* (a=setup:passive) and let the full,
      // controlling peer be the DTLS *client* (a=setup:active) that sends
      // the ClientHello. Choosing 'client'/active for a lite peer inverts
      // the roles — the lite peer would be expected to drive DTLS but, being
      // ICE-controlled, can't drive the underlying connection, so the
      // handshake deadlocks (ICE never progresses, no STUN checks flow).
      //
      // resolveSetup() echoes the offer's a=setup (actpass → active), which
      // is correct for a normal full-ICE answerer but wrong for a lite peer.
      // Force 'server' in lite mode — unless the remote said passive: it
      // is then the DTLS server itself, and RFC 4145 §4 / RFC 5763 §5 leave
      // us one answer, active. Answering passive to passive (what this did)
      // put both sides waiting for a ClientHello: no DTLS ever.
      if (state.mode === 'lite' && tSec.setup !== 'passive') {
        state.dtlsRole = 'server';
      } else {
        state.dtlsRole = SDP.resolveSetup(tSec.setup) === 'active' ? 'client' : 'server';
      }
      _diag('[tc] → dtlsRole set to:', state.dtlsRole);
    }
  }

  // ── Candidates + SCTP params. ──
  // remoteCandidates is the cumulative roster of remote candidates seen
  // through the current ICE session. The ICE-restart check above already
  // wiped it on a credential change; here we only append the new SDP's
  // candidates. (Trickled candidates arrive via addTrickleCandidate.)
  for (var k = 0; k < parsed.media.length; k++) {
    var m = parsed.media[k];
    // A rejected section's candidates belong to a transport that is gone
    // (Chrome keeps listing its old ones there) — not checked.
    var _mCands = SDP.isRejected(m) ? [] : m.candidates;
    for (var c = 0; c < _mCands.length; c++) {
      state.remoteCandidates.push(_mCands[c]);
    }
    if (m.type === 'application' && m.sctpPort) {
      state.remoteSctpPort = m.sctpPort;
    }
    // RFC 8841: peer's a=max-message-size advertises the largest message
    // they will RECEIVE. Caps OUR outgoing sends. RFC 8831 §6.6: absent
    // attribute means assume 65536. Effective send cap is the tighter of
    // local and peer.
    if (m.type === 'application') {
      // ZERO MEANS NO LIMIT (RFC 8841), which is a different statement
      // from the attribute being ABSENT (where 65536 is assumed). Both
      // collapsed to the same substituted 65536 here, so a peer that
      // explicitly said "send me anything" was capped at 64KB and our
      // reported sctp.maxMessageSize contradicted what it had asked for.
      var peerMax = (m.maxMessageSize != null) ? m.maxMessageSize : 65536;
      state.remoteMaxMessageSize = peerMax;
      state.sendMaxMessageSize   = (peerMax === 0)
        ? state.maxMessageSize
        : Math.min(state.maxMessageSize, peerMax);
    }
  }
}

// a=rtcp-rsize of the transport (see applyRemoteDescription).
function _rtcpRsizeOf(parsed, tSec) {
  if (!tSec) return false;
  if (tSec.type !== 'application') return !!tSec.rtcpRsize;
  for (var i = 0; i < parsed.media.length; i++) {
    var m = parsed.media[i];
    if (m.type === 'application' || SDP.isRejected(m)) continue;
    return !!m.rtcpRsize;
  }
  return false;
}

/**
 * Push remote candidates accumulated by applyRemoteDescription into the
 * IceAgent. Split out from applyRemoteDescription because the IceAgent
 * may not exist yet (lite mode creates it in createOffer/Answer; full
 * mode creates it on the setLocalDescription cascade).
 *
 * Idempotent — adding the same candidate twice is harmless at the
 * IceAgent level (it dedupes by foundation).
 *
 * @param {Object} state
 * @param {Object} parsed
 * @param {Object} iceAgent       null-ok; no-op if absent
 */
function pushCandidatesToIceAgent(state, parsed, iceAgent) {
  if (!iceAgent) return;
  for (var i = 0; i < parsed.media.length; i++) {
    // Rejected sections: see applyRemoteDescription.
    if (SDP.isRejected(parsed.media[i])) continue;
    var cands = parsed.media[i].candidates;
    for (var c = 0; c < cands.length; c++) {
      iceAgent.addRemoteCandidate(cands[c]);
    }
  }
  // a=end-of-candidates on the transport's section (RFC 8840 §8.2): the
  // agent's end-of-candidates (RFC 8838 §8).
  if (remoteEndOfCandidates(parsed, state.transportMid)) iceAgent.addRemoteCandidate(null);
}

/**
 * Has the peer signalled end-of-candidates for the one ICE transport?
 * The transport's section is the one with mid `transportMid` (the BUNDLE
 * tag), else the first section not rejected.
 *
 * Before, end-of-candidates stopped at the SDP (a=end-of-candidates in
 * remoteDescription): the IceAgent never heard it, so a session whose
 * candidates formed no pair could never fail (W3C 4.3.3 'failed' needs
 * "received an indication that there are no more remote candidates").
 */
function remoteEndOfCandidates(parsed, transportMid) {
  if (!parsed || !parsed.media) return false;
  var sec = null;
  for (var i = 0; i < parsed.media.length; i++) {
    var m = parsed.media[i];
    if (SDP.isRejected(m)) continue;
    if (transportMid != null) {
      if (String(m.mid) === String(transportMid)) { sec = m; break; }
    } else { sec = m; break; }
  }
  if (!sec && transportMid != null) return remoteEndOfCandidates(parsed, null);
  return !!(sec && sec.endOfCandidates);
}

/**
 * Add a single trickled remote candidate to state and (if the IceAgent
 * already exists) to the agent.
 *
 * @param {Object} state
 * @param {Object} candidate
 * @param {Object} iceAgent       null-ok
 */
function addTrickleCandidate(state, candidate, iceAgent) {
  state.remoteCandidates.push(candidate);
  if (iceAgent) {
    iceAgent.addRemoteCandidate(candidate);
  }
}


/* ========================= Transport ownership (BUNDLE tag) ========================= */

/**
 * The mid whose m-section owns the session's transport (ICE pair, DTLS
 * association, SRTP context, SCTP association) under a completed
 * negotiation: the BUNDLE-tagged m-section — the first live mid of the
 * description's first BUNDLE group (RFC 8843 §7). Without a group, the
 * first live m-section (a lone m-section is its own transport). null when
 * every m-section is rejected.
 *
 * SDP.isRejected (port 0) is safe for bundle-only sections: the parser
 * already gave a live a=bundle-only section a non-zero port.
 *
 * @param {Object} parsed  — SDP.parseOffer/parseAnswer output of the ANSWER that
 *                           completed the negotiation
 * @returns {string|null}
 */
function bundleTransportMid(parsed) {
  if (!parsed || !parsed.media) return null;
  var live = {};
  var firstLive = null;
  for (var i = 0; i < parsed.media.length; i++) {
    var m = parsed.media[i];
    if (!m || SDP.isRejected(m) || m.mid == null) continue;
    live[String(m.mid)] = true;
    if (firstLive === null) firstLive = String(m.mid);
  }
  var group = parsed.bundleGroups ? SDP.getBundleMids(parsed) : [];
  if (group.length) {
    for (var g = 0; g < group.length; g++) {
      if (live[String(group[g])]) return String(group[g]);
    }
    return null;
  }
  return firstLive;
}

/**
 * The m-section to read the session's transport parameters from — ICE
 * ufrag/pwd, DTLS fingerprint and setup. BUNDLE (RFC 8843 §9.2) makes them
 * one transport's, so one section is read: the one that owns the transport
 * (bundleTransportMid), else the first live section carrying them; only
 * when every section is rejected, any section that carries them.
 *
 * Not simply the first section that carries them: Chrome keeps a rejected
 * (port 0) m-section in every later description WITH its attributes,
 * frozen at their old values. After the first m-section was stopped and an
 * ICE restart followed, its ufrag/pwd were the pre-restart ones: we checked
 * with stale credentials, every check was refused and ICE never came back,
 * while the restart itself went undetected (seen with Chrome: a restart
 * offer carrying m=video 0 ... a=ice-ufrag:<old> next to m=audio ...
 * a=ice-ufrag:<new>).
 *
 * @param {Object} parsed — SDP.parseOffer/parseAnswer output
 * @returns {Object|null} the media section, or null
 */
function transportSection(parsed) {
  if (!parsed || !parsed.media) return null;
  var media = parsed.media;
  var owner = bundleTransportMid(parsed);
  var i;
  if (owner != null) {
    for (i = 0; i < media.length; i++) {
      if (media[i] && media[i].iceUfrag && String(media[i].mid) === owner) return media[i];
    }
  }
  for (i = 0; i < media.length; i++) {
    if (media[i] && media[i].iceUfrag && !SDP.isRejected(media[i])) return media[i];
  }
  for (i = 0; i < media.length; i++) {
    if (media[i] && media[i].iceUfrag) return media[i];
  }
  return null;
}

/**
 * Does the negotiation that just completed move the transport to another
 * m-section?
 *
 * Chrome (libwebrtc) ties a transport to the m-section that owns it. When
 * that m-section is rejected — a stopped transceiver at the BUNDLE tag —
 * the group gets a new tag and Chrome brings up a NEW transport for it:
 * new sockets, a new DTLS handshake (same certificate and roles), new SRTP
 * keys and a new SCTP association, with ICE checks on the new candidates
 * under the same credentials. The old transport is closed. Seen in
 * Chrome-to-Chrome: transport T01 → T11, the old RTCDtlsTransport
 * 'closed', a data channel kept open across it. We kept using the old DTLS
 * association, which Chrome had closed, and the connection never came back.
 *
 * Returns { from, to } when the owner changed (the caller brings up the
 * new transport), null otherwise:
 *   - first negotiation (no previous owner): nothing to move;
 *   - every m-section rejected (no new owner): nothing to move to yet. The
 *     previous owner is kept, so the first live m-section added later —
 *     necessarily a new mid (JSEP 5.2.2) — still counts as a change, as
 *     Chrome builds a new transport for it too.
 *
 * Only a final answer completes a negotiation; offers, pranswers and
 * rollbacks never reach this.
 *
 * @param {string|null} prevMid — the owner before this negotiation
 * @param {Object} answerParsed — SDP.parseAnswer output of the final answer
 * @returns {{from: string, to: string}|null}
 */
function transportOwnerChange(prevMid, answerParsed) {
  var next = bundleTransportMid(answerParsed);
  if (prevMid == null || next == null) return null;
  if (String(prevMid) === next) return null;
  return { from: String(prevMid), to: next };
}


/* ========================= DTLS association ========================= */

/**
 * Ensure state has a local a=tls-id value (RFC 8842 §4). Generated once, on
 * the first createOffer / createAnswer, and kept: an unchanged value (with
 * an unchanged fingerprint set) says the DTLS association continues, so it
 * changes only when a new association is negotiated (an answer to an offer
 * that asks for one: state.pendingLocalTlsId, sdp_offer_answer).
 */
function ensureLocalTlsId(state) {
  if (!state.localTlsId) state.localTlsId = SDP.generateTlsId();
}

// The fingerprint set of a section as one comparable key: every (hash
// function, value) pair, the function's name case-insensitive (RFC 8122 §5:
// hash-func is a token compared as such, IANA names are lower case) and the
// value case-insensitive (RFC 8122 §5: "UHEX", compared case-insensitively),
// sorted (a set: the order of the lines carries no meaning).
function _fingerprintSetKey(sec) {
  var fps = (sec.fingerprints && sec.fingerprints.length)
    ? sec.fingerprints : (sec.fingerprint ? [sec.fingerprint] : []);
  var keys = [];
  for (var i = 0; i < fps.length; i++) {
    if (!fps[i]) continue;
    var k = String(fps[i].algorithm || '').toLowerCase() + ' ' + String(fps[i].value || '').toUpperCase();
    if (keys.indexOf(k) < 0) keys.push(k);
  }
  keys.sort();
  return keys.join(',');
}

/**
 * Does a remote description ask for a NEW DTLS association, and if it does,
 * is it part of an ICE restart?
 *
 * RFC 8842 §3.1: a new DTLS association follows an offer / answer that
 * modifies, adds or removes a fingerprint value, or changes the a=tls-id
 * value. JSEP (RFC 9429) 5.11: "If the remote DTLS fingerprint has been
 * changed or the value of the a=tls-id attribute has changed, tear down the
 * DTLS connection ... If a DTLS connection needs to be torn down but the
 * answer does not indicate an ICE restart or, in the case of
 * have-remote-pranswer, new ICE credentials, an error MUST be generated";
 * 5.8.3, for a re-offer: a tls-id different from that presently in use
 * "MUST be part of an ICE restart, together with new ufrag and password
 * values". RFC 8842 §6 says why: the new association needs ICE candidates
 * not used for the old one, which only an ICE restart gives.
 *
 * `baseline` is the remote description presently in use (the current remote
 * description, or the provisional answer in have-remote-pranswer); with none
 * (the first negotiation) there is no association to change. A tls-id is
 * compared only when both carry one: a peer that does not use the attribute
 * (RFC 8842 §4: "If an offer or answer does not contain a tls-id") is judged
 * by its fingerprint set alone.
 *
 * THE DTLS SETUP ROLE. `ourRole` is our role in the association ('client'
 * | 'server', null before one is negotiated); the description's a=setup
 * (active / passive; actpass and holdconn name no role) says which role it
 * leaves us. When that differs:
 *   - both descriptions carry the same tls-id and the fingerprint set is
 *     unchanged: the association is continued (RFC 8842 §4: "An unchanged
 *     local tls-id attribute value, in combination with non-changed
 *     fingerprints, indicates that the endpoint intends to reuse the
 *     existing DTLS association"), and JSEP 5.8.3 wants the setup value
 *     "consistent with the selected role of the current DTLS connection,
 *     if one exists and is being continued" — {roleConflict: true}, an
 *     error;
 *   - otherwise (the description carries no tls-id): RFC 8842 §4, "If an
 *     offer or answer does not contain a tls-id attribute ..., a
 *     modification of ... DTLS setup role ... MUST be treated as an
 *     indication that an endpoint wants to establish a new DTLS
 *     association" — a new association, as a fingerprint change is.
 *
 * @param {Object|null} baseline — parsed remote description presently in use
 * @param {Object} parsed — the parsed remote description being applied
 * @param {string|null} [ourRole] — state.dtlsRole
 * @returns {{iceRestart: boolean}|{roleConflict: true}|null} null when the
 *          association continues
 */
function dtlsAssociationChange(baseline, parsed, ourRole) {
  var old = transportSection(baseline);
  var neu = transportSection(parsed);
  if (!old || !neu) return null;
  var fpChanged = _fingerprintSetKey(old) !== _fingerprintSetKey(neu);
  var tlsChanged = !!(old.tlsId && neu.tlsId && old.tlsId !== neu.tlsId);
  // The role the description's a=setup leaves us (RFC 4145 §4).
  var leaves = neu.setup === 'active' ? 'server' : (neu.setup === 'passive' ? 'client' : null);
  var roleChanged = !!(ourRole && leaves && leaves !== ourRole);
  if (!fpChanged && !tlsChanged) {
    if (!roleChanged) return null;
    if (old.tlsId && neu.tlsId) return { roleConflict: true };
  }
  // An ICE restart changes both the ufrag and the password (RFC 8839
  // §4.4.1.1.1; JSEP 5.8.3 "together with new ufrag and password values").
  var iceRestart = !!(neu.iceUfrag && neu.icePwd &&
                      neu.iceUfrag !== old.iceUfrag && neu.icePwd !== old.icePwd);
  return { iceRestart: iceRestart };
}


/* ========================= Exports ========================= */

export {
  // Local creds + fingerprint
  ensureLocalIceCreds,
  ensureLocalFingerprint,
  ensureLocalTlsId,
  dtlsAssociationChange,
  dtlsRoleForSdp,

  // Remote-description extraction
  applyRemoteDescription,
  pushCandidatesToIceAgent,
  addTrickleCandidate,
  remoteEndOfCandidates,

  // Transport ownership
  bundleTransportMid,
  transportOwnerChange,
  transportSection,
};
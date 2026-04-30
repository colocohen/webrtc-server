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

import crypto from 'node:crypto';
import { createSecureContext } from 'lemon-tls';
import { generateCertificate } from './cert.js';
import * as SDP from './sdp.js';


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
    var generated = generateCertificate();
    state.cert = generated.cert;
    state.key = generated.key;
    state.localFingerprint = { algorithm: 'sha-256', value: generated.fingerprint };
    return;
  }
  try {
    var sctx = createSecureContext({
      key:  typeof state.key  === 'string' ? state.key  : state.key.toString(),
      cert: typeof state.cert === 'string' ? state.cert : state.cert.toString(),
    });
    var certDer = sctx.certificateChain[0].cert;
    var fpHash = crypto.createHash('sha256').update(certDer).digest();
    state.localFingerprint = {
      algorithm: 'sha-256',
      value: Array.from(new Uint8Array(fpHash)).map(function(b) {
        return b.toString(16).padStart(2, '0').toUpperCase();
      }).join(':'),
    };
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
    var fallback = generateCertificate();
    state.cert = fallback.cert;
    state.key  = fallback.key;
    state.localFingerprint = { algorithm: 'sha-256', value: fallback.fingerprint };
  }
}

/**
 * What a=setup value to put in a freshly built SDP.
 *
 * Returns 'active' / 'passive' if our DTLS role has already been decided
 * (because we set a remote description first and learned it from the
 * peer's a=setup). Returns null if the role is not yet decided — the
 * caller falls back to 'actpass' for the offerer-side neutral stance,
 * or echoes the peer's offer for answer-side resolution.
 *
 * Once DTLS is established we MUST keep the same role forever (RFC 8842).
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
  function _latchExtId(uri, id, msMid) {
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
    }
  }

  // ── ICE creds + DTLS fingerprint + role. ──
  // BUNDLE (RFC 8843 §9.2) means ICE creds, fingerprint, and setup are
  // identical across all bundled m-sections — so reading from the first
  // section that *has* them is sufficient. Critically: media[0] may be a
  // rejected (port=0) or recycled section that didn't carry these
  // attributes. Scan until we find a section with iceUfrag — the
  // canonical signal that this section participates in transport — and
  // read the rest from there.
  var firstWithCreds = null;
  for (var fmi = 0; fmi < parsed.media.length; fmi++) {
    if (parsed.media[fmi].iceUfrag) { firstWithCreds = parsed.media[fmi]; break; }
  }
  if (firstWithCreds) {
    // Detect ICE restart: peer ufrag (or pwd) changed since the last
    // applied remote description. Per RFC 8839 §5, an ICE restart is
    // signaled by changing ufrag and/or pwd. The previously-collected
    // remote candidates were authenticated against the OLD creds — STUN
    // checks against them with the new creds would fail MESSAGE-INTEGRITY.
    // Drop them; the new SDP's candidates + future trickled candidates
    // will populate cleanly. (iceAgent's own restart handling is driven
    // separately via the cascade in cm.js.)
    var iceRestart = state.remoteIceUfrag != null &&
                     (firstWithCreds.iceUfrag !== state.remoteIceUfrag ||
                      (firstWithCreds.icePwd && firstWithCreds.icePwd !== state.remoteIcePwd));
    if (iceRestart) {
      state.remoteCandidates.length = 0;
    }
    state.remoteIceUfrag = firstWithCreds.iceUfrag;
    if (firstWithCreds.icePwd)      state.remoteIcePwd      = firstWithCreds.icePwd;
    if (firstWithCreds.fingerprint) state.remoteFingerprint = firstWithCreds.fingerprint;
    if (firstWithCreds.setup && !state.dtlsRole) {
      state.dtlsRole = SDP.resolveSetup(firstWithCreds.setup) === 'active' ? 'client' : 'server';
    }
  }

  // ── Candidates + SCTP params. ──
  // remoteCandidates is the cumulative roster of remote candidates seen
  // through the current ICE session. The ICE-restart check above already
  // wiped it on a credential change; here we only append the new SDP's
  // candidates. (Trickled candidates arrive via addTrickleCandidate.)
  for (var k = 0; k < parsed.media.length; k++) {
    var m = parsed.media[k];
    for (var c = 0; c < m.candidates.length; c++) {
      state.remoteCandidates.push(m.candidates[c]);
    }
    if (m.type === 'application' && m.sctpPort) {
      state.remoteSctpPort = m.sctpPort;
    }
    // RFC 8841: peer's a=max-message-size advertises the largest message
    // they will RECEIVE. Caps OUR outgoing sends. RFC 8831 §6.6: absent
    // attribute means assume 65536. Effective send cap is the tighter of
    // local and peer.
    if (m.type === 'application') {
      var peerMax = m.maxMessageSize != null ? m.maxMessageSize : 65536;
      state.remoteMaxMessageSize = peerMax;
      state.sendMaxMessageSize   = Math.min(state.maxMessageSize, peerMax);
    }
  }
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
    var cands = parsed.media[i].candidates;
    for (var c = 0; c < cands.length; c++) {
      iceAgent.addRemoteCandidate(cands[c]);
    }
  }
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


/* ========================= Exports ========================= */

export {
  // Local creds + fingerprint
  ensureLocalIceCreds,
  ensureLocalFingerprint,
  dtlsRoleForSdp,

  // Remote-description extraction
  applyRemoteDescription,
  pushCandidatesToIceAgent,
  addTrickleCandidate,
};

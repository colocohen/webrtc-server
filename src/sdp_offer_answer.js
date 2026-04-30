// src/sdp_offer_answer.js
//
// SdpOfferAnswer — the W3C signaling control plane.
//
// Owns the offer/answer state machine: signalingState, current/pending
// local & remote descriptions, the operations chain, and the
// negotiation-needed flag. Mirrors libwebrtc's SdpOfferAnswerHandler.
//
// Architecture (libwebrtc-inspired, EventEmitter-based à la SctpAssociation):
//
//   ConnectionManager (composition root, "PeerConnection")
//     ├─ SdpOfferAnswer  (this class — signaling)
//     ├─ SctpAssociation (DataChannel transport, runtime)
//     ├─ IceAgent        (ICE runtime)
//     ├─ DTLSSession     (DTLS runtime)
//     └─ data plane: handleIncomingRtp / Rtcp / etc.
//
// Style: callbacks + events, no Promises. Promises live ONLY in api.js,
// where the W3C surface mandates them. This matches SctpAssociation and
// the rest of the internal stack.
//
// The class owns its private state (signaling-specific). Things shared
// with the data plane (transceivers, localSsrcs, dataChannels,
// remoteSsrcMap) stay on cm.js's state object and the class accesses
// them via the `sharedState` reference passed in its constructor.
//
// Communication out:
//   - Method completion: cb(err, result) callbacks.
//   - State changes / async notifications: events
//     ('signalingstatechange', 'negotiationneeded',
//      'localDescriptionApplied', 'remoteDescriptionApplied',
//      'iceRestart', 'chainDrained').
//
// Communication in:
//   - cm.js calls our methods.
//   - cm.js can read public getters (signalingState, etc.).
//   - Constructor takes refs (getClosed, sharedState).
//
// Part of the SDP-layer refactor; see SDP_REFACTOR_PLAN.md.

import { EventEmitter } from 'node:events';
import * as RtpManager from './rtp_transmission_manager.js';
import * as MediaSessionFactory from './media_session_factory.js';
import * as SDP from './sdp.js';
import * as TransportController from './transport_controller.js';


class SdpOfferAnswer extends EventEmitter {
  /**
   * @param {Object} deps
   * @param {Object} deps.sharedState  cm.js's state object (for access to
   *   transceivers, localSsrcs, dataChannels, etc. that the data plane
   *   also reads).
   * @param {Function} deps.getClosed  () => boolean. True if the PC has
   *   been closed.
   */
  constructor(deps) {
    super();

    if (!deps || typeof deps.getClosed !== 'function') {
      throw new TypeError('SdpOfferAnswer: deps.getClosed required');
    }

    this._deps = deps;
    this._sharedState = deps.sharedState || null;

    /* ──────────── Signaling state ──────────── */
    // The W3C §4.3 PeerConnection signaling slots — currentLocal/Remote,
    // pendingLocal/Remote, parsed forms, the most-recent offer/answer for
    // the operations chain.
    //
    // Architectural note: signalingState, currentLocal/Remote, pendingLocal/
    // Remote, parsedLocalSdp, parsedCurrentLocalSdp, parsedRemoteSdp all
    // live in sharedState (passed in via deps.sharedState). cm.js reactive
    // cascades observe signalingState changes there, and api.js reads
    // descriptions via manager.state.* directly. _commitDescription writes
    // them; getters below read them. lastOffer / lastAnswer / negotiation
    // bookkeeping are class-private since no other layer needs to observe
    // their transitions.
    this._lastOffer = null;
    this._lastAnswer = null;
    this._negotiationNeeded = false;
    this._needsIceRestart = false;

    // Pre-commit snapshot (W3C §4.4.1.5/6 rollback). _commitDescription
    // takes a shallow snapshot of state slots that rollback might restore;
    // rollback() restores from it and clears it. null when there's no
    // pending uncommitted state to roll back to.
    this._preCommitSnapshot = null;

    /* ──────────── Operations chain (W3C §4.3.3) ──────────── */
    this._operations = [];
    // True when an in-chain mutation found checkIfNegotiationIsNeeded
    // would have wanted to fire but the chain was non-empty. Re-evaluation
    // runs on chain drain via the 'chainDrained' event.
    this._updateNegOnEmpty = false;
  }


  /* ====================== Operations chain ====================== */
  //
  // chainOperation(op, done) queues op to run when it reaches the head
  // of the chain. op is called with `next(err, result)`; the chain
  // advances after op invokes next.
  //
  // op may also throw synchronously — the chain will catch it and treat
  // it like next(err). op may NOT both throw AND call next; doing both
  // is a programming error (the second invocation is ignored).
  //
  // The chain is FIFO and per-PC.

  /**
   * Append an operation to the chain.
   *
   * @param {Function} op       fn(next): receives a node-style cb
   *                            next(err, result). May call sync or async.
   * @param {Function} [done]   cb(err, result) — invoked after op's
   *                            next() fires, before next op runs. Optional.
   */
  chainOperation(op, done) {
    var entry = { op: op, done: done || noop };
    this._operations.push(entry);
    if (this._operations.length === 1) {
      this._runHead();
    }
  }

  /**
   * Reject any pending operations — used by ConnectionManager.close()
   * to surface InvalidStateError on each. The currently-running op
   * (head) checks getClosed() inside the runner and reports the same
   * error to its done callback.
   */
  rejectPendingOperations() {
    var queued = this._operations;
    for (var i = 0; i < queued.length; i++) {
      var err = new Error('peer connection is closed');
      err.name = 'InvalidStateError';
      try { queued[i].done(err); } catch (e) { /* swallow */ }
    }
    queued.length = 0;
  }

  /**
   * True if the chain has any operation queued or running. Used by
   * updateNegotiationNeededFlag (W3C §4.7.3 step 2): a non-empty chain
   * defers the flag check until drain.
   *
   * @returns {boolean}
   */
  isChainBusy() {
    return this._operations.length > 0;
  }

  /**
   * Mark that updateNegotiationNeededFlag wanted to fire while the chain
   * was busy. We'll fire 'chainDrained' when the chain empties so cm.js
   * can re-run the algorithm.
   */
  scheduleNegotiationNeededOnEmpty() {
    this._updateNegOnEmpty = true;
  }

  /**
   * Internal: run the head of the queue. Calls op(next); when op
   * invokes next(err, result), forwards to the entry's done callback,
   * then schedules advance to next op asynchronously so observers see
   * the result before the next op begins.
   *
   * Guards against:
   *   - PC closed at run time (rejects with InvalidStateError before op).
   *   - op throwing synchronously (caught and forwarded as err).
   *   - op invoking next twice (second call ignored via `settled` flag).
   */
  _runHead() {
    var entry = this._operations[0];
    if (!entry) return;

    if (this._deps.getClosed()) {
      var err = new Error('peer connection is closed');
      err.name = 'InvalidStateError';
      try { entry.done(err); } catch (e) { /* swallow user-cb errors */ }
      this._scheduleAdvance();
      return;
    }

    var self = this;
    var settled = false;
    var safeNext = function (err, result) {
      if (settled) return;     // double-invoke protection
      settled = true;
      try {
        if (err) entry.done(err);
        else     entry.done(null, result);
      } catch (e) {
        // User's done() callback threw. Don't let it stop the chain;
        // surface for visibility but keep going.
        // eslint-disable-next-line no-console
        console.error('SdpOfferAnswer: done() callback threw:', e);
      }
      self._scheduleAdvance();
    };

    try {
      entry.op(safeNext);
    } catch (e) {
      // Synchronous throw inside op → treat as next(err).
      safeNext(e);
    }
  }

  /**
   * Schedule the chain to advance one position, asynchronously. The
   * async hop guarantees observers of the just-settled op run before
   * the next op begins (spec step 7.4).
   */
  _scheduleAdvance() {
    var self = this;
    setTimeout(function () { self._advanceChain(); }, 0);
  }

  /**
   * Internal: pop the head and run the next op. If the chain drains
   * and a deferred negotiation-needed evaluation is pending, re-run it.
   */
  _advanceChain() {
    if (this._deps.getClosed()) return;
    this._operations.shift();
    if (this._operations.length > 0) {
      this._runHead();
      return;
    }
    // Chain drained.
    if (this._updateNegOnEmpty) {
      this._updateNegOnEmpty = false;
      // Re-run the deferred negotiation-needed evaluation. Also emit
      // 'chainDrained' for consumers that want to react (cm.js used to
      // listen here; kept for back-compat through the migration).
      this.updateNegotiationNeededFlag();
      this.emit('chainDrained');
    }
  }


  /* ====================== Negotiation-needed flag (W3C §4.7.3) ====================== */
  //
  // Three entry paths:
  //   (a) cm.js / api.js mutations call updateNegotiationNeededFlag()
  //       directly after committing a mutation (addTrack, addTransceiver,
  //       direction change, createDataChannel, transceiver.stop, …).
  //   (b) The chain drain path inside _advanceChain re-runs the algorithm
  //       when an earlier mutation tripped scheduleNegotiationNeededOnEmpty.
  //   (c) cm.js's signalingstatechange listener calls us when the round
  //       returns to 'stable' — covering deferrals from a non-stable round.
  //
  // The check has two parts:
  //   - RtpManager.checkIfNegotiationIsNeeded — transceivers + DataChannels.
  //   - this._needsIceRestart — set by setNeedsIceRestart() / restartIce.

  /**
   * Run the W3C §4.7.3 "update the negotiation-needed flag" algorithm.
   * Idempotent and dedupe-friendly: multiple calls only fire one
   * 'negotiationneeded' event (per round of being 'true').
   */
  updateNegotiationNeededFlag() {
    // 1. closed → abort.
    if (this._deps.getClosed()) return;

    // 2. Operations chain non-empty → defer; we'll re-run on drain.
    if (this.isChainBusy()) {
      this.scheduleNegotiationNeededOnEmpty();
      return;
    }

    // 3. signalingState != stable → abort. cm.js's signalingstatechange
    //    listener will call us again when we return to stable.
    var sigState = this._sharedState.signalingState;
    if (sigState !== 'stable') return;

    // 4. checkIfNeeded === false → clear flag, abort.
    var needed = RtpManager.checkIfNegotiationIsNeeded(this._sharedState) ||
                 this._needsIceRestart;
    if (!needed) {
      this._negotiationNeeded = false;
      return;
    }

    // 5. flag already true → dedupe.
    if (this._negotiationNeeded) return;

    // 6. Set flag and queue task to fire event.
    this._negotiationNeeded = true;
    var self = this;
    queueMicrotask(function () {
      if (self._deps.getClosed()) return;
      // Could have been cleared between scheduling and execution.
      if (!self._negotiationNeeded) return;
      self.emit('negotiationneeded');
    });
  }

  /**
   * Mark that the next createOffer must do ICE restart. Set by restartIce()
   * or createOffer({iceRestart:true}). Cleared by createOffer once the
   * restart is consumed.
   */
  setNeedsIceRestart() {
    this._needsIceRestart = true;
  }

  /**
   * Clear the ICE-restart pending flag. Called by createOffer once the
   * restart has been folded into the new offer.
   */
  clearNeedsIceRestart() {
    this._needsIceRestart = false;
  }


  /* ====================== Signaling methods ====================== */

  /**
   * Build a new offer SDP. Equivalent to W3C RTCPeerConnection.createOffer
   * (the chained, public version is api.js's wrapper that returns a Promise).
   *
   * Two-stage flow:
   *   1. Runtime prelude (cm.js owns): ensure local creds + fingerprint,
   *      bring up iceAgent in lite mode, fold pending ICE restart.
   *      Delegated via deps.prepareForCreateOffer(iceRestart, cb).
   *   2. SDP build (pure): MediaSessionFactory.buildOffer with the prep
   *      context (DTLS setup, lite candidates).
   *
   * @param {Object} options          { iceRestart?: boolean }
   * @param {Function} cb             cb(err, desc)  desc = {type:'offer', sdp:string}
   */
  createOffer(options, cb) {
    var self = this;
    if (this._deps.getClosed()) {
      var closedErr = new Error('peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return cb(closedErr);
    }

    // ICE restart (W3C §4.4.1.6): triggered either by an earlier
    // restartIce() (this._needsIceRestart) or explicitly via
    // options.iceRestart=true. Consumed by clearNeedsIceRestart() once
    // the prelude has woven it into the new ufrag/pwd + iceAgent.restart().
    var iceRestart = !!(this._needsIceRestart ||
                        (options && options.iceRestart));

    this._deps.prepareForCreateOffer(iceRestart, function (err, prepCtx) {
      if (err) return cb(err);
      if (iceRestart) self.clearNeedsIceRestart();

      // Build the SDP.
      var sdp;
      try {
        sdp = MediaSessionFactory.buildOffer(self._sharedState, {
          setup:          prepCtx.setup,
          liteCandidates: prepCtx.liteCandidates,
        });
      } catch (e) {
        return cb(e);
      }

      var desc = { type: 'offer', sdp: sdp };
      self._lastOffer = desc;
      cb(null, desc);
    });
  }

  /**
   * Build an answer SDP for the currently-set remote offer. Equivalent
   * to W3C RTCPeerConnection.createAnswer.
   *
   * Same two-stage flow as createOffer:
   *   1. Runtime prelude (cm.js owns) via deps.prepareForCreateAnswer(cb).
   *      Returns {setup, liteCandidates}. cm.js picks `setup` based on
   *      pinned dtlsRole vs the remote's a=setup (RFC 5763 negotiation).
   *   2. SDP build (pure): MediaSessionFactory.buildAnswer.
   *
   * Fails with InvalidStateError if no remote description is set
   * (setRemoteDescription({type:'offer'}) must precede this).
   *
   * @param {Object} options    reserved; currently unused, kept for shape
   *                            parity with createOffer.
   * @param {Function} cb       cb(err, desc) — desc = {type:'answer', sdp:string}
   */
  createAnswer(options, cb) {
    var self = this;
    if (this._deps.getClosed()) {
      var closedErr = new Error('peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return cb(closedErr);
    }
    if (!this._sharedState.parsedRemoteSdp) {
      var noRemoteErr = new Error('No remote offer');
      noRemoteErr.name = 'InvalidStateError';
      return cb(noRemoteErr);
    }

    this._deps.prepareForCreateAnswer(function (err, prepCtx) {
      if (err) return cb(err);

      var sdp;
      try {
        sdp = MediaSessionFactory.buildAnswer(self._sharedState, {
          setup:          prepCtx.setup,
          liteCandidates: prepCtx.liteCandidates,
        });
      } catch (e) {
        return cb(e);
      }

      var desc = { type: 'answer', sdp: sdp };
      self._lastAnswer = desc;
      cb(null, desc);
    });
  }

  /**
   * Apply a local description (offer or answer). Equivalent to W3C
   * RTCPeerConnection.setLocalDescription.
   *
   * Two forms:
   *   - Explicit: caller passes {type, sdp}; we apply.
   *   - Implicit: caller passes nothing (or {} without type); we
   *     generate via createOffer or createAnswer based on signalingState,
   *     then apply.
   *
   * Side effects on success:
   *   - signalingState transition (offer → have-local-offer; answer → stable).
   *   - parsedLocalSdp updated.
   *   - pendingLocalDescription / currentLocalDescription bookkeeping.
   *   - Stamper extmap synced (deps.syncStamperExtMap).
   *   - For answers: applyDirectionsFromAnswer commits CurrentDirection.
   *
   * @param {Object|null} desc   {type, sdp} or null/undefined for implicit
   * @param {Function} cb        cb(err) — no result on success
   */
  setLocalDescription(desc, cb) {
    var self = this;
    if (this._deps.getClosed()) {
      var closedErr = new Error('peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return cb(closedErr);
    }

    // W3C §4.4.1.5 — implicit form: when no description (or no .type) is
    // provided, generate one based on the current signalingState.
    //   stable | have-local-offer        → createOffer (re-offer)
    //   have-remote-offer | -pranswer    → createAnswer
    //   anything else                    → InvalidStateError
    if (!desc || desc.type === undefined) {
      var sigState = this._sharedState.signalingState;
      if (sigState === 'stable' || sigState === 'have-local-offer') {
        this.createOffer({}, function (err, generated) {
          if (err) return cb(err);
          self._applySetLocal(generated, cb);
        });
        return;
      } else if (sigState === 'have-remote-offer' ||
                 sigState === 'have-remote-pranswer') {
        this.createAnswer({}, function (err, generated) {
          if (err) return cb(err);
          self._applySetLocal(generated, cb);
        });
        return;
      } else {
        var stateErrImpl = new Error('Cannot implicit-setLocal in state: ' + sigState);
        stateErrImpl.name = 'InvalidStateError';
        return cb(stateErrImpl);
      }
    }

    this._applySetLocal(desc, cb);
  }

  /**
   * Apply a fully-formed local description. Internal helper shared by
   * the explicit and implicit paths in setLocalDescription.
   *
   * Atomicity: takes a pre-mutation snapshot. If any step in the apply
   * sequence (_commitDescription's slot updates, applyStateUpdates,
   * syncStamperExtMap, applyDirectionsFromAnswer) throws, restores the
   * snapshot so subsequent rollback() / retry sees a consistent state.
   * Without this, a partial commit (descriptions updated, signalingState
   * not transitioned) would strand the state machine — rollback() checks
   * `state.signalingState === requiredState` and would fail on the
   * stranded state, with no way out short of close().
   */
  _applySetLocal(desc, cb) {
    if (!desc.sdp) {
      // W3C §4.4.1.5 step 4.2 — empty/missing SDP after explicit type.
      return cb(new TypeError('Invalid description: missing sdp'));
    }

    var state = this._sharedState;
    var atomicSnap = this._takeSnapshot();

    try {
      var commit = this._commitDescription(desc, 'local');

      this._deps.applyStateUpdates({ signalingState: commit.nextState });

      // Sync the outgoing-RTP extension stamper. The extension IDs we put
      // on outgoing packets are determined by our local description (offer
      // or answer). For an answer specifically this matters — RFC 5285 §6
      // recommends matching the offerer's IDs, which can differ from our
      // hardcoded defaults. Without this sync our outgoing RTP stamps
      // extensions with IDs the peer won't recognize.
      this._deps.syncStamperExtMap(commit.parsed);

      if (desc.type === 'answer') {
        // W3C §4.4.1.6 step 11.1.7.4 — commit the negotiated direction onto
        // each associated transceiver's [[CurrentDirection]] slot. This is
        // OUR answer, so directions are already in our perspective.
        RtpManager.applyDirectionsFromAnswer(state, commit.parsed, true);
      }

      // ICE gathering is triggered reactively by the applyStateUpdates
      // cascade (cm.js detects signalingState change + localIceUfrag exists
      // → creates agent + gathers).
      cb(null);
    } catch (e) {
      this._restoreAtomicSnapshot(atomicSnap);
      cb(e);
    }
  }

  /**
   * Apply a remote description. Companion to _applySetLocal — invoked from
   * setRemoteDescription. The shared validation + slot-updates live in
   * _commitDescription; this method owns the remote-side cascade order:
   * transport extraction first, then state-cascade, then directions, then
   * candidate forwarding, then media processing.
   */
  _applySetRemote(desc, cb) {
    if (!desc.sdp) {
      this._deps.diag('[cm-diag] setRemoteDescription REJECTED — desc=' +
        (desc ? 'truthy type=' + desc.type + ' sdp=' +
          (desc.sdp ? ('len=' + desc.sdp.length) : 'MISSING/null') : 'null'));
      return cb(new TypeError('Invalid description: missing sdp'));
    }

    var state = this._sharedState;
    var atomicSnap = this._takeSnapshot();

    try {
      this._deps.diag('[cm-diag] ── REMOTE SDP (' + desc.type + ') ──');
      this._deps.diag(desc.sdp);
      this._deps.diag('[cm-diag] ── end remote SDP ──');

      var commit = this._commitDescription(desc, 'remote');

      // Extract ICE creds, fingerprint, candidates, SCTP params, and RTP
      // header extension IDs from the parsed SDP into state.
      TransportController.applyRemoteDescription(state, commit.parsed);
      if (state.remoteTransportCcExtId != null) {
        this._deps.diag('[cm-diag] transport-cc extension id (remote): ' +
          state.remoteTransportCcExtId);
      }
      if (state.remoteRidExtId != null) {
        this._deps.diag('[cm-diag] rid extension id (remote): ' + state.remoteRidExtId +
          (state.remoteRepairedRidExtId != null
            ? ' (repaired=' + state.remoteRepairedRidExtId + ')' : ''));
      }

      var firstMedia = commit.parsed.media[0];
      if (firstMedia) {
        this._deps.diag('[cm-diag] setRemoteDescription type=' + desc.type +
          ' firstMedia.type=' + firstMedia.type +
          ' firstMedia.setup=' + firstMedia.setup +
          ' current dtlsRole=' + state.dtlsRole);
      }

      // applyStateUpdates triggers cascades: ICE remote creds, DTLS role, etc.
      this._deps.applyStateUpdates({
        signalingState:  commit.nextState,
        parsedRemoteSdp: commit.parsed,
      });

      if (desc.type === 'answer') {
        // W3C §4.4.1.6 step 11.1.7.4 — commit the negotiated direction onto
        // each associated transceiver's [[CurrentDirection]] slot, but ONLY
        // for answer/pranswer applications (offers don't yet finalize
        // direction). This is the REMOTE peer's answer, so their m-section
        // direction is in their perspective — applyDirectionsFromAnswer
        // flips via REVERSE_DIRECTION.
        //
        // Runs after applyStateUpdates so signalingState is 'stable' and
        // downstream consumers (processRemoteMedia below, future getStats
        // readers) observe a consistent post-negotiation state.
        RtpManager.applyDirectionsFromAnswer(state, commit.parsed, false);
      }

      // Feed remote candidates to ICE agent (if it exists already).
      TransportController.pushCandidatesToIceAgent(state, commit.parsed,
        this._deps.getIceAgent());

      // Process remote media tracks.
      this._deps.processRemoteMedia(commit.parsed);

      cb(null);
    } catch (e) {
      this._restoreAtomicSnapshot(atomicSnap);
      cb(e);
    }
  }

  /**
   * Validate the signalingState transition implied by applying `desc` from
   * `source`, then commit the description-slot updates (pending/current
   * shuffle per W3C §4.4.1). Returns metadata for the caller's cascade:
   *   - parsed     : the parsed SDP (for downstream consumers).
   *   - nextState  : the post-application signalingState; the caller passes
   *                  this to applyStateUpdates at the right point in its
   *                  cascade ordering.
   *
   * Throws InvalidStateError on illegal transitions.
   *
   * The state-machine table this enforces (W3C §4.3.2):
   *   source=local,  type=offer  : stable          → have-local-offer
   *   source=local,  type=answer : have-remote-offer → stable
   *   source=remote, type=offer  : stable          → have-remote-offer
   *   source=remote, type=answer : have-local-offer  → stable
   * pranswer types are intentionally not supported (matches existing
   * behaviour pre-refactor; would require additional cases here).
   *
   * Side effects on success:
   *   - description fields rewired (pending vs current; the answer path
   *     promotes the matching peer's pending → current too).
   *   - state.parsedLocalSdp updated when source='local'.
   *   - state.parsedRemoteSdp left to the caller — the remote path passes
   *     it through applyStateUpdates so the cascade sees a single atomic
   *     update.
   */
  _commitDescription(desc, source) {
    var state = this._sharedState;
    var isLocal = source === 'local';

    var parsed = desc.type === 'offer'
      ? SDP.parseOffer(desc.sdp)
      : SDP.parseAnswer(desc.sdp);

    // ── 1. Validate transition. ──
    var requiredState, nextState;
    if (desc.type === 'offer') {
      requiredState = 'stable';
      nextState = isLocal ? 'have-local-offer' : 'have-remote-offer';
    } else {
      requiredState = isLocal ? 'have-remote-offer' : 'have-local-offer';
      nextState = 'stable';
    }
    if (state.signalingState !== requiredState) {
      var err = new Error('Cannot set ' + source + ' ' + desc.type +
        ' in state: ' + state.signalingState);
      err.name = 'InvalidStateError';
      throw err;
    }

    // ── 1b. Snapshot for rollback (W3C §4.4.1.5/6). Taken AFTER validation
    // (so a failed transition doesn't strand a stale snapshot) but BEFORE
    // any state mutation. rollback() restores from this; clears it after.
    //
    // Snapshot only on offer commits — answers transition the chain from
    // have-X-offer → stable, after which rollback isn't applicable per spec
    // (rollback is only valid in have-local-offer or have-remote-offer).
    if (desc.type === 'offer') {
      this._preCommitSnapshot = this._takeSnapshot();
    } else {
      // An answer was just committed — we're in 'stable' on the other side
      // of the negotiation. Any prior offer-side snapshot is no longer
      // restorable (its semantic anchor is gone). Discard.
      this._preCommitSnapshot = null;
    }

    // ── 2. Update description slots. ──
    if (desc.type === 'offer') {
      if (isLocal) state.pendingLocalDescription = desc;
      else         state.pendingRemoteDescription = desc;
    } else {
      // Answer: the matching peer's pending also promotes to current.
      // Maintain parsedCurrentLocalSdp / parsedCurrentRemoteSdp alongside
      // currentLocalDescription / currentRemoteDescription:
      //   - local answer:  our answer IS the new current local → cache
      //     `parsed`. The peer's pending offer becomes current remote →
      //     cache the parsed offer view (state.parsedRemoteSdp).
      //   - remote answer: peer's answer IS the new current remote →
      //     cache `parsed`. Our pending offer becomes current local →
      //     cache the parsed offer view (state.parsedLocalSdp).
      // Symmetric maintenance of parsedCurrent{Local,Remote}Sdp lets
      // api.js's getParameters read them directly instead of re-parsing
      // current{Local,Remote}Description.sdp on every call.
      if (isLocal) {
        state.currentLocalDescription  = desc;
        state.currentRemoteDescription = state.pendingRemoteDescription;
        state.parsedCurrentLocalSdp    = parsed;
        state.parsedCurrentRemoteSdp   = state.parsedRemoteSdp;
      } else {
        state.currentRemoteDescription = desc;
        state.currentLocalDescription  = state.pendingLocalDescription;
        state.parsedCurrentLocalSdp    = state.parsedLocalSdp;
        state.parsedCurrentRemoteSdp   = parsed;
      }
      state.pendingLocalDescription  = null;
      state.pendingRemoteDescription = null;
    }

    // ── 3. Cache parsed view (local side; remote is passed through cascade). ──
    if (isLocal) {
      state.parsedLocalSdp = parsed;
    }

    return { parsed: parsed, nextState: nextState };
  }

  /**
   * Capture a snapshot of state slots that rollback / atomicity restore may use.
   * Called from _commitDescription right before mutations (rollback path) and
   * from setLocalDescription / setRemoteDescription (atomicity path).
   *
   * Slots captured:
   *   - signalingState
   *   - pending and current descriptions (4 slots)
   *   - parsedLocalSdp / parsedRemoteSdp / parsedCurrentLocalSdp — DEEP-CLONED
   *     via SDP.cloneParsedSdp so subsequent mutations don't corrupt the
   *     captured view. (No code in this codebase mutates parsed SDPs in
   *     place; the deep clone is defensive — and very cheap, ~5-50KB
   *     JSON-roundtrip.)
   *   - transceivers (shallow array — to identify ones added since)
   *   - localSsrcs / remoteSsrcMap (shallow object copies)
   *   - localIceUfrag / localIcePwd — captured for rollback after ICE
   *     restart so subsequent createOffer doesn't leak post-restart creds
   *     as if they were the original session's. iceAgent has no clean
   *     "undo restart" — restart() is destructive (clears checkList,
   *     pendingTransactions, validList; the previous selected pair moves
   *     to _previousPair for media continuity, but the new check session
   *     is gone). Best we can do on rollback: realign creds via
   *     iceAgent.setLocalParameters so STUN messages match what's in our
   *     restored SDP. _previousPair preserves media flow on the original
   *     selected pair through this re-alignment.
   *   - private flags (negotiationNeeded, needsIceRestart, preCommitSnapshot)
   */
  _takeSnapshot() {
    var state = this._sharedState;
    return {
      signalingState:            state.signalingState,
      pendingLocalDescription:   state.pendingLocalDescription,
      pendingRemoteDescription:  state.pendingRemoteDescription,
      currentLocalDescription:   state.currentLocalDescription,
      currentRemoteDescription:  state.currentRemoteDescription,
      parsedLocalSdp:            SDP.cloneParsedSdp(state.parsedLocalSdp),
      parsedRemoteSdp:           SDP.cloneParsedSdp(state.parsedRemoteSdp),
      parsedCurrentLocalSdp:     SDP.cloneParsedSdp(state.parsedCurrentLocalSdp),
      parsedCurrentRemoteSdp:    SDP.cloneParsedSdp(state.parsedCurrentRemoteSdp),
      transceivers:              state.transceivers ? state.transceivers.slice() : [],
      localSsrcs:                state.localSsrcs    ? Object.assign({}, state.localSsrcs)    : {},
      remoteSsrcMap:             state.remoteSsrcMap ? Object.assign({}, state.remoteSsrcMap) : {},
      localIceUfrag:             state.localIceUfrag,
      localIcePwd:               state.localIcePwd,
      negotiationNeeded:         this._negotiationNeeded,
      needsIceRestart:           this._needsIceRestart,
      preCommitSnapshot:         this._preCommitSnapshot,
    };
  }

  /**
   * Restore from a snapshot produced by _takeSnapshot. Used by the
   * atomicity paths in _applySetLocal / _applySetRemote when an apply
   * step throws partway through, so the state machine doesn't strand in
   * a half-committed state where rollback() can't recover.
   *
   * Differences from the rollback restore (_applyRollback):
   *   - signalingState is set DIRECTLY (no applyStateUpdates cascade).
   *     Atomicity is internal — no observer should see the transient
   *     mid-apply state, so the cascade-fire side effects of
   *     applyStateUpdates would be a misleading double-emission.
   *   - Transceivers added during the failed apply are NOT stopped (they
   *     might just be defensive ones that the next attempt will reuse).
   *     The signaling-state revert + description revert is enough to
   *     keep the machine consistent.
   *   - Includes preCommitSnapshot — _commitDescription mutates that
   *     slot (sets new for offers, nulls for answers); atomicity must
   *     restore it so a subsequent rollback() finds the right anchor.
   *   - Skips iceAgent setLocalParameters: the failed apply didn't
   *     necessarily restart the agent; if it DID (implicit form +
   *     iceRestart), creds restoration will be pursued by the user via
   *     a fresh restartIce() call. Atomicity preserves description-
   *     level invariants only.
   */
  _restoreAtomicSnapshot(snap) {
    var state = this._sharedState;
    state.signalingState           = snap.signalingState;
    state.pendingLocalDescription  = snap.pendingLocalDescription;
    state.pendingRemoteDescription = snap.pendingRemoteDescription;
    state.currentLocalDescription  = snap.currentLocalDescription;
    state.currentRemoteDescription = snap.currentRemoteDescription;
    state.parsedLocalSdp           = snap.parsedLocalSdp;
    state.parsedRemoteSdp          = snap.parsedRemoteSdp;
    state.parsedCurrentLocalSdp    = snap.parsedCurrentLocalSdp;
    state.parsedCurrentRemoteSdp   = snap.parsedCurrentRemoteSdp;
    if (state.transceivers && Array.isArray(state.transceivers)) {
      state.transceivers.length = 0;
      for (var ti = 0; ti < snap.transceivers.length; ti++) {
        state.transceivers.push(snap.transceivers[ti]);
      }
    }
    if (state.localSsrcs) {
      var lsKeys = Object.keys(state.localSsrcs);
      for (var lki = 0; lki < lsKeys.length; lki++) delete state.localSsrcs[lsKeys[lki]];
      var snapLsKeys = Object.keys(snap.localSsrcs);
      for (var slki = 0; slki < snapLsKeys.length; slki++) {
        state.localSsrcs[snapLsKeys[slki]] = snap.localSsrcs[snapLsKeys[slki]];
      }
    }
    if (state.remoteSsrcMap) {
      var rsKeys = Object.keys(state.remoteSsrcMap);
      for (var rki = 0; rki < rsKeys.length; rki++) delete state.remoteSsrcMap[rsKeys[rki]];
      var snapRsKeys = Object.keys(snap.remoteSsrcMap);
      for (var srki = 0; srki < snapRsKeys.length; srki++) {
        state.remoteSsrcMap[snapRsKeys[srki]] = snap.remoteSsrcMap[snapRsKeys[srki]];
      }
    }
    this._negotiationNeeded = snap.negotiationNeeded;
    this._needsIceRestart   = snap.needsIceRestart;
    this._preCommitSnapshot = snap.preCommitSnapshot;
  }

  /**
   * Apply a remote description (offer or answer). Equivalent to W3C
   * RTCPeerConnection.setRemoteDescription.
   *
   * Side effects on success:
   *   - parsedRemoteSdp updated.
   *   - TransportController.applyRemoteDescription latches ICE creds,
   *     fingerprint, candidates, SCTP params, and RTP extension IDs.
   *   - signalingState transition (offer → have-remote-offer; answer → stable).
   *   - For answers: applyDirectionsFromAnswer commits CurrentDirection
   *     (with reverse=true since the directions are in the peer's perspective).
   *   - pushCandidatesToIceAgent feeds remote cands to a live agent.
   *   - processRemoteMedia handles the inbound transceivers.
   *
   * @param {Object} desc   {type: 'offer'|'answer', sdp: string}
   * @param {Function} cb   cb(err) — no result on success
   */
  setRemoteDescription(desc, cb) {
    if (this._deps.getClosed()) {
      var closedErr = new Error('peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return cb(closedErr);
    }
    if (!desc) {
      return cb(new TypeError('Invalid description: missing sdp'));
    }
    this._applySetRemote(desc, cb);
  }

  /**
   * Add a remote ICE candidate (trickle path). Equivalent to W3C
   * RTCPeerConnection.addIceCandidate.
   *
   * Three valid shapes:
   *   - null/undefined → end-of-candidates signal, accepted always.
   *   - { candidate: '' }  → same end-of-candidates.
   *   - { candidate: 'candidate:...' } → parse and feed to iceAgent.
   *
   * Per W3C §4.4.1.10, non-EOC candidates require a remoteDescription
   * to have been set first; called inside the chain so a queued
   * setRemoteDescription has already committed by the time we run.
   *
   * @param {Object|null} candidate   { candidate: string, sdpMid?, sdpMLineIndex? }
   * @param {Function} cb             cb(err) — no result on success
   */
  addIceCandidate(candidate, cb) {
    if (this._deps.getClosed()) {
      var closedErr = new Error('peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return cb(closedErr);
    }

    // null / empty string → end-of-candidates. Valid even without remoteDescription.
    if (!candidate || !candidate.candidate) return cb(null);

    if (!this._sharedState.parsedRemoteSdp) {
      var noRemoteErr = new Error('cannot add candidate before remoteDescription');
      noRemoteErr.name = 'InvalidStateError';
      return cb(noRemoteErr);
    }

    try {
      var parsed = SDP.parseCandidate(candidate.candidate);
      if (parsed) {
        TransportController.addTrickleCandidate(
          this._sharedState, parsed, this._deps.getIceAgent());
      }
      cb(null);
    } catch (e) {
      cb(e);
    }
  }

  /**
   * ICE restart (W3C §4.4.1.6). Marks the needsIceRestart flag so the
   * next createOffer will regenerate ufrag/pwd and call IceAgent.restart(),
   * then fires negotiationneeded so the app issues that offer.
   *
   * Routes through updateNegotiationNeededFlag for the standard debounce /
   * deferral behaviour (no fire when chain busy / not stable / closed).
   *
   * Synchronous void return — no callback. This is a setter, not an
   * operation; nothing to fail or wait on.
   */
  restartIce() {
    if (this._deps.getClosed()) return;
    this.setNeedsIceRestart();
    this.updateNegotiationNeededFlag();
  }


  /* ====================== Rollback (W3C §4.4.1.5/6) ====================== */

  /**
   * Roll back a pending offer. Equivalent to W3C
   * setLocalDescription({type:'rollback'}) (when source='local') or
   * setRemoteDescription({type:'rollback'}) (when source='remote').
   *
   * Validity:
   *   - source='local'  requires signalingState 'have-local-offer'
   *   - source='remote' requires signalingState 'have-remote-offer'
   *   - any other state → InvalidStateError
   *
   * On success:
   *   - Restore all snapshotted state slots (signalingState, descriptions,
   *     parsed forms, transceivers list, localSsrcs, remoteSsrcMap, flags).
   *   - Transceivers added since the snapshot are marked stopped per
   *     W3C §4.4.1.5 step 4.5.2 ("set [[Stopped]] to true").
   *   - signalingstatechange event fires (chain-driven by cm.js cascade).
   *   - The snapshot is consumed; subsequent rollback without a new
   *     setLocal/Remote returns InvalidStateError.
   *
   * Routed through chainOperation so it serializes with createOffer /
   * setLocal / setRemote per spec.
   *
   * @param {'local'|'remote'} source   which side is rolling back
   * @param {Function} cb               cb(err) — no result on success
   */
  rollback(source, cb) {
    if (this._deps.getClosed()) {
      var closedErr = new Error('peer connection is closed');
      closedErr.name = 'InvalidStateError';
      return cb(closedErr);
    }

    var self = this;
    this.chainOperation(function (next) {
      try {
        self._applyRollback(source);
        next(null);
      } catch (err) {
        next(err);
      }
    }, cb);
  }

  /**
   * Synchronous rollback application. Caller (rollback) is responsible
   * for chain integration and error wrapping. Throws InvalidStateError
   * on disallowed transitions; otherwise mutates state in place.
   */
  _applyRollback(source) {
    var state = this._sharedState;
    var requiredState = source === 'local' ? 'have-local-offer' : 'have-remote-offer';

    if (state.signalingState !== requiredState) {
      var stateErr = new Error('Cannot rollback ' + source + ' description in state: ' +
        state.signalingState);
      stateErr.name = 'InvalidStateError';
      throw stateErr;
    }

    var snap = this._preCommitSnapshot;
    if (!snap) {
      // Defensive — shouldn't happen if signalingState is correct, but
      // guards against a code path that mutates state without snapshotting.
      var noSnapErr = new Error('Cannot rollback: no snapshot available');
      noSnapErr.name = 'InvalidStateError';
      throw noSnapErr;
    }

    // ── 1. Stop transceivers added since the snapshot. ──
    //
    // W3C §4.4.1.5 step 4.5.2: "For each transceiver added by the rolled-
    // back operation, set [[Stopped]] slot to true." We identify them by
    // set-difference: any transceiver in current state but not in snapshot.
    if (state.transceivers && Array.isArray(state.transceivers)) {
      var snapSet = new Set(snap.transceivers);
      for (var i = 0; i < state.transceivers.length; i++) {
        var tx = state.transceivers[i];
        if (!snapSet.has(tx)) {
          tx.stopped = true;
          // currentDirection / direction transitions: per W3C §5.3.1,
          // a stopped transceiver reports 'stopped' as both direction
          // and currentDirection. Preserve existing values if the
          // transceiver was somehow already stopped.
          if (tx.currentDirection !== 'stopped') tx.currentDirection = 'stopped';
          if (tx.direction        !== 'stopped') tx.direction        = 'stopped';
        }
      }
    }

    // ── 2. Restore state slots. ──
    //
    // signalingState is intentionally restored last via applyStateUpdates
    // (not set directly here): applyStateUpdates diffs against current
    // state to decide which 'X-statechange' events fire, so leaving
    // signalingState untouched until that call ensures 'signalingstatechange'
    // is emitted to listeners.
    state.pendingLocalDescription  = snap.pendingLocalDescription;
    state.pendingRemoteDescription = snap.pendingRemoteDescription;
    state.currentLocalDescription  = snap.currentLocalDescription;
    state.currentRemoteDescription = snap.currentRemoteDescription;
    state.parsedLocalSdp           = snap.parsedLocalSdp;
    state.parsedRemoteSdp          = snap.parsedRemoteSdp;
    state.parsedCurrentLocalSdp    = snap.parsedCurrentLocalSdp;
    state.parsedCurrentRemoteSdp   = snap.parsedCurrentRemoteSdp;
    if (state.transceivers && Array.isArray(state.transceivers)) {
      state.transceivers.length = 0;
      for (var ti = 0; ti < snap.transceivers.length; ti++) {
        state.transceivers.push(snap.transceivers[ti]);
      }
    }
    if (state.localSsrcs) {
      var lsKeys = Object.keys(state.localSsrcs);
      for (var lki = 0; lki < lsKeys.length; lki++) delete state.localSsrcs[lsKeys[lki]];
      var snapLsKeys = Object.keys(snap.localSsrcs);
      for (var slki = 0; slki < snapLsKeys.length; slki++) {
        state.localSsrcs[snapLsKeys[slki]] = snap.localSsrcs[snapLsKeys[slki]];
      }
    }
    if (state.remoteSsrcMap) {
      var rsKeys = Object.keys(state.remoteSsrcMap);
      for (var rki = 0; rki < rsKeys.length; rki++) delete state.remoteSsrcMap[rsKeys[rki]];
      var snapRsKeys = Object.keys(snap.remoteSsrcMap);
      for (var srki = 0; srki < snapRsKeys.length; srki++) {
        state.remoteSsrcMap[snapRsKeys[srki]] = snap.remoteSsrcMap[snapRsKeys[srki]];
      }
    }
    this._negotiationNeeded = snap.negotiationNeeded;
    this._needsIceRestart   = snap.needsIceRestart;

    // ── ICE creds: restore + sync iceAgent. ──
    //
    // Prior implementation intentionally skipped this on the assumption
    // that "once set on the wire, undoing them is meaningless." That's
    // partially true (peer may have seen the offer), but it left state
    // inconsistent in the post-rollback retry path: the next createOffer
    // would reuse post-restart creds without an iceRestart flag, looking
    // like a non-restart offer to the peer that nonetheless changed
    // creds. The peer would then either accept (graceful but spec-
    // violating) or reject the dangling state.
    //
    // Restore creds in state, then realign iceAgent via setLocalParameters
    // so any future STUN check uses the restored creds. iceAgent's
    // restart() was destructive (checkList/validList/pendingTransactions
    // cleared) and we can't fully undo that — but the _previousPair
    // mechanism in iceAgent preserves the original selected pair for
    // send() continuity, so media stays on the established path while
    // the realigned creds match what's in our SDP. No new STUN session
    // is forced; if the user issues a fresh createOffer, that path will
    // reset cleanly.
    state.localIceUfrag = snap.localIceUfrag;
    state.localIcePwd   = snap.localIcePwd;
    var iceAgent = this._deps.getIceAgent && this._deps.getIceAgent();
    if (iceAgent && typeof iceAgent.setLocalParameters === 'function' &&
        snap.localIceUfrag && snap.localIcePwd) {
      iceAgent.setLocalParameters({
        ufrag: snap.localIceUfrag,
        pwd:   snap.localIcePwd,
      });
    }

    // ── 3. Snapshot consumed. Subsequent rollback without a new
    // setLocal/Remote will fail with InvalidStateError above. ──
    this._preCommitSnapshot = null;

    // ── 4. Restore signalingState through applyStateUpdates so cm.js's
    // cascade fires 'signalingstatechange' to API listeners. ──
    this._deps.applyStateUpdates({ signalingState: snap.signalingState });
  }


  /* ====================== Public read-only getters ====================== */
  // How api.js (and cm.js) read our state. Mutation happens through the
  // public methods (createOffer, setLocal, etc.). Description-related
  // getters proxy to sharedState (the source of truth — see constructor
  // comment); chain/negotiation getters reflect class-private state.

  get signalingState()           { return this._sharedState.signalingState; }
  get currentLocalDescription()  { return this._sharedState.currentLocalDescription; }
  get currentRemoteDescription() { return this._sharedState.currentRemoteDescription; }
  get pendingLocalDescription()  { return this._sharedState.pendingLocalDescription; }
  get pendingRemoteDescription() { return this._sharedState.pendingRemoteDescription; }
  get parsedLocalSdp()           { return this._sharedState.parsedLocalSdp; }
  get parsedCurrentLocalSdp()    { return this._sharedState.parsedCurrentLocalSdp; }
  get parsedCurrentRemoteSdp()   { return this._sharedState.parsedCurrentRemoteSdp; }
  get parsedRemoteSdp()          { return this._sharedState.parsedRemoteSdp; }
  get lastOffer()                { return this._lastOffer; }
  get lastAnswer()               { return this._lastAnswer; }
  get negotiationNeeded()        { return this._negotiationNeeded; }
  get needsIceRestart()          { return this._needsIceRestart; }
}


function noop() {}


export { SdpOfferAnswer };

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
  /**
   * Yield before an operation's REAL WORK (W3C 4.4.1: operations run
   * "in parallel" and settle from a queued task).
   *
   * PLACEMENT IS THE DESIGN: state preconditions run BEFORE this and
   * reject within microtasks, so an IDLE chain still looks idle to a
   * probe; only the work after them is deferred, so a BUSY chain looks
   * busy. A blanket deferral in _runHead breaks the first half; the
   * preconditions alone break the second.
   */
  _yieldBeforeWork(fn) {
    setTimeout(fn, 0);
  }

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
    // W3C 4.4.3 (WPT: 'Closing ... neither resolves nor rejects'): when
    // the connection closes, queued description operations are DROPPED —
    // their promises never settle. Rejecting them here produced
    // observable InvalidStateError rejections the spec forbids.
    this._operations.length = 0;
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
      var err = new DOMException('peer connection is closed', 'InvalidStateError');
      try { entry.done(err); } catch (e) { /* swallow user-cb errors */ }
      this._scheduleAdvance();
      return;
    }

    var self = this;
    var settled = false;
    var safeNext = function (err, result) {
      if (settled) return;     // double-invoke protection
      settled = true;
      // W3C 4.4.1: an operation runs "in parallel" and then QUEUES A TASK
      // to settle its promise. Settling in the same turn made the chain
      // drain before anything could observe it occupied — our createOffer
      // builds its SDP synchronously, so a caller (or WPT's chain probe)
      // that looked right after the call always saw an EMPTY chain, and
      // a second operation issued in the same turn never actually queued
      // behind the first. The single deferral here is what makes the
      // chain observable; it is the only place an operation completes,
      // so nothing else needs to know about it.
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

    // OPERATION TIMING — measured, not assumed (round 106).
    //
    // W3C 4.4.1 says an operation runs "in parallel" and queues a task to
    // settle. Our engine builds SDP synchronously, so the chain drains
    // inside the very call that filled it and is never observably
    // occupied — which is what WPT's isOperationsChainEmpty probe
    // measures. THREE variants were implemented and measured against the
    // suite before choosing:
    //   • settle deferred by a macrotask — operations 14 to 6, and the
    //     file truncated (the probe never saw an idle chain, so later
    //     tests started against a chain that looked permanently busy);
    //   • settle deferred by a microtask — exactly neutral, 14;
    //   • operation START deferred by a macrotask — createOffer 3 to 4
    //     but operations 14 to 8, a net loss of five.
    // ROUND 107 went further and built the full asynchronous model: a
    // _yieldBeforeWork seam placed AFTER each operation's state
    // preconditions (so a bad state still rejects within microtasks and
    // an idle chain still looks idle) but BEFORE its real work (so a
    // busy chain looks busy), plus a microtask — rather than task —
    // chain advance so an awaited operation leaves the queue before the
    // caller's next line runs.
    // IT WORKED: operations 14 to 20, createOffer 3 to CLEAN 5/5.
    // IT WAS STILL REVERTED: setRemoteDescription-offer dropped from 15
    // subtests to 8 — not failing, HANGING. The "naive rollback is not
    // glare-proof" case (rollback + addIceCandidate + sRD issued
    // together) stopped settling, so every test after it never ran. Net
    // +3 subtests for a hang in a real glare shape is a bad trade.
    // Finishing this means making that three-operation glare sequence
    // settle deterministically FIRST, then re-applying the seam.
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
    // The finished entry leaves the queue on a MICROTASK: a caller
    // awaiting an operation resumes on a microtask too, so a
    // task-deferred drain left the completed entry at the head and the
    // chain looked busy right after an awaited operation finished.
    var self = this;
    queueMicrotask(function () { self._advanceChain(); });
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
    setTimeout(function () {
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
      var closedErr = new DOMException('peer connection is closed', 'InvalidStateError');
      return cb(closedErr);
    }

    // ICE restart (W3C §4.4.1.6): triggered either by an earlier
    // restartIce() (this._needsIceRestart) or explicitly via
    // options.iceRestart=true. Consumed by clearNeedsIceRestart() once
    // the prelude has woven it into the new ufrag/pwd + iceAgent.restart().
    var iceRestart = !!(this._needsIceRestart ||
                        (options && options.iceRestart));

    var _stO = this._sharedState.signalingState;
    if (_stO !== 'stable' && _stO !== 'have-local-offer') {
      return cb(new DOMException(
        'createOffer: cannot create an offer in signalingState ' + _stO, 'InvalidStateError'));
    }
    var _selfO = this;
    this._yieldBeforeWork(function () {
    _selfO._deps.prepareForCreateOffer(iceRestart, function (err, prepCtx) {
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
      var closedErr = new DOMException('peer connection is closed', 'InvalidStateError');
      return cb(closedErr);
    }
    if (!this._sharedState.parsedRemoteSdp) {
      var noRemoteErr = new DOMException('No remote offer', 'InvalidStateError');
      return cb(noRemoteErr);
    }

    var _selfA = this;
    this._yieldBeforeWork(function () {
    _selfA._deps.prepareForCreateAnswer(function (err, prepCtx) {
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
      var closedErr = new DOMException('peer connection is closed', 'InvalidStateError');
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
        var stateErrImpl = new DOMException('Cannot implicit-setLocal in state: ' + sigState, 'InvalidStateError');
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
  _applySetLocal(desc, cb, alreadyYielded) {
    if (!desc.sdp) {
      // W3C §4.4.1.5 step 4.2 — empty/missing SDP after explicit type.
      return cb(new TypeError('Invalid description: missing sdp'));
    }

    var _selfL = this;
    var _runWork = function () {
      // NEVER-SETTLE ON CLOSE (W3C 4.4.3) survives the deferral: if the
      // connection closed while this operation waited for its task, the
      // promise is DROPPED, not rejected — the same rule
      // rejectPendingOperations enforces for still-queued work.
      if (_selfL._deps.getClosed()) return;
    var state = _selfL._sharedState;
    var atomicSnap = _selfL._takeSnapshot();

    try {
      var commit = _selfL._commitDescription(desc, 'local');

      _selfL._deps.applyStateUpdates({ signalingState: commit.nextState });

      // Sync the outgoing-RTP extension stamper. The extension IDs we put
      // on outgoing packets are determined by our local description (offer
      // or answer). For an answer specifically this matters — RFC 5285 §6
      // recommends matching the offerer's IDs, which can differ from our
      // hardcoded defaults. Without this sync our outgoing RTP stamps
      // extensions with IDs the peer won't recognize.
      _selfL._deps.syncStamperExtMap(commit.parsed);

      if (desc.type === 'answer' || desc.type === 'pranswer') {
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
      _selfL._restoreAtomicSnapshot(atomicSnap);
      cb(e);
    }
    };
    if (alreadyYielded) _runWork(); else this._yieldBeforeWork(_runWork);
  }

  /**
   * Apply a remote description. Companion to _applySetLocal — invoked from
   * setRemoteDescription. The shared validation + slot-updates live in
   * _commitDescription; this method owns the remote-side cascade order:
   * transport extraction first, then state-cascade, then directions, then
   * candidate forwarding, then media processing.
   */
  _applySetRemote(desc, cb, alreadyYielded) {
    if (!desc.sdp) {
      this._deps.diag('[cm-diag] setRemoteDescription REJECTED — desc=' +
        (desc ? 'truthy type=' + desc.type + ' sdp=' +
          (desc.sdp ? ('len=' + desc.sdp.length) : 'MISSING/null') : 'null'));
      return cb(new TypeError('Invalid description: missing sdp'));
    }

    // W3C 4.4.1.6 step 4 / RFC 4566: a description that is not valid SDP
    // is an RTCError with errorDetail 'sdp-syntax-error' — NOT a silent
    // accept. Minimum well-formedness: a v= line, an o= line and an s=
    // line, in a CRLF/LF-separated body. (Rolled-back state must survive
    // this rejection, so the check runs BEFORE any mutation.)
    // ORDER MATTERS (two WPT files, one rule): the STATE check precedes
    // the SDP check — an answer in 'stable' is an InvalidStateError even
    // when its SDP is also garbage. Only once the type is legal for the
    // current state does malformed SDP become sdp-syntax-error.
    var _sigNow = this._sharedState.signalingState;
    if ((desc.type === 'answer' || desc.type === 'pranswer') && _sigNow === 'stable') {
      return cb(new DOMException(
        'setRemoteDescription: cannot apply an answer in stable', 'InvalidStateError'));
    }
    var _sdpText = String(desc.sdp);
    var _looksLikeSdp = /(^|[\r\n])v=/.test(_sdpText) &&
                        /(^|[\r\n])o=/.test(_sdpText) &&
                        /(^|[\r\n])s=/.test(_sdpText);
    if (!_looksLikeSdp) {
      // api.js owns the RTCError class and imports THIS module, so we
      // cannot import it back (cycle). The api layer installs the ctor
      // on the shared state at construction; fall back to a DOMException
      // carrying the same observable fields if it is unavailable.
      var _ErrCtor = this._sharedState && this._sharedState._RTCErrorCtor;
      var _sdpErr;
      if (typeof _ErrCtor === 'function') {
        _sdpErr = new _ErrCtor({ errorDetail: 'sdp-syntax-error', sdpLineNumber: 1 },
                               'setRemoteDescription: invalid SDP');
      } else {
        _sdpErr = new DOMException('setRemoteDescription: invalid SDP', 'OperationError');
        _sdpErr.errorDetail = 'sdp-syntax-error';
      }
      return cb(_sdpErr);
    }

    var _selfR = this;
    var _runWork = function () {
      // NEVER-SETTLE ON CLOSE (W3C 4.4.3) survives the deferral: if the
      // connection closed while this operation waited for its task, the
      // promise is DROPPED, not rejected — the same rule
      // rejectPendingOperations enforces for still-queued work.
      if (_selfR._deps.getClosed()) return;
    var state = _selfR._sharedState;
    // W3C 5.10 / RFC 8830: the same msid (stream id + track id) may not
    // appear in two m-sections — a track lives in exactly one m-line, and
    // duplicates make receive-side stream reconstruction ambiguous.
    try {
      // Count msids per LIVE m-section only. A rejected section (port 0)
      // keeps its attributes but describes no track, so counting it
      // produced false duplicates — the bundle-tag-rejected case hit
      // exactly that and a legitimate description was refused.
      var _seen = {};
      var _sections = _sdpText.split(/(?=[\r\n]m=)/);
      for (var _si = 0; _si < _sections.length; _si++) {
        var _sec = _sections[_si];
        if (!/[\r\n]?m=/.test(_sec)) continue;
        if (/[\r\n]?m=\S+ 0 /.test(_sec)) continue;      // rejected section
        var _lines = _sec.match(/(^|[\r\n])a=msid:[^\r\n]+/g) || [];
        for (var _di = 0; _di < _lines.length; _di++) {
          var _key = _lines[_di].replace(/[\r\n]/g, '').trim();
          if (_seen[_key]) {
            return cb(new DOMException(
              'setRemoteDescription: duplicate msid', 'InvalidAccessError'));
          }
          _seen[_key] = true;
        }
      }
    } catch (eDup) {}

    var atomicSnap = _selfR._takeSnapshot();

    try {
      _selfR._deps.diag('[cm-diag] ── REMOTE SDP (' + desc.type + ') ──');
      _selfR._deps.diag(desc.sdp);
      _selfR._deps.diag('[cm-diag] ── end remote SDP ──');

      var commit = _selfR._commitDescription(desc, 'remote');

      // Extract ICE creds, fingerprint, candidates, SCTP params, and RTP
      // header extension IDs from the parsed SDP into state.
      TransportController.applyRemoteDescription(state, commit.parsed);
      if (state.remoteTransportCcExtId != null) {
        _selfR._deps.diag('[cm-diag] transport-cc extension id (remote): ' +
          state.remoteTransportCcExtId);
      }
      if (state.remoteRidExtId != null) {
        _selfR._deps.diag('[cm-diag] rid extension id (remote): ' + state.remoteRidExtId +
          (state.remoteRepairedRidExtId != null
            ? ' (repaired=' + state.remoteRepairedRidExtId + ')' : ''));
      }

      var firstMedia = commit.parsed.media[0];
      if (firstMedia) {
        _selfR._deps.diag('[cm-diag] setRemoteDescription type=' + desc.type +
          ' firstMedia.type=' + firstMedia.type +
          ' firstMedia.setup=' + firstMedia.setup +
          ' current dtlsRole=' + state.dtlsRole);
      }

      // applyStateUpdates triggers cascades: ICE remote creds, DTLS role, etc.
      _selfR._deps.applyStateUpdates({
        signalingState:  commit.nextState,
        parsedRemoteSdp: commit.parsed,
      });

      if (desc.type === 'answer' || desc.type === 'pranswer') {
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
        _selfR._deps.getIceAgent());

      // Process remote media tracks.
      _selfR._deps.processRemoteMedia(commit.parsed);

      cb(null);
    } catch (e) {
      _selfR._restoreAtomicSnapshot(atomicSnap);
      cb(e);
    }
    };
    if (alreadyYielded) _runWork(); else this._yieldBeforeWork(_runWork);
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
    // RFC 8841: capture the peer's a=max-message-size (session or media
    // level). Absent attribute leaves null (getter assumes 65536).
    if (source === 'remote' && desc && desc.sdp) {
      var _mmsM = desc.sdp.match(/a=max-message-size:\s*(\d+)/);
      state.remoteMaxMessageSize = _mmsM ? parseInt(_mmsM[1], 10) : null;
    }
    // W3C: under rtcpMuxPolicy 'require' (the only modern value), a
    // remote description whose media sections do not declare a=rtcp-mux
    // is unusable — reject with InvalidAccessError before any state
    // is touched.
    if (source === 'remote' && parsed && parsed.media) {
      for (var _rmI = 0; _rmI < parsed.media.length; _rmI++) {
        var _rmM = parsed.media[_rmI];
        if (_rmM.port === 0) continue;                     // rejected section
        if (_rmM.type !== 'audio' && _rmM.type !== 'video') continue;  // rtcp-mux is an RTP concern
        if (!_rmM.rtcpMux) {
          throw new DOMException(
            'setRemoteDescription: media section ' + _rmI + ' lacks a=rtcp-mux ' +
            'but rtcpMuxPolicy is "require"', 'InvalidAccessError');
        }
      }
    }
   // pranswer shares the answer grammar

    // ── 1. Validate transition. ──
    // WPT harvest — provisional answers (W3C §4.4.1.6): pranswer is a
    // repeatable partial answer; a final 'answer' from a pranswer state
    // completes to stable.
    var requiredStates, nextState;
    if (desc.type === 'offer') {
      // re-setting an offer while one is pending is legal (W3C/WPT:
      // 'creating and setting offer multiple times should succeed').
      requiredStates = isLocal ? ['stable', 'have-local-offer']
                               : ['stable', 'have-remote-offer'];
      nextState = isLocal ? 'have-local-offer' : 'have-remote-offer';
    } else if (desc.type === 'pranswer') {
      requiredStates = isLocal
        ? ['have-remote-offer', 'have-local-pranswer']
        : ['have-local-offer', 'have-remote-pranswer'];
      nextState = isLocal ? 'have-local-pranswer' : 'have-remote-pranswer';
    } else {
      requiredStates = isLocal
        ? ['have-remote-offer', 'have-local-pranswer']
        : ['have-local-offer', 'have-remote-pranswer'];
      nextState = 'stable';
    }
    if (requiredStates.indexOf(state.signalingState) === -1) {
      var err = new DOMException('Cannot set ' + source + ' ' + desc.type +
        ' in state: ' + state.signalingState, 'InvalidStateError');
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
    if (desc.type === 'offer' || desc.type === 'pranswer') {
      // A PRANSWER is provisional by definition (W3C 4.4.1.5): it lands
      // in the PENDING slot and current stays null until the final
      // answer promotes everything. Treating it like an answer published
      // it as currentLocalDescription and left pendingLocalDescription
      // null — the exact inverse of what the spec (and apps polling
      // pendingLocalDescription during early media) expect.
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
transceiverMids:           state.transceivers.map(function (t) { return t.mid; }),
            transceiverAssoc:          state.transceivers
        ? state.transceivers.map(function (t) { return !!t._associated; }) : [],
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
    // W3C §4.4.1.6 — IMPLICIT ROLLBACK (WPT harvest; the mechanism
    // perfect-negotiation is built on): receiving an offer while in
    // have-local-offer rolls the local offer back automatically, then
    // applies the remote one. The visit through 'stable' fires the
    // signaling events; negotiationneeded is suppressed until settled.
    if (desc && desc.type === 'offer' &&
        this._sharedState.signalingState === 'have-local-offer') {
      // CHAIN DEADLOCK FIX (the field-fatal glare hang): this method
      // already runs INSIDE a chain operation, so routing the rollback
      // through this.rollback() queued it BEHIND ourselves — the queued
      // op waited for us, we waited for its callback, and the glare
      // setRemoteDescription NEVER SETTLED. Perfect negotiation stalls
      // there forever (engine: negotiation latched, no media). Apply the
      // rollback SYNCHRONOUSLY (it is a pure state operation) and
      // continue in-place.
      try {
        this._applyRollback('local');
      } catch (rbErr) {
        return cb(rbErr);
      }
      // GLARE-PROOFNESS (W3C 4.4.1.6): the visit through 'stable' must be
      // OBSERVABLE — apps (and WPT) await signalingstatechange and then
      // run operations against the rolled-back state before the remote
      // offer lands. Yield one macrotask so 'stable' is delivered first.
      var _selfG = this;
      return setTimeout(function () {
        if (_selfG._deps.getClosed()) return;   // never-settle on close
        _selfG._applySetRemote(desc, cb, true);   // this task IS the yield
      }, 0);
    }
    if (this._deps.getClosed()) {
      var closedErr = new DOMException('peer connection is closed', 'InvalidStateError');
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
      var closedErr = new DOMException('peer connection is closed', 'InvalidStateError');
      return cb(closedErr);
    }

    // WPT harvest — addressing validation (W3C §4.4.2 steps 5-8):
    // unknown sdpMid / out-of-range sdpMLineIndex / unknown ufrag reject
    // with OperationError.
    var prsV = this._sharedState.parsedRemoteSdp;
    // candidate may legitimately be null/undefined (end-of-candidates
    // signal — stable-webrtc's drain sends exactly that); the addressing
    // validation only applies when there IS an init to validate.
    if (candidate && prsV && prsV.media) {
      if (candidate.sdpMid != null) {
        var midOk = prsV.media.some(function (mm) { return String(mm.mid) === String(candidate.sdpMid); });
        if (!midOk) return cb(new DOMException('addIceCandidate: unknown sdpMid "' + candidate.sdpMid + '"', 'OperationError'));
      } else if (candidate.sdpMLineIndex != null) {
        if (candidate.sdpMLineIndex >= prsV.media.length) {
          return cb(new DOMException('addIceCandidate: sdpMLineIndex out of range', 'OperationError'));
        }
      }
      if (candidate.usernameFragment != null) {
        var sesU = prsV.session && prsV.session.iceUfrag;
        var mlU = function (mm) { return mm.iceUfrag || sesU; };
        if (candidate.sdpMid != null || candidate.sdpMLineIndex != null) {
          var target = candidate.sdpMid != null
            ? prsV.media.filter(function (mm) { return String(mm.mid) === String(candidate.sdpMid); })[0]
            : prsV.media[candidate.sdpMLineIndex];
          if (target && mlU(target) !== candidate.usernameFragment) {
            return cb(new DOMException('addIceCandidate: usernameFragment does not match the addressed m-line', 'OperationError'));
          }
        } else {
          var ufragOk = prsV.media.some(function (mm) { return mlU(mm) === candidate.usernameFragment; }) ||
                        sesU === candidate.usernameFragment;
          if (!ufragOk) return cb(new DOMException('addIceCandidate: unknown usernameFragment', 'OperationError'));
        }
      }
    }


    // null / empty string → end-of-candidates (W3C §4.4.2; WPT harvest:
    // the marker must become VISIBLE — tests read remoteDescription.sdp
    // and expect a=end-of-candidates appended to the addressed m-section,
    // or to every m-section when no sdpMid/sdpMLineIndex was given).
    if (!candidate || !candidate.candidate) {
      var prs = this._sharedState.parsedRemoteSdp;
      if (prs && prs.media) {
        var tgtMid = candidate && candidate.sdpMid != null ? String(candidate.sdpMid) : null;
        var tgtIdx = candidate && candidate.sdpMLineIndex != null ? candidate.sdpMLineIndex : null;
        for (var mi = 0; mi < prs.media.length; mi++) {
          var mm = prs.media[mi];
          if (tgtMid != null && String(mm.mid) !== tgtMid) continue;
          if (tgtMid == null && tgtIdx != null && mi !== tgtIdx) continue;
          if (candidate && candidate.usernameFragment != null && tgtMid == null && tgtIdx == null) {
            var mmU = mm.iceUfrag || (prs.session && prs.session.iceUfrag);
            if (mmU !== candidate.usernameFragment) continue;
          }
          if (!mm.endOfCandidates) mm.endOfCandidates = true;
        }
        // re-render the visible remoteDescription so sdp readers see it
        var _rdField = this._sharedState.pendingRemoteDescription ? 'pendingRemoteDescription' : 'currentRemoteDescription';
        if (this._sharedState[_rdField] &&
            this._sharedState[_rdField].sdp &&
            this._sharedState[_rdField].sdp.indexOf('a=end-of-candidates') === -1) {
          var sepE = this._sharedState[_rdField].sdp.indexOf('\r\n') !== -1 ? '\r\n' : '\n';
          var lines = this._sharedState[_rdField].sdp.split(/\r?\n/);
          // Render PER-SECTION: an end-of-candidates addressed to one
          // m-line (by sdpMid, sdpMLineIndex or usernameFragment) belongs
          // to THAT section only. The previous loop stamped every
          // section unconditionally, so a targeted EOC silently closed
          // candidate gathering on m-lines the peer was still trickling.
          var out = [], sec = -1;
          for (var li = 0; li < lines.length; li++) {
            var isM = lines[li].indexOf('m=') === 0;
            if (isM && sec >= 0 && prs.media[sec] && prs.media[sec].endOfCandidates) {
              out.push('a=end-of-candidates');
            }
            if (isM) sec++;
            out.push(lines[li]);
          }
          if (sec >= 0 && prs.media[sec] && prs.media[sec].endOfCandidates) {
            while (out.length && out[out.length - 1] === '') out.pop();
            out.push('a=end-of-candidates', '');
          }
          var eocSdp = out.join(sepE);
          this._sharedState[_rdField] =
            { type: this._sharedState[_rdField].type, sdp: eocSdp };
        }
      }
      return cb(null);
    }

    if (!this._sharedState.parsedRemoteSdp) {
      var noRemoteErr = new DOMException('cannot add candidate before remoteDescription', 'InvalidStateError');
      return cb(noRemoteErr);
    }

    try {
      var parsed = SDP.parseCandidate(candidate.candidate);
      if (parsed) {
        TransportController.addTrickleCandidate(
          this._sharedState, parsed, this._deps.getIceAgent());
        // WPT harvest: the candidate must become VISIBLE — tests read
        // remoteDescription.sdp and expect the a=candidate line inside
        // the addressed m-section (before any end-of-candidates marker).
        var _rdF = this._sharedState.pendingRemoteDescription ? 'pendingRemoteDescription' : 'currentRemoteDescription';
        var crd = this._sharedState[_rdF];
        if (crd && crd.sdp) {
          var candLine = 'a=' + (candidate.candidate.indexOf('candidate:') === 0
            ? candidate.candidate : 'candidate:' + candidate.candidate.replace(/^a=candidate:/, ''));
          candLine = candLine.replace(/^a=a=/, 'a=');
          var tMid = candidate.sdpMid != null ? String(candidate.sdpMid) : null;
          var tIdx = candidate.sdpMLineIndex != null ? candidate.sdpMLineIndex : null;
          var sepT = crd.sdp.indexOf('\r\n') !== -1 ? '\r\n' : '\n';
          var lines = crd.sdp.split(/\r?\n/), out = [], sec = -1, curMid = null, placed = false;
          var flushAt = function (i) {
            var inTarget = (tMid != null ? curMid === tMid : (tIdx != null ? sec === tIdx : sec === 0));
            return inTarget && !placed;
          };
          for (var li = 0; li < lines.length; li++) {
            var L = lines[li];
            var isM = L.indexOf('m=') === 0;
            if ((isM && sec >= 0) || (li === lines.length - 1 && L === '')) {
              if (flushAt(li)) { out.push(candLine); placed = true; }
            }
            if (isM) { sec++; curMid = null; }
            if (L.indexOf('a=mid:') === 0) curMid = L.slice(6);
            if (L.indexOf('a=end-of-candidates') === 0 && flushAt(li)) {
              out.push(candLine); placed = true;
            }
            out.push(L);
          }
          if (!placed && sec >= 0) {
            while (out.length && out[out.length - 1] === '') out.pop();
            out.push(candLine, '');
          }
          this._sharedState[_rdF] = { type: crd.type, sdp: out.join(sepT) };
        }
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
      var closedErr = new DOMException('peer connection is closed', 'InvalidStateError');
      return cb(closedErr);
    }

    // STATE PRECONDITION before the chain (W3C 4.4.1.5): rollback is
    // only legal from have-local-offer / have-local-pranswer (local) or
    // have-remote-offer / have-remote-pranswer (remote). Rejecting here
    // — ahead of the work yield inside the operation — is the same rule
    // createOffer follows: a bad state fails within microtasks so an
    // IDLE chain still looks idle to anything probing it.
    var _stRb = this._sharedState.signalingState;
    var _legal = (source === 'local')
      ? (_stRb === 'have-local-offer' || _stRb === 'have-local-pranswer')
      : (_stRb === 'have-remote-offer' || _stRb === 'have-remote-pranswer');
    if (!_legal) {
      return cb(new DOMException(
        'rollback: cannot roll back in signalingState ' + _stRb, 'InvalidStateError'));
    }

    var self = this;
    this.chainOperation(function (next) {
      // Same work-yield as every other operation, and it matters MORE
      // here: a rollback's signalingstatechange is the event callers
      // wait for, and they assign the handler on the line AFTER the
      // call. Applying synchronously inside the call emitted 'stable'
      // before anyone could be listening — the event was simply lost,
      // and a caller awaiting it waited forever.
      self._yieldBeforeWork(function () {
        if (self._deps.getClosed()) return;   // never-settle on close
        try {
          self._applyRollback(source);
          next(null);
        } catch (err) {
          next(err);
        }
      });
    }, cb);
  }

  /**
   * Synchronous rollback application. Caller (rollback) is responsible
   * for chain integration and error wrapping. Throws InvalidStateError
   * on disallowed transitions; otherwise mutates state in place.
   */
  _applyRollback(source) {
    var state = this._sharedState;
    // W3C: rollback is legal from the offer AND pranswer pending states.
    var requiredStates = source === 'local'
      ? ['have-local-offer', 'have-local-pranswer']
      : ['have-remote-offer', 'have-remote-pranswer'];

    if (requiredStates.indexOf(state.signalingState) === -1) {
      var stateErr = new DOMException('Cannot rollback ' + source + ' description in state: ' +
        state.signalingState, 'InvalidStateError');
      throw stateErr;
    }

    var snap = this._preCommitSnapshot;
    if (!snap) {
      // Defensive — shouldn't happen if signalingState is correct, but
      // guards against a code path that mutates state without snapshotting.
      var noSnapErr = new DOMException('Cannot rollback: no snapshot available', 'InvalidStateError');
      throw noSnapErr;
    }

    // ── 1. Dis-associate transceivers touched by the rolled-back apply. ──
    // MODERN W3C semantics (WPT harvest): rolled-back-created transceivers
    // SURVIVE, dis-associated (public mid → null), available for reuse.
    // Nothing is stopped, nothing removed. (The 2017-era text said stop-
    // and-remove; current spec and every browser keep them.)
    if (state.transceivers && Array.isArray(state.transceivers)) {
      var snapSet = new Set(snap.transceivers);
      for (var i = 0; i < state.transceivers.length; i++) {
        var tx = state.transceivers[i];
        if (!snapSet.has(tx)) tx._associated = false;
      }
      for (var si2 = 0; si2 < snap.transceivers.length; si2++) {
        snap.transceivers[si2]._associated =
          !!(snap.transceiverAssoc && snap.transceiverAssoc[si2]);
        // JSEP: rollback also RESTORES the mid the rolled-back offer
        // assigned (the two-transceivers-claiming-mid-3 collision: the
        // send transceiver kept its bound mid while a fresh SRD-created
        // one took the same mid, and the re-offer then served only one
        // of them — the sender went silent). Re-key its ssrc slot back.
        if (snap.transceiverMids) {
          var _prevMid = snap.transceiverMids[si2];
          var _curMid = snap.transceivers[si2].mid;
          if (String(_prevMid) !== String(_curMid)) {
            snap.transceivers[si2].mid = _prevMid;
            if (state.localSsrcs && state.localSsrcs[_curMid]) {
              state.localSsrcs[_prevMid] = state.localSsrcs[_curMid];
              delete state.localSsrcs[_curMid];
            }
          }
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
    // transceiver ARRAY: current spec/JSEP — transceivers CREATED BY the
    // rolled-back apply (never previously associated) are REMOVED from
    // the list; pre-existing ones survive dis-associated. (The union-
    // keep here matched an older draft.)
    if (state.transceivers && Array.isArray(state.transceivers)) {
      // JSEP-precise: only transceivers CREATED BY the rolled-back
      // description apply (_srdCreated) are removed; app-created ones
      // (addTrack/addTransceiver during glare — perfect negotiation!)
      // MUST survive. The blanket snapshot-only restore silently
      // swallowed the app's video sender mid-glare (field bug).
      var createdDuring = state.transceivers.filter(function (t) {
        if (snap.transceivers.indexOf(t) !== -1) return false;
        // An SRD-created transceiver that the APP has since attached a
        // track to is no longer purely remote-created — addTrack reused
        // it, so the app holds a sender on it and rollback must KEEP it
        // (dis-associated, mid null) rather than delete the app's work.
        if (t._srdCreated && !(t.sender && t.sender.track)) return false;
        // A survivor is FULLY dis-associated: the description that gave
        // it a mid is gone, so mid must read null again (the public
        // getter keys on the birth flags, and leaving _srdCreated set
        // kept the rolled-back mid observable).
        t._srdCreated = false;
        t._adopted = false;
        t._associated = false;
        t.mid = null;
        return true;
      });
      state.transceivers.length = 0;
      for (var ti = 0; ti < snap.transceivers.length; ti++) {
        state.transceivers.push(snap.transceivers[ti]);
      }
      for (var ci = 0; ci < createdDuring.length; ci++) {
        state.transceivers.push(createdDuring[ci]);
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
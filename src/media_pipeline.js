// src/media_pipeline.js
// Glue between MediaStreamTrack and the RTP send path.
//
// Responsibilities:
//   - Create a VideoEncoder (media-processing) sized for the track
//   - Create a VP8 packetizer (rtp-packet) with the sender's SSRC
//   - Subscribe to track.on('frame') — feed frames into the encoder
//   - Forward encoded chunks through the packetizer to manager.sendRtp()
//
// Phase 1 scope:
//   - Video only, VP8 hardcoded
//   - No codec negotiation (ignores the negotiated SDP)
//   - No setParameters (fixed bitrate/fps/resolution)
//   - No NACK/RTX
//
// The pipeline defers sending until SRTP keys are ready. It listens on the
// manager's 'srtp:ready' event and switches from "drop" mode to "send" mode
// at that point. If SRTP is already ready when the pipeline is created,
// sending starts immediately.

import { EventEmitter } from 'events';
import { VideoEncoder, VideoDecoder, AudioEncoder, AudioDecoder, MediaStreamTrack } from 'media-processing';
import {
  VP8Packetizer, VP8Depacketizer,
  VP9Packetizer, VP9Depacketizer,
  H264Packetizer, H264Depacketizer,
  AV1Packetizer, AV1Depacketizer,
  OpusPacketizer, OpusDepacketizer,
  JitterBuffer, parse as parseRtp,
} from 'rtp-packet';


/**
 * Video codec registry.
 *
 * Keyed by the codec name as it appears in SDP `a=rtpmap:PT NAME/CLOCK`.
 * Each entry has:
 *   - Packetizer   / Depacketizer      classes from rtp-packet
 *   - decoderCodec                      string passed to VideoDecoder.configure
 *   - parseKeyframeDims(data) → {width,height}|null
 *       Parse the first keyframe payload to learn coded dimensions. Required
 *       because WebCodecs VideoDecoder.configure() is required to know
 *       codedWidth/codedHeight up front.
 *   - requiresDescription    whether configure() needs a `description` blob
 *       (H264 AVCC format needs SPS/PPS; Annex-B does not)
 */
var VIDEO_CODECS = {
  VP8: {
    Packetizer:         VP8Packetizer,
    Depacketizer:       VP8Depacketizer,
    decoderCodec:       'vp8',
    parseKeyframeDims:  parseVp8KeyframeDimensions,
    requiresDescription: false,
  },
  VP9: {
    Packetizer:         VP9Packetizer,
    Depacketizer:       VP9Depacketizer,
    decoderCodec:       'vp09.00.10.08',  // profile 0, level 1.0, 8-bit
    parseKeyframeDims:  parseVp9KeyframeDimensions,
    requiresDescription: false,
  },
  H264: {
    Packetizer:         H264Packetizer,
    Depacketizer:       H264Depacketizer,
    decoderCodec:       'avc1.42E01F',   // baseline 3.1 — overridden by fmtp
    parseKeyframeDims:  parseH264KeyframeDimensions,
    requiresDescription: false,          // rtp-packet's depacketizer yields Annex-B
  },
  // AV1 — RFC 9798 RTP payload format. Like VP9, the bitstream carries
  // its own sequence header (OBU_SEQUENCE_HEADER), so the decoder reconfigures
  // itself; we don't need to parse keyframe dimensions out of the OBUs to
  // call decoder.configure(). Default 1280x720 is a reasonable starter
  // (matches what Chrome guesses for AV1 if no dims are supplied up-front).
  AV1: {
    Packetizer:         AV1Packetizer,
    Depacketizer:       AV1Depacketizer,
    decoderCodec:       'av01.0.04M.08',  // Main profile, level 4.0, 8-bit
    parseKeyframeDims:  parseAv1KeyframeDimensions,
    requiresDescription: false,
  },
};


/**
 * VP8 keyframe header parse (RFC 6386 §9.1).
 *
 *   byte 0 bit 0 : 0 = keyframe, 1 = interframe
 *   bytes 3..5   : start code, must be 9d 01 2a
 *   bytes 6..7   : width  (14 bits, little-endian)
 *   bytes 8..9   : height (14 bits, little-endian)
 */
function parseVp8KeyframeDimensions(data) {
  if (!data || data.length < 10) return null;
  if ((data[0] & 0x01) !== 0) return null;
  if (data[3] !== 0x9d || data[4] !== 0x01 || data[5] !== 0x2a) return null;
  var w = (data[6] | (data[7] << 8)) & 0x3FFF;
  var h = (data[8] | (data[9] << 8)) & 0x3FFF;
  if (w === 0 || h === 0) return null;
  return { width: w, height: h };
}


/**
 * VP9 keyframe header parse.
 * TODO Phase 1.5: real implementation. For now, returns a default so the
 * decoder gets configured; Chrome's VP9 decoder re-adapts from the bitstream
 * anyway. Users with non-default resolutions should request a reconfigure.
 */
function parseVp9KeyframeDimensions(data) {
  if (!data || data.length < 2) return null;
  // frame_marker (2 bits) must be 0b10
  if (((data[0] >> 6) & 0x03) !== 0x02) return null;
  // TODO: proper VP9 uncompressed header parse — for now return defaults.
  // Chrome's VP9 decoder sizes from the bitstream anyway, so 640x480 works
  // until we add the real parser.
  return { width: 640, height: 480 };
}


/**
 * H.264 keyframe header parse — looks for the first SPS NALU and reads
 * pic_width_in_mbs/pic_height_in_map_units.
 * TODO Phase 1.5: real implementation (Exp-Golomb decoding). For now, returns
 * a default. Chrome's H264 decoder reconfigures from the SPS in the bitstream.
 */
function parseH264KeyframeDimensions(data) {
  if (!data || data.length < 5) return null;
  // Annex-B: find NALU with type 7 (SPS). nal_unit_type = byte & 0x1F
  // TODO: scan for 00 00 00 01 or 00 00 01, find SPS, parse.
  return { width: 640, height: 480 };
}


/**
 * AV1 keyframe header parse — would walk OBUs to find OBU_SEQUENCE_HEADER
 * and decode max_frame_width_minus_1 / max_frame_height_minus_1.
 * TODO Phase 1.5: real implementation (LEB128 OBU sizes + Annex-B-like bit
 * decoding of the sequence header). Returns a sensible default until then.
 * Chrome's AV1 decoder reconfigures itself from OBU_SEQUENCE_HEADER in the
 * bitstream, so a 1280x720 default works as a bootstrap.
 */
function parseAv1KeyframeDimensions(data) {
  if (!data || data.length < 2) return null;
  // OBU header byte: forbidden_bit(0) | type(4) | extension(1) | has_size(1) | reserved(1)
  // No structural validation here yet; the bitstream override handles the real size.
  return { width: 1280, height: 720 };
}


// Defaults for Phase 1. A future setParameters() will make these dynamic.
var DEFAULT_BITRATE   = 1_000_000;
var DEFAULT_FRAMERATE = 30;
var DEFAULT_MTU       = 1200;

// Force a keyframe every N frames even without explicit request. This is a
// safety net: the receiver also requests keyframes via PLI/FIR when it needs
// to re-latch. libwebrtc's default is effectively "never" (~100s) — we pick
// something much shorter so a newly-joining receiver doesn't wait forever,
// but not so short that keyframe bursts dominate the wire.
//
// At 30 fps: 150 frames = 5 seconds.
// Keyframes are large (~10-30KB vs. ~2KB for delta frames). Every keyframe
// fans out to ~25 packets sent back-to-back, which stresses the send path
// and the remote jitter buffer. Keep the cadence as low as the worst-case
// receiver-join latency allows.
var KEYFRAME_INTERVAL_FRAMES = 150;


/**
 * Create a pipeline that forwards frames from `track` through an encoder
 * + packetizer + SRTP to the remote peer.
 *
 * @param {object} opts
 * @param {object} opts.track     MediaStreamTrack (from media-processing)
 * @param {object} opts.manager   ConnectionManager instance
 * @param {number} opts.ssrc      RTP SSRC for the outgoing stream
 * @param {number} [opts.payloadType=96]  RTP payload type
 * @param {string} [opts.codec='vp8']  Codec name — one of 'vp8'|'vp9'|'h264'|'av1'
 *                                     (case-insensitive). Used to pick both the
 *                                     packetizer (rtp-packet) and the WebCodecs
 *                                     encoder codec string.
 * @param {number} [opts.width]   Encoder width (defaults to track setting)
 * @param {number} [opts.height]  Encoder height (defaults to track setting)
 * @param {number} [opts.bitrate] Target bitrate in bps
 * @param {number} [opts.framerate] Target framerate
 * @returns {{stop: Function}}
 */
function createVideoSendPipeline(opts) {
  if (!opts || !opts.track || !opts.manager || opts.ssrc == null) {
    throw new Error('createVideoSendPipeline: track, manager, ssrc required');
  }

  var track       = opts.track;
  var manager     = opts.manager;
  var ssrc        = opts.ssrc;
  var payloadType = opts.payloadType != null ? opts.payloadType : 96;
  // Codec lookup: same VIDEO_CODECS table the receive side uses. Case-
  // insensitive on the input ('vp8' / 'VP8' / 'h264' / 'H264' all work).
  // Until SDP-driven negotiation is plumbed end-to-end (Phase 1.5), the
  // caller (api.js RTCRtpSender) defaults to 'vp8' to preserve existing
  // behavior — wire-format compatibility with an existing peer that's
  // expecting VP8 packetization is preserved.
  var codecName   = (opts.codec || 'vp8').toUpperCase();
  var codecInfo   = VIDEO_CODECS[codecName];
  if (!codecInfo) {
    throw new Error('createVideoSendPipeline: unsupported codec: ' + codecName);
  }
  // Starting bitrate/framerate come from either explicit opts, the
  // encoding parameters (maxBitrate/maxFramerate from RTCRtpSender), or
  // the codec defaults. maxBitrate=0 in the W3C RTCRtpEncodingParameters
  // spec means "unbounded", which we interpret as "use our default".
  var bitrate     = opts.bitrate   ||
                    (opts.maxBitrate   > 0 ? opts.maxBitrate   : DEFAULT_BITRATE);
  var framerate   = opts.framerate ||
                    (opts.maxFramerate > 0 ? opts.maxFramerate : DEFAULT_FRAMERATE);
  var scaleDown   = opts.scaleResolutionDownBy > 0 ? opts.scaleResolutionDownBy : 1;

  // Pull resolution from the track's settings if available, else defaults,
  // then apply scaleResolutionDownBy.
  var settings = (typeof track.getSettings === 'function') ? track.getSettings() : {};
  var width    = Math.round((opts.width  || settings.width  || 640) / scaleDown);
  var height   = Math.round((opts.height || settings.height || 480) / scaleDown);

  var packetizer = new codecInfo.Packetizer({
    ssrc:        ssrc,
    payloadType: payloadType,
    mtu:         DEFAULT_MTU,
    // RTP sequence-number continuity across pipeline restarts (e.g.
    // replaceTrack(track2) after replaceTrack(null)). The caller (api.js
    // RTCRtpSender) saves the last seq emitted before stopPipeline() and
    // passes (lastSeq + 1) here so the new pipeline picks up where the
    // old one left off — matching libwebrtc's RtpSender::SetTrack which
    // keeps the encoder/packetizer alive across track swaps.
    initialSequenceNumber: opts.initialSequenceNumber,
  });

  var frameCount = 0;   // counts frames fed to the encoder (for keyframe cadence)
  var stopped    = false;
  // When false, frames are dropped from the source AND chunks written to
  // `writable` are dropped. Controlled via setParameters()
  // (encodings[0].active) so callers can pause the stream without tearing
  // the pipeline down. Declared here (rather than next to the track
  // subscription below) so both _processChunkForSend and onFrame can see
  // it without relying on var hoisting.
  var active = true;

  // Encoded-streams state. Before takeStreams() is called, the encoder's
  // output feeds the packetizer directly (the "default pipe"). After
  // takeStreams(), the default pipe is broken:
  //   encoder output → readable (app reads it)
  //   writable      → packetizer + sendRtp (app writes it)
  // This lets the app transform chunks (E2EE, metadata, etc.) or just do
  // a pass-through with readable.pipeTo(writable).
  var streamsTaken = false;
  var _readableController = null;
  var readable = new ReadableStream({
    start: function (controller) { _readableController = controller; },
    cancel: function () {
      // If the app stops reading, we don't tear the pipeline down —
      // the writable side may still be in use (or a future pipeTo).
    },
  }, {
    // Bounded queue: roughly 1 second at 30 fps of encoded video. If the
    // app isn't reading, we'd rather drop encoded chunks than leak memory.
    // (Chrome's equivalent behaviour is implementation-defined; we choose
    // drop-newest.)
    highWaterMark: 30,
    size: function () { return 1; },
  });

  /**
   * Take a pre-encoded chunk and push it through packetizer + sendRtp.
   * The packetizer owns the SSRC and monotonic sequence state, so this
   * function enforces the spec-required "use sender's SSRC, not the
   * chunk's source SSRC" invariant automatically — we simply never look
   * at getMetadata().synchronizationSource on input chunks.
   *
   * Called from two sources:
   *   1. encoder.output (when the default pipe is active, before takeStreams)
   *   2. writable.write (after takeStreams; app-supplied chunks)
   */
  // Tracks whether ANY packet has been emitted on this pipeline. Used to
  // gate getLastSequenceNumber() — before the first packetize() call,
  // packetizer.sequenceNumber is the (random or caller-supplied) initial
  // value, not a "last emitted" value, so we mustn't treat it as one.
  var _packetsSent = 0;

  function _processChunkForSend(chunk) {
    if (stopped || !active) return;
    if (!manager.state.srtpSession) return;   // SRTP not ready — drop

    var o = manager.state.outboundStats[ssrc];
    if (!o) {
      o = manager.state.outboundStats[ssrc] = {
        packets: 0, bytes: 0, payloadType: payloadType,
        firstPacketAt: Date.now(), lastPacketAt: Date.now(),
      };
    }
    if (!o.framesEncoded) o.framesEncoded = 0;
    if (!o.keyFramesEncoded) o.keyFramesEncoded = 0;
    o.framesEncoded++;
    if (chunk.type === 'key') o.keyFramesEncoded++;
    o.targetBitrate = bitrate;
    o.frameWidth    = width;
    o.frameHeight   = height;
    o.framesPerSecond = framerate;

    var pkts;
    try {
      pkts = packetizer.packetize(chunk);
    } catch (e) {
      // A malformed chunk (bad data shape, wrong buffer type, etc.) must not
      // poison the whole stream — log and drop. When this callback is driven
      // from WritableStream.write(), throwing would put the stream into
      // 'errored' state permanently, locking out all future chunks.
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] packetize failed:', e && e.message || e);
      }
      return;
    }
    for (var i = 0; i < pkts.length; i++) {
      manager.sendRtp(pkts[i]);
      _packetsSent++;
    }
  }

  /**
   * Enqueue an encoder-produced chunk onto the app-facing readable. Called
   * only after takeStreams() — before that, chunks flow directly through
   * _processChunkForSend.
   */
  function _emitToReadable(chunk) {
    if (!_readableController) return;
    // Drop if the app isn't draining — prevents unbounded queue growth
    // when someone calls createEncodedStreams() without consuming.
    if (_readableController.desiredSize != null &&
        _readableController.desiredSize <= 0) return;
    // Build an RTCEncodedVideoFrame-shaped wrapper, matching the receive side.
    // getMetadata() surfaces the sender's SSRC (not a remote source SSRC),
    // which is the natural thing for a sender-side stream to report.
    var encoded = {
      type:      chunk.type,
      timestamp: chunk.timestamp,
      data:      chunk.data,
      getMetadata: function () {
        return {
          synchronizationSource: ssrc,
          payloadType:           payloadType,
          contributingSources:   [],
        };
      },
    };
    try { _readableController.enqueue(encoded); }
    catch (e) { /* controller may be closed */ }
  }

  var encoder = new VideoEncoder({
    output: function (chunk) {
      if (stopped) return;
      if (streamsTaken) {
        // Default pipe is broken — app controls chunks via writable.
        _emitToReadable(chunk);
      } else {
        _processChunkForSend(chunk);
      }
    },
    error: function (err) {
      // Encoder errors are not fatal for the connection — log and continue.
      // A persistent error will stall the stream but the PC stays up.
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] encoder error:', err && err.message || err);
      }
    },
  });

  // Normalize an incoming chunk's data field for the packetizer.
  //
  // rtp-packet (post-Uint8Array compat) accepts both Buffer and
  // Uint8Array natively and converts internally without a copy. The
  // only thing it doesn't accept is a raw ArrayBuffer (rare —
  // WebCodecs and most pipelines hand back typed-array views, not
  // detached ArrayBuffers). For that case we still need to wrap.
  // Other typed arrays (Int8Array, Uint16Array...) get re-viewed as
  // Uint8Array so the byte layout matches the packetizer's expectation.
  //
  // Returning null signals "unusable chunk, drop quietly".
  function _normalizeChunkData(data) {
    if (Buffer.isBuffer(data) || data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return Buffer.from(data);
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    return null;
  }

  // WritableStream sink that feeds the packetizer + sendRtp path. Accepts
  // RTCEncodedVideoFrame-shaped objects (same shape as the receiver's
  // readable emits). Pre-takeStreams this is wired but unused — the encoder
  // output goes directly to _processChunkForSend. Once the app calls
  // createEncodedStreams(), writable becomes the sole input path.
  var writable = new WritableStream({
    write: function (encoded) {
      if (stopped) return;
      if (!encoded) return;
      var buf = _normalizeChunkData(encoded.data);
      if (!buf) return;   // unsupported data type — drop
      // Normalize to packetizer shape. We intentionally do NOT copy the
      // chunk's synchronizationSource anywhere — packetizer injects its
      // own SSRC, and sequence numbers come from its internal counter.
      _processChunkForSend({
        data:      buf,
        type:      encoded.type,
        timestamp: encoded.timestamp,
      });
    },
    close: function () { /* no-op; sender lifecycle is managed by stop() */ },
    abort: function () { /* same */ },
  });

  encoder.configure({
    codec:                codecInfo.decoderCodec,
    width:                width,
    height:               height,
    bitrate:              bitrate,
    framerate:            framerate,
    latencyMode:          'realtime',
    hardwareAcceleration: 'prefer-software',
  });


  /* ── Frame subscription ─────────────────────────────────────────────── */

  // When true, the next outgoing frame is forced to be a keyframe. Used by
  // requestKeyFrame() in response to PLI/FIR from the remote receiver.
  var pendingKeyFrame = false;

  var onFrame = function (frame) {
    // QUICK-8: media-source.frames counts every frame originating from
    // the source, including ones we drop here (per W3C webrtc-stats:
    // "the total number of frames originating from this source").
    // Tick the counter before any drop checks.
    if (opts.onSourceFrame) {
      try { opts.onSourceFrame(); } catch (e) { /* never let stats throw into the pipeline */ }
    }
    if (stopped || !active) {
      // Must close the VideoFrame we received even when dropping, otherwise
      // the source's VideoFrame buffer pool starves.
      try { if (frame && typeof frame.close === 'function') frame.close(); } catch (e) {}
      return;
    }
    var forceKey = pendingKeyFrame || (frameCount % KEYFRAME_INTERVAL_FRAMES === 0);
    if (pendingKeyFrame) pendingKeyFrame = false;
    frameCount++;
    try {
      encoder.encode(frame, forceKey ? { keyFrame: true } : undefined);
    } catch (e) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] encode threw:', e && e.message || e);
      }
    }
  };

  var onTrackEnded = function () {
    stop();
  };

  track.on('frame', onFrame);
  track.on('ended', onTrackEnded);


  /* ── Keyframe requests from the remote peer ─────────────────────────── */
  // When the remote sends a PLI/FIR, connection_manager emits 'keyframe:request'
  // with the mid. We honor it by asking the encoder for a keyframe on the next
  // frame. (The encoder itself has no "send keyframe now" API; we piggy-back
  // on the next encode() call.)

  var onKeyframeRequest = function () {
    // Reset the counter so the next frame becomes a keyframe.
    frameCount = 0;
  };
  if (manager.ev && typeof manager.ev.on === 'function') {
    manager.ev.on('keyframe:request', onKeyframeRequest);
  }


  /* ── Cleanup ─────────────────────────────────────────────────────────── */

  function stop() {
    if (stopped) return;
    stopped = true;
    track.off('frame', onFrame);
    track.off('ended', onTrackEnded);
    if (manager.ev && typeof manager.ev.off === 'function') {
      manager.ev.off('keyframe:request', onKeyframeRequest);
    }
    try { encoder.close(); } catch (e) {}
    // Close the readable so any pending reader gets {done:true} instead of
    // hanging forever. Matches WHATWG Streams idiom on termination.
    if (_readableController) {
      try { _readableController.close(); } catch (e) {}
    }
  }

  // requestKeyFrame(): flip the pending flag so the next frame will be
  // encoded as a keyframe. Called when the receiver sends PLI/FIR asking
  // for an intra-frame to recover from packet loss.
  function requestKeyFrame() {
    pendingKeyFrame = true;
  }

  /**
   * Apply new encoding parameters to the live pipeline. Called by
   * RTCRtpSender.setParameters() or by an internal bandwidth-adaptive
   * loop. The encoder is re-configured per the WebCodecs spec, which
   * allows configure() to be called repeatedly.
   *
   * A keyframe is forced after the change so the decoder can latch onto
   * the new resolution/bitrate cleanly.
   *
   * @param {object} params
   *   maxBitrate:            number — bps. 0 means "unbounded" (use current)
   *   maxFramerate:          number — fps. 0 means "unbounded"
   *   scaleResolutionDownBy: number — divisor applied to native resolution
   *   active:                boolean — if false, stop encoding (pipeline
   *                                    stays allocated so we can resume)
   */
  function reconfigure(params) {
    if (stopped) return;
    params = params || {};

    var changed = false;
    // Track separately whether the change requires the decoder to re-latch
    // (i.e. a new keyframe). Only resolution changes need that — bitrate
    // and framerate are "soft" parameters that libvpx adjusts on the fly
    // without losing decoder state, and forcing a keyframe on every
    // adaptive bitrate nudge produces ~1 keyframe/sec bursts that
    // dominate the wire and cause the remote jitter buffer to see spikes.
    var needsKeyframe = false;

    if (typeof params.maxBitrate === 'number' && params.maxBitrate > 0 &&
        params.maxBitrate !== bitrate) {
      bitrate = params.maxBitrate;
      changed = true;
    }
    if (typeof params.maxFramerate === 'number' && params.maxFramerate > 0 &&
        params.maxFramerate !== framerate) {
      framerate = params.maxFramerate;
      changed = true;
    }
    if (typeof params.scaleResolutionDownBy === 'number' &&
        params.scaleResolutionDownBy > 0 &&
        params.scaleResolutionDownBy !== scaleDown) {
      scaleDown = params.scaleResolutionDownBy;
      var nativeW = (settings && settings.width)  || 640;
      var nativeH = (settings && settings.height) || 480;
      width  = Math.round(nativeW / scaleDown);
      height = Math.round(nativeH / scaleDown);
      changed = true;
      needsKeyframe = true;   // new dimensions → decoder must re-latch
    }
    if (typeof params.active === 'boolean') {
      active = params.active;
      // 'active' gating happens at the per-frame check; no encoder
      // reconfigure needed when toggling it.
    }

    if (changed) {
      try {
        encoder.configure({
          codec:                codecInfo.decoderCodec,
          width:                width,
          height:               height,
          bitrate:              bitrate,
          framerate:            framerate,
          latencyMode:          'realtime',
          hardwareAcceleration: 'prefer-software',
        });
        // Only force a keyframe for resolution changes. Bitrate/framerate
        // adjustments alone don't require one.
        if (needsKeyframe) pendingKeyFrame = true;
      } catch (e) {
        if (typeof console !== 'undefined' && console.error) {
          console.error('[media_pipeline] encoder.configure failed:', e && e.message || e);
        }
      }
    }
  }

  /**
   * Encoded-streams handoff (called by RTCRtpSender.createEncodedStreams).
   * Per spec, can only be called once per sender. After this call:
   *   - encoder output stops flowing directly to the wire; it enters
   *     `readable` instead
   *   - `writable` becomes the sole input to the packetizer + sendRtp path
   *   - the app is responsible for wiring readable → writable (either
   *     directly, or through a transform)
   */
  function takeStreams() {
    if (streamsTaken) {
      throw new Error('createEncodedStreams can only be called once');
    }
    streamsTaken = true;
    return { readable: readable, writable: writable };
  }

  return {
    stop:            stop,
    requestKeyFrame: requestKeyFrame,
    reconfigure:     reconfigure,
    readable:        readable,
    writable:        writable,
    takeStreams:     takeStreams,
    // Expose the packetizer's running 16-bit RTP seq counter so the
    // RTCRtpSender wrapper can hold the last-emitted seq across a
    // pipeline restart (replaceTrack flow). packetizer.sequenceNumber is
    // the NEXT seq to emit; subtract 1 (mod 65536) to get the last sent.
    // Returns null if nothing has been packetized yet on this pipeline.
    getLastSequenceNumber: function () {
      if (!packetizer || packetizer.sequenceNumber == null) return null;
      // Initial value (before any packetize call) === initialSequenceNumber
      // if provided, else a random initial. Either way "next" minus one is
      // the last actually emitted, modulo 16-bit wrap. We only return a
      // meaningful value if we know packets were actually sent; the
      // _packetsSent counter handles that gate.
      if (!_packetsSent) return null;
      return (packetizer.sequenceNumber - 1) & 0xFFFF;
    },
  };
}


/**
 * Multi-layer (simulcast) video send pipeline.
 *
 * Creates N parallel single-layer pipelines, one per encoding. A single
 * track subscription feeds all N — each incoming frame is cloned for each
 * encoder (RFC 7667 §3.7). Per-layer state (encoder, packetizer, SSRC,
 * RID, scale, bitrate) stays encapsulated in the child pipelines.
 *
 * This is Chrome's native approach for VP8/H264: N separate encoders, each
 * producing its own resolution/bitrate. For VP9/AV1 with scalabilityMode,
 * a single encoder with temporal/spatial layers would be more efficient,
 * but we don't cover that yet — layers[i].scalabilityMode is stored and
 * passed through for future use.
 *
 * API mirrors the single-layer pipeline so RTCRtpSender can use either
 * without branching: stop, requestKeyFrame, reconfigure (targets layer[0]
 * for compat), plus a new reconfigureLayer(rid, params) for per-layer
 * control, and reads the shared readable/writable off layer[0].
 *
 * @param {object} opts
 * @param {MediaStreamTrack} opts.track
 * @param {object} opts.manager
 * @param {Array} opts.layers  — [{rid, ssrc, rtxSsrc, scaleResolutionDownBy,
 *                               maxBitrate, maxFramerate, active,
 *                               scalabilityMode}, ...]
 * @param {number} [opts.payloadType=96]
 * @param {string} [opts.codec='vp8']  Codec name, forwarded to every layer
 *                                     pipeline (all simulcast layers share
 *                                     the same codec by definition).
 * @returns {object} — stop, requestKeyFrame, reconfigure, reconfigureLayer,
 *                    readable, writable, takeStreams
 */
function createVideoSendSimulcastPipeline(opts) {
  if (!opts || !opts.track || !opts.manager || !Array.isArray(opts.layers) || !opts.layers.length) {
    throw new Error('createVideoSendSimulcastPipeline: track, manager, layers required');
  }

  var track       = opts.track;
  var layerConfigs = opts.layers;
  var stopped     = false;

  // One sub-EventEmitter per layer. Each one acts as the layer-pipeline's
  // "track source" — when the shared track fires 'frame', we emit on each
  // sub-emitter with a cloned frame. The single-layer pipeline subscribes
  // to sub-emitter's 'frame' the same way it would to a real track, so
  // no branching in createVideoSendPipeline.
  var subEmitters = layerConfigs.map(function () { return new EventEmitter(); });

  // Dispatcher: fan out each incoming frame to all layers. We clone the
  // frame N-1 times and pass the original to the last subscriber so one
  // reference stays un-cloned (marginal optimization).
  var mainOnFrame = function (frame) {
    // QUICK-8: count once per source frame, regardless of how many layers
    // we fan out to. Done in the outer dispatcher (here) and explicitly
    // NOT passed down to sub-pipelines, otherwise N layers → N counts per
    // source frame. Tick before any drop check (see single-layer onFrame
    // for the spec rationale).
    if (opts.onSourceFrame) {
      try { opts.onSourceFrame(); } catch (e) { /* never let stats throw */ }
    }
    if (stopped) {
      try { if (frame && typeof frame.close === 'function') frame.close(); } catch (e) {}
      return;
    }
    for (var i = 0; i < subEmitters.length; i++) {
      var f = (i === subEmitters.length - 1)
              ? frame
              : (typeof frame.clone === 'function' ? frame.clone() : frame);
      subEmitters[i].emit('frame', f);
    }
  };
  var mainOnEnded = function () {
    for (var i = 0; i < subEmitters.length; i++) subEmitters[i].emit('ended');
  };
  track.on('frame', mainOnFrame);
  track.on('ended', mainOnEnded);

  // Build one sub-pipeline per layer. Each gets a fake track that forwards
  // its sub-emitter's events.
  var layerPipelines = [];
  for (var i = 0; i < layerConfigs.length; i++) {
    var lc = layerConfigs[i];
    var em = subEmitters[i];
    var fakeTrack = (function (emitter) {
      return {
        kind: 'video',
        on:  function (ev, fn) { emitter.on(ev, fn); },
        off: function (ev, fn) { emitter.off(ev, fn); },
        getSettings: function () {
          return (typeof track.getSettings === 'function') ? track.getSettings() : {};
        },
      };
    })(em);

    layerPipelines.push(createVideoSendPipeline({
      track:                 fakeTrack,
      manager:               opts.manager,
      ssrc:                  lc.ssrc,
      rtxSsrc:               lc.rtxSsrc,
      rid:                   lc.rid,
      payloadType:           opts.payloadType != null ? opts.payloadType : 96,
      // Simulcast layers all share the same codec — that's the whole
      // point of simulcast (multiple resolutions, one codec). Forward
      // the parent's codec selection so each layer's sub-pipeline picks
      // the right Packetizer.
      codec:                 opts.codec,
      maxBitrate:            lc.maxBitrate || 0,
      maxFramerate:          lc.maxFramerate || 0,
      scaleResolutionDownBy: lc.scaleResolutionDownBy || 1,
      scalabilityMode:       lc.scalabilityMode || null,
      // Per-layer RTP sequence-number continuity. Caller (api.js) supplies
      // a Map keyed by rid (or by layer SSRC) of last-emitted seq from a
      // previous pipeline; we look up this layer's entry by its rid.
      initialSequenceNumber: opts.initialSequenceNumbers &&
                             opts.initialSequenceNumbers[lc.rid] != null
                             ? opts.initialSequenceNumbers[lc.rid]
                             : undefined,
    }));
  }

  function findLayerIdx(rid) {
    for (var i = 0; i < layerConfigs.length; i++) {
      if (layerConfigs[i].rid === rid) return i;
    }
    return -1;
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    track.off('frame', mainOnFrame);
    track.off('ended', mainOnEnded);
    for (var i = 0; i < layerPipelines.length; i++) {
      try { layerPipelines[i].stop(); } catch (e) {}
    }
  }

  function requestKeyFrame() {
    // Blanket — triggers all layers. Used when the caller doesn't know
    // (or care) which layer needs the keyframe. A remote PLI will take
    // the more surgical requestKeyFrameForRid path instead.
    for (var i = 0; i < layerPipelines.length; i++) {
      try { layerPipelines[i].requestKeyFrame(); } catch (e) {}
    }
  }

  function requestKeyFrameForRid(rid) {
    // Surgical: only the matching layer emits a keyframe. Prevents
    // over-keyframing (3× unnecessary I-frames) when a remote PLI
    // targets one specific simulcast layer.
    var idx = findLayerIdx(rid);
    if (idx >= 0) {
      try { layerPipelines[idx].requestKeyFrame(); } catch (e) {}
    }
  }

  function reconfigure(params) {
    // Legacy single-layer reconfigure path — applies to layer[0]. Callers
    // who want per-layer control should use reconfigureLayer(rid, params).
    if (layerPipelines.length > 0 && typeof layerPipelines[0].reconfigure === 'function') {
      layerPipelines[0].reconfigure(params);
    }
  }

  function reconfigureLayer(rid, params) {
    var idx = findLayerIdx(rid);
    if (idx < 0) {
      throw new Error('reconfigureLayer: no layer with rid "' + rid + '"');
    }
    if (typeof layerPipelines[idx].reconfigure === 'function') {
      layerPipelines[idx].reconfigure(params);
    }
  }

  // Encoded streams for simulcast — layer[0]'s readable/writable serve the
  // primary layer. Per-layer access for apps that want all layers will be
  // added when there's a concrete use case; today the common patterns
  // (transform on the primary, pass-through) work with just layer[0].
  return {
    stop:                  stop,
    requestKeyFrame:       requestKeyFrame,
    requestKeyFrameForRid: requestKeyFrameForRid,
    reconfigure:           reconfigure,
    reconfigureLayer:      reconfigureLayer,
    readable:              layerPipelines[0].readable,
    writable:              layerPipelines[0].writable,
    takeStreams:           function () { return layerPipelines[0].takeStreams(); },
    // Per-layer last-emitted RTP seq, keyed by rid. Used by RTCRtpSender
    // (api.js) to preserve sequence continuity across pipeline restarts
    // (replaceTrack flow). null entries are omitted.
    getLastSequenceNumbers: function () {
      var m = {};
      for (var i = 0; i < layerPipelines.length; i++) {
        var lp = layerPipelines[i];
        var rid = layerConfigs[i].rid;
        if (rid && typeof lp.getLastSequenceNumber === 'function') {
          var seq = lp.getLastSequenceNumber();
          if (seq != null) m[rid] = seq;
        }
      }
      return m;
    },
  };
}


export {
  createVideoSendPipeline,
  createVideoSendSimulcastPipeline,
  createVideoReceivePipeline,
  createVideoReceiveSimulcastPipeline,
  createAudioSendPipeline,
  createAudioReceivePipeline,
};


/* ══════════════════════════════════════════════════════════════════════
 *                             AUDIO (Opus)
 * ══════════════════════════════════════════════════════════════════════ */

var AUDIO_CODECS = {
  OPUS: {
    Packetizer:   OpusPacketizer,
    Depacketizer: OpusDepacketizer,
    decoderCodec: 'opus',
    clockRate:    48000,
    numberOfChannels: 2,
  },
};


/**
 * Create a pipeline that feeds encoded Opus audio from a MediaStreamTrack
 * through the packetizer and out via manager.sendRtp().
 *
 * Audio tracks emit 'data' events (not 'frame' — that's video) with
 * AudioData-shaped objects from media-processing.
 *
 * @param {object} opts
 * @param {object} opts.track       MediaStreamTrack (audio kind)
 * @param {object} opts.manager     ConnectionManager
 * @param {number} opts.ssrc        Outgoing SSRC
 * @param {number} [opts.payloadType=111]   Opus default PT in WebRTC
 * @param {number} [opts.bitrate=40000]
 * @returns {{stop: Function}}
 */
function createAudioSendPipeline(opts) {
  if (!opts || !opts.track || !opts.manager || opts.ssrc == null) {
    throw new Error('createAudioSendPipeline: track, manager, ssrc required');
  }

  var track       = opts.track;
  var manager     = opts.manager;
  var ssrc        = opts.ssrc;
  var payloadType = opts.payloadType != null ? opts.payloadType : 111;
  // Starting bitrate: explicit opts.bitrate, else maxBitrate from
  // RTCRtpSender (if > 0), else Opus default. Opus supports 6-510 kbps.
  var bitrate     = opts.bitrate ||
                    (opts.maxBitrate > 0 ? opts.maxBitrate : 40000);

  var codecInfo = AUDIO_CODECS.OPUS;

  var packetizer = new codecInfo.Packetizer({
    ssrc:        ssrc,
    payloadType: payloadType,
    // RTP sequence-number continuity across pipeline restarts (see the
    // video send pipeline for the full rationale — same flow for audio).
    initialSequenceNumber: opts.initialSequenceNumber,
  });

  var stopped = false;
  var active  = true;

  // Encoded-streams state — same pattern as video send pipeline. See the
  // detailed comment there; for audio there are no keyframes, so the
  // handoff is even simpler: encoder produces Opus frames, either they
  // flow straight to packetizer (default) or app intercepts them.
  var streamsTaken = false;
  var _readableController = null;
  var readable = new ReadableStream({
    start: function (controller) { _readableController = controller; },
    cancel: function () { /* sender lifecycle stays with stop() */ },
  }, {
    // Bounded queue: roughly 1 second at 50 pps of Opus frames (20ms each).
    // If the app isn't reading, drop rather than leak.
    highWaterMark: 50,
    size: function () { return 1; },
  });

  // Tracks whether ANY packet has been emitted on this pipeline. Used to
  // gate getLastSequenceNumber() — see video send for rationale.
  var _packetsSent = 0;

  function _processChunkForSend(chunk) {
    if (stopped || !active) return;
    if (!manager.state.srtpSession) return;
    var pkts;
    try {
      pkts = packetizer.packetize(chunk);
    } catch (e) {
      // See video send's equivalent: a bad chunk in writable must not
      // error the stream permanently.
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] audio packetize failed:', e && e.message || e);
      }
      return;
    }
    for (var i = 0; i < pkts.length; i++) {
      manager.sendRtp(pkts[i]);
      _packetsSent++;
    }
  }

  function _emitToReadable(chunk) {
    if (!_readableController) return;
    if (_readableController.desiredSize != null &&
        _readableController.desiredSize <= 0) return;
    var encoded = {
      type:      chunk.type || 'key',   // Opus frames are all "key" (no inter)
      timestamp: chunk.timestamp,
      data:      chunk.data,
      getMetadata: function () {
        return {
          synchronizationSource: ssrc,
          payloadType:           payloadType,
          contributingSources:   [],
        };
      },
    };
    try { _readableController.enqueue(encoded); }
    catch (e) { /* controller may be closed */ }
  }

  var encoder = new AudioEncoder({
    output: function (chunk) {
      if (stopped) return;
      if (streamsTaken) _emitToReadable(chunk);
      else              _processChunkForSend(chunk);
    },
    error: function (err) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] audio encoder error:', err && err.message || err);
      }
    },
  });

  // See video sender's equivalent for the rationale. Same logic — only
  // raw ArrayBuffer needs explicit conversion now that rtp-packet
  // accepts Buffer and Uint8Array natively.
  function _normalizeChunkData(data) {
    if (Buffer.isBuffer(data) || data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return Buffer.from(data);
    if (ArrayBuffer.isView(data)) {
      return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    return null;
  }

  var writable = new WritableStream({
    write: function (encoded) {
      if (stopped) return;
      if (!encoded) return;
      var buf = _normalizeChunkData(encoded.data);
      if (!buf) return;
      _processChunkForSend({
        data:      buf,
        type:      encoded.type,
        timestamp: encoded.timestamp,
      });
    },
    close: function () {},
    abort: function () {},
  });

  encoder.configure({
    codec:            codecInfo.decoderCodec,
    sampleRate:       codecInfo.clockRate,
    numberOfChannels: codecInfo.numberOfChannels,
    bitrate:          bitrate,
  });

  var onData = function (audioData) {
    if (stopped || !active) {
      try { if (audioData && typeof audioData.close === 'function') audioData.close(); } catch (e) {}
      return;
    }
    try { encoder.encode(audioData); }
    catch (e) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] audio encode threw:', e && e.message || e);
      }
    }
  };

  var onTrackEnded = function () { stop(); };
  track.on('data', onData);
  track.on('ended', onTrackEnded);

  function stop() {
    if (stopped) return;
    stopped = true;
    track.off('data', onData);
    track.off('ended', onTrackEnded);
    try { encoder.close(); } catch (e) {}
    if (_readableController) {
      try { _readableController.close(); } catch (e) {}
    }
  }

  /**
   * Change encoding parameters on the fly. Called by RTCRtpSender.
   * setParameters() or an adaptive bandwidth loop. Opus supports
   * bitrate changes in-place without re-init, but AudioEncoder.configure()
   * is the WebCodecs spec path so we use it.
   */
  function reconfigure(params) {
    if (stopped) return;
    params = params || {};

    var changed = false;
    if (typeof params.maxBitrate === 'number' && params.maxBitrate > 0 &&
        params.maxBitrate !== bitrate) {
      bitrate = params.maxBitrate;
      changed = true;
    }
    if (typeof params.active === 'boolean') active = params.active;

    if (changed) {
      try {
        encoder.configure({
          codec:            codecInfo.decoderCodec,
          sampleRate:       codecInfo.clockRate,
          numberOfChannels: codecInfo.numberOfChannels,
          bitrate:          bitrate,
        });
      } catch (e) {
        if (typeof console !== 'undefined' && console.error) {
          console.error('[media_pipeline] audio encoder.configure failed:', e && e.message || e);
        }
      }
    }
  }

  function takeStreams() {
    if (streamsTaken) {
      throw new Error('createEncodedStreams can only be called once');
    }
    streamsTaken = true;
    return { readable: readable, writable: writable };
  }

  return {
    stop:        stop,
    reconfigure: reconfigure,
    readable:    readable,
    writable:    writable,
    takeStreams: takeStreams,
    // See video send pipeline's getLastSequenceNumber.
    getLastSequenceNumber: function () {
      if (!packetizer || packetizer.sequenceNumber == null) return null;
      if (!_packetsSent) return null;
      return (packetizer.sequenceNumber - 1) & 0xFFFF;
    },
  };
}


/**
 * Create a pipeline that receives Opus RTP, depacketizes, and exposes
 * WHATWG streams + auto-decoding to the track.
 *
 * Same shape as createVideoReceivePipeline — audio has no keyframes so
 * the decoder can be configured immediately.
 *
 * @returns {object}
 *    stop, readable, writable, takeStreams — same contract as video
 */
function createAudioReceivePipeline(opts) {
  if (!opts || !opts.track || !opts.manager || opts.ssrc == null) {
    throw new Error('createAudioReceivePipeline: track, manager, ssrc required');
  }

  var track   = opts.track;
  var manager = opts.manager;
  var ssrc    = opts.ssrc;

  var codecInfo = AUDIO_CODECS.OPUS;

  var stopped          = false;
  var streamsTaken     = false;
  var autoDecodeActive = false;
  var decoder          = null;


  /* ── Depacketizer ──────────────────────────────────────────────────── */

  var depacketizer = new codecInfo.Depacketizer({
    output: function (chunk) {
      if (stopped) return;
      if (streamsTaken || opts.autoDecode === false) {
        _enqueueToReadable(chunk);
      } else {
        _decodeChunkDirect(chunk);
      }
    },
    error: function (err) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] audio depacketizer:', err && err.message || err);
      }
    },
  });


  /* ── JitterBuffer ───────────────────────────────────────────────────── */

  var jitterBuffer = new JitterBuffer({
    latency: opts.jitterLatencyMs != null ? opts.jitterLatencyMs : 20,
    output:  function (parsedPacket) {
      if (stopped) return;
      try { depacketizer.depacketize(parsedPacket); }
      catch (e) {}
    },
    onLoss: function (lostSeq, count) {
      // Record packet-concealment events. Opus has built-in PLC (packet
      // loss concealment) in the decoder, which is triggered by passing
      // null/empty data — but our depacketizer skips lost packets so the
      // decoder never sees them. For telemetry purposes we still count
      // them: each lost packet represents ~20ms of concealed/dropped
      // audio (Opus default frame length).
      var lostCount = count || 1;
      var FRAME_MS = 20;  // Opus minptime from negotiated fmtp
      manager.updatePlayoutStats('audio', {
        synthesizedSamplesEvents:   lostCount,
        synthesizedSamplesDuration: (lostCount * FRAME_MS) / 1000,
      });
    },
  });


  /* ── ReadableStream of encoded audio chunks ────────────────────────── */

  var _readableController = null;

  var readable = new ReadableStream({
    start: function (controller) { _readableController = controller; },
    cancel: function () { if (!autoDecodeActive) stop(); },
  });

  function _enqueueToReadable(chunk) {
    if (!_readableController) return;
    var encoded = {
      type:      'key',                     // Opus frames are all self-contained
      timestamp: chunk.timestamp,
      // WebRTC Opus uses a 20ms ptime by default (negotiated via
      // a=fmtp:111 minptime=10;useinbandfec=1). The decoder uses
      // `duration` to size each OGG page's granule advancement — if
      // we were wrong here by a factor of 2, the stream's apparent
      // timing would drift, but Opus frames are still decodable as
      // long as the framing is preserved.
      duration:  20000,                     // microseconds
      data:      chunk.data,
      getMetadata: function () {
        return {
          synchronizationSource: ssrc,
          payloadType:           chunk.payloadType || 111,
          contributingSources:   [],
        };
      },
    };
    try { _readableController.enqueue(encoded); }
    catch (e) {}
  }


  /* ── WritableStream → decoder ──────────────────────────────────────── */

  var writable = new WritableStream({
    write: function (encoded) {
      if (stopped) return;
      _ensureDecoder();
      try { decoder.decode(encoded); }
      catch (e) {
        if (typeof console !== 'undefined' && console.error) {
          console.error('[media_pipeline] audio decode threw:', e && e.message || e);
        }
      }
    },
    close: function () {
      if (decoder) { try { decoder.close(); } catch (e) {} decoder = null; }
    },
    abort: function () {
      if (decoder) { try { decoder.close(); } catch (e) {} decoder = null; }
    },
  });

  function _ensureDecoder() {
    if (decoder) return;
    decoder = new AudioDecoder({
      output: function (audioData) {
        if (stopped) return;

        // Playout telemetry — each AudioData carries numberOfFrames samples
        // per channel. We report the mono-equivalent sample count (frames,
        // not frames × channels — per W3C spec, totalSamplesCount is the
        // audio-frame count) and the playout duration (frames / sampleRate).
        // totalPlayoutDelay accumulates per-emission — a simple
        // approximation of the jitter-buffer latency contributed to this
        // frame, using the configured jitter buffer latency.
        try {
          if (audioData && audioData.numberOfFrames && audioData.sampleRate) {
            var durationSec = audioData.numberOfFrames / audioData.sampleRate;
            // Approximate per-frame playout delay as the configured
            // jitter-buffer latency (seconds). Accumulates so getStats
            // divides by totalSamplesCount to get average.
            var latencySec = (opts.jitterLatencyMs || 20) / 1000;
            manager.updatePlayoutStats('audio', {
              totalSamplesCount:     audioData.numberOfFrames,
              totalSamplesDuration:  durationSec,
              totalPlayoutDelay:     latencySec * audioData.numberOfFrames,
            });
          }
        } catch (e) {}

        try { track._push(audioData); }
        catch (e) {}
      },
      error: function (err) {
        if (typeof console !== 'undefined' && console.error) {
          console.error('[media_pipeline] audio decoder error:', err && err.message || err);
        }
      },
    });
    decoder.configure({
      codec:            codecInfo.decoderCodec,
      sampleRate:       codecInfo.clockRate,
      numberOfChannels: codecInfo.numberOfChannels,
      // WebRTC delivers Opus as raw frames in the RTP payload (RFC 7587),
      // not as an OGG/WebM-wrapped container stream. Tell the decoder
      // to expect raw frames so it can internally wrap them in OGG
      // before handing to FFmpeg — FFmpeg's decoder pipeline requires
      // a container, there is no supported way to feed it raw Opus
      // packets via stdin directly.
      rawFrames:        true,
    });
  }


  /* ── Auto-decode wiring ─────────────────────────────────────────────── */
  //
  // When autoDecode is on (default) and streamsTaken is still false, the
  // depacketizer output goes directly to _decodeChunkDirect — it bypasses
  // the readable entirely. This keeps the readable UNLOCKED so a later
  // takeStreams() can safely return { readable, writable } for the app
  // to consume.
  //
  // Once takeStreams() is called (or opts.autoDecode === false), chunks
  // flow into the readable instead. The app takes over — typically by
  // piping readable (optionally through a transform) to writable, which
  // will feed the decoder via _ensureDecoder.

  function _decodeChunkDirect(chunk) {
    if (stopped) return;
    _ensureDecoder();
    try { decoder.decode(chunk); }
    catch (e) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] decoder.decode threw:', e && e.message || e);
      }
    }
  }
  autoDecodeActive = (opts.autoDecode !== false);


  /* ── Incoming packet subscription ───────────────────────────────────── */

  var onRtp = function (rtpBuf, rinfo, info) {
    if (stopped) return;
    if (info.ssrc !== ssrc) return;
    var parsed = parseRtp(rtpBuf);
    if (!parsed) return;
    jitterBuffer.push(parsed);
  };

  // RTT updates from RTCP exchange. The jitter buffer uses RTT to
  // extend its loss-declaration wait window so RTX-recovered packets
  // can slot back into order before we give up on them. Without this
  // hookup, a packet loss followed by a successful RTX retransmission
  // would still result in a declared loss because the RTX arrives
  // after the fixed jitter latency expired.
  var onRttUpdate = function (rttMs) {
    if (stopped) return;
    if (jitterBuffer && typeof jitterBuffer.setRtt === 'function') {
      jitterBuffer.setRtt(rttMs);
    }
  };

  if (manager.ev && typeof manager.ev.on === 'function') {
    manager.ev.on('rtp', onRtp);
    manager.ev.on('rtt:update', onRttUpdate);
  }

  var onTrackEnded = function () { stop(); };
  track.on('ended', onTrackEnded);


  function stop() {
    if (stopped) return;
    stopped = true;
    if (manager.ev && typeof manager.ev.off === 'function') {
      manager.ev.off('rtp', onRtp);
      manager.ev.off('rtt:update', onRttUpdate);
    }
    track.off('ended', onTrackEnded);
    try { jitterBuffer.close(); } catch (e) {}
    try { depacketizer.close(); } catch (e) {}
    try { if (_readableController) _readableController.close(); } catch (e) {}
    if (decoder) { try { decoder.close(); } catch (e) {} decoder = null; }
  }

  function takeStreams() {
    if (streamsTaken) throw new Error('createEncodedStreams can only be called once');
    streamsTaken = true;
    return { readable: readable, writable: writable };
  }

  return {
    stop:        stop,
    readable:    readable,
    writable:    writable,
    takeStreams: takeStreams,
  };
}


/**
 * Create a pipeline that receives RTP packets, reassembles encoded chunks,
 * and exposes them as a standard WHATWG ReadableStream (per the WebRTC
 * Encoded Transforms / Insertable Streams spec).
 *
 * The pipeline owns:
 *   - a JitterBuffer     (reorders packets, detects loss)
 *   - a Depacketizer     (reassembles encoded chunks from RTP)
 *   - a ReadableStream   (emits RTCEncodedVideoFrame-shaped objects)
 *   - a WritableStream   (sink; frames written here go to the decoder)
 *   - a VideoDecoder     (LAZY — built only when a decoder is actually needed)
 *
 * Wiring model:
 *
 *   RTP ─► JitterBuffer ─► Depacketizer ─► readable
 *                                             │
 *                                  user code decides: ───────────────────┐
 *                                                                        │
 *                    ┌───────────────────────────────────────────────────┤
 *                    │                                                   │
 *             readable.pipeTo(writable)                         reader.read() loop
 *                    │                                          (user takes chunks,
 *                    ▼                                           no decode, no track
 *             VideoDecoder ─► VideoFrame ─► track._push                  ├──  frames)
 *                                                                        │
 *                                                                        ▼
 *                                                              (user could also
 *                                                               forward chunks to
 *                                                               another peer, etc.)
 *
 * Defaults:
 *   - If the user attaches a `frame` listener to the track OR calls
 *     `receiver.track`-related APIs, we assume they want decoded frames and
 *     implicitly set up `readable.pipeTo(writable)`. This matches the default
 *     behavior of `RTCPeerConnection` without any transform.
 *   - If the user calls `receiver.createEncodedStreams()` and processes the
 *     readable themselves, the default auto-decode is NOT set up. They can
 *     opt into decoding by piping to writable.
 *
 * @param {object} opts
 * @param {object} opts.track     MediaStreamTrack to push decoded frames to
 * @param {object} opts.manager   ConnectionManager instance
 * @param {number} opts.ssrc      Remote RTP SSRC for this stream
 * @param {string} [opts.codec]   Codec name ('vp8'). Default 'vp8'.
 * @param {number} [opts.jitterLatencyMs=50]
 * @returns {object}
 *    stop            — tear down pipeline
 *    readable        — ReadableStream of encoded chunks
 *    writable        — WritableStream sink (feeds internal decoder)
 *    takeStreams     — called ONCE by createEncodedStreams(); returns
 *                      { readable, writable } and disables auto-decode.
 *                      Subsequent calls throw per spec.
 */
function createVideoReceivePipeline(opts) {
  if (!opts || !opts.track || !opts.manager || opts.ssrc == null) {
    throw new Error('createVideoReceivePipeline: track, manager, ssrc required');
  }

  var track   = opts.track;
  var manager = opts.manager;
  var ssrc    = opts.ssrc;
  var codecName = (opts.codec || 'vp8').toUpperCase();

  var codecInfo = VIDEO_CODECS[codecName];
  if (!codecInfo) {
    throw new Error('createVideoReceivePipeline: unsupported codec: ' + codecName);
  }

  var stopped             = false;
  var streamsTaken        = false;   // set true after createEncodedStreams()
  var autoDecodeActive    = false;   // true when we've wired readable→writable
  var decoderConfigured   = false;
  var decoder             = null;    // lazy — built on first write to writable


  /* ── Depacketizer ──────────────────────────────────────────────────── */
  //
  // Depacketizer emits encoded chunks. Their destination depends on mode:
  //   • Default (autoDecode, pre-takeStreams): chunks go STRAIGHT to the
  //     decoder — the readable is unused. Avoids locking the readable by
  //     an internal pipeTo, which would make takeStreams() unusable.
  //   • After takeStreams() or when opts.autoDecode === false: chunks go
  //     into the readable. The app pipes readable to writable (via a
  //     transform or directly) to feed the decoder.

  var depacketizer = new codecInfo.Depacketizer({
    output: function (chunk) {
      if (stopped) return;
      // Always enqueue to readable: encoded chunks are always available
      // for SFU forwarding, RTP rewriting, or any other in-flight use
      // case. The readable's bounded queue drops if the app isn't
      // reading, so the overhead is just an object alloc when no
      // consumer is attached. This unlocks the API-9 "SFU forwarding
      // without decode" pattern: the app reads encoded chunks via
      // pipeline.readable while leaving the track unattached, so the
      // lazy decoder never spins up.
      _enqueueToReadable(chunk);
      // Decode only in the default auto-decode mode — and even then,
      // _decodeChunkDirect bails if the track has no sink (lazy decode,
      // mirroring Chrome). After takeStreams() the decoder is fed by
      // the app via writable instead.
      if (!streamsTaken && opts.autoDecode !== false) {
        _decodeChunkDirect(chunk);
      }
    },
    error: function (err) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] depacketizer:', err && err.message || err);
      }
    },
  });


  /* ── JitterBuffer ───────────────────────────────────────────────────── */

  var jitterBuffer = new JitterBuffer({
    latency: opts.jitterLatencyMs != null ? opts.jitterLatencyMs : 50,
    output:  function (parsedPacket) {
      if (stopped) return;
      try { depacketizer.depacketize(parsedPacket); }
      catch (e) { /* depacketizer already reports via error callback */ }
    },
    onLoss: function (/* seq */) {
      // TODO Phase 6: send PLI via manager.requestKeyframe(mid).
    },
  });


  /* ── ReadableStream of encoded chunks ──────────────────────────────── */
  // Per spec, these are RTCEncodedVideoFrame-shaped objects. Used only
  // when streamsTaken === true OR opts.autoDecode === false — otherwise
  // depacketizer output goes straight to the decoder and the readable
  // stays empty.

  var _readableController = null;

  var readable = new ReadableStream({
    start: function (controller) { _readableController = controller; },
    cancel: function () {
      // App stopped reading — pipeline lifecycle is still tied to the
      // track and explicit stop(). Don't tear down here.
    },
  }, {
    // Bounded queue — if the app isn't draining, drop rather than leak.
    // ~1 second at 30 fps of encoded video.
    highWaterMark: 30,
    size: function () { return 1; },
  });

  function _enqueueToReadable(chunk) {
    if (!_readableController) return;
    // Drop if the app isn't draining — prevents unbounded queue growth.
    if (_readableController.desiredSize != null &&
        _readableController.desiredSize <= 0) return;
    // Build an RTCEncodedVideoFrame-ish object per spec shape.
    var encoded = {
      type:      chunk.type,              // 'key' | 'delta'
      timestamp: chunk.timestamp,          // microseconds (monotonic)
      data:      chunk.data,               // Buffer (user can view as ArrayBuffer)
      getMetadata: function () {
        return {
          synchronizationSource: ssrc,
          payloadType:           chunk.payloadType || 96,
          contributingSources:   [],
          // TODO: width, height, frameId, dependencies, spatialIndex, temporalIndex
        };
      },
    };
    try { _readableController.enqueue(encoded); }
    catch (e) { /* controller may be closed */ }
  }


  /* ── WritableStream sink (feeds the decoder) ───────────────────────── */
  // Any chunk written here is passed to the internal VideoDecoder, which is
  // built lazily on the first write.

  var writable = new WritableStream({
    write: function (encoded) {
      if (stopped) return;
      _feedDecoder(encoded);
    },
    close: function () {
      if (decoder) { try { decoder.close(); } catch (e) {} decoder = null; }
    },
    abort: function () {
      if (decoder) { try { decoder.close(); } catch (e) {} decoder = null; }
    },
  });

  function _ensureDecoder() {
    if (decoder) return decoder;
    decoder = new VideoDecoder({
      output: function (videoFrame) {
        if (stopped) return;

        // Update per-SSRC decode counters for getStats. state.rtpStats[ssrc]
        // was created by handleIncomingRtp on the first packet; we just
        // increment the frame counters here.
        var s = manager.state.rtpStats[ssrc];
        if (s) {
          if (!s.framesDecoded) s.framesDecoded = 0;
          s.framesDecoded++;
          // Coded dimensions — surface the latest VideoFrame's codedWidth/Height.
          if (videoFrame.codedWidth)  s.frameWidth  = videoFrame.codedWidth;
          if (videoFrame.codedHeight) s.frameHeight = videoFrame.codedHeight;
        }

        try { track._push(videoFrame); }
        catch (e) { /* track may be ended */ }
      },
      error: function (err) {
        // Count decode errors as frames dropped.
        var s = manager.state.rtpStats[ssrc];
        if (s) {
          if (!s.framesDropped) s.framesDropped = 0;
          s.framesDropped++;
        }
        if (typeof console !== 'undefined' && console.error) {
          console.error('[media_pipeline] decoder error:', err && err.message || err);
        }
      },
    });
    return decoder;
  }

  function _feedDecoder(encoded) {
    var dec = _ensureDecoder();

    if (!decoderConfigured) {
      // Parse dimensions from the first keyframe.
      var dims = codecInfo.parseKeyframeDims(encoded.data);
      if (!dims) return;  // wait for a keyframe
      try {
        dec.configure({
          codec:                codecInfo.decoderCodec,
          codedWidth:           dims.width,
          codedHeight:          dims.height,
          hardwareAcceleration: 'prefer-software',
        });
        decoderConfigured = true;
      } catch (e) {
        if (typeof console !== 'undefined' && console.error) {
          console.error('[media_pipeline] decoder.configure failed:', e && e.message || e);
        }
        return;
      }
    }

    // Count keyframes (cumulative, per-SSRC).
    var s = manager.state.rtpStats[ssrc];
    if (s && encoded.type === 'key') {
      if (!s.keyFramesDecoded) s.keyFramesDecoded = 0;
      s.keyFramesDecoded++;
    }

    // The media-processing VideoDecoder expects chunks in the shape
    // { data, timestamp, type }. Our `encoded` object already has those.
    try { dec.decode(encoded); }
    catch (e) {
      if (typeof console !== 'undefined' && console.error) {
        console.error('[media_pipeline] decode threw:', e && e.message || e);
      }
    }
  }


  /* ── Auto-decode wiring ─────────────────────────────────────────────── */
  //
  // Same pattern as video receive: the depacketizer chooses between
  // direct-decode (fast path, readable stays empty) or enqueue-to-readable
  // (when streamsTaken or opts.autoDecode === false). No pipeTo means
  // the readable is never locked, so a later takeStreams() works cleanly.

  function _decodeChunkDirect(chunk) {
    if (stopped) return;
    // Lazy decode (Chrome-symmetric): if no sink is attached to the track,
    // skip decoding entirely. The track has no consumer, so decoded frames
    // would just be dropped — wasted CPU and FFmpeg memory. This mirrors
    // Chrome's optimization where receive-side decode runs only when track
    // is attached to a sink (<video>, MediaRecorder, etc.).
    //
    // Detection: track._ee.listenerCount('frame') > 0 means at least one
    // sink (VideoSink, MediaStreamTrackProcessor, MediaRecorder, ...) is
    // listening. Node's EventEmitter exposes this natively, so we don't
    // need any sink-tracking API in media-processing's MediaStreamTrack.
    if (track._ee && typeof track._ee.listenerCount === 'function' &&
        track._ee.listenerCount('frame') === 0) {
      return;   // No consumer — drop chunk, save CPU.
    }
    // Delegate to _feedDecoder, which owns the configure-on-first-keyframe
    // sequence. Calling decoder.decode() directly here would throw
    // InvalidStateError on every chunk forever — video must wait for a
    // keyframe before configure() can be called.
    _feedDecoder(chunk);
  }

  // Wire up sink-attachment hooks: when first sink attaches, request a
  // keyframe (PLI) from the peer so the decoder gets a clean start —
  // otherwise it has to wait for the next periodic keyframe (potentially
  // several seconds). When the last sink detaches, close the decoder to
  // free FFmpeg subprocess + buffers (it'll be lazily rebuilt if a sink
  // attaches again later).
  if (track._ee && typeof track._ee.on === 'function') {
    track._ee.on('newListener', function (event) {
      if (event !== 'frame') return;
      var hadConsumersBefore = track._ee.listenerCount('frame') > 0;
      if (!hadConsumersBefore) {
        // First sink attaching — request a fresh keyframe so the decoder
        // can start cleanly. requestKeyframe is on MediaTransport via the
        // manager facade; if missing (older builds), we degrade silently
        // and the consumer will see the next periodic keyframe instead.
        if (manager && typeof manager.requestKeyframe === 'function') {
          try { manager.requestKeyframe(ssrc); } catch (e) {}
        }
      }
    });
    track._ee.on('removeListener', function (event) {
      if (event !== 'frame') return;
      // After detach, the count reflects post-removal. Zero = last sink left.
      if (track._ee.listenerCount('frame') === 0 && decoder) {
        try { decoder.close(); } catch (e) {}
        decoder = null;
        decoderConfigured = false;
      }
    });
  }
  autoDecodeActive = (opts.autoDecode !== false);


  /* ── Incoming packet subscription ───────────────────────────────────── */

  var _diagOnRtpCount = 0;
  var onRtp = function (rtpBuf, rinfo, info) {
    if (stopped) return;
    // DIAG — log first 30 calls BEFORE the SSRC filter, with the raw
    // RTP header bytes so we can see what sequence number is actually
    // on the wire vs what parseRtp returns. RTP header layout:
    //   byte 0: V|P|X|CC
    //   byte 1: M|PT
    //   byte 2-3: sequence number (big-endian)
    //   byte 4-7: timestamp
    //   byte 8-11: SSRC
    if (_diagOnRtpCount < 30) {
      _diagOnRtpCount++;
      var hdrBytes = rtpBuf && rtpBuf.length >= 12
        ? Array.from(rtpBuf.slice(0, 12)).map(function (b) { return b.toString(16).padStart(2, '0'); }).join(' ')
        : '(short)';
      var wireSeq = rtpBuf && rtpBuf.length >= 4
        ? ((rtpBuf[2] << 8) | rtpBuf[3])
        : -1;
      var wireSsrc = rtpBuf && rtpBuf.length >= 12
        ? ((rtpBuf[8] << 24) | (rtpBuf[9] << 16) | (rtpBuf[10] << 8) | rtpBuf[11]) >>> 0
        : 0;
      console.log('[onRtp video #' + _diagOnRtpCount +
                  ' pipeline-ssrc=' + ssrc + '] info.ssrc=' + (info && info.ssrc) +
                  ' wireSsrc=' + wireSsrc +
                  ' wireSeq=' + wireSeq +
                  ' bufLen=' + (rtpBuf && rtpBuf.length) +
                  ' hdr=' + hdrBytes);
    }
    if (info.ssrc !== ssrc) return;
    var parsed = parseRtp(rtpBuf);
    if (!parsed) return;
    jitterBuffer.push(parsed);
  };

  // RTT updates from RTCP exchange. See audio pipeline for the
  // detailed rationale; in short, the jitter buffer extends its
  // loss-declaration window to ≥ 2×RTT + safety so RTX recovery
  // has time to land before we give up on the packet.
  var onRttUpdate = function (rttMs) {
    if (stopped) return;
    if (jitterBuffer && typeof jitterBuffer.setRtt === 'function') {
      jitterBuffer.setRtt(rttMs);
    }
  };

  if (manager.ev && typeof manager.ev.on === 'function') {
    manager.ev.on('rtp', onRtp);
    manager.ev.on('rtt:update', onRttUpdate);
  }

  var onTrackEnded = function () { stop(); };
  track.on('ended', onTrackEnded);


  /* ── Cleanup ─────────────────────────────────────────────────────────── */

  function stop() {
    if (stopped) return;
    stopped = true;
    if (manager.ev && typeof manager.ev.off === 'function') {
      manager.ev.off('rtp', onRtp);
      manager.ev.off('rtt:update', onRttUpdate);
    }
    track.off('ended', onTrackEnded);
    try { jitterBuffer.close(); } catch (e) {}
    try { depacketizer.close(); } catch (e) {}
    try { if (_readableController) _readableController.close(); } catch (e) {}
    if (decoder) { try { decoder.close(); } catch (e) {} decoder = null; }
  }


  /* ── Encoded streams handoff (called by createEncodedStreams) ──────── */

  function takeStreams() {
    if (streamsTaken) {
      throw new Error('createEncodedStreams can only be called once');
    }
    streamsTaken = true;

    // If auto-decode had already started piping, we can't take back those
    // chunks — the browser spec says createEncodedStreams must be called
    // early (before the first packet). We don't enforce it strictly — user
    // gets whatever is still in the pipeline.
    // Note: the pipeTo we set up earlier will drain whatever's in the
    // readable — after takeStreams() the user's reader competes with that
    // pipeTo. In practice, user should call this before any RTP arrives.

    return { readable: readable, writable: writable };
  }


  // ── Pipeline control hooks for RTCRtpReceiver ────────────────────────
  //
  // setJitterBufferTarget(ms)   — forwards to JitterBuffer.setLatency
  // setPlayoutDelayHint(seconds) — currently stored as a hint; not yet used
  //   for active playout scheduling (no per-frame delay amplification in our
  //   track._push path), but the receiver's getter reads it back so the API
  //   round-trips correctly.
  var _playoutDelayHint = null;
  function setJitterBufferTarget(ms) {
    if (jitterBuffer && typeof jitterBuffer.setLatency === 'function') {
      jitterBuffer.setLatency(ms);
    }
  }
  function setPlayoutDelayHint(seconds) {
    _playoutDelayHint = seconds;
  }


  return {
    stop:                   stop,
    readable:               readable,
    writable:               writable,
    takeStreams:            takeStreams,
    setJitterBufferTarget:  setJitterBufferTarget,
    setPlayoutDelayHint:    setPlayoutDelayHint,
    // Uniform interface with simulcast pipeline — single-layer returns
    // a Map of one entry. Key is empty string (the m-section's only
    // layer) so the app can write portable code that does
    // `pipeline.getLayerTracks().get(rid || '')`.
    getLayerTracks: function () {
      var m = new Map();
      m.set('', track);
      return m;
    },
    getLayerEncodedStreams: function () {
      var m = new Map();
      m.set('', readable);
      return m;
    },
  };
}


/**
 * Multi-layer (simulcast) video receive pipeline.
 *
 * Creates N parallel single-layer receive pipelines, one per incoming
 * SSRC. Each sub-pipeline handles its own JitterBuffer + Depacketizer,
 * filtering 'rtp' events by SSRC. Chunks from all layers flow into ONE
 * merged readable — each chunk's getMetadata() returns the layer's rid
 * so the app can sort packets per layer (the SFU use case).
 *
 * Only layer[0] auto-decodes to the track. Non-primary layers run with
 * `autoDecode: false` — they emit chunks to the merged readable but do
 * NOT spin up a decoder. This keeps resource use reasonable (1 decoder
 * for simulcast receive, not N).
 *
 * The receiver.writable is the primary layer's writable — writing to it
 * feeds the single decoder. Simulcast-receive apps typically ignore
 * writable; they consume readable for forwarding.
 *
 * @param {object} opts
 * @param {MediaStreamTrack} opts.track          — single track for primary layer decode
 * @param {object} opts.manager
 * @param {Array} opts.layers                    — [{rid, ssrc}, ...] from SDP a=rid / simulcast
 * @param {string} [opts.codec='vp8']
 * @param {number} [opts.jitterLatencyMs=50]
 * @returns {object}
 *    stop, readable, writable, takeStreams, setJitterBufferTarget, setPlayoutDelayHint
 */
function createVideoReceiveSimulcastPipeline(opts) {
  if (!opts || !opts.track || !opts.manager) {
    throw new Error('createVideoReceiveSimulcastPipeline: track, manager required');
  }

  var stopped = false;
  var layers = Array.isArray(opts.layers) ? opts.layers.slice() : [];

  // Shared merged readable that emits chunks from all layers. Each chunk's
  // getMetadata() returns the layer's rid so the app can distinguish.
  var _mergedController = null;
  var mergedReadable = new ReadableStream({
    start: function (c) { _mergedController = c; },
    cancel: function () { /* lifecycle managed by stop() */ },
  }, {
    // Bounded queue — ~1 second at 3 layers × 30 fps. Drop on overflow.
    highWaterMark: 90,
    size: function () { return 1; },
  });

  // Forward a chunk onto the merged readable. The rid is looked up LIVE
  // from manager.state.remoteSsrcMap[ssrc].rid at forward time — this is
  // critical for the runtime-learning flow, where a layer's sub-pipeline
  // might be created before we know its rid (the RID header extension
  // arrives on the first RTP packet). Looking up dynamically means the
  // chunk metadata always reflects the latest known rid.
  function _forwardToMerged(chunk) {
    if (!_mergedController) return;
    if (_mergedController.desiredSize != null &&
        _mergedController.desiredSize <= 0) return;
    var baseMd = (typeof chunk.getMetadata === 'function') ? chunk.getMetadata() : {};
    var ssrc = baseMd.synchronizationSource;
    var mapping = ssrc != null ? opts.manager.state.remoteSsrcMap[ssrc] : null;
    var rid = mapping ? (mapping.rid || null) : null;
    var wrapped = {
      type:      chunk.type,
      timestamp: chunk.timestamp,
      data:      chunk.data,
      getMetadata: function () {
        baseMd.rid = rid;
        return baseMd;
      },
    };
    try { _mergedController.enqueue(wrapped); }
    catch (e) { /* controller may be closed */ }
  }

  var layerPipelines = [];   // [{ sub, ssrc, rid, track, isPrimary }]
  var havePrimary    = false;

  // Internal: wire a freshly-created sub-pipeline's readable into the merged
  // readable. The sub-pipeline always writes encoded chunks to its readable
  // (per the lazy-decode refactor in createVideoReceivePipeline) — we
  // intercept those for the merged feed used by SFU forwarding patterns.
  // The decoder for that layer runs lazily inside the sub-pipeline (only
  // when the layer's track has a sink attached).
  function _wireSub(sub) {
    var reader = sub.readable.getReader();
    (function drain() {
      reader.read().then(function (r) {
        if (r.done || stopped) return;
        _forwardToMerged(r.value);
        drain();
      }).catch(function () {});
    })();
  }

  // Build sub-pipeline for a single layer. The PRIMARY layer (= first one
  // discovered) reuses opts.track so receiver.track is populated for
  // Chrome-compatible apps. Non-primary layers get their own freshly-built
  // MediaStreamTrack — exposed via getLayerTracks() so the app can attach
  // sinks per layer (the API-9 extension).
  function _addLayerInternal(ssrc, rid) {
    var isPrimary = !havePrimary;
    var layerTrack;
    if (isPrimary) {
      havePrimary = true;
      layerTrack = opts.track;
    } else {
      // Non-primary layer — fresh track. Label includes rid for diagnosability.
      layerTrack = new MediaStreamTrack({
        kind:  'video',
        label: 'simulcast-layer-' + (rid || 'rid?'),
      });
    }

    var sub = createVideoReceivePipeline({
      track:           layerTrack,
      manager:         opts.manager,
      ssrc:            ssrc,
      codec:           opts.codec,
      jitterLatencyMs: opts.jitterLatencyMs,
      // autoDecode left at default (true). The lazy-decode in
      // createVideoReceivePipeline ensures the decoder doesn't actually
      // run until a sink attaches to layerTrack — so secondary layers
      // cost ~depacketize only if no one is watching them.
    });

    _wireSub(sub);
    layerPipelines.push({
      sub:       sub,
      ssrc:      ssrc,
      rid:       rid || null,
      track:     layerTrack,
      isPrimary: isPrimary,
    });

    if (typeof console !== 'undefined') {
      console.log('[mp-diag] simulcast pipeline: added ' +
                  (isPrimary ? 'PRIMARY' : 'secondary') +
                  ' layer ssrc=' + ssrc + ' rid=' + (rid || '(unknown)'));
    }
  }

  // Backwards-compat alias — old name still referenced internally by addLayer.
  var _addPrimaryInternal = _addLayerInternal;

  // Initial layers, if provided up front. For simulcast offers where SSRCs
  // are declared in SDP (e.g. Firefox), opts.layers carries them.
  for (var i = 0; i < layers.length; i++) {
    if (layers[i] && layers[i].ssrc != null) {
      _addPrimaryInternal(layers[i].ssrc, layers[i].rid);
    }
  }

  function addLayer(info) {
    if (stopped) return;
    if (!info || info.ssrc == null) return;

    if (info.isRtx) {
      // RTX layer — we don't build a sub-pipeline for RTX (the primary sub's
      // jitter buffer doesn't currently consume retransmits). Just note the
      // association so getStats/diagnostics can pair the RTX SSRC with its
      // primary rid. The actual NACK/RTX-recovery path is a separate gap
      // (see note in session-level TODO).
      if (typeof console !== 'undefined') {
        console.log('[mp-diag] simulcast pipeline: noted RTX ssrc=' + info.ssrc +
                    ' for rid=' + (info.rid || '(unknown)') +
                    ' (receive-side RTX not yet wired)');
      }
      return;
    }

    // Skip if we already have a sub for this SSRC.
    for (var li = 0; li < layerPipelines.length; li++) {
      if (layerPipelines[li].ssrc === info.ssrc) {
        // Existing layer — maybe learn its rid now.
        if (!layerPipelines[li].rid && info.rid) layerPipelines[li].rid = info.rid;
        return;
      }
    }

    _addPrimaryInternal(info.ssrc, info.rid);
  }

  function stop() {
    if (stopped) return;
    stopped = true;
    for (var si = 0; si < layerPipelines.length; si++) {
      try { layerPipelines[si].sub.stop(); } catch (e) {}
    }
    try { if (_mergedController) _mergedController.close(); } catch (e) {}
  }

  function takeStreams() {
    // Simulcast receiver's encoded streams are read-only. Writable is
    // null because the app can't push chunks back into the demux —
    // each layer has its own packetization state that only the
    // depacketizer owns.
    return { readable: mergedReadable, writable: null };
  }

  function setJitterBufferTarget(ms) {
    for (var si = 0; si < layerPipelines.length; si++) {
      if (typeof layerPipelines[si].sub.setJitterBufferTarget === 'function') {
        layerPipelines[si].sub.setJitterBufferTarget(ms);
      }
    }
  }

  function setPlayoutDelayHint(seconds) {
    for (var si = 0; si < layerPipelines.length; si++) {
      if (typeof layerPipelines[si].sub.setPlayoutDelayHint === 'function') {
        layerPipelines[si].sub.setPlayoutDelayHint(seconds);
      }
    }
  }

  // ─── API-9 extension: per-layer tracks + encoded streams ─────────────
  //
  // getLayerTracks(): Map<rid, MediaStreamTrack>. Returned by
  // RTCRtpReceiver.tracks. Each layer has its own track; the PRIMARY
  // layer's track === opts.track (= receiver.track in api.js), so the
  // Chrome-compatible single-track shape still works for callers that
  // only know about receiver.track.
  //
  // getLayerEncodedStreams(): Map<rid, ReadableStream<EncodedVideoChunk>>.
  // Returned by RTCRtpReceiver.getLayerEncodedStreams(). For SFU
  // forwarding without decode: the readable carries depacketized chunks,
  // and the lazy decoder in the sub-pipeline never spins up if no sink
  // is attached to the layer's track.
  //
  // For runtime-learned layers (rid only known after first packet with
  // RID header extension arrives), the maps reflect the latest known rid.
  // Layers without a rid yet appear under a synthetic key 'ssrc-<N>' so
  // the app can still address them; once rid is learned, the canonical
  // entry is updated.
  function _layerKey(lp) {
    return lp.rid || ('ssrc-' + lp.ssrc);
  }
  function getLayerTracks() {
    var m = new Map();
    for (var i = 0; i < layerPipelines.length; i++) {
      m.set(_layerKey(layerPipelines[i]), layerPipelines[i].track);
    }
    return m;
  }
  function getLayerEncodedStreams() {
    var m = new Map();
    for (var i = 0; i < layerPipelines.length; i++) {
      m.set(_layerKey(layerPipelines[i]), layerPipelines[i].sub.readable);
    }
    return m;
  }

  return {
    stop:                  stop,
    readable:              mergedReadable,
    // writable is whatever the PRIMARY sub's writable is, once a primary
    // exists. We expose it lazily via a getter so the first-added primary
    // sets it.
    get writable() {
      for (var wi = 0; wi < layerPipelines.length; wi++) {
        if (layerPipelines[wi].isPrimary) return layerPipelines[wi].sub.writable;
      }
      return null;
    },
    takeStreams:            takeStreams,
    setJitterBufferTarget:  setJitterBufferTarget,
    setPlayoutDelayHint:    setPlayoutDelayHint,
    addLayer:               addLayer,
    getLayerTracks:         getLayerTracks,
    getLayerEncodedStreams: getLayerEncodedStreams,
  };
}

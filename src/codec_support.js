// src/codec_support.js
// Which registry codecs this process can SEND (encode) and RECEIVE
// (decode), per direction — what getCapabilities() reports and what the
// offers and answers list.
//
// W3C webrtc-pc 5.2 / 5.3: RTCRtpSender.getCapabilities lists the
// "implemented send codecs", RTCRtpReceiver.getCapabilities the
// "implemented receive codecs". RFC 3264 §5.1 / RFC 9429 (JSEP) 5.2.1: an
// offer lists the formats the offerer is willing to receive, and for
// sendrecv / sendonly also to send; JSEP 5.3.1 / RFC 3264 §6.1: an answer
// only formats supported in the section's direction. webrtc-pc's
// createOffer / createAnswer filter the codec preferences the same way:
// sendrecv / sendonly drop codecs not in the send list, sendrecv /
// recvonly those not in the receive list (inactive: no filter).
//
// The registry (sdp.js CODEC_REGISTRY) is every codec the RTP layer can
// packetize. Before, every offer and answer listed all of it, whatever
// media-processing's FFmpeg could do: without libx265, H.265 was offered
// and answered, getCapabilities left it out, and a peer that picked it
// got a send pipeline that failed at the first frame.
//
// Sources, in this order:
//   1. setCodecSupport(spec): a pinned set (tests, the differential
//      generators, an application that knows better);
//   2. media-processing's getCodecAvailability(): FFmpeg's -encoders /
//      -decoders listings, probed once and cached there (two FFmpeg runs,
//      synchronous, at the first need);
//   3. neither (FFmpeg could not be run): unknown, every registry codec
//      both ways, as before.
//
// A registry entry with no media-processing name (telephone-event: the
// DTMF sender makes it, no encoder) is available both ways.
//
// PASS-THROUGH: a connection made with the non-standard
// `passthroughCodecs: true` (an SFU that forwards RTP it never decodes or
// encodes, an application that writes and reads encoded frames itself
// through createEncodedStreams) negotiates every registry codec, both
// ways: packetizing an already-encoded frame needs no codec.
//
// Layering: sdp.js stays import-free; this module reads its registry and
// hands the filtered tables to sdp.js as data.

import { getCodecAvailability } from 'media-processing';
import * as SDP from './sdp.js';

var DIRECTIONS = ['sendrecv', 'sendonly', 'recvonly', 'inactive'];

var _pinned = null;

function _set(list) {
  var out = {};
  for (var i = 0; i < (list || []).length; i++) out[String(list[i]).toLowerCase()] = true;
  return out;
}

/**
 * Pin the codec set: { audio: { send: [...], recv: [...] },
 * video: { send: [...], recv: [...] } }, media-processing short names
 * (opus, g711-alaw, g711-ulaw, vp8, vp9, h264, h265, av1). 'all' pins
 * every registry codec both ways; null goes back to probing.
 */
function setCodecSupport(spec) {
  if (spec == null) { _pinned = null; return; }
  if (spec === 'all') { _pinned = 'all'; return; }
  _pinned = {
    audio: { send: _set(spec.audio && spec.audio.send), recv: _set(spec.audio && spec.audio.recv) },
    video: { send: _set(spec.video && spec.video.send), recv: _set(spec.video && spec.video.recv) },
  };
}

// { audio: { send, recv }, video: { send, recv } } of name → true, or null
// (everything).
function _support() {
  if (_pinned === 'all') return null;
  if (_pinned) return _pinned;
  var a = null;
  try { a = getCodecAvailability(); } catch (e) { a = null; }
  if (!a) return null;
  return {
    audio: { send: _set(a.audio.encode), recv: _set(a.audio.decode) },
    video: { send: _set(a.video.encode), recv: _set(a.video.decode) },
  };
}

/** The registry entry of a codec ({ name, clockRate }), or null. */
function _registryEntry(kind, codec) {
  var list = SDP.CODEC_REGISTRY[kind] || [];
  var name = String(codec && codec.name || '').toLowerCase();
  for (var i = 0; i < list.length; i++) {
    if (String(list[i].name).toLowerCase() !== name) continue;
    if (codec.clockRate && list[i].clockRate !== codec.clockRate) continue;
    return list[i];
  }
  return null;
}

/** Can this process send ('send') / receive ('recv') a registry entry? */
function registryEntryAvailable(kind, entry, way) {
  if (!entry || !entry.mpName) return true;
  var s = _support();
  if (!s || !s[kind]) return true;
  return !!s[kind][way][String(entry.mpName).toLowerCase()];
}

/**
 * Is a codec ({ name, clockRate }) usable in a section of this direction
 * (ours: sendrecv needs both ways, sendonly sending, recvonly receiving,
 * inactive either)? A codec outside the registry is left alone (true).
 */
function usable(kind, codec, direction, passthrough) {
  if (passthrough) return true;
  var e = _registryEntry(kind, codec);
  if (!e) return true;
  var send = registryEntryAvailable(kind, e, 'send');
  var recv = registryEntryAvailable(kind, e, 'recv');
  if (direction === 'sendrecv') return send && recv;
  if (direction === 'sendonly') return send;
  if (direction === 'recvonly') return recv;
  return send || recv;
}

/** The codecs of `list` usable in `direction` (strict: may be empty). */
function filter(kind, list, direction, passthrough) {
  if (passthrough || !list) return list;
  return list.filter(function (c) { return usable(kind, c, direction, passthrough); });
}

/**
 * The codecs of an OFFER's section: `list` filtered by direction. An
 * m-line needs at least one format, so when nothing is usable in that
 * direction the codecs usable either way are offered, and when nothing at
 * all is (no encoder or decoder of this kind), the list as given.
 */
function forOffer(kind, list, direction, passthrough) {
  var out = filter(kind, list, direction, passthrough);
  if (out && out.length) return out;
  out = filter(kind, list, 'inactive', passthrough);
  return (out && out.length) ? out : list;
}

/**
 * The local codec tables of an ANSWER, per direction, for sdp.js's
 * createAnswer (config.localCodecsByDirection); null for a pass-through
 * connection or unknown support (sdp.js then uses its default tables).
 */
function answerTables(passthrough) {
  if (passthrough || !_support()) return null;
  var out = {};
  var kinds = { audio: SDP.DEFAULT_AUDIO_CODECS, video: SDP.DEFAULT_VIDEO_CODECS };
  for (var kind in kinds) {
    out[kind] = {};
    for (var d = 0; d < DIRECTIONS.length; d++) {
      out[kind][DIRECTIONS[d]] = filter(kind, kinds[kind], DIRECTIONS[d], false);
    }
  }
  return out;
}

export {
  setCodecSupport,
  registryEntryAvailable,
  usable,
  filter,
  forOffer,
  answerTables,
};

// src/sdp/webrtc.js
// WebRTC SDP layer — offer/answer, codec negotiation, BUNDLE, ICE, DTLS.
// Built on top of sdp-transform for generic SDP parse/write.

import sdpTransform from 'sdp-transform';
import crypto from 'node:crypto';


/* ========================= Constants ========================= */

var DIRECTIONS = ['sendrecv', 'sendonly', 'recvonly', 'inactive'];

var REVERSE_DIRECTION = {
  sendrecv: 'sendrecv',
  sendonly: 'recvonly',
  recvonly: 'sendonly',
  inactive: 'inactive',
};

/**
 * Compute the correct answer-side direction given:
 *   - offerDir          The direction in the peer's offer m-section.
 *   - hasLocalSsrc      True if we have a track to send on this m-section
 *                       (proxy for "can we send"). Set by the caller from
 *                       the presence of an SSRC in localSsrcs[mid].
 *   - userPreferredDir  The transceiver's user-set direction (from
 *                       transceiver.direction). Default 'sendrecv' if
 *                       absent — matches pre-fix behavior for callers
 *                       that don't supply preferences.
 *
 * Per W3C §5.5 step 2 ("Compute the new direction"), the answer's
 * direction is the intersection of:
 *   (a) what the offerer's direction allows us to do
 *   (b) what our transceiver's direction allows us to do
 *   (c) what we have the means to do (hasLocalSsrc gate)
 *
 * RFC 3264 §6.1 — the answer's direction must be compatible with the
 * offer's. The previous 2-arg implementation correctly intersected (a)
 * and (c), but skipped (b) — meaning a user who set
 * `transceiver.direction = 'inactive'` to pause receive temporarily
 * still saw a 'recvonly' answer go out, the peer kept sending, and the
 * pause was invisible on the wire. The 3rd arg fixes this. Backward
 * compat: callers passing only 2 args get pref='sendrecv', identical
 * to the old behavior.
 *
 * Same conceptual fix as MSF buildMediaForTransceiver direction
 * resolution (item 23 (a)), but on the answer path. Both layers must
 * respect user pref or the bug surfaces in either offer or answer.
 */
function computeAnswerDirection(offerDir, hasLocalSsrc, userPreferredDir) {
  var peerSends    = (offerDir === 'sendrecv' || offerDir === 'sendonly');
  var peerReceives = (offerDir === 'sendrecv' || offerDir === 'recvonly');

  var pref = userPreferredDir || 'sendrecv';
  var userWantsSend    = (pref === 'sendrecv' || pref === 'sendonly');
  var userWantsReceive = (pref === 'sendrecv' || pref === 'recvonly');

  var weSend    = hasLocalSsrc && peerReceives && userWantsSend;
  var weReceive = peerSends && userWantsReceive;

  if (weSend && weReceive) return 'sendrecv';
  if (weSend)              return 'sendonly';
  if (weReceive)           return 'recvonly';
  return 'inactive';
}

// Default codecs we support (can be overridden)
var DEFAULT_AUDIO_CODECS = [
  { name: 'opus', clockRate: 48000, channels: 2, fmtp: { minptime: 10, useinbandfec: 1 }, feedback: ['transport-cc'] },
];

// Feedback order matches Chrome 147 output for visual parity in dumps.
// goog-remb is included because Chrome still advertises it (legacy BWE path).
var DEFAULT_VIDEO_CODECS = [
  { name: 'VP8',  clockRate: 90000, feedback: ['goog-remb', 'transport-cc', 'ccm fir', 'nack', 'nack pli'], rtx: true },
  { name: 'VP9',  clockRate: 90000, feedback: ['goog-remb', 'transport-cc', 'ccm fir', 'nack', 'nack pli'], rtx: true },
  { name: 'H264', clockRate: 90000, feedback: ['goog-remb', 'transport-cc', 'ccm fir', 'nack', 'nack pli'], rtx: true,
    fmtp: { 'profile-level-id': '42e01f', 'level-asymmetry-allowed': 1, 'packetization-mode': 1 } },
];

/* ========================= Default header extensions =========================
 *
 * RFC 8285 — A General Mechanism for RTP Header Extensions.
 * These URIs are what Chrome 147 declares via a=extmap; declaring them in our
 * SDP makes Chrome actually put them on the wire for us to parse.
 *
 * CRITICAL — RFC 8285 §6 + JSEP:
 *   Within a single BUNDLE group, an extension ID must refer to the SAME URI
 *   across all m-sections. The on-the-wire RTP header uses only the numeric ID;
 *   the receiver looks up the URI from its SDP mapping. If audio declares
 *   id=1 → ssrc-audio-level and video declares id=1 → toffset, the peer cannot
 *   know which URI is being carried and Chrome rejects the offer with
 *     "BUNDLE group contains a codec collision for header extension id=1".
 *
 * Our numbering is chosen so that:
 *   (a) audio defaults match Chrome's typical audio-only scheme (ids 1..4) —
 *       so when Chrome starts with audio and we later add video, the audio
 *       ids we preserve from its offer line up with our video defaults;
 *   (b) shared URIs (abs-send-time, transport-wide-cc, sdes:mid) use the same
 *       id in both audio and video;
 *   (c) video-only URIs use ids >= 5 so they never collide with audio ids.
 *
 * IMPORTANT — declaring ≠ wire-level support:
 *   - Declaring these URIs only tells the peer "you MAY send these extensions".
 *   - The receiving side (rtp-packet / media-processing) already skips unknown
 *     header extensions correctly (any RTP parser must, per RFC 3550 §5.3.1).
 *   - Wire-level writing of sdes:mid on outbound RTP is a separate piece of
 *     work in the packetizer — not part of this change.
 */

var DEFAULT_AUDIO_EXTENSIONS = [
  { id:  1, uri: 'urn:ietf:params:rtp-hdrext:ssrc-audio-level' },                                //   audio-only (RFC 6464)
  { id:  2, uri: 'http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time' },                 // ← shared with video
  { id:  3, uri: 'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01' },  // ← shared with video
  { id:  4, uri: 'urn:ietf:params:rtp-hdrext:sdes:mid' },                                        // ← shared with video (BUNDLE demux)
];

var DEFAULT_VIDEO_EXTENSIONS = [
  { id:  2, uri: 'http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time' },                 // ← shared with audio
  { id:  3, uri: 'http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01' },  // ← shared with audio
  { id:  4, uri: 'urn:ietf:params:rtp-hdrext:sdes:mid' },                                        // ← shared with audio
  { id:  5, uri: 'urn:ietf:params:rtp-hdrext:toffset' },                                         //   video-only (RFC 5450)
  { id:  6, uri: 'urn:3gpp:video-orientation' },                                                 //   video-only (3GPP TS 26.114)
  { id:  7, uri: 'http://www.webrtc.org/experiments/rtp-hdrext/playout-delay' },
  { id:  8, uri: 'http://www.webrtc.org/experiments/rtp-hdrext/video-content-type' },
  { id:  9, uri: 'http://www.webrtc.org/experiments/rtp-hdrext/video-timing' },
  { id: 10, uri: 'http://www.webrtc.org/experiments/rtp-hdrext/color-space' },
  { id: 11, uri: 'urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id' },                              //   video-only (RFC 8852 — simulcast)
  { id: 12, uri: 'urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id' },                     //   video-only (RFC 8852 — rid on RTX)
];


/* ========================= Parse helpers ========================= */

// Parse fmtp config string → object
// "minptime=10;useinbandfec=1" → { minptime: '10', useinbandfec: '1' }
function parseFmtpConfig(config) {
  if (!config) return {};
  var out = {};
  var parts = config.split(';');
  for (var i = 0; i < parts.length; i++) {
    var seg = parts[i].trim();
    if (!seg) continue;
    // Split on FIRST '=' only — values may legitimately contain '=' (e.g.
    // base64-encoded fmtp parameters; some experimental codecs). The
    // previous `split('=')` returned >2 segments for "key=val=ue" and
    // dropped the entry entirely; using indexOf preserves value fidelity.
    var eq = seg.indexOf('=');
    if (eq > 0) {
      out[seg.slice(0, eq).trim()] = seg.slice(eq + 1).trim();
    } else {
      // Bare token (no '='): present-as-flag, like "0-15" for telephone-event.
      out[seg] = true;
    }
  }
  return out;
}

// Build fmtp config string from object
function buildFmtpConfig(obj) {
  if (!obj) return '';
  var parts = [];
  var keys = Object.keys(obj);
  for (var i = 0; i < keys.length; i++) {
    var v = obj[keys[i]];
    if (v === true) parts.push(keys[i]);
    else parts.push(keys[i] + '=' + v);
  }
  return parts.join(';');
}

// Extract codecs from a media section (sdp-transform format)
function extractCodecs(media) {
  var codecs = [];
  var rtpMap = {};
  var fmtpMap = {};
  var fbMap = {};

  // Build lookup maps
  if (media.rtp) {
    for (var i = 0; i < media.rtp.length; i++) {
      var r = media.rtp[i];
      rtpMap[r.payload] = r;
    }
  }
  if (media.fmtp) {
    for (var j = 0; j < media.fmtp.length; j++) {
      fmtpMap[media.fmtp[j].payload] = media.fmtp[j].config;
    }
  }
  if (media.rtcpFb) {
    for (var k = 0; k < media.rtcpFb.length; k++) {
      var fb = media.rtcpFb[k];
      if (!fbMap[fb.payload]) fbMap[fb.payload] = [];
      var fbStr = fb.type;
      if (fb.subtype) fbStr += ' ' + fb.subtype;
      fbMap[fb.payload].push(fbStr);
    }
  }

  // Parse payloads — two-pass to handle RTX→primary association regardless
  // of payload list order. Chrome/Firefox/Safari always emit primary before
  // RTX in the m-line payload list, but RFC 4588 doesn't mandate that order.
  // The previous single-pass loop walked `codecs[]` (which only contained
  // primaries already pushed) at the moment an RTX entry was visited — if
  // RTX appeared before its primary, the lookup found nothing, the RTX
  // association silently failed, and the primary codec ended up with
  // rtxPayloadType=null (no NACK retransmission for that codec).
  //
  //   Pass 1: collect primaries (audio/video codecs, skipping RTX/RED/ulpfec)
  //   Pass 2: walk payloads again, attaching RTX entries to their apt= primary
  var payloads = sdpTransform.parsePayloads(media.payloads);

  for (var p = 0; p < payloads.length; p++) {
    var pt = payloads[p];
    var rtp = rtpMap[pt];
    if (!rtp) continue;

    var codecName = rtp.codec.toLowerCase();
    if (codecName === 'rtx' || codecName === 'red' || codecName === 'ulpfec') continue;

    codecs.push({
      payloadType: pt,
      name: rtp.codec,
      clockRate: rtp.rate || 0,
      channels: rtp.encoding || 0,
      fmtp: parseFmtpConfig(fmtpMap[pt]),
      feedback: fbMap[pt] || [],
      rtxPayloadType: null,
    });
  }

  // Pass 2: RTX association. Each `apt=N` fmtp links the RTX PT back to
  // its primary's PT. Walk all payloads again; now `codecs[]` is fully
  // populated with primaries, so the lookup is guaranteed to find any
  // valid RTX→primary pair.
  for (var p2 = 0; p2 < payloads.length; p2++) {
    var pt2 = payloads[p2];
    var rtp2 = rtpMap[pt2];
    if (!rtp2 || rtp2.codec.toLowerCase() !== 'rtx') continue;

    var aptFmtp = parseFmtpConfig(fmtpMap[pt2]);
    var apt = aptFmtp.apt ? parseInt(aptFmtp.apt, 10) : null;
    if (apt === null) continue;

    for (var c = 0; c < codecs.length; c++) {
      if (codecs[c].payloadType === apt) {
        codecs[c].rtxPayloadType = pt2;
        break;
      }
    }
  }

  return codecs;
}

// Extract SSRCs from a media section
function extractSsrcs(media) {
  var ssrcMap = {};

  if (media.ssrcs) {
    for (var i = 0; i < media.ssrcs.length; i++) {
      var s = media.ssrcs[i];
      if (!ssrcMap[s.id]) ssrcMap[s.id] = {};
      ssrcMap[s.id][s.attribute] = s.value;
    }
  }

  var ssrcs = [];
  var ids = Object.keys(ssrcMap);
  for (var j = 0; j < ids.length; j++) {
    var id = parseInt(ids[j], 10);
    var attrs = ssrcMap[id];
    ssrcs.push({
      id: id,
      cname: attrs.cname || null,
      msid: attrs.msid || null,
      label: attrs.label || null,
    });
  }

  return ssrcs;
}

// Extract SSRC groups (FID for RTX, SIM for simulcast)
function extractSsrcGroups(media) {
  if (!media.ssrcGroups) return [];
  var groups = [];
  for (var i = 0; i < media.ssrcGroups.length; i++) {
    var g = media.ssrcGroups[i];
    groups.push({
      semantics: g.semantics,
      ssrcs: g.ssrcs.split(' ').map(function(s) { return parseInt(s, 10); }),
    });
  }
  return groups;
}

// Extract RTP header extensions
function extractExtensions(media) {
  if (!media.ext) return [];
  var exts = [];
  for (var i = 0; i < media.ext.length; i++) {
    exts.push({
      id: media.ext[i].value,
      uri: media.ext[i].uri,
      direction: media.ext[i].direction || null,
    });
  }
  return exts;
}

/**
 * Remap extension IDs to avoid collisions within a BUNDLE group.
 *
 * RFC 8843 §9.2 + libwebrtc ValidateBundledRtpHeaderExtensions: within a BUNDLE
 * group, the SAME id must refer to the same URI across ALL bundled m-sections.
 * Chrome uses different extmap schemes depending on context (video-only uses
 * id=3 for video-orientation; audio+video uses id=3 for transport-wide-cc).
 * Any static default table will collide with SOME Chrome ordering.
 *
 * This function takes a set of desired extensions (with "suggested" ids from our
 * defaults) and a map of ids already in use elsewhere in the BUNDLE, and returns
 * a new extension list where:
 *   - URIs already present in `usedMap` reuse their existing id (shared across BUNDLE)
 *   - URIs not yet seen are assigned the smallest free id (1-14 first, then 15-255)
 *   - The relative order of `desired` is preserved
 *
 * @param {Array<{id:number, uri:string, direction?:string}>} desired - desired extensions
 * @param {Object<number,string>} usedMap - id → uri already in use in this BUNDLE
 * @returns {Array<{id:number, uri:string, direction?:string}>}
 */
function assignExtensionIds(desired, usedMap) {
  // Build reverse lookup: uri → id already used
  var uriToId = {};
  var inUse = new Set();
  Object.keys(usedMap).forEach(function(k) {
    var id = parseInt(k, 10);
    inUse.add(id);
    uriToId[usedMap[k]] = id;
  });

  function nextFreeId() {
    // Prefer 1-byte range (1-14), then 2-byte range (15-255). Per RFC 8285:
    // - ids 1-14 fit in a 1-byte header
    // - ids 15-255 require a 2-byte header (and extmap-allow-mixed)
    // Chrome accepts both; staying in 1-14 is more efficient.
    for (var i = 1; i <= 14; i++) {
      if (!inUse.has(i)) return i;
    }
    for (var j = 15; j <= 255; j++) {
      if (!inUse.has(j)) return j;
    }
    return null; // space exhausted (24 extensions is way past practical)
  }

  var result = [];
  for (var d = 0; d < desired.length; d++) {
    var ext = desired[d];
    var id;
    if (uriToId[ext.uri] != null) {
      // Reuse id that's already associated with this URI in the BUNDLE
      id = uriToId[ext.uri];
    } else {
      id = nextFreeId();
      if (id == null) break; // out of ids — drop remaining extensions
      inUse.add(id);
      uriToId[ext.uri] = id;
    }
    var entry = { id: id, uri: ext.uri };
    if (ext.direction) entry.direction = ext.direction;
    result.push(entry);
  }
  return result;
}

// Extract ICE candidates from a media section
function extractCandidates(media) {
  if (!media.candidates) return [];
  var cands = [];
  for (var i = 0; i < media.candidates.length; i++) {
    var c = media.candidates[i];
    cands.push({
      foundation: String(c.foundation),
      component: c.component,
      protocol: c.transport,
      priority: c.priority,
      ip: c.ip,
      port: c.port,
      type: c.type,
      relatedAddress: c.raddr || null,
      relatedPort: c.rport || null,
      tcpType: c.tcptype || null,
    });
  }
  return cands;
}


/* ========================= parseOffer / parseAnswer ========================= */

function parseRemoteSdp(sdpString) {
  var raw = sdpTransform.parse(sdpString);

  var result = {
    type: null,  // set by caller: 'offer' or 'answer'
    raw: raw,

    // Session-level
    origin: raw.origin ? {
      username:        raw.origin.username,
      sessionId:       String(raw.origin.sessionId),
      sessionVersion:  Number(raw.origin.sessionVersion),
      netType:         raw.origin.netType,
      ipVer:           raw.origin.ipVer,
      address:         raw.origin.address,
    } : null,
    sessionName:        raw.name || null,
    bundleGroups:       [],
    bundleMids:         [],     // flat list of all mids in BUNDLE (first group)
    extmapAllowMixed:   !!raw.extmapAllowMixed,
    msidSemantic:       raw.msidSemantic ? {
      semantic: raw.msidSemantic.semantic,
      token:    raw.msidSemantic.token,
    } : null,
    iceOptions:         raw.iceOptions || null,
    iceLite:            !!raw.icelite,

    // Media sections
    media: [],
  };

  // Parse BUNDLE groups
  if (raw.groups) {
    for (var g = 0; g < raw.groups.length; g++) {
      if (raw.groups[g].type === 'BUNDLE') {
        var mids = String(raw.groups[g].mids);
        var list = mids.split(' ').filter(Boolean);
        result.bundleGroups.push(list);
        if (result.bundleMids.length === 0) result.bundleMids = list;
      }
    }
  }

  // Parse each media section
  for (var i = 0; i < raw.media.length; i++) {
    var m = raw.media[i];

    // Media-level a=msid (separate from per-SSRC msid attribute)
    var mediaMsid = null;
    if (m.msid) {
      // sdp-transform may return either a string "- trackId" or an array of
      // {id, appdata} objects depending on version. Normalize to "id appdata".
      if (typeof m.msid === 'string') {
        mediaMsid = m.msid;
      } else if (Array.isArray(m.msid) && m.msid.length > 0) {
        mediaMsid = [m.msid[0].id, m.msid[0].appdata].filter(Boolean).join(' ');
      } else if (m.msid.id) {
        mediaMsid = [m.msid.id, m.msid.appdata].filter(Boolean).join(' ');
      }
    }

    var section = {
      mid: String(m.mid != null ? m.mid : i),
      type: m.type,          // 'audio' | 'video' | 'application'
      port: m.port,
      protocol: m.protocol,
      direction: m.direction || 'sendrecv',

      // ICE
      // ice-ufrag / ice-pwd CAN be declared at session level per RFC 8839
      // §5.2 (rare in practice — Chrome puts them at media level — but
      // some implementations do session-level). Per spec, session-level
      // applies to all m-sections unless overridden at media level. Fall
      // back so we don't miss creds on peers that use session-level.
      iceUfrag: m.iceUfrag || raw.iceUfrag || null,
      icePwd: m.icePwd || raw.icePwd || null,
      iceOptions: m.iceOptions || null,
      candidates: extractCandidates(m),
      endOfCandidates: !!(m.endOfCandidates),

      // DTLS
      // a=fingerprint MAY be declared at session level (applies to all
      // m-sections) OR at media level (overrides session-level for that
      // section) per RFC 8122 §5. Firefox emits at session level only;
      // Chrome emits both. Fall back to session-level when media-level
      // is absent — without this fallback, applyRemoteDescription would
      // see no fingerprint and DTLS verification would fail with
      // "remote SDP did not declare a=fingerprint" against fully-spec-
      // compliant peers.
      fingerprint: (m.fingerprint || raw.fingerprint) ? {
        algorithm: (m.fingerprint || raw.fingerprint).type,
        value:     (m.fingerprint || raw.fingerprint).hash,
      } : null,
      setup: m.setup || null,

      // RTP
      codecs: extractCodecs(m),
      extensions: extractExtensions(m),
      ssrcs: extractSsrcs(m),
      ssrcGroups: extractSsrcGroups(m),
      msid: mediaMsid,

      // Simulcast (RFC 8853) — rids + simulcast block carried through as-is
      // so the peer's accepted layer set can be reconciled against what we
      // offered. `rids` is an array of {id, direction, params?}, `simulcast`
      // is {dir1, list1, dir2?, list2?}. Both are null/undefined for
      // non-simulcast m-sections.
      rids:      Array.isArray(m.rids) ? m.rids.slice() : null,
      simulcast: m.simulcast || null,

      // Flags
      rtcpMux: !!m.rtcpMux,
      rtcpRsize: !!m.rtcpRsize,
      rtcp: m.rtcp || null,

      // SCTP (for DataChannel)
      sctpPort: m.sctpPort || null,
      maxMessageSize: m.maxMessageSize || null,
    };

    result.media.push(section);
  }

  return result;
}

function parseOffer(sdpString) {
  var result = parseRemoteSdp(sdpString);
  result.type = 'offer';
  return result;
}

function parseAnswer(sdpString) {
  var result = parseRemoteSdp(sdpString);
  result.type = 'answer';
  return result;
}


/* ========================= Codec negotiation ========================= */

// Intersect remote codecs with local capabilities
// Returns codecs we both support, preserving remote payload types
function negotiateCodecs(remoteCodecs, localCodecs) {
  var matched = [];

  for (var i = 0; i < remoteCodecs.length; i++) {
    var remote = remoteCodecs[i];

    for (var j = 0; j < localCodecs.length; j++) {
      var local = localCodecs[j];

      if (remote.name.toLowerCase() !== local.name.toLowerCase()) continue;
      if (remote.clockRate !== local.clockRate) continue;

      // H264: also match profile-level-id.
      // RFC 6184 §8.1: when profile-level-id is absent, the default value
      // is the constrained baseline profile (42e01f). Treating absence as
      // empty string '' would silently fail to match against our own
      // 42e01f default — so peers that offer H264 without fmtp (legal,
      // less common but seen in lightweight SIP gateways and some
      // non-Chrome WebRTC stacks) would lose H264 compatibility.
      // Compare first 4 hex chars (profile_idc + profile_iop / constraint set).
      if (remote.name.toLowerCase() === 'h264') {
        var rProfile = (remote.fmtp && remote.fmtp['profile-level-id']) || '42e01f';
        var lProfile = (local.fmtp && local.fmtp['profile-level-id']) || '42e01f';
        if (rProfile.slice(0, 4).toLowerCase() !== lProfile.slice(0, 4).toLowerCase()) continue;
      }

      matched.push({
        payloadType: remote.payloadType,  // use remote's PT
        name: remote.name,
        clockRate: remote.clockRate,
        channels: remote.channels || local.channels || 0,
        fmtp: remote.fmtp || local.fmtp || {},
        feedback: intersectFeedback(remote.feedback, local.feedback),
        rtxPayloadType: remote.rtxPayloadType,
      });
      break;
    }
  }

  return matched;
}

function intersectFeedback(remoteFb, localFb) {
  if (!remoteFb || !localFb) return [];
  // RFC 4585 §4.2: rtcp-fb attribute names ("nack", "ccm", "transport-cc",
  // etc.) are case-insensitive. Chrome and Firefox always emit lowercase,
  // so this is defensive against non-mainstream implementations that
  // might use mixed case.
  var local = {};
  for (var i = 0; i < localFb.length; i++) {
    local[localFb[i].toLowerCase()] = localFb[i];
  }
  var result = [];
  for (var j = 0; j < remoteFb.length; j++) {
    var rfb = remoteFb[j].toLowerCase();
    if (local[rfb]) result.push(remoteFb[j]);
  }
  return result;
}


/* ========================= createAnswer ========================= */

function createAnswer(parsedOffer, config) {
  config = config || {};

  var ice = config.ice || {};
  var dtls = config.dtls || {};
  var localCodecs = config.codecs || {};
  var localAudioCodecs = localCodecs.audio || DEFAULT_AUDIO_CODECS;
  var localVideoCodecs = localCodecs.video || DEFAULT_VIDEO_CODECS;

  // Generate session-level fields
  var sessionId = config.sessionId || String(Date.now());

  var sdpObj = {
    version: 0,
    origin: {
      username: '-',
      sessionId: sessionId,
      sessionVersion: 2,  // Chrome convention (JSEP)
      netType: 'IN',
      ipVer: 4,
      address: '127.0.0.1',
    },
    name: '-',
    timing: { start: 0, stop: 0 },
    groups: [],
    extmapAllowMixed: 'extmap-allow-mixed',  // RFC 8285 §6
    msidSemantic: { semantic: 'WMS', token: '*' },  // '*' is sdp-transform friendly; functionally equivalent
    media: [],
  };

  // ICE Lite — session-level flag (RFC 8839). Declaring this tells the peer
  // we're controlled, won't send connectivity checks, and only gather host
  // candidates. Emitted only when the caller explicitly says mode: 'lite'.
  // sdp-transform key is 'icelite' (one word); value is literal 'ice-lite'.
  if (config.mode === 'lite') {
    sdpObj.icelite = 'ice-lite';
  }

  // BUNDLE: mirror offer's BUNDLE groups
  if (parsedOffer.bundleGroups.length > 0) {
    for (var g = 0; g < parsedOffer.bundleGroups.length; g++) {
      sdpObj.groups.push({
        type: 'BUNDLE',
        mids: parsedOffer.bundleGroups[g].join(' '),
      });
    }
  }

  // Build media sections
  for (var i = 0; i < parsedOffer.media.length; i++) {
    var offer = parsedOffer.media[i];
    var mediaObj = buildAnswerMedia(offer, {
      ice: ice,
      dtls: dtls,
      localAudioCodecs: localAudioCodecs,
      localVideoCodecs: localVideoCodecs,
      localSsrc: config.ssrcs ? config.ssrcs[offer.mid] : null,
      localCname: config.cname || crypto.randomBytes(8).toString('hex'),
      localExtensions: config.extensions ? config.extensions[offer.type] : null,
      // User-set transceiver.direction for this mid (from MSF). Per W3C §5.5
      // step 2, the answer's direction is the intersection of offer dir,
      // ability-to-send, AND user preference. Falls back to 'sendrecv' in
      // computeAnswerDirection when absent (back-compat).
      userPreferredDir: config.directions ? config.directions[offer.mid] : null,
      // ICE candidates to embed in this m-section. With ice-lite or when
      // half-trickle is desired, pass the full candidate list here so it's
      // included in the answer SDP. The peer then needs no separate trickle.
      candidates: config.candidates || null,
      // When true, emit a=end-of-candidates (RFC 8838 §8). Tells the peer
      // "no more candidates will arrive — stop waiting". Use in ice-lite
      // mode where all candidates are known at answer time.
      endOfCandidates: !!config.endOfCandidates,
    });
    sdpObj.media.push(mediaObj);
  }

  return sdpTransform.write(sdpObj);
}

function buildAnswerMedia(offerMedia, config) {
  var m = {
    type: offerMedia.type,
    port: 9,
    protocol: offerMedia.protocol,
    payloads: '',
    connection: { version: 4, ip: '0.0.0.0' },
    rtcp: { port: 9, netType: 'IN', ipVer: 4, address: '0.0.0.0' },

    // ICE
    iceUfrag: config.ice.ufrag || null,
    icePwd: config.ice.pwd || null,
    iceOptions: 'trickle',  // RFC 8840

    // DTLS
    fingerprint: config.dtls.fingerprint ? {
      type: config.dtls.fingerprint.algorithm || 'sha-256',
      hash: config.dtls.fingerprint.value,
    } : null,
    setup: resolveSetup(offerMedia.setup),

    // MID
    mid: offerMedia.mid,

    // Direction — depends on (a) the peer's offer dir, (b) whether we have
    // something to send (config.localSsrc presence), and (c) the user's
    // preferred direction on this transceiver (config.userPreferredDir,
    // populated by MSF buildAnswer from state.transceivers). See
    // computeAnswerDirection for the full intersection table.
    direction: computeAnswerDirection(
      offerMedia.direction,
      !!config.localSsrc,
      config.userPreferredDir
    ),

    // Flags
    rtcpMux: 'rtcp-mux',
  };

  // ICE candidates — embed directly in the m-section (half-trickle or lite).
  // sdp-transform's candidate shape uses `transport` for the protocol and
  // `component` for the ICE component ID. We mirror the exact fields used
  // by addCandidate() below for consistency.
  if (config.candidates && config.candidates.length > 0) {
    m.candidates = [];
    for (var ci = 0; ci < config.candidates.length; ci++) {
      var c = config.candidates[ci];
      m.candidates.push({
        foundation: c.foundation,
        component:  c.component || 1,
        transport:  c.protocol,
        priority:   c.priority,
        ip:         c.ip,
        port:       c.port,
        type:       c.type,
        raddr:      c.relatedAddress || undefined,
        rport:      c.relatedPort != null ? c.relatedPort : undefined,
        tcptype:    c.tcpType || undefined,
      });
    }
  }

  // End-of-candidates marker (RFC 8838 §8). Applied when the caller knows
  // the candidate list is complete at SDP time — most commonly ice-lite.
  if (config.endOfCandidates) {
    m.endOfCandidates = 'end-of-candidates';
  }

  // DataChannel (SCTP) — application m-sections don't carry a media direction
  // (sendrecv/recvonly/...). Chrome never emits direction on these; emitting
  // recvonly here appears to confuse Chrome's state machine around
  // DataChannel + BUNDLE during renegotiation.
  if (offerMedia.type === 'application') {
    m.payloads = 'webrtc-datachannel';
    m.sctpPort = offerMedia.sctpPort || 5000;
    m.maxMessageSize = offerMedia.maxMessageSize || 262144;
    delete m.direction;
    return m;
  }

  // rtcp-rsize — RFC 5506 — only for RTP m-sections (not application/SCTP).
  m.rtcpRsize = 'rtcp-rsize';

  // Codec negotiation
  var localCodecs = (offerMedia.type === 'audio') ? config.localAudioCodecs : config.localVideoCodecs;
  var negotiated = negotiateCodecs(offerMedia.codecs, localCodecs);

  // Build rtp, fmtp, rtcpFb, payloads
  var rtp = [];
  var fmtp = [];
  var rtcpFb = [];
  var payloadList = [];

  for (var i = 0; i < negotiated.length; i++) {
    var codec = negotiated[i];
    payloadList.push(codec.payloadType);

    rtp.push({
      payload: codec.payloadType,
      codec: codec.name,
      rate: codec.clockRate,
      encoding: codec.channels || undefined,
    });

    // FMTP
    var fmtpStr = buildFmtpConfig(codec.fmtp);
    if (fmtpStr) {
      fmtp.push({ payload: codec.payloadType, config: fmtpStr });
    }

    // RTCP-FB
    for (var f = 0; f < codec.feedback.length; f++) {
      var parts = codec.feedback[f].split(' ');
      rtcpFb.push({
        payload: codec.payloadType,
        type: parts[0],
        subtype: parts.slice(1).join(' ') || undefined,
      });
    }

    // RTX
    if (codec.rtxPayloadType) {
      payloadList.push(codec.rtxPayloadType);
      rtp.push({
        payload: codec.rtxPayloadType,
        codec: 'rtx',
        rate: codec.clockRate,
      });
      fmtp.push({
        payload: codec.rtxPayloadType,
        config: 'apt=' + codec.payloadType,
      });
    }
  }

  m.rtp = rtp;
  m.fmtp = fmtp;
  m.rtcpFb = rtcpFb;
  m.payloads = payloadList.join(' ');

  // RTP header extensions — preference order:
  //   1. config.localExtensions (caller override)
  //   2. mirror offer's extensions (most common — intersection-by-presence)
  //   3. our DEFAULT_*_EXTENSIONS
  // In practice Chrome's offer already contains our default set, so (2) and (3)
  // give the same result; (3) is the fallback for non-Chrome peers that offer
  // a skinny SDP.
  var extsToDeclare = null;
  if (config.localExtensions) {
    extsToDeclare = config.localExtensions;
  } else if (offerMedia.extensions && offerMedia.extensions.length > 0) {
    extsToDeclare = offerMedia.extensions;
  } else {
    extsToDeclare = (offerMedia.type === 'audio') ? DEFAULT_AUDIO_EXTENSIONS : DEFAULT_VIDEO_EXTENSIONS;
  }
  if (extsToDeclare && extsToDeclare.length > 0) {
    m.ext = [];
    for (var e = 0; e < extsToDeclare.length; e++) {
      m.ext.push({ value: extsToDeclare[e].id, uri: extsToDeclare[e].uri });
    }
  }

  // Media-level a=msid — modern WebRTC Unified Plan (RFC 8830).
  // sdp-transform grammar: push field, array of {id, appdata}.
  if (config.localSsrc && config.localSsrc.msid) {
    var msidParts = String(config.localSsrc.msid).split(/\s+/);
    m.msid = [{ id: msidParts[0], appdata: msidParts[1] || undefined }];
  }

  // SSRCs (local)
  if (config.localSsrc) {
    var ssrc = config.localSsrc;
    var cname = config.localCname;
    m.ssrcs = [];
    m.ssrcGroups = [];

    // Whether to emit RTX SSRCs at all. We allocate rtxSsrc unconditionally
    // for every transceiver in addTransceiverInternal, but RTX is only
    // meaningful for codecs that declare an `apt=` rtx payload type. Audio
    // (Opus, G.711, etc.) does not. If we declare a=ssrc-group:FID with an
    // RTX SSRC but no `a=rtpmap:NN rtx/...` in the same m-section, Chrome
    // rejects the answer with:
    //   "Failed to add remote stream ssrc: NNN to {mid: X, media_type: audio}"
    // because the FID group references an SSRC with no payload type binding.
    // Only emit RTX-related lines when RTX was actually negotiated for at
    // least one codec in this m-section.
    var rtxNegotiated = false;
    for (var rti = 0; rti < negotiated.length; rti++) {
      if (negotiated[rti].rtxPayloadType) { rtxNegotiated = true; break; }
    }

    function _emitLayerSsrcsA(primary, rtx) {
      if (primary == null) return;
      m.ssrcs.push({ id: primary, attribute: 'cname', value: cname });
      if (ssrc.msid) {
        m.ssrcs.push({ id: primary, attribute: 'msid', value: ssrc.msid });
      }
      if (rtx != null && rtxNegotiated) {
        m.ssrcs.push({ id: rtx, attribute: 'cname', value: cname });
        if (ssrc.msid) {
          m.ssrcs.push({ id: rtx, attribute: 'msid', value: ssrc.msid });
        }
        m.ssrcGroups.push({ semantics: 'FID', ssrcs: primary + ' ' + rtx });
      }
    }

    var ansLayers = (ssrc.layers && ssrc.layers.length)
                    ? ssrc.layers
                    : [{ rid: null, ssrc: ssrc.id, rtxSsrc: ssrc.rtxId }];

    for (var ali = 0; ali < ansLayers.length; ali++) {
      _emitLayerSsrcsA(ansLayers[ali].ssrc, ansLayers[ali].rtxSsrc);
    }

    var ansRids = [];
    var ansSimSsrcs = [];
    for (var ari = 0; ari < ansLayers.length; ari++) {
      if (ansLayers[ari].rid) ansRids.push(ansLayers[ari].rid);
      if (ansLayers[ari].ssrc != null) ansSimSsrcs.push(ansLayers[ari].ssrc);
    }
    if (ansRids.length > 1) {
      m.rids = [];
      for (var arri = 0; arri < ansRids.length; arri++) {
        m.rids.push({ id: ansRids[arri], direction: 'send' });
      }
      m.simulcast = { dir1: 'send', list1: ansRids.join(';') };
      // SIM group — see offer path for rationale.
      if (ansSimSsrcs.length > 1) {
        m.ssrcGroups.push({ semantics: 'SIM', ssrcs: ansSimSsrcs.join(' ') });
      }
    }

    if (m.ssrcGroups.length === 0) delete m.ssrcGroups;
  }

  // Answer-side simulcast mirror (RFC 8853). When the OFFER declares
  // simulcast:send (peer wants to send us layers), our answer MUST
  // reciprocate with simulcast:recv naming the same RIDs — otherwise
  // the publisher typically falls back to non-simulcast (single layer).
  //
  // This runs whether or not we ALSO have our own send-side simulcast
  // (the send path above emits dir1=send; we stack dir2=recv). The
  // common case here is we're a pure receiver (SFU publish scenario),
  // so no send-side simulcast was emitted and we populate dir1=recv.
  if (offerMedia.simulcast &&
      (offerMedia.simulcast.dir1 === 'send' || offerMedia.simulcast.dir2 === 'send')) {
    var offeredList = (offerMedia.simulcast.dir1 === 'send')
      ? (offerMedia.simulcast.list1 || '')
      : (offerMedia.simulcast.list2 || '');
    if (offeredList) {
      // Parse the offered RID list and emit a=rid:<id> recv per RID.
      var offeredRids = offeredList.split(';').map(function (r) {
        r = r.trim();
        if (r.charAt(0) === '~') r = r.slice(1);
        var comma = r.indexOf(',');
        return comma >= 0 ? r.slice(0, comma).trim() : r;
      }).filter(function (r) { return !!r; });

      if (offeredRids.length) {
        // Merge with any existing m.rids (if we also sent simulcast above).
        if (!m.rids) m.rids = [];
        for (var ori = 0; ori < offeredRids.length; ori++) {
          m.rids.push({ id: offeredRids[ori], direction: 'recv' });
        }
        // Emit simulcast block. If send-side simulcast already populated
        // dir1, use dir2 for the recv side; otherwise populate dir1.
        if (m.simulcast) {
          m.simulcast.dir2 = 'recv';
          m.simulcast.list2 = offeredRids.join(';');
        } else {
          m.simulcast = { dir1: 'recv', list1: offeredRids.join(';') };
        }
      }
    }
  }

  return m;
}


/* ========================= createOffer ========================= */

function createOffer(config) {
  config = config || {};

  var ice = config.ice || {};
  var dtls = config.dtls || {};
  var sessionId = config.sessionId || String(Date.now());
  var media = config.media || [];

  var sdpObj = {
    version: 0,
    origin: {
      username: '-',
      sessionId: sessionId,
      sessionVersion: 2,  // Chrome uses 2 (JSEP convention). Version '1' worked but diverged visually.
      netType: 'IN',
      ipVer: 4,
      address: '127.0.0.1',
    },
    name: '-',
    timing: { start: 0, stop: 0 },
    groups: [],
    extmapAllowMixed: 'extmap-allow-mixed',  // RFC 8285 §6 — allow mixing 1-byte / 2-byte extension headers
    msidSemantic: { semantic: 'WMS', token: '*' },  // sdp-transform requires both fields or it writes 'undefined'; '*' is RFC-safe
    media: [],
  };

  // ICE Lite — session-level flag (RFC 8839). Declaring this tells the peer
  // we're controlled, won't send connectivity checks, and only gather host
  // candidates. Emitted only when the caller explicitly says mode: 'lite'.
  // sdp-transform key is 'icelite' (one word); value is literal 'ice-lite'.
  if (config.mode === 'lite') {
    sdpObj.icelite = 'ice-lite';
  }

  // Collect mids for BUNDLE
  var mids = [];

  for (var i = 0; i < media.length; i++) {
    var spec = media[i];
    var mid = spec.mid != null ? String(spec.mid) : String(i);
    mids.push(mid);

    var m = {
      type: spec.type,
      // Most m-sections use port 9 (placeholder per RFC 4566; the actual
      // wire endpoint is decided by ICE). spec.port=0 is the JSEP §5.2.2
      // signal for a *rejected* m-section — preserved across renegotiation
      // when a transceiver was stopped and no new transceiver recycled
      // its slot. We honor spec.port if supplied, else default to 9.
      port: (typeof spec.port === 'number') ? spec.port : 9,
      protocol: spec.protocol || 'UDP/TLS/RTP/SAVPF',
      payloads: '',
      connection: { version: 4, ip: '0.0.0.0' },
      rtcp: { port: 9, netType: 'IN', ipVer: 4, address: '0.0.0.0' },
      iceUfrag: ice.ufrag || null,
      icePwd: ice.pwd || null,
      iceOptions: 'trickle',  // RFC 8840 — tell peer we support trickle on this m-section
      fingerprint: dtls.fingerprint ? {
        type: dtls.fingerprint.algorithm || 'sha-256',
        hash: dtls.fingerprint.value,
      } : null,
      setup: dtls.setup || 'actpass',
      mid: mid,
      direction: spec.direction || 'sendrecv',
      rtcpMux: 'rtcp-mux',
    };

    // ICE candidates — embed directly in this m-section when supplied by
    // the caller (half-trickle or lite-mode: all host candidates known up
    // front, no need for separate a=candidate trickle events).
    if (config.candidates && config.candidates.length > 0) {
      m.candidates = [];
      for (var ci = 0; ci < config.candidates.length; ci++) {
        var c = config.candidates[ci];
        m.candidates.push({
          foundation: c.foundation,
          component:  c.component || 1,
          transport:  c.protocol,
          priority:   c.priority,
          ip:         c.ip,
          port:       c.port,
          type:       c.type,
          raddr:      c.relatedAddress || undefined,
          rport:      c.relatedPort != null ? c.relatedPort : undefined,
          tcptype:    c.tcpType || undefined,
        });
      }
    }

    // End-of-candidates marker (RFC 8838 §8). Most useful in ice-lite where
    // the full candidate list is known at offer time.
    if (config.endOfCandidates) {
      m.endOfCandidates = 'end-of-candidates';
    }

    if (spec.type === 'application') {
      // DataChannel — Chrome never emits a direction attribute on m=application.
      // In offers, we previously emitted a default 'sendrecv' here; in answers
      // we already stripped it (buildAnswerMedia). Remove for symmetry so our
      // offer and Chrome's offer look the same for DataChannel.
      m.protocol = 'UDP/DTLS/SCTP';
      m.payloads = 'webrtc-datachannel';
      m.sctpPort = spec.sctpPort || 5000;
      m.maxMessageSize = spec.maxMessageSize || 262144;
      delete m.direction;
    } else {
      // Audio/Video
      var codecs = spec.codecs || [];
      var rtp = [];
      var fmtpArr = [];
      var rtcpFb = [];
      var payloadList = [];

      // rtcp-rsize — RFC 5506 — reduced-size RTCP. Chrome always includes this.
      m.rtcpRsize = 'rtcp-rsize';

      for (var c = 0; c < codecs.length; c++) {
        var codec = codecs[c];
        payloadList.push(codec.payloadType);

        rtp.push({
          payload: codec.payloadType,
          codec: codec.name,
          rate: codec.clockRate,
          encoding: codec.channels || undefined,
        });

        var fmtpStr = buildFmtpConfig(codec.fmtp);
        if (fmtpStr) {
          fmtpArr.push({ payload: codec.payloadType, config: fmtpStr });
        }

        if (codec.feedback) {
          for (var f = 0; f < codec.feedback.length; f++) {
            var parts = codec.feedback[f].split(' ');
            rtcpFb.push({
              payload: codec.payloadType,
              type: parts[0],
              subtype: parts.slice(1).join(' ') || undefined,
            });
          }
        }

        if (codec.rtxPayloadType) {
          payloadList.push(codec.rtxPayloadType);
          rtp.push({ payload: codec.rtxPayloadType, codec: 'rtx', rate: codec.clockRate });
          fmtpArr.push({ payload: codec.rtxPayloadType, config: 'apt=' + codec.payloadType });
        }
      }

      m.rtp = rtp;
      m.fmtp = fmtpArr;
      m.rtcpFb = rtcpFb;
      m.payloads = payloadList.join(' ');

      // Header extensions — use caller-provided set if present, otherwise our
      // Chrome-aligned defaults. Declaring extmap doesn't obligate us to USE
      // every extension on the wire; see DEFAULT_*_EXTENSIONS comment.
      var exts = spec.extensions;
      if (exts == null) {
        exts = (spec.type === 'audio') ? DEFAULT_AUDIO_EXTENSIONS : DEFAULT_VIDEO_EXTENSIONS;
      }
      if (exts && exts.length > 0) {
        m.ext = [];
        for (var e = 0; e < exts.length; e++) {
          m.ext.push({ value: exts[e].id, uri: exts[e].uri });
        }
      }

      // Media-level a=msid (modern WebRTC Unified Plan — RFC 8830).
      // sdp-transform's grammar has this as a `push` field: array of {id, appdata}.
      // spec.ssrc.msid is a single "<stream-id> <track-id>" string; split into parts.
      if (spec.ssrc && spec.ssrc.msid) {
        var msidParts = String(spec.ssrc.msid).split(/\s+/);
        m.msid = [{ id: msidParts[0], appdata: msidParts[1] || undefined }];
      }

      if (spec.ssrc) {
        var cname = spec.ssrc.cname || config.cname || 'node';
        m.ssrcs = [];
        m.ssrcGroups = [];

        // RTX gating: same reasoning as buildAnswerMedia. Only emit RTX
        // SSRCs and the FID group when at least one codec in this
        // m-section has rtxPayloadType. Audio doesn't, so for audio
        // m-sections we'd otherwise produce a=ssrc-group:FID pointing
        // at an SSRC with no payload type binding — which Chrome rejects.
        var rtxNegotiated = false;
        for (var rti = 0; rti < codecs.length; rti++) {
          if (codecs[rti].rtxPayloadType) { rtxNegotiated = true; break; }
        }

        // Helper to emit one layer's SSRCs (primary + optional RTX).
        function _emitLayerSsrcs(primary, rtx) {
          if (primary == null) return;
          m.ssrcs.push({ id: primary, attribute: 'cname', value: cname });
          if (spec.ssrc.msid) {
            m.ssrcs.push({ id: primary, attribute: 'msid', value: spec.ssrc.msid });
          }
          if (rtx != null && rtxNegotiated) {
            m.ssrcs.push({ id: rtx, attribute: 'cname', value: cname });
            if (spec.ssrc.msid) {
              m.ssrcs.push({ id: rtx, attribute: 'msid', value: spec.ssrc.msid });
            }
            // FID (RFC 4588 §4) pairs the primary SSRC with its RTX SSRC
            m.ssrcGroups.push({ semantics: 'FID', ssrcs: primary + ' ' + rtx });
          }
        }

        // Simulcast (RFC 8853) — multiple layers, each with its own SSRC and RID.
        // Emit a=ssrc per layer, a=ssrc-group:FID per layer, then a=rid:<id> send
        // for each RID, followed by a=simulcast:send <rid1>;<rid2>;...
        //
        // Non-simulcast is just layers.length===1 with rid=null — falls through
        // to the _emitLayerSsrcs path without a=rid/a=simulcast.
        var layers = (spec.ssrc.layers && spec.ssrc.layers.length)
                     ? spec.ssrc.layers
                     : [{ rid: null, ssrc: spec.ssrc.id, rtxSsrc: spec.ssrc.rtxId }];

        for (var li = 0; li < layers.length; li++) {
          _emitLayerSsrcs(layers[li].ssrc, layers[li].rtxSsrc);
        }

        // RID + simulcast attributes (only when there are actually multiple
        // named layers — single anonymous layer keeps the simpler form).
        var namedRids = [];
        var simSsrcsList = [];
        for (var ri = 0; ri < layers.length; ri++) {
          if (layers[ri].rid) namedRids.push(layers[ri].rid);
          if (layers[ri].ssrc != null) simSsrcsList.push(layers[ri].ssrc);
        }
        if (namedRids.length > 1) {
          m.rids = [];
          for (var rri = 0; rri < namedRids.length; rri++) {
            m.rids.push({ id: namedRids[rri], direction: 'send' });
          }
          m.simulcast = { dir1: 'send', list1: namedRids.join(';') };

          // a=ssrc-group:SIM <ssrc1> <ssrc2> ... — declares the primary
          // SSRCs of each simulcast layer in a single group. RFC 5576 §4.2
          // style, widely used by Chrome for simulcast. Receivers use SIM
          // ordering + simulcast list ordering to infer SSRC→RID mapping
          // when RIDs aren't delivered via the rtp-stream-id extension yet.
          if (simSsrcsList.length > 1) {
            m.ssrcGroups.push({ semantics: 'SIM', ssrcs: simSsrcsList.join(' ') });
          }
        }

        // Legacy: if ssrcGroups ended up empty (no RTX layers at all),
        // drop the field so the writer doesn't emit an empty line.
        if (m.ssrcGroups.length === 0) delete m.ssrcGroups;
      }
    }

    sdpObj.media.push(m);
  }

  // BUNDLE group
  if (mids.length > 0) {
    sdpObj.groups.push({ type: 'BUNDLE', mids: mids.join(' ') });
  }

  return sdpTransform.write(sdpObj);
}


/* ========================= ICE candidates ========================= */

// Add trickle ICE candidate to an SDP string
function addCandidate(sdpString, candidate, mid) {
  var raw = sdpTransform.parse(sdpString);

  for (var i = 0; i < raw.media.length; i++) {
    var m = raw.media[i];
    if (String(m.mid) === String(mid)) {
      if (!m.candidates) m.candidates = [];
      m.candidates.push({
        foundation: candidate.foundation,
        component: candidate.component || 1,
        transport: candidate.protocol,
        priority: candidate.priority,
        ip: candidate.ip,
        port: candidate.port,
        type: candidate.type,
        raddr: candidate.relatedAddress || undefined,
        // Use `!= null` (not `||`) so port 0 (legitimate for some
        // candidate types) isn't silently dropped to undefined. Mirrors
        // the same check in buildAnswerMedia / createOffer's candidate
        // emission path.
        rport: candidate.relatedPort != null ? candidate.relatedPort : undefined,
        tcptype: candidate.tcpType || undefined,
      });
      return sdpTransform.write(raw);
    }
  }

  // mid not found — log a warning rather than silently no-op, since this
  // almost always means the SDP and candidate are out of sync (e.g.,
  // trickle candidate arriving for a stopped/recycled m-section).
  if (typeof console !== 'undefined' && console.warn) {
    console.warn('[sdp] addCandidate: mid="' + mid + '" not found in SDP; candidate dropped');
  }
  return sdpString;
}

// Parse a candidate string "candidate:..." → object
function parseCandidate(candidateString) {
  // Remove "candidate:" prefix if present, and add "a=" if missing for sdp-transform
  var line = candidateString;
  if (line.startsWith('candidate:')) line = 'a=' + line;
  else if (!line.startsWith('a=candidate:')) line = 'a=candidate:' + line;

  // sdp-transform doesn't parse single lines, so we manually parse
  var parts = line.replace('a=candidate:', '').split(/\s+/);
  if (parts.length < 8) return null;

  var cand = {
    foundation: parts[0],
    component: parseInt(parts[1], 10),
    protocol: parts[2].toLowerCase(),
    priority: parseInt(parts[3], 10),
    ip: parts[4],
    port: parseInt(parts[5], 10),
    // parts[6] = "typ"
    type: parts[7],
    relatedAddress: null,
    relatedPort: null,
    tcpType: null,
  };

  // Parse remaining key-value pairs
  for (var i = 8; i + 1 < parts.length; i += 2) {
    if (parts[i] === 'raddr') cand.relatedAddress = parts[i + 1];
    else if (parts[i] === 'rport') cand.relatedPort = parseInt(parts[i + 1], 10);
    else if (parts[i] === 'tcptype') cand.tcpType = parts[i + 1];
  }

  return cand;
}

// Build candidate string from object
function buildCandidateString(candidate) {
  var str = 'candidate:' + candidate.foundation + ' ' +
    (candidate.component || 1) + ' ' +
    candidate.protocol + ' ' +
    candidate.priority + ' ' +
    candidate.ip + ' ' +
    candidate.port + ' typ ' +
    candidate.type;

  if (candidate.relatedAddress) str += ' raddr ' + candidate.relatedAddress;
  if (candidate.relatedPort != null) str += ' rport ' + candidate.relatedPort;
  if (candidate.tcpType) str += ' tcptype ' + candidate.tcpType;

  return str;
}


/* ========================= Utility ========================= */

// Resolve DTLS setup role: offer=actpass → answer=active
function resolveSetup(offerSetup) {
  if (offerSetup === 'actpass') return 'active';
  if (offerSetup === 'active') return 'passive';
  if (offerSetup === 'passive') return 'active';
  return 'active';
}

// Generate random ICE credentials
function generateIceCredentials() {
  return {
    ufrag: crypto.randomBytes(4).toString('hex'),
    pwd: crypto.randomBytes(16).toString('base64'),
  };
}

// Generate random SSRC
function generateSsrc() {
  return crypto.randomBytes(4).readUInt32BE(0);
}

// Get the first BUNDLE group mids (most common case)
function getBundleMids(parsedSdp) {
  if (parsedSdp.bundleGroups.length > 0) return parsedSdp.bundleGroups[0];
  return [];
}

// Check if two media sections are in the same BUNDLE group
function isBundled(parsedSdp, mid1, mid2) {
  for (var i = 0; i < parsedSdp.bundleGroups.length; i++) {
    var group = parsedSdp.bundleGroups[i];
    var has1 = false, has2 = false;
    for (var j = 0; j < group.length; j++) {
      if (group[j] === String(mid1)) has1 = true;
      if (group[j] === String(mid2)) has2 = true;
    }
    if (has1 && has2) return true;
  }
  return false;
}

// Find media section by MID
function getMediaByMid(parsedSdp, mid) {
  for (var i = 0; i < parsedSdp.media.length; i++) {
    if (parsedSdp.media[i].mid === String(mid)) return parsedSdp.media[i];
  }
  return null;
}


/* ========================= Helpers added for SDP-layer refactor ========================= */
//
// These helpers reduce duplication across the new modules
// (rtp_transmission_manager.js, jsep_transport_controller.js, etc.) that
// will be carved out of connection_manager.js. Each is a small wrapper
// around the existing parseOffer/parseAnswer output format — there is no
// new data model. See SDP_REFACTOR_PLAN.md for the broader plan.

/**
 * Find the first media section of a given kind ('audio', 'video',
 * 'application'), or null if none. Useful for "is there video at all?"
 * checks during negotiation.
 *
 * @param {Object} parsedSdp
 * @param {string} kind  'audio' | 'video' | 'application'
 * @returns {Object|null}
 */
function firstMediaByKind(parsedSdp, kind) {
  if (!parsedSdp || !parsedSdp.media) return null;
  for (var i = 0; i < parsedSdp.media.length; i++) {
    if (parsedSdp.media[i].type === kind) return parsedSdp.media[i];
  }
  return null;
}

/**
 * True if the parsed SDP has an m=application section that wasn't rejected.
 * Used by checkIfNegotiationIsNeeded to know whether a DataChannel slot
 * already exists in the local description.
 *
 * @param {Object} parsedSdp
 * @returns {boolean}
 */
function hasMediaApplication(parsedSdp) {
  if (!parsedSdp || !parsedSdp.media) return false;
  for (var i = 0; i < parsedSdp.media.length; i++) {
    if (parsedSdp.media[i].type === 'application' && parsedSdp.media[i].port !== 0) {
      return true;
    }
  }
  return false;
}

/**
 * True if the m-section was rejected (port = 0). Per RFC 3264 §6,
 * a port of 0 means the section is reserved (kept in the SDP for
 * mid stability and future recycle) but not active.
 *
 * @param {Object} media   one entry from parsedSdp.media[]
 * @returns {boolean}
 */
function isRejected(media) {
  return !!media && media.port === 0;
}

/**
 * Convert the raw a=simulcast info into a structured form.
 *
 * The raw form (from sdp-transform) is:
 *   m.simulcast = { dir1: 'send', list1: 'h;m;~l', dir2?: 'recv', list2?: '...' }
 * where each list is semicolon-separated rids, optionally prefixed with
 * '~' for paused. Alternatives are comma-separated within an entry
 * (e.g. 'h,m;l' = "either h or m, and l" — rare in practice).
 *
 * The structured form is:
 *   {
 *     sendLayers: SimulcastLayer[][] | null,    // outer: alternatives, inner: layers
 *     recvLayers: SimulcastLayer[][] | null,
 *   }
 * where SimulcastLayer = { rid: string, isPaused: boolean }.
 *
 * Returns null if the m-section has no a=simulcast.
 *
 * @param {Object} media   one entry from parsedSdp.media[]
 * @returns {{sendLayers: Array|null, recvLayers: Array|null}|null}
 */
function getSimulcastStructure(media) {
  if (!media || !media.simulcast) return null;

  function parseList(listStr) {
    // 'h;m;~l' → [[{rid:'h',paused:false},{rid:'m',paused:false},{rid:'l',paused:true}]]
    // 'h,m;l'  → [[{rid:'h',paused:false},{rid:'l',paused:false}],     ← alt 1: h+l
    //             [{rid:'m',paused:false},{rid:'l',paused:false}]]      ← alt 2: m+l
    // For our use case (single alternative is the common case), the inner
    // commas are very rare. We model alternatives as the outer array but
    // the simple case is one entry inside.
    if (!listStr) return null;
    var entries = String(listStr).split(';');
    // Each entry can be 'h' or 'h,m' (alternatives within a slot).
    // For the simple single-alternative case, return [[layers...]].
    var hasAlts = false;
    for (var i = 0; i < entries.length; i++) {
      if (entries[i].indexOf(',') >= 0) { hasAlts = true; break; }
    }
    if (!hasAlts) {
      var layers = [];
      for (var j = 0; j < entries.length; j++) {
        var e = entries[j].trim();
        if (!e) continue;
        var paused = (e.charAt(0) === '~');
        var rid    = paused ? e.substring(1) : e;
        layers.push({ rid: rid, isPaused: paused });
      }
      return [layers];
    }
    // Rare: alternatives within a slot. Build alternatives as the
    // cross-product of choices per slot.
    var slots = [];
    for (var k = 0; k < entries.length; k++) {
      var slot = entries[k].split(',').map(function (x) {
        x = x.trim();
        if (!x) return null;
        var p = (x.charAt(0) === '~');
        return { rid: p ? x.substring(1) : x, isPaused: p };
      }).filter(Boolean);
      slots.push(slot);
    }
    // Cross-product
    var alts = [[]];
    for (var s = 0; s < slots.length; s++) {
      var nextAlts = [];
      for (var a = 0; a < alts.length; a++) {
        for (var c = 0; c < slots[s].length; c++) {
          nextAlts.push(alts[a].concat([slots[s][c]]));
        }
      }
      alts = nextAlts;
    }
    return alts;
  }

  var result = { sendLayers: null, recvLayers: null };
  var sc = media.simulcast;
  if (sc.dir1 === 'send') result.sendLayers = parseList(sc.list1);
  if (sc.dir1 === 'recv') result.recvLayers = parseList(sc.list1);
  if (sc.dir2 === 'send') result.sendLayers = parseList(sc.list2);
  if (sc.dir2 === 'recv') result.recvLayers = parseList(sc.list2);
  return result;
}

/**
 * Deep clone of a parsed SDP. Used by snapshots-before-mutation
 * (eventually for rollback support). JSON-friendly: every field in the
 * parsed SDP is a string/number/boolean/array/plain-object, so
 * JSON.parse(JSON.stringify(...)) is a safe deep copy here.
 *
 * The .raw field (sdp-transform's full output) is intentionally dropped
 * — it's the source-of-truth string view, not needed for copies. Callers
 * who need the raw form should keep the SDP string instead.
 *
 * @param {Object} parsedSdp
 * @returns {Object}
 */
function cloneParsedSdp(parsedSdp) {
  if (!parsedSdp) return parsedSdp;
  var raw = parsedSdp.raw;
  parsedSdp.raw = undefined;
  var copy;
  try {
    copy = JSON.parse(JSON.stringify(parsedSdp));
  } finally {
    parsedSdp.raw = raw;
  }
  return copy;
}


/* ========================= Exports ========================= */

export {
  // Parse
  parseOffer, parseAnswer, parseCandidate,

  // Build
  createOffer, createAnswer, addCandidate, buildCandidateString,

  // Negotiation
  negotiateCodecs,

  // Utilities
  generateIceCredentials, generateSsrc, resolveSetup,
  getBundleMids, isBundled, getMediaByMid,
  firstMediaByKind, hasMediaApplication, isRejected,
  getSimulcastStructure, cloneParsedSdp,
  assignExtensionIds,

  // Direction helpers
  REVERSE_DIRECTION, computeAnswerDirection,

  // Defaults (can be used by PeerConnection)
  DEFAULT_AUDIO_CODECS, DEFAULT_VIDEO_CODECS,
  DEFAULT_AUDIO_EXTENSIONS, DEFAULT_VIDEO_EXTENSIONS,

  // Low-level (for advanced use)
  extractCodecs, extractSsrcs, extractExtensions, extractCandidates,
  parseFmtpConfig, buildFmtpConfig,
};
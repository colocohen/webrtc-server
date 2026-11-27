// src/sdp_grammar.js
// The SDP grammar: text <-> object, by RFC 8866 and the attribute RFCs
// WebRTC uses. sdp.js builds offers and answers on top of it.
//
//   parse(text)          -> { version, origin, name, timing, ..., media: [...] }
//   write(object)        -> text, CRLF line ends
//   parsePayloads(text)  -> the payload types of an m= line's format list
//
// THE OBJECT'S SHAPE is the one sdp.js was written against (sdp-transform's,
// the npm package this module replaces): the same keys, a "push" attribute
// as an array of objects, a flag attribute as its own name ('rtcp-mux'), an
// attribute we do not know as { value } on `invalid`. What differs, and
// why, is listed under "The grammar, by attribute" below and in
// webrtc-server-rs/PORTING.md ("SDP: our grammar against sdp-transform").
//
// THE RULES THE PARSER KEEPS
//
// - Lines end in CRLF; a bare LF is taken too (RFC 8866 §5: "parsers SHOULD
//   be tolerant and also accept records terminated with a single newline
//   character"). A lone CR is not a line end. The writer always ends lines
//   in CRLF.
// - A line is <type>=<value>, the type one lower-case letter, no space
//   around the '=' (RFC 8866 §5). A line of any other form, a type we do not
//   know and k= (RFC 8866 §5.12: obsolete) are skipped.
// - parse never throws: a description is judged by its reader
//   (sdp_offer_answer's checks), not refused half-read here.
// - An attribute is read by its grammar, all of it: an attribute whose value
//   does not match its grammar (a payload type that is not a number, a
//   setup role RFC 4145 does not define, a value after a flag) is not read
//   into its field; it stays on `invalid`, as an attribute we do not know
//   does, so nothing in the text is lost and write(parse(x)) gives it back.
// - A single-valued attribute given twice (a=mid, a=setup, a=ice-ufrag ...,
//   which their RFCs allow once per level) keeps the first; the second goes
//   to `invalid`. Repeatable ones (a=fingerprint, RFC 8122 §5.1; a=msid,
//   RFC 8830 §2; a=candidate, a=rtpmap, a=ssrc ...) are arrays.
// - Tokens stay strings ('0' is a mid, a foundation, a rid, not a number);
//   the fields the grammars make numbers (ports, payload types, SSRCs,
//   priorities, rates) are numbers.
//
// Apache-2.0. Written from the RFCs; no code of sdp-transform's.


/* ========================= Character classes ========================= */

// token-char (RFC 8866 §9): %x21 / %x23-27 / %x2A-2B / %x2D-2E / %x30-39 /
// %x41-5A / %x5E-7E
function isTokenChar(c) {
  return c === 0x21 || (c >= 0x23 && c <= 0x27) || c === 0x2A || c === 0x2B ||
         c === 0x2D || c === 0x2E || (c >= 0x30 && c <= 0x39) ||
         (c >= 0x41 && c <= 0x5A) || (c >= 0x5E && c <= 0x7E);
}

function isToken(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (var i = 0; i < s.length; i++) if (!isTokenChar(s.charCodeAt(i))) return false;
  return true;
}

// ice-char (RFC 8839 §5.1): ALPHA / DIGIT / "+" / "/"
function isIceChars(s, min, max) {
  if (typeof s !== 'string' || s.length < min || s.length > max) return false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (!((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) ||
          c === 0x2B || c === 0x2F)) return false;
  }
  return true;
}

// tls-id-value (RFC 8842 §4): 20*255 of ALPHA / DIGIT / "+" / "/" / "-" / "_"
function isTlsId(s) {
  if (typeof s !== 'string' || s.length < 20 || s.length > 255) return false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (!((c >= 0x41 && c <= 0x5A) || (c >= 0x61 && c <= 0x7A) || (c >= 0x30 && c <= 0x39) ||
          c === 0x2B || c === 0x2F || c === 0x2D || c === 0x5F)) return false;
  }
  return true;
}

// A non-empty run of characters that are neither a space nor a control
// (VCHAR, and the UTF-8 RFC 8866 §5 allows in values: byte-string).
function isWord(s) {
  if (typeof s !== 'string' || s.length === 0) return false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c <= 0x20 || c === 0x7F) return false;
  }
  return true;
}

// 1*n DIGIT
function isDigits(s, max) {
  if (typeof s !== 'string' || s.length === 0 || s.length > (max || 1e9)) return false;
  for (var i = 0; i < s.length; i++) {
    var c = s.charCodeAt(i);
    if (c < 0x30 || c > 0x39) return false;
  }
  return true;
}

// A decimal: 1*DIGIT ["." 1*DIGIT] (RFC 8866 §6.4 ptime, §6.8 framerate).
function isDecimal(s) {
  if (typeof s !== 'string') return false;
  var dot = s.indexOf('.');
  if (dot < 0) return isDigits(s);
  return isDigits(s.slice(0, dot)) && isDigits(s.slice(dot + 1));
}

// A port (RFC 8866 §9: port = 1*DIGIT; a UDP / TCP port is 16 bits).
function portOf(s) {
  if (!isDigits(s, 5)) return null;
  var n = Number(s);
  return n <= 65535 ? n : null;
}

// An integer of at most `maxDigits` digits, or null. No field takes more
// than 15 digits: every value stays an exact Number (below 2^53).
function intOf(s, maxDigits) {
  return isDigits(s, maxDigits) ? Number(s) : null;
}

// An RTP payload type: 0..127 (RFC 3550 §5.1, a 7-bit field).
function payloadTypeOf(s) {
  var n = intOf(s, 3);
  return (n !== null && n <= 127) ? n : null;
}

// "IP4" / "IP6" -> 4 / 6 (RFC 8866 §5.7 addrtype).
function ipVerOf(s) {
  return s === 'IP4' ? 4 : (s === 'IP6' ? 6 : null);
}

// "a b c" split on single spaces; null when two spaces meet, or at an end
// (RFC 8866 §5: fields are separated by a single space).
function fields(s) {
  var f = s.split(' ');
  for (var i = 0; i < f.length; i++) if (f[i] === '') return null;
  return f;
}

// The text before the first space, and after it ('' when none).
function firstWord(s) {
  var sp = s.indexOf(' ');
  return sp < 0 ? [s, null] : [s.slice(0, sp), s.slice(sp + 1)];
}


/* ========================= The grammar, by attribute =========================
 *
 * Each entry: the attribute's name on the wire, the KEY it is read into,
 * whether it repeats (PUSH: an array of objects) or is a FLAG (a=rtcp-mux:
 * the key holds the attribute's name), and
 *   read(value) -> the field's value, or null when the value does not
 *                  match the grammar (the line then stays on `invalid`)
 *   show(v)     -> the value written after 'a=<name>:'
 * The table's ORDER is the order write() emits attributes in — the order
 * sdp.js's descriptions have always been written in, so this module writes
 * them byte for byte as before.
 */

// A value that is a string of any characters but none (RFC 8866 §5.13
// att-value = byte-string): taken whole.
function readText(v) { return v.length ? v : null; }
function showText(v) { return String(v); }

var ATTRS = [
  // RFC 8866 §6.6: rtpmap:<payload type> <encoding name>/<clock rate>
  // [/<encoding parameters>] - the parameters an audio channel count.
  { name: 'rtpmap', key: 'rtp', push: true,
    read: function (v) {
      var p = firstWord(v);
      var pt = payloadTypeOf(p[0]);
      if (pt === null || p[1] === null) return null;
      var parts = p[1].split('/');
      if (parts.length < 2 || parts.length > 3 || !isToken(parts[0])) return null;
      var rate = intOf(parts[1], 10);
      if (rate === null) return null;
      var o = { payload: pt, codec: parts[0], rate: rate };
      if (parts.length === 3) {
        var enc = intOf(parts[2], 10);
        if (enc === null) return null;
        o.encoding = enc;
      }
      return o;
    },
    show: function (o) {
      return o.payload + ' ' + o.codec +
        (o.rate != null ? '/' + o.rate + (o.encoding != null ? '/' + o.encoding : '') : '');
    } },

  // RFC 8866 §6.15: fmtp:<format> <format specific parameters>
  { name: 'fmtp', key: 'fmtp', push: true,
    read: function (v) {
      var p = firstWord(v);
      var pt = payloadTypeOf(p[0]);
      if (pt === null || !p[1]) return null;
      return { payload: pt, config: p[1] };
    },
    show: function (o) { return o.payload + ' ' + o.config; } },

  // RFC 2326 §C.1.1 (RTSP): control:<url>
  { name: 'control', key: 'control', read: readText, show: showText },

  // RFC 3605 §2.1: rtcp:<port> [<nettype> <addrtype> <connection-address>]
  { name: 'rtcp', key: 'rtcp',
    read: function (v) {
      var f = fields(v);
      if (!f || (f.length !== 1 && f.length !== 4)) return null;
      var port = portOf(f[0]);
      if (port === null) return null;
      if (f.length === 1) return { port: port };
      var ver = ipVerOf(f[2]);
      if (!isToken(f[1]) || ver === null || !isWord(f[3])) return null;
      return { port: port, netType: f[1], ipVer: ver, address: f[3] };
    },
    show: function (o) {
      return o.address != null
        ? o.port + ' ' + o.netType + ' IP' + o.ipVer + ' ' + o.address
        : String(o.port);
    } },

  // RFC 4585 §3.6.1: rtcp-fb:<pt or *> trr-int <interval>
  { name: 'rtcp-fb', key: 'rtcpFbTrrInt', push: true,
    read: function (v) {
      var f = fields(v);
      if (!f || f.length !== 3 || f[1] !== 'trr-int') return null;
      var pt = (f[0] === '*') ? '*' : payloadTypeOf(f[0]);
      var val = intOf(f[2], 10);
      if (pt === null || val === null) return null;
      return { payload: pt, value: val };
    },
    show: function (o) { return o.payload + ' trr-int ' + o.value; } },

  // RFC 4585 §4.2: rtcp-fb:<pt or *> <type> [<parameters>]. The parameters
  // are kept whole ("ccm tmmbr smaxpr=120": type ccm, subtype "tmmbr
  // smaxpr=120"), so sdp.js's "type subtype" string is the line as sent.
  { name: 'rtcp-fb', key: 'rtcpFb', push: true,
    read: function (v) {
      var p = firstWord(v);
      var pt = (p[0] === '*') ? '*' : payloadTypeOf(p[0]);
      if (pt === null || p[1] === null) return null;
      var q = firstWord(p[1]);
      if (!isToken(q[0]) || q[0] === 'trr-int') return null;
      if (q[1] !== null && !q[1].length) return null;
      var o = { payload: pt, type: q[0] };
      if (q[1] !== null) o.subtype = q[1];
      return o;
    },
    show: function (o) { return o.payload + ' ' + o.type + (o.subtype != null ? ' ' + o.subtype : ''); } },

  // RFC 8285 §8: extmap:<value>["/"<direction>] <URI> <extensionattributes>,
  // and RFC 6904 §4's encrypted form: extmap:<value> urn:ietf:params:rtp-
  // hdrext:encrypt <URI> <extensionattributes>. The attributes are the rest
  // of the line, spaces and all.
  { name: 'extmap', key: 'ext', push: true,
    read: function (v) {
      var p = firstWord(v);
      if (p[1] === null) return null;
      var slash = p[0].indexOf('/');
      var idText = slash < 0 ? p[0] : p[0].slice(0, slash);
      var id = intOf(idText, 5);
      if (id === null) return null;
      var o = { value: id };
      if (slash >= 0) {
        var dir = p[0].slice(slash + 1);
        if (DIRECTION_VALUES.indexOf(dir) < 0) return null;
        o.direction = dir;
      }
      var q = firstWord(p[1]);
      if (!isWord(q[0])) return null;
      if (q[0] === ENCRYPT_URI && q[1] !== null) {
        o['encrypt-uri'] = q[0];
        q = firstWord(q[1]);
        if (!isWord(q[0])) return null;
      }
      o.uri = q[0];
      if (q[1] !== null) {
        if (!q[1].length) return null;
        o.config = q[1];
      }
      return o;
    },
    show: function (o) {
      return o.value + (o.direction ? '/' + o.direction : '') +
        (o['encrypt-uri'] ? ' ' + o['encrypt-uri'] : '') + ' ' + o.uri +
        (o.config ? ' ' + o.config : '');
    } },

  // RFC 8285 §6
  { name: 'extmap-allow-mixed', key: 'extmapAllowMixed', flag: true },

  // RFC 4568 §9.1: crypto:<tag> <crypto-suite> <key-params> [<session-params>]
  { name: 'crypto', key: 'crypto', push: true,
    read: function (v) {
      var f = v.split(' ');
      if (f.length < 3) return null;
      var tag = intOf(f[0], 9);
      if (tag === null || !isToken(f[1]) || !isWord(f[2])) return null;
      var o = { id: tag, suite: f[1], config: f[2] };
      if (f.length > 3) {
        var rest = f.slice(3).join(' ');
        if (!rest.length) return null;
        o.sessionConfig = rest;
      }
      return o;
    },
    show: function (o) {
      return o.id + ' ' + o.suite + ' ' + o.config + (o.sessionConfig != null ? ' ' + o.sessionConfig : '');
    } },

  // RFC 4145 §4: setup:active / passive / actpass / holdconn
  { name: 'setup', key: 'setup',
    read: function (v) { return SETUP_VALUES.indexOf(v) >= 0 ? v : null; },
    show: showText },

  // RFC 4145 §5: connection:new / existing
  { name: 'connection', key: 'connectionType',
    read: function (v) { return (v === 'new' || v === 'existing') ? v : null; },
    show: showText },

  // RFC 5888 §4: mid:<identification-tag>, a token
  { name: 'mid', key: 'mid',
    read: function (v) { return isToken(v) ? v : null; },
    show: showText },

  // RFC 8830 §2: msid:<msid-id> [<msid-appdata>], each 1*64token-char. One
  // line per MediaStream the track belongs to.
  { name: 'msid', key: 'msid', push: true,
    read: function (v) {
      var f = fields(v);
      if (!f || f.length > 2) return null;
      for (var i = 0; i < f.length; i++) if (!isToken(f[i]) || f[i].length > 64) return null;
      var o = { id: f[0] };
      if (f.length === 2) o.appdata = f[1];
      return o;
    },
    show: function (o) { return o.id + (o.appdata != null ? ' ' + o.appdata : ''); } },

  // RFC 8866 §6.4 / §6.5: ptime / maxptime in milliseconds, a decimal
  { name: 'ptime', key: 'ptime',
    read: function (v) { return isDecimal(v) ? Number(v) : null; }, show: showText },
  { name: 'maxptime', key: 'maxptime',
    read: function (v) { return isDecimal(v) ? Number(v) : null; }, show: showText },

  // RFC 8866 §6.7: the media direction (four flags, one field)
  { name: 'sendrecv', key: 'direction', flag: true },
  { name: 'recvonly', key: 'direction', flag: true },
  { name: 'sendonly', key: 'direction', flag: true },
  { name: 'inactive', key: 'direction', flag: true },

  // RFC 8839 §5.3
  { name: 'ice-lite', key: 'icelite', flag: true },

  // RFC 8839 §5.4: ufrag = 4*256ice-char, password = 22*256ice-char
  { name: 'ice-ufrag', key: 'iceUfrag',
    read: function (v) { return isIceChars(v, 4, 256) ? v : null; }, show: showText },
  { name: 'ice-pwd', key: 'icePwd',
    read: function (v) { return isIceChars(v, 22, 256) ? v : null; }, show: showText },

  // RFC 8122 §5: fingerprint:<hash-func> <fingerprint>, fingerprint =
  // 2UHEX *(":" 2UHEX). Several per level (§5.1: one per certificate and
  // hash function). Lower-case hex is taken too: RFC 8122 compares the
  // value case-insensitively, and some endpoints send it.
  { name: 'fingerprint', key: 'fingerprints', push: true,
    read: function (v) {
      var f = fields(v);
      if (!f || f.length !== 2 || !isToken(f[0]) || !isHexPairs(f[1])) return null;
      return { type: f[0], hash: f[1] };
    },
    show: function (o) { return o.type + ' ' + o.hash; } },

  // RFC 8842 §4: tls-id:<tls-id-value>, tls-id-value = 20*255(tls-id-char),
  // tls-id-char = ALPHA / DIGIT / "+" / "/" / "-" / "_". Identifies the
  // DTLS association (with the other side's value); media level, one per
  // section.
  { name: 'tls-id', key: 'tlsId',
    read: function (v) { return isTlsId(v) ? v : null; },
    show: showText },

  // RFC 8839 §5.1:
  //   candidate:<foundation> <component-id> <transport> <priority>
  //     <connection-address> <port> typ <cand-type>
  //     [raddr <rel-addr>] [rport <rel-port>] *(<ext-name> <ext-value>)
  // The extensions WebRTC names (RFC 6544 tcptype; libwebrtc's generation,
  // network-id, network-cost) have fields; any other is kept, in order, on
  // `extensions` as { name, value }.
  { name: 'candidate', key: 'candidates', push: true, read: readCandidate, show: showCandidate },

  // RFC 8840 §8.2 (and RFC 8838)
  { name: 'end-of-candidates', key: 'endOfCandidates', flag: true },

  // RFC 8839 §5.2: remote-candidates:<component-id> <address> <port> ...
  { name: 'remote-candidates', key: 'remoteCandidates', read: readText, show: showText },

  // RFC 8839 §5.6: ice-options:<ice-option-tag> *(SP <ice-option-tag>) -
  // every tag ("trickle renomination"), not the first only.
  { name: 'ice-options', key: 'iceOptions',
    read: function (v) {
      var f = fields(v);
      if (!f) return null;
      for (var i = 0; i < f.length; i++) if (!isIceChars(f[i], 1, Infinity)) return null;
      return v;
    },
    show: showText },

  // RFC 8839 §5.7: ice-pacing:<1*10DIGIT> (milliseconds)
  { name: 'ice-pacing', key: 'icePacing',
    read: function (v) { return intOf(v, 10); }, show: showText },

  // RFC 5576 §4.1: ssrc:<ssrc-id> <attribute>[:<value>]
  { name: 'ssrc', key: 'ssrcs', push: true,
    read: function (v) {
      var p = firstWord(v);
      var id = ssrcOf(p[0]);
      if (id === null || !p[1]) return null;
      var colon = p[1].indexOf(':');
      var att = colon < 0 ? p[1] : p[1].slice(0, colon);
      if (!isToken(att)) return null;
      var o = { id: id, attribute: att };
      if (colon >= 0) o.value = p[1].slice(colon + 1);
      return o;
    },
    show: function (o) {
      return o.id + (o.attribute != null ? ' ' + o.attribute + (o.value != null ? ':' + o.value : '') : '');
    } },

  // RFC 5576 §4.2: ssrc-group:<semantics> *(SP <ssrc-id>)
  { name: 'ssrc-group', key: 'ssrcGroups', push: true,
    read: function (v) {
      var p = firstWord(v);
      if (!isToken(p[0])) return null;
      if (p[1] !== null) {
        var f = fields(p[1]);
        if (!f) return null;
        for (var i = 0; i < f.length; i++) if (ssrcOf(f[i]) === null) return null;
      }
      return { semantics: p[0], ssrcs: p[1] === null ? '' : p[1] };
    },
    show: function (o) { return o.semantics + (o.ssrcs !== '' && o.ssrcs != null ? ' ' + o.ssrcs : ''); } },

  // msid-semantic (draft-ietf-mmusic-msid-05 §4, what WebRTC endpoints
  // still send): "msid-semantic: WMS" [SP <identifiers>] - the space after
  // the colon is optional on read and always written.
  { name: 'msid-semantic', key: 'msidSemantic',
    read: function (v) {
      var s = v.charAt(0) === ' ' ? v.slice(1) : v;
      var p = firstWord(s);
      if (!isToken(p[0])) return null;
      var o = { semantic: p[0] };
      if (p[1] !== null) {
        var f = fields(p[1]);
        if (!f) return null;
        o.token = p[1];
      }
      return o;
    },
    show: function (o) { return ' ' + o.semantic + (o.token != null && o.token !== '' ? ' ' + o.token : ''); } },

  // RFC 5888 §5: group:<semantics> *(SP <identification-tag>)
  { name: 'group', key: 'groups', push: true,
    read: function (v) {
      var p = firstWord(v);
      if (!isToken(p[0])) return null;
      if (p[1] !== null) {
        var f = fields(p[1]);
        if (!f) return null;
        for (var i = 0; i < f.length; i++) if (!isToken(f[i])) return null;
      }
      return { type: p[0], mids: p[1] === null ? '' : p[1] };
    },
    show: function (o) { return o.type + (o.mids !== '' && o.mids != null ? ' ' + o.mids : ''); } },

  // RFC 5761 §5.1.1; RFC 8858 §3 (rtcp-mux-only: its own attribute, not
  // a=rtcp-mux with something after it)
  { name: 'rtcp-mux', key: 'rtcpMux', flag: true },
  { name: 'rtcp-mux-only', key: 'rtcpMuxOnly', flag: true },
  // RFC 5506 §5
  { name: 'rtcp-rsize', key: 'rtcpRsize', flag: true },

  // draft-ietf-mmusic-sctp-sdp-05 §4 (the legacy data channel form):
  // sctpmap:<number> <app> [<max-message-size>]
  { name: 'sctpmap', key: 'sctpmap',
    read: function (v) {
      var f = fields(v);
      if (!f || f.length < 2 || f.length > 3) return null;
      var num = portOf(f[0]);
      if (num === null || !isToken(f[1])) return null;
      var o = { sctpmapNumber: num, app: f[1] };
      if (f.length === 3) {
        var mms = intOf(f[2], 15);
        if (mms === null) return null;
        o.maxMessageSize = mms;
      }
      return o;
    },
    show: function (o) {
      return o.sctpmapNumber + ' ' + o.app + (o.maxMessageSize != null ? ' ' + o.maxMessageSize : '');
    } },

  // libwebrtc's x-google-flag:conference
  { name: 'x-google-flag', key: 'xGoogleFlag',
    read: function (v) { return isWord(v) ? v : null; }, show: showText },

  // RFC 8851 §10: rid:<rid-id> SP <send|recv> [SP <rid-param-list>],
  // rid-id = 1*(alpha-numeric / "-" / "_")
  { name: 'rid', key: 'rids', push: true,
    read: function (v) {
      var p = firstWord(v);
      if (!isRidId(p[0]) || p[1] === null) return null;
      var q = firstWord(p[1]);
      if (q[0] !== 'send' && q[0] !== 'recv') return null;
      var o = { id: p[0], direction: q[0] };
      if (q[1] !== null) {
        if (!q[1].length) return null;
        o.params = q[1];
      }
      return o;
    },
    show: function (o) { return o.id + ' ' + o.direction + (o.params ? ' ' + o.params : ''); } },

  // RFC 6236 §3.1: imageattr:<PT or *> <send|recv> <attr-list or *>
  // [<recv|send> <attr-list or *>], attr-list = 1*("[" ... "]") separated
  // by spaces.
  { name: 'imageattr', key: 'imageattrs', push: true, read: readImageattr,
    show: function (o) {
      return o.pt + ' ' + o.dir1 + ' ' + o.attrs1 + (o.dir2 ? ' ' + o.dir2 + ' ' + o.attrs2 : '');
    } },

  // RFC 8853 §5.1: simulcast:<send|recv> <sc-str-list> [SP <recv|send>
  // <sc-str-list>], each list ";"-separated alternatives of ","-separated
  // ["~"]rid-id.
  { name: 'simulcast', key: 'simulcast',
    read: function (v) {
      var f = fields(v);
      if (!f || (f.length !== 2 && f.length !== 4)) return null;
      if ((f[0] !== 'send' && f[0] !== 'recv') || !isSimulcastList(f[1])) return null;
      var o = { dir1: f[0], list1: f[1] };
      if (f.length === 4) {
        if ((f[2] !== 'send' && f[2] !== 'recv') || f[2] === f[0] || !isSimulcastList(f[3])) return null;
        o.dir2 = f[2];
        o.list2 = f[3];
      }
      return o;
    },
    show: function (o) { return o.dir1 + ' ' + o.list1 + (o.dir2 ? ' ' + o.dir2 + ' ' + o.list2 : ''); } },

  // RFC 8866 §6.8: framerate:<frame rate>, a decimal
  { name: 'framerate', key: 'framerate',
    read: function (v) { return isDecimal(v) ? Number(v) : null; }, show: showText },

  // RFC 4570 §3: source-filter: <filter-mode> <nettype> <address-types>
  // <dest-address> <src-list>
  { name: 'source-filter', key: 'sourceFilter',
    read: function (v) {
      var s = v.replace(/^ +/, '');
      var f = s.split(' ');
      if (f.length < 5) return null;
      if ((f[0] !== 'incl' && f[0] !== 'excl') || !isToken(f[1]) ||
          (f[2] !== 'IP4' && f[2] !== 'IP6' && f[2] !== '*') || !isWord(f[3])) return null;
      var src = f.slice(4).join(' ');
      if (!src.length) return null;
      return { filterMode: f[0], netType: f[1], addressTypes: f[2], destAddress: f[3], srcList: src };
    },
    show: function (o) {
      return ' ' + o.filterMode + ' ' + o.netType + ' ' + o.addressTypes + ' ' + o.destAddress + ' ' + o.srcList;
    } },

  // RFC 8843 §6
  { name: 'bundle-only', key: 'bundleOnly', flag: true },

  // RFC 4574 §4: label:<pointer>
  { name: 'label', key: 'label', read: readText, show: showText },

  // RFC 8841 §5.1 / §6.1: sctp-port:<port>, max-message-size:<1*DIGIT>
  { name: 'sctp-port', key: 'sctpPort',
    read: function (v) { return portOf(v); }, show: showText },
  { name: 'max-message-size', key: 'maxMessageSize',
    read: function (v) { return intOf(v, 15); }, show: showText },

  // RFC 7273 §4.8: ts-refclk:<clksrc>[=<clksrc-ext>]
  { name: 'ts-refclk', key: 'tsRefClocks', push: true,
    read: function (v) {
      if (!isWord(v)) return null;
      var eq = v.indexOf('=');
      if (eq === 0) return null;
      var o = { clksrc: eq < 0 ? v : v.slice(0, eq) };
      if (eq >= 0) o.clksrcExt = v.slice(eq + 1);
      return o;
    },
    show: function (o) { return o.clksrc + (o.clksrcExt != null ? '=' + o.clksrcExt : ''); } },

  // RFC 7273 §5.2: mediaclk:[id=<id> ]<mediaclock>[=<value>][ rate=<n>/<d>]
  { name: 'mediaclk', key: 'mediaClk', read: readMediaclk,
    show: function (o) {
      return (o.id != null ? 'id=' + o.id + ' ' : '') + o.mediaClockName +
        (o.mediaClockValue != null ? '=' + o.mediaClockValue : '') +
        (o.rateNumerator != null ? ' rate=' + o.rateNumerator : '') +
        (o.rateDenominator != null ? '/' + o.rateDenominator : '');
    } },

  // RFC 8866 §6.1: keywds:<keywords>
  { name: 'keywds', key: 'keywords', read: readText, show: showText },
  // RFC 4796 §5: content:<mediacnt> *("," <mediacnt>)
  { name: 'content', key: 'content', read: readText, show: showText },

  // BFCP (RFC 8856 §5, §6)
  { name: 'floorctrl', key: 'bfcpFloorCtrl',
    read: function (v) { return (v === 'c-only' || v === 's-only' || v === 'c-s') ? v : null; },
    show: showText },
  { name: 'confid', key: 'bfcpConfId', read: function (v) { return intOf(v, 10); }, show: showText },
  { name: 'userid', key: 'bfcpUserId', read: function (v) { return intOf(v, 10); }, show: showText },
  { name: 'floorid', key: 'bfcpFloorId',
    read: function (v) {
      var f = fields(v);
      if (!f || f.length !== 2) return null;
      var m = /^(?:mstrm|m-stream):(.+)$/.exec(f[1]);
      if (!isWord(f[0]) || !m) return null;
      return { id: f[0], mStream: m[1] };
    },
    show: function (o) { return o.id + ' mstrm:' + o.mStream; } },
];

var DIRECTION_VALUES = ['sendrecv', 'sendonly', 'recvonly', 'inactive'];
var SETUP_VALUES = ['active', 'passive', 'actpass', 'holdconn'];
var ENCRYPT_URI = 'urn:ietf:params:rtp-hdrext:encrypt';

// The fields of a=candidate's extensions that have their own keys, in the
// order write() emits them.
var CANDIDATE_NUMERIC_EXTS = ['generation', 'network-id', 'network-cost'];

// 2HEXDIG *(":" 2HEXDIG)
function isHexPairs(s) {
  var parts = s.split(':');
  for (var i = 0; i < parts.length; i++) {
    if (!/^[0-9A-Fa-f]{2}$/.test(parts[i])) return false;
  }
  return true;
}

// ssrc-id = integer 0..2^32-1 (RFC 5576 §4.1)
function ssrcOf(s) {
  var n = intOf(s, 10);
  return (n !== null && n <= 4294967295) ? n : null;
}

// rid-id = 1*(alpha-numeric / "-" / "_") (RFC 8851 §10)
function isRidId(s) { return /^[A-Za-z0-9_-]+$/.test(s); }

// sc-str-list (RFC 8853 §5.1): alternatives ";"-separated, each of ","-
// separated ["~"] rid-id
function isSimulcastList(s) {
  var alts = s.split(';');
  for (var i = 0; i < alts.length; i++) {
    var ids = alts[i].split(',');
    for (var j = 0; j < ids.length; j++) {
      var id = ids[j].charAt(0) === '~' ? ids[j].slice(1) : ids[j];
      if (!isRidId(id)) return false;
    }
  }
  return true;
}

function readCandidate(v) {
  var f = fields(v);
  if (!f || f.length < 8 || f[6] !== 'typ') return null;
  var component = intOf(f[1], 3);
  var priority = intOf(f[3], 10);
  var port = portOf(f[5]);
  if (!isIceChars(f[0], 1, 32) || component === null || !isToken(f[2]) || priority === null ||
      !isWord(f[4]) || port === null || !isToken(f[7])) return null;
  if ((f.length - 8) % 2 !== 0) return null;
  var o = { foundation: f[0], component: component, transport: f[2], priority: priority,
            ip: f[4], port: port, type: f[7] };
  var extensions = [];
  for (var i = 8; i < f.length; i += 2) {
    var name = f[i], value = f[i + 1];
    if (!isToken(name) || !isWord(value)) return null;
    if (name === 'raddr' && o.raddr === undefined) { o.raddr = value; continue; }
    if (name === 'rport' && o.rport === undefined) {
      var rp = portOf(value);
      if (rp === null) return null;
      o.rport = rp;
      continue;
    }
    if (name === 'tcptype' && o.tcptype === undefined) { o.tcptype = value; continue; }
    if (CANDIDATE_NUMERIC_EXTS.indexOf(name) >= 0 && o[name] === undefined && isDigits(value, 10)) {
      o[name] = Number(value);
      continue;
    }
    extensions.push({ name: name, value: value });
  }
  if (extensions.length) o.extensions = extensions;
  return o;
}

function showCandidate(o) {
  var s = o.foundation + ' ' + o.component + ' ' + o.transport + ' ' + o.priority + ' ' +
          o.ip + ' ' + o.port + ' typ ' + o.type;
  if (o.raddr != null) s += ' raddr ' + o.raddr;
  if (o.rport != null) s += ' rport ' + o.rport;
  if (o.tcptype != null) s += ' tcptype ' + o.tcptype;
  for (var i = 0; i < CANDIDATE_NUMERIC_EXTS.length; i++) {
    var k = CANDIDATE_NUMERIC_EXTS[i];
    if (o[k] != null) s += ' ' + k + ' ' + o[k];
  }
  if (o.extensions) {
    for (var e = 0; e < o.extensions.length; e++) {
      s += ' ' + o.extensions[e].name + ' ' + o.extensions[e].value;
    }
  }
  return s;
}

// imageattr: the attribute list after a direction is "*" or one or more
// bracketed sets separated by single spaces; it ends where the other
// direction's keyword starts, or at the end.
function readImageattr(v) {
  var p = firstWord(v);
  var pt = (p[0] === '*') ? '*' : payloadTypeOf(p[0]);
  if (pt === null || p[1] === null) return null;
  var f = fields(p[1]);
  if (!f) return null;
  var o = { pt: pt };
  var i = 0;
  for (var n = 1; n <= 2 && i < f.length; n++) {
    var dir = f[i++];
    if ((dir !== 'send' && dir !== 'recv') || (n === 2 && dir === o.dir1)) return null;
    var sets = [];
    if (f[i] === '*') { sets.push('*'); i++; }
    else {
      while (i < f.length && f[i].charAt(0) === '[') {
        if (!isBracketSet(f[i])) return null;
        sets.push(f[i++]);
      }
    }
    if (!sets.length) return null;
    o['dir' + n] = dir;
    o['attrs' + n] = sets.join(' ');
  }
  if (i !== f.length) return null;
  return o;
}

// "[" ... "]" with its brackets balanced (RFC 6236 §3.1: a set may hold
// ranges, "[x=[48:1920],y=[48:1080]]"), no space inside.
function isBracketSet(s) {
  if (s.charAt(0) !== '[' || s.charAt(s.length - 1) !== ']' || s.length < 3) return false;
  var depth = 0;
  for (var i = 0; i < s.length; i++) {
    var c = s.charAt(i);
    if (c === '[') depth++;
    else if (c === ']') { depth--; if (depth < 0 || (depth === 0 && i !== s.length - 1)) return false; }
  }
  return depth === 0;
}

function readMediaclk(v) {
  var s = v, o = {};
  if (s.indexOf('id=') === 0) {
    var p = firstWord(s);
    if (p[1] === null || p[0].length < 4) return null;
    o.id = p[0].slice(3);
    s = p[1];
  }
  var q = firstWord(s);
  var head = q[0];
  if (!head.length) return null;
  var eq = head.indexOf('=');
  o.mediaClockName = eq < 0 ? head : head.slice(0, eq);
  if (!o.mediaClockName.length) return null;
  if (eq >= 0) o.mediaClockValue = head.slice(eq + 1);
  if (q[1] !== null) {
    var m = /^rate=(\d+)(?:\/(\d+))?$/.exec(q[1]);
    if (!m) return null;
    o.rateNumerator = Number(m[1]);
    if (m[2] !== undefined) o.rateDenominator = Number(m[2]);
  }
  return o;
}

// name -> the entries for that attribute name, in table order (rtcp-fb has
// two: trr-int first)
var BY_NAME = {};
for (var _a = 0; _a < ATTRS.length; _a++) {
  var _n = ATTRS[_a].name;
  if (!Object.prototype.hasOwnProperty.call(BY_NAME, _n)) BY_NAME[_n] = [];
  BY_NAME[_n].push(ATTRS[_a]);
}

// The keys of the table in write order, each once (the four directions
// share 'direction').
var WRITE_KEYS = [];
for (var _w = 0; _w < ATTRS.length; _w++) {
  if (WRITE_KEYS.indexOf(ATTRS[_w].key) < 0) WRITE_KEYS.push(ATTRS[_w].key);
}
var ENTRY_BY_KEY = {};
for (var _k = 0; _k < ATTRS.length; _k++) {
  if (!ENTRY_BY_KEY[ATTRS[_k].key]) ENTRY_BY_KEY[ATTRS[_k].key] = ATTRS[_k];
}


/* ========================= parse ========================= */

// Read one a= line into `loc` (the session or a media section).
function parseAttribute(loc, text) {
  var colon = text.indexOf(':');
  var name = colon < 0 ? text : text.slice(0, colon);
  var entries = Object.prototype.hasOwnProperty.call(BY_NAME, name) ? BY_NAME[name] : null;
  if (entries) {
    for (var i = 0; i < entries.length; i++) {
      var e = entries[i];
      var val;
      if (e.flag) {
        if (colon >= 0) break;
        val = name;
      } else {
        if (colon < 0) break;
        val = e.read(text.slice(colon + 1));
        if (val === null) continue;
      }
      if (e.push) {
        if (!loc[e.key]) loc[e.key] = [];
        loc[e.key].push(val);
        return;
      }
      if (loc[e.key] !== undefined) break;     // given twice: the first stands
      loc[e.key] = val;
      return;
    }
  }
  if (!loc.invalid) loc.invalid = [];
  loc.invalid.push({ value: text });
}

// c=<nettype> <addrtype> <connection-address> (RFC 8866 §5.7)
function parseConnection(v) {
  var f = fields(v);
  if (!f || f.length !== 3 || f[0] !== 'IN') return null;
  var ver = ipVerOf(f[1]);
  if (ver === null || !isWord(f[2])) return null;
  return { version: ver, ip: f[2] };
}

// b=<bwtype>:<bandwidth> (RFC 8866 §5.8)
function parseBandwidth(v) {
  var colon = v.indexOf(':');
  if (colon <= 0) return null;
  var type = v.slice(0, colon);
  var limit = intOf(v.slice(colon + 1), 15);
  if (!isToken(type) || limit === null) return null;
  return { type: type, limit: limit };
}

// m=<media> <port>[/<number of ports>] <proto> <fmt> ... (RFC 8866 §5.14)
function parseMediaLine(v) {
  var f = fields(v);
  if (!f || f.length < 3 || !isToken(f[0])) return null;
  var slash = f[1].indexOf('/');
  var port = portOf(slash < 0 ? f[1] : f[1].slice(0, slash));
  if (port === null) return null;
  var o = { type: f[0], port: port };
  if (slash >= 0) {
    var np = intOf(f[1].slice(slash + 1), 5);
    if (np === null) return null;
    o.numPorts = np;
  }
  var protos = f[2].split('/');
  for (var i = 0; i < protos.length; i++) if (!isToken(protos[i])) return null;
  o.protocol = f[2];
  o.payloads = f.slice(3).join(' ');
  return o;
}

// o=<username> <sess-id> <sess-version> <nettype> <addrtype>
// <unicast-address> (RFC 8866 §5.2). The ids are digit strings of up to 64
// bits and more, kept as text (a Number would round them past 2^53).
function parseOrigin(v) {
  var f = fields(v);
  if (!f || f.length !== 6) return null;
  var ver = ipVerOf(f[4]);
  if (!isWord(f[0]) || !isDigits(f[1]) || !isDigits(f[2]) || !isToken(f[3]) || ver === null ||
      !isWord(f[5])) return null;
  return { username: f[0], sessionId: f[1], sessionVersion: f[2], netType: f[3], ipVer: ver, address: f[5] };
}

function parse(sdp) {
  var session = {};
  var media = [];
  var loc = session;
  var lines = String(sdp).split('\n');
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (line.charCodeAt(line.length - 1) === 0x0D) line = line.slice(0, -1);
    if (line.length < 2 || line.charAt(1) !== '=') continue;
    var type = line.charAt(0);
    var value = line.slice(2);
    var inMedia = (loc !== session);
    switch (type) {
      case 'v':
        if (!inMedia && session.version === undefined && isDigits(value, 15)) session.version = Number(value);
        break;
      case 'o':
        if (!inMedia && session.origin === undefined) {
          var o = parseOrigin(value);
          if (o) session.origin = o;
        }
        break;
      case 's':
        if (!inMedia && session.name === undefined) session.name = value;
        break;
      case 'i':
        if (loc.description === undefined) loc.description = value;
        break;
      case 'u':
        if (!inMedia && session.uri === undefined) session.uri = value;
        break;
      case 'e':
        if (!inMedia && session.email === undefined) session.email = value;
        break;
      case 'p':
        if (!inMedia && session.phone === undefined) session.phone = value;
        break;
      case 'z':
        if (!inMedia && session.timezones === undefined) session.timezones = value;
        break;
      case 'r':
        if (!inMedia && session.repeats === undefined) session.repeats = value;
        break;
      case 't':
        if (!inMedia && session.timing === undefined) {
          var t = fields(value);
          if (t && t.length === 2 && isDigits(t[0], 15) && isDigits(t[1], 15)) {
            session.timing = { start: Number(t[0]), stop: Number(t[1]) };
          }
        }
        break;
      case 'c':
        if (loc.connection === undefined) {
          var c = parseConnection(value);
          if (c) loc.connection = c;
        }
        break;
      case 'b':
        var b = parseBandwidth(value);
        if (b) {
          if (!loc.bandwidth) loc.bandwidth = [];
          loc.bandwidth.push(b);
        }
        break;
      case 'm':
        // A new section starts on every m= line; one that does not parse
        // still opens one (its attributes must not land on the previous).
        var m = { rtp: [], fmtp: [] };
        var ml = parseMediaLine(value);
        if (ml) {
          m.type = ml.type;
          m.port = ml.port;
          if (ml.numPorts !== undefined) m.numPorts = ml.numPorts;
          m.protocol = ml.protocol;
          m.payloads = ml.payloads;
        }
        media.push(m);
        loc = m;
        break;
      case 'a':
        parseAttribute(loc, value);
        break;
      default:
        break;   // k= (obsolete) and unknown types
    }
  }
  session.media = media;
  return session;
}


/* ========================= write ========================= */

function need(v, what) {
  if (v === undefined || v === null) {
    throw new TypeError('sdp_grammar.write: ' + what + ' is missing');
  }
  return v;
}

// The a= lines of one location, in table order, then `invalid`.
function writeAttributes(loc, out) {
  for (var i = 0; i < WRITE_KEYS.length; i++) {
    var key = WRITE_KEYS[i];
    var v = loc[key];
    if (v === undefined || v === null) continue;
    if (key === 'direction') {
      if (DIRECTION_VALUES.indexOf(v) < 0) throw new TypeError('sdp_grammar.write: direction "' + v + '"');
      out.push('a=' + v);
      continue;
    }
    if (key === 'rtcpFbTrrInt' || key === 'rtcpFb') {
      var fe = (key === 'rtcpFb') ? BY_NAME['rtcp-fb'][1] : BY_NAME['rtcp-fb'][0];
      for (var r = 0; r < v.length; r++) out.push('a=rtcp-fb:' + fe.show(v[r]));
      continue;
    }
    var e = ENTRY_BY_KEY[key];
    if (e.flag) {
      if (v) out.push('a=' + e.name);
      continue;
    }
    if (e.push) {
      for (var p = 0; p < v.length; p++) {
        if (v[p] == null) continue;
        out.push('a=' + e.name + ':' + e.show(v[p]));
      }
      continue;
    }
    out.push('a=' + e.name + ':' + e.show(v));
  }
  if (loc.invalid) {
    for (var k = 0; k < loc.invalid.length; k++) out.push('a=' + loc.invalid[k].value);
  }
}

function writeConnection(c, out) {
  out.push('c=IN IP' + need(c.version, 'connection.version') + ' ' + need(c.ip, 'connection.ip'));
}

function writeBandwidth(b, out) {
  for (var i = 0; i < b.length; i++) out.push('b=' + b[i].type + ':' + b[i].limit);
}

function write(session) {
  var out = [];
  out.push('v=' + (session.version != null ? session.version : 0));
  if (session.origin) {
    var o = session.origin;
    out.push('o=' + o.username + ' ' + o.sessionId + ' ' + o.sessionVersion + ' ' + o.netType +
             ' IP' + o.ipVer + ' ' + o.address);
  }
  out.push('s=' + (session.name != null ? session.name : ' '));
  if (session.description != null) out.push('i=' + session.description);
  if (session.uri != null) out.push('u=' + session.uri);
  if (session.email != null) out.push('e=' + session.email);
  if (session.phone != null) out.push('p=' + session.phone);
  if (session.connection) writeConnection(session.connection, out);
  if (session.bandwidth) writeBandwidth(session.bandwidth, out);
  if (session.timing) out.push('t=' + session.timing.start + ' ' + session.timing.stop);
  if (session.repeats != null) out.push('r=' + session.repeats);
  if (session.timezones != null) out.push('z=' + session.timezones);
  writeAttributes(session, out);

  var media = session.media || [];
  for (var i = 0; i < media.length; i++) {
    var m = media[i];
    var payloads = (m.payloads != null) ? String(m.payloads) : '';
    out.push('m=' + need(m.type, 'media.type') + ' ' + need(m.port, 'media.port') +
             (m.numPorts != null ? '/' + m.numPorts : '') + ' ' + need(m.protocol, 'media.protocol') +
             (payloads !== '' ? ' ' + payloads : ''));
    if (m.description != null) out.push('i=' + m.description);
    if (m.connection) writeConnection(m.connection, out);
    if (m.bandwidth) writeBandwidth(m.bandwidth, out);
    writeAttributes(m, out);
  }
  return out.join('\r\n') + '\r\n';
}


/* ========================= parsePayloads ========================= */

// The payload types of an m= line's <fmt> list ("111 63 9"): each number,
// in order; a format that is not a number (webrtc-datachannel) is not one.
function parsePayloads(payloads) {
  var out = [];
  var f = String(payloads == null ? '' : payloads).split(' ');
  for (var i = 0; i < f.length; i++) {
    var pt = payloadTypeOf(f[i]);
    if (pt !== null) out.push(pt);
  }
  return out;
}


export { parse, write, parsePayloads };

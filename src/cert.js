// src/cert.js
// Generate self-signed ECDSA (P-256) certificates for DTLS.
// Zero dependencies — uses node:crypto + manual DER/ASN.1 encoding.
//
// Usage:
//   import { generateCertificate } from './cert.js';
//   var { cert, key, fingerprint } = generateCertificate();
//   // cert = PEM string, key = PEM string, fingerprint = 'sha-256 AA:BB:CC:...'

import crypto from 'node:crypto';


/* ========================= DER / ASN.1 helpers ========================= */

// Tag-Length-Value wrapper
function derWrap(tag, content) {
  var len = content.length;
  var header;

  if (len < 128) {
    header = Buffer.alloc(2);
    header[0] = tag;
    header[1] = len;
  } else if (len < 256) {
    header = Buffer.alloc(3);
    header[0] = tag;
    header[1] = 0x81;
    header[2] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[0] = tag;
    header[1] = 0x82;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(6);
    header[0] = tag;
    header[1] = 0x84;
    header.writeUInt32BE(len, 2);
  }

  return Buffer.concat([header, content]);
}

function derSequence(items) {
  return derWrap(0x30, Buffer.concat(items));
}

function derSet(items) {
  return derWrap(0x31, Buffer.concat(items));
}

function derInteger(value) {
  if (typeof value === 'number') {
    // Small integer
    if (value < 0) throw new Error('Negative integers not supported');
    if (value < 128) {
      return derWrap(0x02, Buffer.from([value]));
    }
    // Multi-byte
    var hex = value.toString(16);
    if (hex.length % 2 !== 0) hex = '0' + hex;
    var bytes = Buffer.from(hex, 'hex');
    // If high bit set, prepend 0x00
    if (bytes[0] >= 0x80) bytes = Buffer.concat([Buffer.from([0]), bytes]);
    return derWrap(0x02, bytes);
  }
  // Buffer
  var buf = Buffer.from(value);
  if (buf[0] >= 0x80) buf = Buffer.concat([Buffer.from([0]), buf]);
  return derWrap(0x02, buf);
}

function derBitString(content) {
  // Prepend 0x00 (no unused bits)
  return derWrap(0x03, Buffer.concat([Buffer.from([0]), content]));
}

function derOctetString(content) {
  return derWrap(0x04, content);
}

function derExplicit(tag, content) {
  return derWrap(0xA0 | tag, content);
}

function derUtf8String(str) {
  return derWrap(0x0C, Buffer.from(str, 'utf8'));
}

function derUtcTime(date) {
  // Format: YYMMDDHHMMSSZ
  var y = date.getUTCFullYear() % 100;
  var s = String(y).padStart(2, '0') +
          String(date.getUTCMonth() + 1).padStart(2, '0') +
          String(date.getUTCDate()).padStart(2, '0') +
          String(date.getUTCHours()).padStart(2, '0') +
          String(date.getUTCMinutes()).padStart(2, '0') +
          String(date.getUTCSeconds()).padStart(2, '0') + 'Z';
  return derWrap(0x17, Buffer.from(s, 'ascii'));
}

// Encode OID from dotted string "1.2.840.10045.2.1"
function derOid(oidStr) {
  var parts = oidStr.split('.').map(Number);
  var bytes = [];

  // First two components combined: 40 * first + second
  bytes.push(40 * parts[0] + parts[1]);

  // Remaining components: base-128 VLQ encoding
  for (var i = 2; i < parts.length; i++) {
    var val = parts[i];
    if (val < 128) {
      bytes.push(val);
    } else {
      var vlq = [];
      while (val > 0) {
        vlq.unshift(val & 0x7F);
        val = val >>> 7;
      }
      for (var j = 0; j < vlq.length - 1; j++) {
        vlq[j] |= 0x80;  // continuation bit
      }
      for (var k = 0; k < vlq.length; k++) {
        bytes.push(vlq[k]);
      }
    }
  }

  return derWrap(0x06, Buffer.from(bytes));
}

// NULL
function derNull() {
  return Buffer.from([0x05, 0x00]);
}


/* ========================= OIDs ========================= */

// ECDSA signature algorithms (X9.62)
var OID_ECDSA_WITH_SHA256 = '1.2.840.10045.4.3.2';
var OID_ECDSA_WITH_SHA384 = '1.2.840.10045.4.3.3';
var OID_ECDSA_WITH_SHA512 = '1.2.840.10045.4.3.4';

// EC public key + curves
var OID_EC_PUBLIC_KEY     = '1.2.840.10045.2.1';
var OID_SECP256R1         = '1.2.840.10045.3.1.7';   // P-256 (NIST)
var OID_SECP384R1         = '1.3.132.0.34';          // P-384 (SECG/NIST)
var OID_SECP521R1         = '1.3.132.0.35';          // P-521 (SECG/NIST)

// RSA (PKCS#1)
var OID_RSA_ENCRYPTION    = '1.2.840.113549.1.1.1';
var OID_SHA1_WITH_RSA     = '1.2.840.113549.1.1.5';  // PKCS#1 sha1WithRSAEncryption
var OID_SHA256_WITH_RSA   = '1.2.840.113549.1.1.11'; // sha256WithRSAEncryption
var OID_SHA384_WITH_RSA   = '1.2.840.113549.1.1.12'; // sha384WithRSAEncryption
var OID_SHA512_WITH_RSA   = '1.2.840.113549.1.1.13'; // sha512WithRSAEncryption

var OID_COMMON_NAME       = '2.5.4.3';


/* ========================= Algorithm parameter resolution ========================= */

// Map W3C namedCurve string → { nodeName, oid }.
// Node's crypto API uses different curve identifiers than the WebCrypto spec.
var EC_CURVES = {
  'P-256': { nodeName: 'prime256v1', oid: OID_SECP256R1 },
  'P-384': { nodeName: 'secp384r1',  oid: OID_SECP384R1 },
  'P-521': { nodeName: 'secp521r1',  oid: OID_SECP521R1 },
};

// Map hash name → { nodeName, ecdsaOid, rsaOid }
// nodeName is what crypto.createSign() expects.
var HASH_ALGS = {
  'SHA-1':   { nodeName: 'SHA1',   ecdsaOid: null,                   rsaOid: OID_SHA1_WITH_RSA },
  'SHA-256': { nodeName: 'SHA256', ecdsaOid: OID_ECDSA_WITH_SHA256,   rsaOid: OID_SHA256_WITH_RSA },
  'SHA-384': { nodeName: 'SHA384', ecdsaOid: OID_ECDSA_WITH_SHA384,   rsaOid: OID_SHA384_WITH_RSA },
  'SHA-512': { nodeName: 'SHA512', ecdsaOid: OID_ECDSA_WITH_SHA512,   rsaOid: OID_SHA512_WITH_RSA },
};

// Resolve a W3C-style keygenAlgorithm into our internal config object.
// Throws TypeError on invalid/unsupported input (the api.js wrapper
// translates that into a rejected Promise with the right error name).
//
// Accepted shapes (mirroring W3C generateCertificate):
//   undefined / null              → default ECDSA P-256
//   string 'ECDSA'                → ECDSA P-256 (defaults)
//   string 'RSASSA-PKCS1-v1_5'    → RSA 2048-bit, e=65537, SHA-256 (defaults)
//   { name: 'ECDSA', namedCurve }
//   { name: 'RSASSA-PKCS1-v1_5', modulusLength, publicExponent, hash }
function _resolveKeygenAlgorithm(input) {
  // Default
  if (input == null) {
    return {
      kind:        'ec',
      curve:       EC_CURVES['P-256'],
      hash:        HASH_ALGS['SHA-256'],
    };
  }

  // String shorthand
  if (typeof input === 'string') {
    if (input === 'ECDSA') return _resolveKeygenAlgorithm({ name: 'ECDSA' });
    if (input === 'RSASSA-PKCS1-v1_5') return _resolveKeygenAlgorithm({ name: 'RSASSA-PKCS1-v1_5' });
    throw new TypeError('generateCertificate: unsupported algorithm name "' + input + '"');
  }

  // Object form — must have name
  if (typeof input !== 'object' || !input.name) {
    throw new TypeError('generateCertificate: keygenAlgorithm must be a string or {name, ...} object');
  }

  if (input.name === 'ECDSA') {
    var curveName = input.namedCurve || 'P-256';
    var curve = EC_CURVES[curveName];
    if (!curve) {
      throw new TypeError('generateCertificate: unsupported namedCurve "' + curveName +
                          '" (supported: P-256, P-384, P-521)');
    }
    // Hash for ECDSA: derive from curve per common practice when not given.
    // ECDSA's certificate signature hash is independent from the EC curve,
    // but Chrome/Firefox pick SHA-256 for P-256, SHA-384 for P-384, SHA-512
    // for P-521 by convention. Allow override via input.hash.
    var ecHashName = input.hash;
    if (!ecHashName) {
      if (curveName === 'P-256') ecHashName = 'SHA-256';
      else if (curveName === 'P-384') ecHashName = 'SHA-384';
      else ecHashName = 'SHA-512';   // P-521
    }
    if (typeof ecHashName === 'object') ecHashName = ecHashName.name;  // {name:'SHA-256'} form
    var ecHash = HASH_ALGS[ecHashName];
    if (!ecHash || !ecHash.ecdsaOid) {
      throw new TypeError('generateCertificate: unsupported hash for ECDSA: "' + ecHashName + '"');
    }
    return { kind: 'ec', curve: curve, hash: ecHash };
  }

  if (input.name === 'RSASSA-PKCS1-v1_5') {
    var modulusLength = input.modulusLength || 2048;
    if (typeof modulusLength !== 'number' || modulusLength < 1024 || modulusLength > 8192) {
      throw new TypeError('generateCertificate: modulusLength must be between 1024 and 8192 (got ' +
                          modulusLength + ')');
    }
    // publicExponent: spec uses Uint8Array (big-endian). Default 65537 = 0x010001.
    // Node's generateKeyPairSync accepts a number directly.
    var publicExponent = 65537;
    if (input.publicExponent) {
      if (typeof input.publicExponent === 'number') {
        publicExponent = input.publicExponent;
      } else if (input.publicExponent.length) {
        // Decode big-endian Uint8Array/Buffer to integer
        publicExponent = 0;
        for (var pe = 0; pe < input.publicExponent.length; pe++) {
          publicExponent = (publicExponent << 8) | input.publicExponent[pe];
        }
      }
    }
    // Hash
    var rsaHashName = input.hash;
    if (!rsaHashName) rsaHashName = 'SHA-256';
    if (typeof rsaHashName === 'object') rsaHashName = rsaHashName.name;
    var rsaHash = HASH_ALGS[rsaHashName];
    if (!rsaHash || !rsaHash.rsaOid) {
      throw new TypeError('generateCertificate: unsupported hash for RSA: "' + rsaHashName + '"');
    }
    return {
      kind:           'rsa',
      modulusLength:  modulusLength,
      publicExponent: publicExponent,
      hash:           rsaHash,
    };
  }

  throw new TypeError('generateCertificate: unsupported algorithm name "' + input.name +
                      '" (supported: ECDSA, RSASSA-PKCS1-v1_5)');
}


/* ========================= Certificate builder ========================= */

function generateCertificate(options) {
  options = options || {};

  // QUICK-4: resolve W3C-style keygenAlgorithm into our internal shape.
  // The caller (api.js's RTCPeerConnection.generateCertificate) passes
  // options.keygenAlgorithm; legacy callers that just want defaults pass
  // nothing (we treat that as ECDSA P-256 / SHA-256, matching the prior
  // behavior).
  var alg = _resolveKeygenAlgorithm(options.keygenAlgorithm);

  // 1. Generate key pair
  var keyPair;
  if (alg.kind === 'ec') {
    keyPair = crypto.generateKeyPairSync('ec', {
      namedCurve: alg.curve.nodeName,
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  } else {
    keyPair = crypto.generateKeyPairSync('rsa', {
      modulusLength:  alg.modulusLength,
      publicExponent: alg.publicExponent,
      publicKeyEncoding:  { type: 'spki',  format: 'der' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
  }

  var publicKeyDer  = keyPair.publicKey;   // DER Buffer (SubjectPublicKeyInfo)
  var privateKeyPem = keyPair.privateKey;  // PEM string

  // 2. Build TBSCertificate

  // Serial number — random 16 bytes
  var serial = crypto.randomBytes(16);
  serial[0] = serial[0] & 0x7F;  // ensure positive

  // Signature algorithm OID — depends on key type + chosen hash.
  // RSA AlgorithmIdentifier requires an explicit NULL parameter per
  // RFC 3279 §2.2.1; ECDSA omits parameters per RFC 5758 §3.2.
  var sigAlgOid = (alg.kind === 'ec') ? alg.hash.ecdsaOid : alg.hash.rsaOid;
  var sigAlgId;
  if (alg.kind === 'rsa') {
    sigAlgId = derSequence([derOid(sigAlgOid), derNull()]);
  } else {
    sigAlgId = derSequence([derOid(sigAlgOid)]);
  }

  // Issuer / Subject: minimal — just CN=webrtc
  var cn = options.commonName || 'webrtc';
  var name = derSequence([
    derSet([
      derSequence([
        derOid(OID_COMMON_NAME),
        derUtf8String(cn),
      ]),
    ]),
  ]);

  // Validity: now → +1 year
  var notBefore = new Date();
  var notAfter = new Date();
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  var validity = derSequence([
    derUtcTime(notBefore),
    derUtcTime(notAfter),
  ]);

  // SubjectPublicKeyInfo — already in DER from node:crypto
  var spki = publicKeyDer;

  // TBSCertificate
  var tbsCert = derSequence([
    derExplicit(0, derInteger(2)),      // version 3 (0-indexed: v3 = integer 2)
    derInteger(serial),                  // serialNumber
    sigAlgId,                            // signature algorithm
    name,                                // issuer
    validity,                            // validity
    name,                                // subject (same as issuer = self-signed)
    spki,                                // subjectPublicKeyInfo
  ]);

  // 3. Sign TBSCertificate with the chosen hash
  var signer = crypto.createSign(alg.hash.nodeName);
  signer.update(tbsCert);

  // Sign with the private key
  var privateKey = crypto.createPrivateKey(privateKeyPem);
  var signature = signer.sign(privateKey);

  // 4. Build Certificate
  var certificate = derSequence([
    tbsCert,
    sigAlgId,
    derBitString(signature),
  ]);

  // 5. Convert to PEM
  var certPem = '-----BEGIN CERTIFICATE-----\n' +
    certificate.toString('base64').match(/.{1,64}/g).join('\n') +
    '\n-----END CERTIFICATE-----\n';

  // 6. Compute SHA-256 fingerprint of the DER cert (for SDP a=fingerprint).
  // Note: the SDP fingerprint hash is independent of the signing hash —
  // RFC 8122 mandates the cert's own digest, not the signing algorithm.
  var fpHash = crypto.createHash('sha256').update(certificate).digest();
  var fingerprint = Array.from(new Uint8Array(fpHash)).map(function(b) {
    return b.toString(16).padStart(2, '0').toUpperCase();
  }).join(':');

  return {
    cert: certPem,
    key: privateKeyPem,
    fingerprint: fingerprint,
    certDer: certificate,
    // Expose the resolved algorithm so RTCCertificate can mirror W3C's
    // RTCCertificate.getAlgorithm(). Shape matches what the caller passed
    // (or defaulted to).
    algorithm: (alg.kind === 'ec')
      ? { name: 'ECDSA', namedCurve: _curveNameOf(alg.curve), hash: { name: _hashNameOf(alg.hash) } }
      : { name: 'RSASSA-PKCS1-v1_5', modulusLength: alg.modulusLength,
          publicExponent: alg.publicExponent, hash: { name: _hashNameOf(alg.hash) } },
  };
}

// Reverse-lookup helpers (small enough to inline rather than dual-map).
function _curveNameOf(curve) {
  for (var k in EC_CURVES) {
    if (Object.prototype.hasOwnProperty.call(EC_CURVES, k) &&
        EC_CURVES[k] === curve) return k;
  }
  return null;
}
function _hashNameOf(hash) {
  for (var k in HASH_ALGS) {
    if (Object.prototype.hasOwnProperty.call(HASH_ALGS, k) &&
        HASH_ALGS[k] === hash) return k;
  }
  return null;
}


/* ========================= Exports ========================= */

export { generateCertificate };
export default generateCertificate;

// src/cert.js
// Generate self-signed ECDSA (P-256) certificates for DTLS.
// The certificate's encoding is cryptographic-formats' (x509_build: the
// TBSCertificate to sign, then the certificate around the signature; the
// keys' PKCS#8 and SPKI); the keys and the signature are
// cryptographic-primitives' (it picks native or pure JavaScript).
//
// Usage:
//   import { generateCertificate } from './cert.js';
//   var { cert, key, fingerprint } = generateCertificate();
//   // cert = PEM string, key = PEM string, fingerprint = 'AA:BB:CC:...'
//
// This file encoded the DER itself, and its INTEGER writer once produced a
// non-minimal serial for about 1 in 256 random serials - which OpenSSL and
// node:crypto refuse, crashing DTLS setup at startup. cryptographic-formats writes
// minimal DER whatever the bytes.

import { x509, x509_build, pem } from 'cryptographic-formats';
import * as PKCS8 from 'cryptographic-formats/pkcs8';
import * as SPKI from 'cryptographic-formats/spki';
import * as SIG from 'cryptographic-formats/signature';
import { p256, p384, p521 } from 'cryptographic-primitives/nist.js';
import * as RSA from 'cryptographic-primitives/rsa.js';
import { sha1_sync } from 'cryptographic-primitives/sha1.js';
import { sha256_sync, sha384_sync, sha512_sync } from 'cryptographic-primitives/sha2.js';
import { random_bytes_sync } from 'cryptographic-primitives/random.js';


/* ========================= Algorithm parameter resolution ========================= */

// W3C namedCurve string → the library's curve, and its name in
// cryptographic-formats (the SPKI / PKCS#8 curve OID).
var EC_CURVES = {
  'P-256': { lib: p256, name: 'secp256r1' },
  'P-384': { lib: p384, name: 'secp384r1' },
  'P-521': { lib: p521, name: 'secp521r1' },
};

// Map hash name → { fn, ecdsaAlg, rsaAlg }
// fn is the library's hash the signature is made with; ecdsaAlg / rsaAlg the signature
// algorithm as cryptographic-formats names it (x509_build writes its OID, and for
// RSA the NULL parameters RFC 3279 §2.2.1 requires).
//
// SHA-1 signs nothing: W3C generateCertificate takes the WebCrypto
// algorithms browsers support, and Chrome refuses a SHA-1 RSASSA key
// (NotSupportedError) as RFC 9155 deprecates SHA-1 signatures in (D)TLS 1.2.
// api.js refused the string form ('SHA-1') only; { name: 'SHA-1' } made a
// sha1WithRSAEncryption certificate.
var HASH_ALGS = {
  'SHA-1':   { fn: sha1_sync,   ecdsaAlg: null,              rsaAlg: null },
  'SHA-256': { fn: sha256_sync, ecdsaAlg: 'ecdsaWithSHA256', rsaAlg: 'sha256WithRSAEncryption' },
  'SHA-384': { fn: sha384_sync, ecdsaAlg: 'ecdsaWithSHA384', rsaAlg: 'sha384WithRSAEncryption' },
  'SHA-512': { fn: sha512_sync, ecdsaAlg: 'ecdsaWithSHA512', rsaAlg: 'sha512WithRSAEncryption' },
};

// The table's own entry for `key`, or undefined: never an inherited
// property ('__proto__', 'toString' named a curve that was then "found").
function _own(table, key) {
  return Object.prototype.hasOwnProperty.call(table, key) ? table[key] : undefined;
}

// WebCrypto's algorithm names compare case-insensitively ("normalize an
// algorithm", WebCrypto §18.4: a case-insensitive match of the name) — the
// algorithm's name and the hash's; a named curve is an exact string.
// Chrome takes { name: 'ecdsa' } and hash 'sha-256'. The canonical
// spelling, or the input as given when nothing matches.
function _canonicalName(names, input) {
  var lower = String(input).toLowerCase();
  for (var i = 0; i < names.length; i++) {
    if (names[i].toLowerCase() === lower) return names[i];
  }
  return input;
}
var ALG_NAMES = ['ECDSA', 'RSASSA-PKCS1-v1_5'];

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
    var strName = _canonicalName(ALG_NAMES, input);
    if (strName === 'ECDSA') return _resolveKeygenAlgorithm({ name: 'ECDSA' });
    if (strName === 'RSASSA-PKCS1-v1_5') return _resolveKeygenAlgorithm({ name: 'RSASSA-PKCS1-v1_5' });
    throw new TypeError('generateCertificate: unsupported algorithm name "' + input + '"');
  }

  // Object form — must have name
  if (typeof input !== 'object' || !input.name) {
    throw new TypeError('generateCertificate: keygenAlgorithm must be a string or {name, ...} object');
  }

  var algName = _canonicalName(ALG_NAMES, input.name);

  if (algName === 'ECDSA') {
    // EcKeyGenParams' namedCurve is a REQUIRED member (WebCrypto §23.4):
    // normalizing { name: 'ECDSA' } without it fails with a TypeError
    // (WebCrypto §18.4, WebIDL dictionary conversion), and W3C
    // generateCertificate rejects with that error (webrtc-pc §4.10.1
    // step 2) — Chrome does. It was taken as P-256. The string form
    // 'ECDSA' normalizes to { name: 'ECDSA' } and fails the same way. The
    // library's own certificate is still P-256: its callers pass the curve
    // (or no algorithm at all, the default above). `normalization` tells
    // api.js not to turn this one into a NotSupportedError.
    if (input.namedCurve === undefined) {
      var normErr = new TypeError('generateCertificate: EcKeyGenParams requires namedCurve');
      normErr.normalization = true;
      throw normErr;
    }
    var curveName = String(input.namedCurve);
    var curve = _own(EC_CURVES, curveName);
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
    var ecHash = _own(HASH_ALGS, _canonicalName(Object.keys(HASH_ALGS), ecHashName));
    if (!ecHash || !ecHash.ecdsaAlg) {
      throw new TypeError('generateCertificate: unsupported hash for ECDSA: "' + ecHashName + '"');
    }
    return { kind: 'ec', curve: curve, hash: ecHash };
  }

  if (algName === 'RSASSA-PKCS1-v1_5') {
    var modulusLength = input.modulusLength || 2048;
    // An integer: WebIDL's [EnforceRange] unsigned long. A fraction reached
    // the key generator, which threw a RangeError of its BigInt arithmetic.
    if (typeof modulusLength !== 'number' || Math.floor(modulusLength) !== modulusLength ||
        modulusLength < 1024 || modulusLength > 8192) {
      throw new TypeError('generateCertificate: modulusLength must be between 1024 and 8192 (got ' +
                          modulusLength + ')');
    }
    // publicExponent: spec uses Uint8Array (big-endian, unsigned: WebCrypto
    // BigInteger). Default 65537 = 0x010001. A number is taken too.
    //
    // It is decoded WITHOUT 32-bit overflow ((e << 8) | byte made
    // [0x80, 0, 0, 1] the exponent -2147483647, and a key was generated with
    // it), and it must be an RSA exponent: odd, at least 3 (RFC 8017 §3.1);
    // at most 2^53 - 1, so the RTCCertificate's algorithm reports it exactly.
    // An even or negative one made a key with e = -3, or failed deep in the
    // key generator.
    var publicExponent = 65537;
    if (input.publicExponent) {
      var peBig;
      if (typeof input.publicExponent === 'number') {
        peBig = Number.isSafeInteger(input.publicExponent) ? BigInt(input.publicExponent) : null;
      } else if (ArrayBuffer.isView(input.publicExponent) || Array.isArray(input.publicExponent)) {
        peBig = 0n;
        for (var pe = 0; pe < input.publicExponent.length; pe++) {
          peBig = (peBig << 8n) | BigInt(input.publicExponent[pe] & 0xFF);
        }
      } else {
        throw new TypeError('generateCertificate: publicExponent must be a Uint8Array or a number');
      }
      if (peBig === null || peBig < 3n || (peBig & 1n) === 0n || peBig > 9007199254740991n) {
        throw new TypeError('generateCertificate: publicExponent must be an odd integer from 3 to 2^53 - 1 (got ' +
                            (peBig === null ? String(input.publicExponent) : String(peBig)) + ')');
      }
      publicExponent = Number(peBig);
    }
    // Hash
    var rsaHashName = input.hash;
    if (!rsaHashName) rsaHashName = 'SHA-256';
    if (typeof rsaHashName === 'object') rsaHashName = rsaHashName.name;
    var rsaHash = _own(HASH_ALGS, _canonicalName(Object.keys(HASH_ALGS), rsaHashName));
    if (!rsaHash || !rsaHash.rsaAlg) {
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

  // 1. Generate the key pair (cryptographic-primitives), and its PKCS#8 and
  //    SPKI (cryptographic-formats). sign(tbs) signs with it, in the form
  //    X.509 carries (ECDSA as DER).
  var publicKeyDer, privateKeyDer, sign;
  if (alg.kind === 'ec') {
    var kp = alg.curve.lib.keygen_sync();
    var point = alg.curve.lib.get_public_key_sync(kp.sk, false);
    privateKeyDer = PKCS8.to_der({ algorithm: 'ecPublicKey', curve: alg.curve.name, scalar: kp.sk, point: point });
    publicKeyDer = SPKI.to_der({ algorithm: 'ecPublicKey', curve: alg.curve.name, point: point });
    sign = function (bytes) {
      var signer = alg.curve.lib.signer_create(kp.sk);
      try {
        var rs = signer.sign_message_sync(alg.hash.fn, bytes);
        return SIG.from_pair({ r: bytes_of(rs.r), s: bytes_of(rs.s) });
      } finally { signer.wipe(); kp.sk.fill(0); }
    };
  } else {
    var k = RSA.keygen_sync(alg.modulusLength, null, BigInt(alg.publicExponent));
    var rsa = { n: bytes_of(k.n), e: bytes_of(k.e), d: bytes_of(k.d), p: bytes_of(k.p), q: bytes_of(k.q),
                dp: bytes_of(k.dp), dq: bytes_of(k.dq), qinv: bytes_of(k.qinv) };
    privateKeyDer = PKCS8.to_der({ algorithm: 'rsaEncryption', rsa: rsa });
    publicKeyDer = SPKI.to_der({ algorithm: 'rsaEncryption', rsa: { n: rsa.n, e: rsa.e } });
    sign = function (bytes) {
      var signer = RSA.signer_create(k);
      try { return signer.sign_pkcs1_message_sync(bytes, alg.hash.fn); } finally { signer.wipe(); }
    };
  }
  var privateKeyPem = pem.encode(privateKeyDer, 'PRIVATE KEY');

  // 2. The TBSCertificate (cryptographic-formats): self-signed, v3, no extensions.
  //    Issuer and subject CN=webrtc (or options.commonName); valid from now
  //    for a year; a random 16-byte serial, positive (the top bit cleared).
  var serial = random_bytes_sync(16);
  serial[0] = serial[0] & 0x7F;

  var cn = options.commonName || 'webrtc';
  var name = [{ commonName: cn }];

  // The year is added in UTC, the time X.509 validity is written in
  // (RFC 5280 §4.1.2.5): in local time a year across a DST change was a
  // year and an hour, or less an hour, depending on the host's time zone.
  var notBefore = new Date();
  var notAfter = new Date(notBefore.getTime());
  notAfter.setUTCFullYear(notAfter.getUTCFullYear() + 1);

  var tbs = x509_build.prepare({
    serial: serial,
    issuer: name,
    subject: name,                       // the same as the issuer: self-signed
    validity: { not_before: notBefore, not_after: notAfter },
    public_key: publicKeyDer,
    signature_algorithm: (alg.kind === 'ec') ? alg.hash.ecdsaAlg : alg.hash.rsaAlg,
  });

  // 3. Sign it with the chosen hash
  var signature = sign(tbs.bytes);

  // 4. The certificate around the signature, and 5. its PEM
  var certificate = Buffer.from(x509_build.assemble(tbs, signature));
  var certPem = pem.encode(certificate, 'CERTIFICATE');

  // 6. Compute SHA-256 fingerprint of the DER cert (for SDP a=fingerprint),
  // and every fingerprint the SDP advertises (certificateFingerprints:
  // SHA-256, and the signature's own hash when that is another).
  var fingerprint = _fingerprintHex(sha256_sync(certificate));

  return {
    cert: certPem,
    key: privateKeyPem,
    fingerprint: fingerprint,
    fingerprints: _fingerprintsOf(certificate, alg.hash),
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

/* ========================= Fingerprints ========================= */

// The fingerprint a=fingerprint carries: the hash as upper-case hex, the
// bytes separated by colons (RFC 8122 §5).
function _fingerprintHex(digest) {
  return Array.from(new Uint8Array(digest)).map(function(b) {
    return b.toString(16).padStart(2, '0').toUpperCase();
  }).join(':');
}

// The SDP hash names (RFC 8122 §5, the IANA "Hash Function Textual
// Names") of the signature hashes, and the functions.
var FP_HASHES = {
  'SHA-256': ['sha-256', sha256_sync],
  'SHA-384': ['sha-384', sha384_sync],
  'SHA-512': ['sha-512', sha512_sync],
};

// Every fingerprint of a certificate the SDP advertises. RFC 8122 §5.1: an
// endpoint "SHOULD include a certificate fingerprint that uses the same
// hash function as the certificate's signature"; and SHA-256 is the one
// every endpoint supports (RFC 8122 §5, RFC 8827 §6.5), the one libwebrtc
// reads. So: SHA-256 first, then the signature's hash when it is another
// (a P-384 certificate is signed with SHA-384, a P-521 one with SHA-512).
// SHA-1 is not added for a SHA-1-signed certificate (a user's own): it is
// no stronger, and RFC 9155 retires it. Only SHA-256 was advertised.
function _fingerprintsOf(der, sigHash) {
  var out = [{ algorithm: 'sha-256', value: _fingerprintHex(sha256_sync(der)) }];
  var name = sigHash ? _hashNameOf(sigHash) : null;
  var h = name ? _own(FP_HASHES, name) : undefined;
  if (h && h[0] !== 'sha-256') out.push({ algorithm: h[0], value: _fingerprintHex(h[1](der)) });
  return out;
}

// certificateFingerprints(der): the same for a certificate of the user's
// (RTCConfiguration's cert / key), its signature hash read from the
// certificate (cryptographic-formats' x509). One that does not parse gets
// SHA-256 alone.
function certificateFingerprints(der) {
  var sigHash = null;
  try {
    var parsed = x509.from_der(der);
    var hname = parsed && parsed.signature_params && parsed.signature_params.hash;
    var byLib = { sha256: 'SHA-256', sha384: 'SHA-384', sha512: 'SHA-512' };
    if (hname && _own(byLib, hname)) sigHash = HASH_ALGS[byLib[hname]];
  } catch (e) { sigHash = null; }
  return _fingerprintsOf(der, sigHash);
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


// A non-negative bigint as big-endian bytes, no leading zeros.
function bytes_of(n) {
  var h = n.toString(16);
  var b = Buffer.from(h.length % 2 ? '0' + h : h, 'hex');
  return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
}


/* ========================= Exports ========================= */

export { generateCertificate, certificateFingerprints };
export default generateCertificate;
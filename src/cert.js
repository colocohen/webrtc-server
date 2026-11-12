// src/cert.js
// Generate self-signed ECDSA (P-256) certificates for DTLS.
// The certificate's encoding is cryptographic-formats' (x509_build: the
// TBSCertificate to sign, then the certificate around the signature); the
// keys and the signature are node:crypto's.
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

import crypto from 'node:crypto';
import { x509_build, pem } from 'cryptographic-formats';


/* ========================= Algorithm parameter resolution ========================= */

// Map W3C namedCurve string → node:crypto's curve name.
// Node's crypto API uses different curve identifiers than the WebCrypto spec.
var EC_CURVES = {
  'P-256': { nodeName: 'prime256v1' },
  'P-384': { nodeName: 'secp384r1' },
  'P-521': { nodeName: 'secp521r1' },
};

// Map hash name → { nodeName, ecdsaAlg, rsaAlg }
// nodeName is what crypto.sign() takes; ecdsaAlg / rsaAlg the signature
// algorithm as cryptographic-formats names it (x509_build writes its OID, and for
// RSA the NULL parameters RFC 3279 §2.2.1 requires).
var HASH_ALGS = {
  'SHA-1':   { nodeName: 'SHA1',   ecdsaAlg: null,              rsaAlg: 'sha1WithRSAEncryption' },
  'SHA-256': { nodeName: 'SHA256', ecdsaAlg: 'ecdsaWithSHA256', rsaAlg: 'sha256WithRSAEncryption' },
  'SHA-384': { nodeName: 'SHA384', ecdsaAlg: 'ecdsaWithSHA384', rsaAlg: 'sha384WithRSAEncryption' },
  'SHA-512': { nodeName: 'SHA512', ecdsaAlg: 'ecdsaWithSHA512', rsaAlg: 'sha512WithRSAEncryption' },
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
    if (!ecHash || !ecHash.ecdsaAlg) {
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

  // 2. The TBSCertificate (cryptographic-formats): self-signed, v3, no extensions.
  //    Issuer and subject CN=webrtc (or options.commonName); valid from now
  //    for a year; a random 16-byte serial, positive (the top bit cleared).
  var serial = crypto.randomBytes(16);
  serial[0] = serial[0] & 0x7F;

  var cn = options.commonName || 'webrtc';
  var name = [{ commonName: cn }];

  var notBefore = new Date();
  var notAfter = new Date();
  notAfter.setFullYear(notAfter.getFullYear() + 1);

  var tbs = x509_build.prepare({
    serial: new Uint8Array(serial),
    issuer: name,
    subject: name,                       // the same as the issuer: self-signed
    validity: { not_before: notBefore, not_after: notAfter },
    public_key: new Uint8Array(publicKeyDer),
    signature_algorithm: (alg.kind === 'ec') ? alg.hash.ecdsaAlg : alg.hash.rsaAlg,
  });

  // 3. Sign it with the chosen hash (an ECDSA signature in DER, as X.509 has it)
  var privateKey = crypto.createPrivateKey(privateKeyPem);
  var signature = crypto.sign(alg.hash.nodeName, Buffer.from(tbs.bytes), privateKey);

  // 4. The certificate around the signature, and 5. its PEM
  var certificate = Buffer.from(x509_build.assemble(tbs, new Uint8Array(signature)));
  var certPem = pem.encode(certificate, 'CERTIFICATE');

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
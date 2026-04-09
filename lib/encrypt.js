/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const crypto = require('crypto');
const common = require('./common');
const ecdh = require('./ecdh');

const Tagged = cbor.Tagged;

const EMPTY_BUFFER = common.EMPTY_BUFFER;
// CBOR tags defined in RFC 8152 §2 for COSE_Encrypt and COSE_Encrypt0
const EncryptTag = exports.EncryptTag = 96;
const Encrypt0Tag = exports.Encrypt0Tag = 16;

const runningInNode = common.runningInNode;

// Maps COSE algorithm names to the cipher identifiers understood by Node's
// built-in `crypto` module.
const COSEAlgToNodeAlg = {
  A128GCM: 'aes-128-gcm',
  A192GCM: 'aes-192-gcm',
  A256GCM: 'aes-256-gcm',

  'AES-CCM-16-64-128': 'aes-128-ccm',
  'AES-CCM-16-64-256': 'aes-256-ccm',
  'AES-CCM-64-64-128': 'aes-128-ccm',
  'AES-CCM-64-64-256': 'aes-256-ccm',
  'AES-CCM-16-128-128': 'aes-128-ccm',
  'AES-CCM-16-128-256': 'aes-256-ccm',
  'AES-CCM-64-128-128': 'aes-128-ccm',
  'AES-CCM-64-128-256': 'aes-256-ccm'
};

// Algorithm IDs that map to AES-GCM — handled directly by Node's crypto.
const isNodeAlg = {
  1: true, // A128GCM
  2: true, // A192GCM
  3: true // A256GCM
};

// Algorithm IDs that map to AES-CCM — only available in Node (not browsers).
const isCCMAlg = {
  10: true, // AES-CCM-16-64-128
  11: true, // AES-CCM-16-64-256
  12: true, // AES-CCM-64-64-128
  13: true, // AES-CCM-64-64-256
  30: true, // AES-CCM-16-128-128
  31: true, // AES-CCM-16-128-256
  32: true, // AES-CCM-64-128-128
  33: true // AES-CCM-64-128-256
};

// Authentication tag lengths in bytes for each algorithm.
// GCM always produces a 16-byte tag; CCM tag length is encoded in the
// algorithm name (e.g. AES-CCM-16-*64*-128 → 8 bytes, AES-CCM-16-*128*-128 → 16 bytes).
const authTagLength = {
  1: 16,
  2: 16,
  3: 16,
  10: 8, // AES-CCM-16-64-128
  11: 8, // AES-CCM-16-64-256
  12: 8, // AES-CCM-64-64-128
  13: 8, // AES-CCM-64-64-256
  30: 16, // AES-CCM-16-128-128
  31: 16, // AES-CCM-16-128-256
  32: 16, // AES-CCM-64-128-128
  33: 16 // AES-CCM-64-128-256
};

// Required IV lengths in bytes for each algorithm.
// GCM requires a 12-byte IV. CCM IV length depends on the message-length
// field size: 16 in the name → 13-byte IV (L=2), 64 → 7-byte IV (L=8).
const ivLength = {
  1: 12, // A128GCM
  2: 12, // A192GCM
  3: 12, // A256GCM
  10: 13, // AES-CCM-16-64-128
  11: 13, // AES-CCM-16-64-256
  12: 7, // AES-CCM-64-64-128
  13: 7, // AES-CCM-64-64-256
  30: 13, // AES-CCM-16-128-128
  31: 13, // AES-CCM-16-128-256
  32: 7, // AES-CCM-64-128-128
  33: 7 // AES-CCM-64-128-256
};

// Symmetric key lengths in bytes for each algorithm.
const keyLength = {
  1: 16, // A128GCM
  2: 24, // A192GCM
  3: 32, // A256GCM
  10: 16, // AES-CCM-16-64-128
  11: 32, // AES-CCM-16-64-256
  12: 16, // AES-CCM-64-64-128
  13: 32, // AES-CCM-64-64-256
  30: 16, // AES-CCM-16-128-128
  31: 32, // AES-CCM-16-128-256
  32: 16, // AES-CCM-64-128-128
  33: 32 // AES-CCM-64-128-256
};

// Builds the Enc_structure (RFC 8152 §5.3) that is authenticated but not
// encrypted. It binds the ciphertext to the protected header and any caller-
// supplied external AAD so that tampering with either is detected.
function createAAD (p, context, externalAAD) {
  p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
  const encStructure = [
    context,
    p,
    externalAAD
  ];
  return cbor.encode(encStructure);
}

function _randomSource (bytes) {
  return crypto.randomBytes(bytes);
}

// Encrypts `payload` with AES-GCM or AES-CCM using Node's built-in crypto.
// The auth tag is appended to the ciphertext so it can be transmitted as a
// single opaque byte string (the COSE convention).
function nodeEncrypt (payload, key, alg, iv, aad, ccm = false) {
  const nodeAlg = COSEAlgToNodeAlg[common.TagsToAlg[alg]];
  // CCM requires the auth-tag length and plaintext length at cipher creation time.
  const chiperOptions = ccm ? { authTagLength: authTagLength[alg] } : null;
  const aadOptions = ccm ? { plaintextLength: Buffer.byteLength(payload) } : null;
  const cipher = crypto.createCipheriv(nodeAlg, key, iv, chiperOptions);
  cipher.setAAD(aad, aadOptions);
  return Buffer.concat([
    cipher.update(payload),
    cipher.final(),
    cipher.getAuthTag()
  ]);
}

// Creates a COSE_Encrypt (tag 96) or COSE_Encrypt0 (tag 16) message.
//
// When `recipients` is an Array the result is COSE_Encrypt: a multi-layer
// structure where the Content Encryption Key (CEK) is wrapped per recipient.
// Currently only a single recipient is supported.
//
// When `recipients` is a plain object (a single key) the result is
// COSE_Encrypt0: the simpler single-layer form with no recipient structure.
exports.create = async function (headers, payload, recipients, options) {
  options = options || {};
  const externalAAD = options.externalAAD || EMPTY_BUFFER;
  const randomSource = options.randomSource || _randomSource;
  let u = headers.u || {};
  let p = headers.p || {};

  // Translate human-readable header names to their COSE integer IDs.
  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);

  // The content encryption algorithm must appear in either the protected or
  // unprotected header (protected takes precedence).
  const alg = common.getAlgorithm(p, u);

  if (!alg) {
    throw new Error('Missing mandatory parameter \'alg\'');
  }

  if (Array.isArray(recipients)) {
    // --- COSE_Encrypt (multi-recipient, tag 96) ---
    if (recipients.length === 0) {
      throw new Error('There has to be at least one recipent');
    }
    if (recipients.length > 1) {
      throw new Error('Encrypting with multiple recipents is not implemented');
    }

    // Generate a fresh IV, or compute one from a Partial IV XOR'd against a
    // shared context IV (used when messages share a key but must have unique IVs).
    let iv;
    if (options.contextIv) {
      const partialIvLength = options.partialIvLength || Math.max(6, ivLength[alg] - 2);
      const partialIv = randomSource(partialIvLength);
      iv = common.xor(partialIv, options.contextIv);
      u.set(common.HeaderParameters.Partial_IV, partialIv);
    } else {
      iv = randomSource(ivLength[alg]);
      u.set(common.HeaderParameters.IV, iv);
    }

    // Build the AAD that covers the protected header and any external AAD.
    const aad = createAAD(p, 'Encrypt', externalAAD);

    let key;
    let recipientStruct;
    if (recipients[0] && recipients[0].p && ecdh.isECDH(recipients[0].p.alg)) {
      const derived = ecdh.deriveKey(recipients[0], alg, keyLength[alg], randomSource);
      key = derived.key;
      recipientStruct = derived.recipientStruct;
    } else {
      key = recipients[0].key;
      const ru = common.TranslateHeaders(recipients[0].u);
      recipientStruct = [[EMPTY_BUFFER, ru, EMPTY_BUFFER]];
    }

    // Encrypt the payload.
    let ciphertext;
    if (isNodeAlg[alg]) {
      ciphertext = nodeEncrypt(payload, key, alg, iv, aad);
    } else if (isCCMAlg[alg] && runningInNode()) {
      ciphertext = nodeEncrypt(payload, key, alg, iv, aad, true);
    } else {
      throw new Error('No implementation for algorithm, ' + alg);
    }

    p = common.encodeProtected(p, options);

    // COSE_Encrypt: [protected, unprotected, ciphertext, [recipients]]
    const encrypted = [p, u, ciphertext, recipientStruct];
    return cbor.encode(options.excludetag ? encrypted : new Tagged(EncryptTag, encrypted));
  } else {
    // --- COSE_Encrypt0 (single recipient, tag 16) ---
    // Simpler form: no recipient layer. The key is shared out-of-band.
    let iv;
    if (options.contextIv) {
      const partialIvLength = options.partialIvLength || Math.max(6, ivLength[alg] - 2);
      const partialIv = randomSource(partialIvLength);
      iv = common.xor(partialIv, options.contextIv);
      u.set(common.HeaderParameters.Partial_IV, partialIv);
    } else {
      iv = randomSource(ivLength[alg]);
      u.set(common.HeaderParameters.IV, iv);
    }

    const key = recipients.key;

    const aad = createAAD(p, 'Encrypt0', externalAAD);
    let ciphertext;
    if (isNodeAlg[alg]) {
      ciphertext = nodeEncrypt(payload, key, alg, iv, aad);
    } else if (isCCMAlg[alg] && runningInNode()) {
      ciphertext = nodeEncrypt(payload, key, alg, iv, aad, true);
    } else {
      throw new Error('No implementation for algorithm, ' + alg);
    }

    p = common.encodeProtected(p, options);

    // COSE_Encrypt0: [protected, unprotected, ciphertext]
    const encrypted = [p, u, ciphertext];
    return cbor.encode(options.excludetag ? encrypted : new Tagged(Encrypt0Tag, encrypted));
  }
};

// Decrypts a single AES-GCM or AES-CCM ciphertext produced by nodeEncrypt.
// The auth tag is expected to be appended to the ciphertext (COSE convention).
function nodeDecrypt (ciphertext, key, alg, iv, tag, aad, ccm = false) {
  const nodeAlg = COSEAlgToNodeAlg[common.TagsToAlg[alg]];
  const chiperOptions = ccm ? { authTagLength: authTagLength[alg] } : null;
  // CCM needs the ciphertext length (== plaintext length) before decryption starts.
  const aadOptions = ccm ? { plaintextLength: Buffer.byteLength(ciphertext) } : null;
  const decipher = crypto.createDecipheriv(nodeAlg, key, iv, chiperOptions);
  decipher.setAuthTag(tag);
  decipher.setAAD(aad, aadOptions);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

// Decodes and decrypts a COSE_Encrypt or COSE_Encrypt0 message.
// `key` must be the raw CEK (key unwrapping for ECDH recipients is not yet
// handled here — callers must derive/unwrap the key before calling read()).
exports.read = async function (data, key, options) {
  options = options || {};
  const externalAAD = options.externalAAD || EMPTY_BUFFER;

  // Decode the outermost CBOR item. It may be a tagged or untagged array.
  let obj = await cbor.decodeFirst(data);

  const validated = common.validateMessage(obj, [EncryptTag, Encrypt0Tag]);
  const msgTag = validated.type || (options.defaultType ? options.defaultType : EncryptTag);
  obj = validated.value;

  // COSE_Encrypt has 4 elements; COSE_Encrypt0 has 3.
  if (msgTag === EncryptTag && obj.length !== 4) {
    throw new Error('Expecting Array of length 4 for COSE Encrypt message');
  }

  if (msgTag === Encrypt0Tag && obj.length !== 3) {
    throw new Error('Expecting Array of length 4 for COSE Encrypt0 message');
  }

  let [p, u, ciphertext] = obj;

  // Decode the protected header bstr into a Map (or leave as EMPTY_BUFFER if absent).
  p = (p.length === 0) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
  p = (!p.size) ? EMPTY_BUFFER : p;
  u = (!u.size) ? EMPTY_BUFFER : u;

  // Algorithm is taken from the protected header first, then unprotected.
  const alg = common.getAlgorithm(p, u);
  if (!common.TagsToAlg[alg]) {
    throw new Error('Unknown or unsupported algorithm ' + alg);
  }

  // Resolve the IV. A Partial IV is XOR'd with a shared context IV to produce
  // the full IV (used when many messages share a key with sequential IVs).
  let iv = u.get ? u.get(common.HeaderParameters.IV) : undefined;
  const partialIv = u.get ? u.get(common.HeaderParameters.Partial_IV) : undefined;
  if (iv && partialIv) {
    throw new Error('IV and Partial IV parameters MUST NOT both be present in the same security layer');
  }
  if (partialIv && !options.contextIv) {
    throw new Error('Context IV must be provided when Partial IV is used');
  }
  if (partialIv && options.contextIv) {
    iv = common.xor(partialIv, options.contextIv);
  }

  // Split off the appended authentication tag from the end of the ciphertext.
  const tagLength = authTagLength[alg];
  const tag = ciphertext.slice(ciphertext.length - tagLength, ciphertext.length);
  ciphertext = ciphertext.slice(0, ciphertext.length - tagLength);

  const aad = createAAD(p, (msgTag === EncryptTag ? 'Encrypt' : 'Encrypt0'), externalAAD);
  if (isNodeAlg[alg]) {
    return nodeDecrypt(ciphertext, key, alg, iv, tag, aad);
  } else if (isCCMAlg[alg] && runningInNode()) {
    return nodeDecrypt(ciphertext, key, alg, iv, tag, aad, true);
  } else {
    throw new Error('No implementation for algorithm, ' + alg);
  }
};

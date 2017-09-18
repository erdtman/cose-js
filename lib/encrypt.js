/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const crypto = require('crypto');
const Promise = require('any-promise');
const common = require('./common');
const Tagged = cbor.Tagged;

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const EncryptTag = 96;
const Encrypt0Tag = 16;

const TagToAlg = {
  1: 'A128GCM',
  2: 'A192GCM',
  3: 'A256GCM'
};

const COSEAlgToNodeAlg = {
  'A128GCM': 'aes-128-gcm',
  'A192GCM': 'aes-192-gcm',
  'A256GCM': 'aes-256-gcm'
};

function createAAD (p, context, externalAAD) {
  const encStructure = [
    context,
    cbor.encode(p),
    externalAAD
  ];
  return cbor.encode(encStructure);
}

function _randomSource (bytes) {
  return crypto.randomBytes(bytes);
}

exports.create = function (headers, payload, recipients, options) {
  options = options || {};
  const externalAAD = options.externalAAD || EMPTY_BUFFER;
  const randomSource = options.randomSource || _randomSource;
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);

  const alg = p.get(common.HeaderParameters.alg) || u.get(common.HeaderParameters.alg);

  if (!alg) {
    throw new Error('Missing mandatory parameter \'alg\'');
  }

  p = (!p.size) ? EMPTY_BUFFER : p;
  u = (!p.size) ? EMPTY_BUFFER : u;

  if (recipients.length === 0) {
    throw new Error('There has to be at least one recipent');
  }

  if (recipients.length === 1) {
    return new Promise((resolve, reject) => {
      let iv;
      if (options.contextIv) {
        let partialIv = randomSource(2);
        iv = common.xor(partialIv, options.contextIv);
        u.set(common.HeaderParameters.Partial_IV, partialIv);
      } else {
        iv = randomSource(12);
        u.set(common.HeaderParameters.IV, iv);
      }

      const nodeAlg = COSEAlgToNodeAlg[TagToAlg[alg]];
      const cipher = crypto.createCipheriv(nodeAlg, recipients[0].key, iv);
      const aad = createAAD(p, options.singleRecipient ? 'Encrypt0' : 'Encrypt', externalAAD);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([
        cipher.update(payload),
        cipher.final(),
        cipher.getAuthTag()
      ]);
      p = cbor.encode(p);
      const ru = common.TranslateHeaders(recipients[0].u);
      const recipient = [[EMPTY_BUFFER, ru, EMPTY_BUFFER]];
      if (options.singleRecipient) {
        resolve(cbor.encode(new Tagged(Encrypt0Tag, [p, u, ciphertext])));
      } else {
        resolve(cbor.encode(new Tagged(EncryptTag, [p, u, ciphertext, recipient])));
      }
    });
  }

  if (recipients.length > 1) {
    throw new Error('Encrypting with multiple recipents is not implemented');
  }
};

exports.read = function (data, key, options) {
  options = options || {};
  const externalAAD = options.externalAAD || EMPTY_BUFFER;
  return cbor.decodeFirst(data)
  .then((obj) => {
    let msgTag = EncryptTag;
    if (obj instanceof Tagged) {
      if (obj.tag !== EncryptTag && obj.tag !== Encrypt0Tag) {
        throw new Error('Unknown tag, ' + obj.tag);
      }

      msgTag = obj.tag;
      obj = obj.value;
    }

    if (!Array.isArray(obj)) {
      throw new Error('Expecting Array');
    }

    if (msgTag === EncryptTag && obj.length !== 4) {
      throw new Error('Expecting Array of lenght 4 for COSE Encrypt message');
    }

    if (msgTag === Encrypt0Tag && obj.length !== 3) {
      throw new Error('Expecting Array of lenght 4 for COSE Encrypt0 message');
    }

    let [p, u, ciphertext] = obj;
    p = cbor.decodeFirstSync(p);
    p = (!p.size) ? EMPTY_BUFFER : p;
    u = (!u.size) ? EMPTY_BUFFER : u;

    let alg = p.get(common.HeaderParameters.alg);
    alg = COSEAlgToNodeAlg[TagToAlg[alg]];

    let iv = u.get(common.HeaderParameters.IV);
    const partialIv = u.get(common.HeaderParameters.Partial_IV);
    if (iv && partialIv) {
      throw new Error('IV and Partial IV parameters MUST NOT both be present in the same security layer');
    }
    if (partialIv && !options.contextIv) {
      throw new Error('Context IV must be provided when Partial IV is used');
    }
    if (partialIv && options.contextIv) {
      iv = common.xor(partialIv, options.contextIv);
    }
    const tag = ciphertext.slice(ciphertext.length - 16, ciphertext.length);
    ciphertext = ciphertext.slice(0, ciphertext.length - 16);
    const decipher = crypto.createDecipheriv(alg, key, iv);
    decipher.setAuthTag(tag);
    const aad = createAAD(p, (msgTag === EncryptTag ? 'Encrypt' : 'Encrypt0'), externalAAD);
    decipher.setAAD(aad);

    const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return dec;
  });
};

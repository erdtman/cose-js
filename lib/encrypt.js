/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const crypto = require('crypto');
const Promise = require('any-promise');
const common = require('./common');
const Tagged = cbor.Tagged;

const EMPTY_BUFFER = common.EMPTY_BUFFER;
const EncryptTag = 992;

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

exports.create = function (headers, payload, recipients, externalAAD, randomSource) {
  externalAAD = externalAAD || EMPTY_BUFFER;
  randomSource = randomSource || _randomSource;
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
      const iv = randomSource(12);
      u.set(common.HeaderParameters.IV, iv);
      const nodeAlg = COSEAlgToNodeAlg[TagToAlg[alg]];
      const cipher = crypto.createCipheriv(nodeAlg, recipients[0].key, iv);
      const aad = createAAD(p, 'Encrypt', externalAAD);
      cipher.setAAD(aad);
      const ciphertext = Buffer.concat([
        cipher.update(payload),
        cipher.final(),
        cipher.getAuthTag()
      ]);
      p = cbor.encode(p);
      const ru = common.TranslateHeaders(recipients[0].u);
      const recipient = [[EMPTY_BUFFER, ru, EMPTY_BUFFER]];
      resolve(cbor.encode(new Tagged(EncryptTag, [p, u, ciphertext, recipient])));
    });
  }

  if (recipients.length > 1) {
    throw new Error('Encrypting with multiple recipents is not implemented');
  }
};

exports.read = function (data, key, externalAAD) {
  externalAAD = externalAAD || EMPTY_BUFFER;
  return cbor.decodeFirst(data)
  .then((obj) => {
    if (obj instanceof Tagged) {
      // TODO verify tag
      obj = obj.value;
    }

    if (!Array.isArray(obj)) {
      throw new Error('Expecting Array');
    }

    if (obj.length !== 4) {
      throw new Error('Expecting Array of lenght 4');
    }

    let [p, u, ciphertext] = obj;
    p = cbor.decodeFirstSync(p);
    p = (!p.size) ? EMPTY_BUFFER : p;
    u = (!u.size) ? EMPTY_BUFFER : u;

    let alg = p.get(common.HeaderParameters.alg);
    alg = COSEAlgToNodeAlg[TagToAlg[alg]];

    const iv = u.get(common.HeaderParameters.IV);
    const tag = ciphertext.slice(ciphertext.length - 16, ciphertext.length);
    ciphertext = ciphertext.slice(0, ciphertext.length - 16);
    const decipher = crypto.createDecipheriv(alg, key, iv);
    decipher.setAuthTag(tag);
    const aad = createAAD(p, 'Encrypt', externalAAD);
    decipher.setAAD(aad);

    const dec = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return dec;
  });
};

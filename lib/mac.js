/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const aesCbcMac = require('aes-cbc-mac');
const crypto = require('crypto');
const common = require('./common');
const Tagged = cbor.Tagged;
const EMPTY_BUFFER = common.EMPTY_BUFFER;

const MAC0Tag = exports.MAC0Tag = 17;
const MACTag = exports.MACTag = 97;

const COSEAlgToNodeAlg = {
  'SHA-256_64': 'sha256',
  'SHA-256': 'sha256',
  HS256: 'sha256',
  'SHA-384': 'sha384',
  'SHA-512': 'sha512',
  'AES-MAC-128/64': 'aes-cbc-mac-64',
  'AES-MAC-128/128': 'aes-cbc-mac-128',
  'AES-MAC-256/64': 'aes-cbc-mac-64',
  'AES-MAC-256/128': 'aes-cbc-mac-128'
};

const CutTo = {
  4: 8,
  5: 32,
  6: 48,
  7: 64
};

const context = {};
context[MAC0Tag] = 'MAC0';
context[MACTag] = 'MAC';

function doMac (context, p, externalAAD, payload, alg, key) {
  const MACstructure = [
    context, // 'MAC0' or 'MAC1', // context
    p, // protected
    externalAAD, // bstr,
    payload // bstr
  ];

  const toBeMACed = cbor.encode(MACstructure);
  if (alg === 'aes-cbc-mac-64') {
    return aesCbcMac.create(key, toBeMACed, 8);
  } else if (alg === 'aes-cbc-mac-128') {
    return aesCbcMac.create(key, toBeMACed, 16);
  } else {
    const hmac = crypto.createHmac(alg, key);
    hmac.update(toBeMACed);
    return hmac.digest();
  }
}

exports.create = async function (headers, payload, recipents, externalAAD, options) {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);

  const alg = common.getAlgorithm(p, u);

  if (!alg) {
    throw new Error('Missing mandatory parameter \'alg\'');
  }

  if (recipents.length === 0) {
    throw new Error('There has to be at least one recipent');
  }

  const predictableP = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
  p = common.encodeProtected(p, options);
  // TODO check crit headers
  if (Array.isArray(recipents)) {
    if (recipents.length > 1) {
      throw new Error('MACing with multiple recipents is not implemented');
    }
    const recipent = recipents[0];
    let tag = doMac('MAC', predictableP, externalAAD, payload, COSEAlgToNodeAlg[common.TagsToAlg[alg]], recipent.key);
    tag = tag.slice(0, CutTo[alg]);
    const ru = common.TranslateHeaders(recipent.u);
    const rp = EMPTY_BUFFER;
    const maced = [p, u, payload, tag, [[rp, ru, EMPTY_BUFFER]]];
    return cbor.encode(options.excludetag ? maced : new Tagged(MACTag, maced));
  } else {
    let tag = doMac('MAC0', predictableP, externalAAD, payload, COSEAlgToNodeAlg[common.TagsToAlg[alg]], recipents.key);
    tag = tag.slice(0, CutTo[alg]);
    const maced = [p, u, payload, tag];
    return cbor.encode(options.excludetag ? maced : new Tagged(MAC0Tag, maced));
  }
};

exports.read = async function (data, key, externalAAD, options) {
  options = options || {};
  externalAAD = externalAAD || EMPTY_BUFFER;

  let obj = await cbor.decodeFirst(data);

  const validated = common.validateMessage(obj, [MAC0Tag, MACTag]);
  const type = validated.type || (options.defaultType ? options.defaultType : MAC0Tag);
  obj = validated.value;

  if (type === MAC0Tag && obj.length !== 4) {
    throw new Error('Expecting Array of length 4');
  }
  if (type === MACTag && obj.length !== 5) {
    throw new Error('Expecting Array of length 5');
  }

  let [p, u, payload, tag] = obj;
  p = (!p.length) ? EMPTY_BUFFER : cbor.decode(p);
  p = (!p.size) ? EMPTY_BUFFER : p;
  u = (!u.size) ? EMPTY_BUFFER : u;

  // TODO validate protected header
  const alg = common.getAlgorithm(p, u);
  p = (!p.size) ? EMPTY_BUFFER : cbor.encode(p);
  if (!common.TagsToAlg[alg]) {
    throw new Error('Unknown algorithm, ' + alg);
  }
  if (!COSEAlgToNodeAlg[common.TagsToAlg[alg]]) {
    throw new Error('Unsupported algorithm, ' + common.TagsToAlg[alg]);
  }

  let calcTag = doMac(context[type], p, externalAAD, payload, COSEAlgToNodeAlg[common.TagsToAlg[alg]], key);
  calcTag = calcTag.slice(0, CutTo[alg]);
  if (!crypto.timingSafeEqual(tag, calcTag)) {
    throw new Error('Tag mismatch');
  }
  return payload;
};

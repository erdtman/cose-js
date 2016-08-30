/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const crypto = require('crypto');
const Promise = require('any-promise');
const common = require('./common');

const AlgTags = {
  // "SHA-256_64":4,
  // TODO implement truncation
  'SHA-256': 5,
  'SHA-384': 6,
  'SHA-512': 7
};

// TODO content type map?

function doMac (context, hProtected, externalAAD, payload, alg, key) {
  return new Promise((resolve, reject) => {
    const MACstructure = [
      context, // "MAC0", // context
      hProtected, // protected
      externalAAD, // bstr,
      payload // bstr
    ];
    const ToBeMaced = cbor.encode(MACstructure);

    const hmac = crypto.createHmac(alg, key);// TODO make algorithm dynamic
    hmac.end(ToBeMaced, function () {
      resolve(hmac.read());
    });
  });
}

exports.create = function (protIn, unprotected, payload, key, externalAAD) {
  externalAAD = externalAAD || null; // TODO default to zero length binary string
  const hProtected = common.TranslateHeaders(protIn);

  if (protIn.alg && AlgTags[protIn.alg]) {
    hProtected.set(common.HeaderParameters.alg, AlgTags[protIn.alg]);
  } else {
    // TODO return better error
    throw new Error('Alg is mandatory and must have a known value');
  }
  // TODO handle empty map -> convert to zero length bstr
  // TODO check crit headers
  return doMac('MAC0', hProtected, externalAAD, payload, 'sha256', key)
  .then((tag) => {
    return cbor.encode([hProtected, unprotected, payload, tag]);
  });
};

exports.read = function (data, key, externalAAD) {
  externalAAD = externalAAD || null;

  return cbor.decodeFirst(data)
  .then((obj) => {
    if (!Array.isArray(obj) || (obj.length < 4)) {
      throw new Error('Expecting Array of length 4');
    }
    const [hProtected, unprotected, payload, tag] = obj;
    unprotected; // prevent unused variable warning

    // TODO validate protected header
    return doMac('MAC0', hProtected, externalAAD, payload, 'sha256', key)
    .then((calcTag) => {
      if (tag.toString('hex') !== calcTag.toString('hex')) {
        throw new Error('Tag mismatch');
      }

      return payload;
    });
  });
};

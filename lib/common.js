/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const AlgToTags = {
  'ES256': -7,
  'direct': -6,
  'A128GCM': 1,
  'A192GCM': 2,
  'A256GCM': 3,
  'SHA-256_64': 4,
  'HS256/64': 4,
  'SHA-256': 5,
  'HS256': 5,
  'SHA-384': 6,
  'HS384': 6,
  'SHA-512': 7,
  'HS512': 7
};

const Translators = {
  'kid': (value) => {
    return Buffer.from(value, 'utf8');
  },
  'alg': (value) => {
    if (!(AlgToTags[value])) {
      throw new Error('Unknown \'alg\' parameter, ' + value);
    }
    return AlgToTags[value];
  }
};

const HeaderParameters = {
  'alg': 1,
  'crit': 2,
  'content_type': 3,
  'ctyp': 3, // one could question this but it makes testing easier
  'kid': 4,
  'IV': 5,
  'Partial_IV': 6,
  'counter_signature': 7
};

exports.EMPTY_BUFFER = Buffer.alloc(0);

exports.TranslateHeaders = function (header) {
  const result = new Map();
  for (const param in header) {
    if (!HeaderParameters[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    let value = header[param];
    if (Translators[param]) {
      value = Translators[param](header[param]);
    }
    result.set(HeaderParameters[param], value);
  }
  return result;
};

module.exports.xor = function (a, b) {
  const buffer = Buffer.alloc(Math.max(a.length, b.length));
  for (let i = 1; i <= buffer.length; ++i) {
    const av = (a.length - i) < 0 ? 0 : a[a.length - i];
    const bv = (b.length - i) < 0 ? 0 : b[b.length - i];
    buffer[buffer.length - i] = av ^ bv;
  }
  return buffer;
};

exports.HeaderParameters = HeaderParameters;

/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const AlgToTags = {
  'direct': -6,
  'A128GCM': 1,
  'A192GCM': 2,
  'A256GCM': 3,
  'SHA-256_64': 4,
  'SHA-256': 5,
  'HS256': 5,
  'SHA-384': 6,
  'SHA-512': 7
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
  'kid': 4,
  'IV': 5,
  'Partial_IV': 6,
  'counter_signature': 7
};

exports.EMPTY_BUFFER = new Buffer(0);

exports.TranslateHeaders = function (header) {
  const result = new Map();
  for (var param in header) {
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

exports.HeaderParameters = HeaderParameters;

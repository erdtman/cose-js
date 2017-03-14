/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const HeaderParameters = {
  'alg': 1,
  'crit': 2,
  'content_type': 3,
  'kid': 4,
  'IV': 5,
  'Partial_IV': 6,
  'counter_signature': 7
};

exports.TranslateHeaders = function (header) {
  const result = new Map();
  for (var param in header) {
    if (!HeaderParameters[param]) {
      throw new Error('Unknown parameter, \'' + param + '\'');
    }
    result.set(HeaderParameters[param], header[param]);
  }
  return result;
};

exports.HeaderParameters = HeaderParameters;

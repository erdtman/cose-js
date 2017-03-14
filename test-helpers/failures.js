/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');

exports.RemoveCBORTag = function (input, value) {
  input = cbor.decode(input);
  return cbor.encode(input.value);
};

exports.ChangeProtected = function (input, value) {
  input = cbor.decode(input);
  input.value[0] = new Buffer(value, 'hex');
  return cbor.encode(input);
};

/*jshint esversion: 6 */
/*jslint node: true */
'use strict';

let cbor = require('cbor');

let cose = require('./index.js').cose;

let COSE_Mac = cose.COSE_Mac;
let COSE_Sign = cose.COSE_Sign;


var hProtected = {
  "alg": "SHA-256",
  "content_type": 5,
};
var external_aad = null;
var key = "secret"
var payload = cbor.encode({"hello": "world"});
var hUnprotected = {};

COSE_Mac.create(hProtected, hUnprotected, payload, key, external_aad).then(function(cose_mac){
  console.log(cose_mac.toString('hex'));
  return COSE_Mac.read(cose_mac, key, external_aad)
}).then(function(data) {
  cbor.decodeFirst(data, function(error, obj) {
      console.log(obj);
  });
}).fail(function(error) {
  console.log(error);
});

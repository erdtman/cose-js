/*jshint esversion: 6 */
/*jslint node: true */
'use strict';

let cbor = require('cbor');

let node_webcrypto_ossl = require('node-webcrypto-ossl');
console.log(node_webcrypto_ossl)
let crypto = new node_webcrypto_ossl();
let cose = require('./index.js');

let COSE_Mac = cose.COSE_Mac;
let COSE_Sign = cose.COSE_Sign;
let COSE_Common = cose.COSE_Common;

function mac() {
  console.log("=== Testing mac ===");
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
}
//mac();





function sign(){
  console.log("=== Testing sing ===");
  var data = "hello world";
  var data = new Uint8Array(4);
  data[0] = 42;
  data[1] = 43;
  data[2] = 44;

  var publicKey = "tmp";
  crypto.subtle.generateKey({
    name: "ECDSA",
    namedCurve: "P-256"},
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //can be any combination of "sign" and "verify"
  ).then(function(key) {
    console.log("keys generated");
      //returns a keypair object
      publicKey = key.publicKey
      var payload = cbor.encode({"hello": "world"});
    return COSE_Sign.create({
      prot:{
        "content_type": 5,
        "alg": 4},
      unprot:{}},
      payload,
      key)

  }).then(function(signed) {
    console.log("signed");
    console.log(signed.toString('hex'));
    cbor.decodeFirst(signed, function(error, obj) {
      console.log(obj);
    });
  }).catch(function(err){
    console.error(err);
  });
}
sign();

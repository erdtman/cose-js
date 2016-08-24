/*jshint esversion: 6 */
/*jslint node: true */
'use strict';

let cbor = require('cbor');
let Q = require('q');
let node_webcrypto_ossl = require('node-webcrypto-ossl');
let crypto = new node_webcrypto_ossl();

let header_parameters = require('./COSE_Common.js').header_parameters;
let translate_headers = require('./COSE_Common.js').translate_headers;


function toArrayBuffer(buf) {
    var ab = new ArrayBuffer(buf.length);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
        view[i] = buf[i];
    }
    return ab;
}

function toBuffer(ab) {
    var buf = new Buffer(ab.byteLength);
    var view = new Uint8Array(ab);
    for (var i = 0; i < buf.length; ++i) {
        buf[i] = view[i];
    }
    return buf;
}


exports.create = function(Headers, payload, key, external_aad) {
  let deferred = Q.defer();
  let protHeader = translate_headers(Headers.prot);
  let cborProtHeader = cbor.encode(protHeader); // TODO handle empty header?
  let Sig_structure = [
       "Signature1",
       cborProtHeader,
       external_aad,
       payload
   ];

   let ToBeSigned = toArrayBuffer(cbor.encode(Sig_structure));

   // TODO read alg and act on it
   console.log(ToBeSigned.byteLength);
   crypto.subtle.sign({
     name: "ECDSA",
     hash: {name: "SHA-256"}},
     key.privateKey,
     ToBeSigned).then(function(signature) {
       console.log(signature.byteLength);
       let COSE_Sign1 = cbor.encode([
          cborProtHeader,
          Headers.unprot,
          payload,
          toBuffer(signature)
       ]);
       deferred.resolve(COSE_Sign1);
     }).catch(function(err){
       console.log(err);
       deferred.reject(err);
     });
  return deferred.promise;
}

/*
return crypto.subtle.verify({
  name: "ECDSA",
  hash: {name: "SHA-256"}},
  publicKey, //from generateKey or importKey above
  signature, //ArrayBuffer of the signature
  data) //ArrayBuffer of the data
  */

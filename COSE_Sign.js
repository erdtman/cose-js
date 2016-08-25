/*jshint esversion: 6 */
/*jslint node: true */
'use strict';

const cbor = require('cbor');
const node_webcrypto_ossl = require('node-webcrypto-ossl');
const crypto = new node_webcrypto_ossl();

const header_parameters = require('./COSE_Common.js').header_parameters;
const translate_headers = require('./COSE_Common.js').translate_headers;


function toArrayBuffer(buf) {
    let ab = new ArrayBuffer(buf.length);
    let view = new Uint8Array(ab);
    for (let i = 0; i < buf.length; ++i) {
        view[i] = buf[i];
    }
    return ab;
}

function toBuffer(ab) {
    let buf = new Buffer(ab.byteLength);
    let view = new Uint8Array(ab);
    for (let i = 0; i < buf.length; ++i) {
        buf[i] = view[i];
    }
    return buf;
}


exports.create = function(Headers, payload, key, external_aad) {
  const protHeader = translate_headers(Headers.prot);
  const cborProtHeader = cbor.encode(protHeader); // TODO handle empty header?
  const Sig_structure = [
      "Signature1",
      cborProtHeader,
      external_aad,
      payload
  ];

  const ToBeSigned = toArrayBuffer(cbor.encode(Sig_structure));

  // TODO read alg and act on it
  return crypto.subtle.sign({
      name: "ECDSA",
      hash: {name: "SHA-256"}
    },
    key.privateKey,
    ToBeSigned)
  .then((signature) => {
      return cbor.encode([
          cborProtHeader,
          Headers.unprot,
          payload,
          toBuffer(signature)
      ]);
    });
}

/*
return crypto.subtle.verify({
  name: "ECDSA",
  hash: {name: "SHA-256"}},
  publicKey, //from generateKey or importKey above
  signature, //ArrayBuffer of the signature
  data) //ArrayBuffer of the data
  */

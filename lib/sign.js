/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const WebCrypto = require('node-webcrypto-ossl');
const crypto = new WebCrypto();
const common = require('./common');

function toArrayBuffer (buf) {
  return Uint8Array.from(buf).buffer;
}

function toBuffer (ab) {
  return Buffer.from(ab);
}

exports.create = function (Headers, payload, key, externalAAD) {
  const protHeader = common.TranslateHeaders(Headers.prot);
  const cborProtHeader = cbor.encode(protHeader); // TODO handle empty header?
  const SigStructure = [
    'Signature1',
    cborProtHeader,
    externalAAD,
    payload
  ];

  const ToBeSigned = toArrayBuffer(cbor.encode(SigStructure));

  // TODO read alg and act on it
  return crypto.subtle.sign({
    name: 'ECDSA',
    hash: {name: 'SHA-256'}
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
};

/*
return crypto.subtle.verify({
  name: "ECDSA",
  hash: {name: "SHA-256"}},
  publicKey, //from generateKey or importKey above
  signature, //ArrayBuffer of the signature
  data) //ArrayBuffer of the data
  */

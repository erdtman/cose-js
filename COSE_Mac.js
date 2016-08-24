/*jshint esversion: 6 */
/*jslint node: true */
'use strict';

const cbor = require('cbor');
const crypto = require('crypto');
const Promise = require('any-promise');

const header_parameters = require('./COSE_Common.js').header_parameters;
let translate_headers = require('./COSE_Common.js').translate_headers;
const alg_tags = {
  //"SHA-256_64":4, // TODO implement truncation
  "SHA-256":5,
  "SHA-384":6,
  "SHA-512":7
}

// TODO content type map?

function doMac(context, hProtected, external_aad, payload, alg, key) {
  return new Promise((res, rej) => {
    const MAC_structure = [
            context, //"MAC0", // context
            hProtected, // protected
            external_aad, // bstr,
            payload]; //bstr

    const ToBeMaced = cbor.encode(MAC_structure)

    const hmac = crypto.createHmac(alg, key);// TODO make algorithm dynamic
    hmac.end(ToBeMaced, function () {
      res(hmac.read());
    });
  });
}

exports.create = function(prot_in, unprotected, payload, key, external_aad) {
  external_aad = external_aad || null; // TODO default to zero length binary string
  const hProtected = translate_headers(prot_in)

  if(prot_in.alg && alg_tags[prot_in.alg]) {
      hProtected.set(header_parameters.alg, alg_tags[prot_in.alg]);
  } else {
      // TODO return better error
      return rej(new Error("Alg is mandatory and must have a known value"));
  }
  // TODO handle empty map -> convert to zero length bstr
  // TODO check crit headers
  return doMac("MAC0", hProtected, external_aad, payload, "sha256", key)
  .then((tag) => {
    return cbor.encode([hProtected, unprotected, payload, tag]);
  });
}

exports.read = function(data, key, external_aad) {
  external_aad = external_aad || null;

  return cbor.decodeFirst(data)
  .then((obj) => {
    const hProtected = obj[0];
    const unprotected = obj[1];
    const payload = obj[2];
    const tag = obj[3];

    // TODO validate protected header
    return doMac("MAC0", hProtected, external_aad, payload, "sha256", key)
    .then((calc_tag) => {
      const encoded = cbor.encode([hProtected, unprotected, payload, tag]);

      if (tag.toString("hex") !== calc_tag.toString("hex")) {
        throw new Error("Tag mismatch");
      }

      return payload;
    });
  });
}

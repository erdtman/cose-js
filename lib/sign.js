/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cbor = require('cbor');
const EC = require('elliptic').ec;
const crypto = require('crypto');
const common = require('./common');
const Promise = require('any-promise');
const EMPTY_BUFFER = common.EMPTY_BUFFER;
const Tagged = cbor.Tagged;

const SignTag = 98;

function doSign (p, u, signer, payload) {
  return new Promise((resolve, reject) => {
    const externalAAD = signer.externalAAD || EMPTY_BUFFER;
    let signerP = signer.p || {};
    let signerU = signer.u || {};
    let bodyP = p || {};

    signerP = common.TranslateHeaders(signerP);
    signerU = common.TranslateHeaders(signerU);
    signerP = (signerP.size === 0) ? EMPTY_BUFFER : cbor.encode(signerP);
    bodyP = (bodyP.size === 0) ? EMPTY_BUFFER : cbor.encode(bodyP);

    const SigStructure = [
      'Signature',
      bodyP,
      signerP,
      externalAAD,
      payload
    ];

    const ec = new EC('p256'); // TODO read alg and act on it
    const key = ec.keyFromPrivate(signer.key.d);

    let ToBeSigned = cbor.encode(SigStructure);
    const hash = crypto.createHash('sha256'); // TODO read alg and act on it
    hash.update(ToBeSigned);
    ToBeSigned = hash.digest();
    const signature = key.sign(ToBeSigned);
    const sig = Buffer.concat([signature.r.toArrayLike(Buffer), signature.s.toArrayLike(Buffer)]);

    resolve([signerP, signerU, sig]);
  });
}

exports.create = function (headers, payload, signers, options) {
  options = options || {};
  let u = headers.u || {};
  let p = headers.p || {};

  p = common.TranslateHeaders(p);
  u = common.TranslateHeaders(u);

  if (signers.length === 0) {
    throw new Error('There has to be at least one signer');
  }

  if (signers.length > 1) {
    throw new Error('Only one signer is supported');
  }
  // TODO handle multiple signers

  return doSign(p, u, signers[0], payload).then((sig) => {
    if (p.size === 0 && options.encodep === 'empty') {
      p = EMPTY_BUFFER;
    } else {
      p = cbor.encode(p);
    }
    const signed = [p, u, payload, [sig]];
    if (options.excludetag) {
      return cbor.encode(signed);
    } else {
      return cbor.encode(new Tagged(SignTag, signed));
    }
  });
};

function doVerify (bodyP, u, signer, verifier, plaintext) {
  return new Promise((resolve, reject) => {
    const externalAAD = verifier.externalAAD || EMPTY_BUFFER;
    let [signerP, , sig] = signer;

    signerP = (!signerP.length) ? EMPTY_BUFFER : signerP;
    bodyP = (!bodyP.size) ? EMPTY_BUFFER : cbor.encode(bodyP);

    const SigStructure = [
      'Signature',
      bodyP,
      signerP,
      externalAAD,
      plaintext
    ];

    let msgHash = cbor.encode(SigStructure);
    const hash = crypto.createHash('sha256'); // TODO read alg and act on it
    hash.update(msgHash);
    msgHash = hash.digest();

    const pub = {'x': verifier.key.x, 'y': verifier.key.y};
    const ec = new EC('p256'); // TODO read alg and act on it
    const key = ec.keyFromPublic(pub);
    sig = {'r': sig.slice(0, sig.length / 2), 's': sig.slice(sig.length / 2)};
    if (key.verify(msgHash, sig)) {
      resolve(plaintext);
    } else {
      throw new Error('Signature missmatch');
    }
  });
}

exports.verify = function (payload, verifier, options) {
  options = options || {};
  return cbor.decodeFirst(payload)
  .then((obj) => {
    if (obj instanceof Tagged) {
      // TODO verify tag
      obj = obj.value;
    }

    if (!Array.isArray(obj)) {
      throw new Error('Expecting Array');
    }

    if (obj.length !== 4) {
      throw new Error('Expecting Array of lenght 4');
    }

    let [p, u, plaintext, signers] = obj;

    p = (!p.length) ? EMPTY_BUFFER : cbor.decodeFirstSync(p);
    u = (!u.size) ? EMPTY_BUFFER : u;

    let signer;
    for (let i = 0; i < signers.length; i++) {
      const kid = signers[i][1].get(common.HeaderParameters.kid); // TODO create constant for header locations
      if (kid.equals(Buffer.from(verifier.key.kid, 'utf8'))) {
        signer = signers[i];
        break;
      }
    }
    if (!signer) {
      throw new Error('Failed to find signer with kid' + verifier.key.kid);
    }

    return doVerify(p, u, signer, verifier, plaintext)
    .then((plaintext) => {
      return plaintext;
    });
  });
};

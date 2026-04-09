/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const crypto = require('crypto');
const cbor = require('cbor');
const EC = require('elliptic').ec;
const HKDF = require('node-hkdf-sync');
const common = require('./common');
const EMPTY_BUFFER = common.EMPTY_BUFFER;

const HKDFAlg = {
  'ECDH-ES': 'sha256',
  'ECDH-ES-512': 'sha512',
  'ECDH-SS': 'sha256',
  'ECDH-SS-512': 'sha512'
};

const nodeCRV = {
  'P-521': 'secp521r1',
  'P-256': 'prime256v1'
};

const ellipticCRV = {
  'P-256': 'p256',
  'P-521': 'p521'
};

const curveKeyLength = {
  'P-521': 66,
  'P-256': 32
};

const ecdhAlgorithms = ['ECDH-ES', 'ECDH-ES-512', 'ECDH-SS', 'ECDH-SS-512'];

exports.isECDH = function (alg) {
  return ecdhAlgorithms.indexOf(alg) !== -1;
};

function isEphemeral (alg) {
  return alg === 'ECDH-ES' || alg === 'ECDH-ES-512';
}

function createContext (rp, alg, keyLengthBits, partyUNonce) {
  return cbor.encode([
    alg,
    [null, (partyUNonce || null), null],
    [null, null, null],
    [keyLengthBits, rp]
  ]);
}

function validatePublicKey (crv, x, y) {
  const ec = new EC(ellipticCRV[crv]);
  const key = ec.keyFromPublic({ x: x, y: y });
  const validation = key.validate();
  if (!validation.result) {
    throw new Error('Invalid recipient public key');
  }
}

exports.deriveKey = function (recipient, contentAlg, contentKeyLength, randomSource) {
  const crv = recipient.key.crv;

  validatePublicKey(crv, recipient.key.x, recipient.key.y);

  const recipientECDH = crypto.createECDH(nodeCRV[crv]);
  const generated = crypto.createECDH(nodeCRV[crv]);
  recipientECDH.setPrivateKey(recipient.key.d);

  let pk;
  if (isEphemeral(recipient.p.alg)) {
    pk = randomSource(curveKeyLength[crv]);
    pk[0] = (crv !== 'P-521' || pk[0] === 1) ? pk[0] : 0;
  } else {
    pk = recipient.sender.d;
  }

  generated.setPrivateKey(pk);
  const senderPublicKey = generated.getPublicKey();

  const recipientPublicKey = Buffer.concat([
    Buffer.from('04', 'hex'),
    recipient.key.x,
    recipient.key.y
  ]);

  const generatedKey = common.TranslateKey({
    crv: crv,
    x: senderPublicKey.slice(1, curveKeyLength[crv] + 1),
    y: senderPublicKey.slice(curveKeyLength[crv] + 1),
    kty: 'EC2'
  });

  const rp = cbor.encode(common.TranslateHeaders(recipient.p));
  const ikm = generated.computeSecret(recipientPublicKey);

  let partyUNonce = null;
  if (!isEphemeral(recipient.p.alg)) {
    partyUNonce = randomSource(64);
  }

  const context = createContext(rp, contentAlg, contentKeyLength * 8, partyUNonce);
  const hkdf = new HKDF(HKDFAlg[recipient.p.alg], undefined, ikm);
  const key = hkdf.derive(context, contentKeyLength);

  let ru = recipient.u;
  if (isEphemeral(recipient.p.alg)) {
    ru.ephemeral_key = generatedKey;
  } else {
    ru.static_key = generatedKey;
  }
  ru.partyUNonce = partyUNonce;
  ru = common.TranslateHeaders(ru);

  const recipientStruct = [[rp, ru, EMPTY_BUFFER]];

  return { key: key, recipientStruct: recipientStruct };
};

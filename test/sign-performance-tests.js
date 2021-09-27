/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const base64url = require('base64url');
const cbor = require('cbor');
const jsonfile = require("jsonfile");

test('create and verify really huge payload', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/ecdsa-01.json');

  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const signers = [{
    'key': {
      'd': base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    'u': example.input.sign.signers[0].unprotected,
    'p': example.input.sign.signers[0].protected
  }];
  const plaintext = Buffer.from('a'.repeat(100 * 160));

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign.signers[0].key.x),
      'y': base64url.toBuffer(example.input.sign.signers[0].key.y),
      'kid': example.input.sign.signers[0].key.kid
    }
  };

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signers
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      return cbor.decodeFirst(buf)
        .then(actual => {
          t.is(actual.value[2].length, 100 * 160);
        })
        .then(() => buf);
    })
    .then(buf => cose.sign.verify(buf, verifier))
    .then(buf => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext.toString('utf8'));
    });
});

/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');

function randomSource (bytes) {
  if (bytes === 12) {
    return Buffer.from('02D1F7E6F26C43D4868D87CE', 'hex');
  } else {
    return Buffer.from('61A7', 'hex');
  }
}

test('create aes-gcm-01', t => {
  const example = jsonfile.readFileSync('test/Examples/encrypted-tests/aes-gcm-01.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    {p: p, u: u},
    plaintext,
    recipient,
    options)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('hex'), example.output.cbor.toLowerCase());
  });
});

test('create enc-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/encrypted-tests/enc-pass-01.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    {p: p, u: u},
    plaintext,
    recipient,
    options)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('hex'), example.output.cbor.toLowerCase());
  });
});

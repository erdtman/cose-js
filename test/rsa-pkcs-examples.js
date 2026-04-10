/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const jwkToPem = require('jwk-to-pem');
const cbor = require('cbor');
const { deepEqual, loadExample } = require('./util.js');

function hexToB64 (hex) {
  return Buffer.from(hex, 'hex').toString('base64');
}

test('create rsa-pkcs-01', async () => {
  const example = loadExample('test/rsa-pkcs-examples/rsa-pkcs-01.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const testKey = example.input.sign0.key;
  const signer = {
    key: jwkToPem({
      kty: testKey.kty,
      n: hexToB64(testKey.n_hex),
      e: hexToB64(testKey.e_hex),
      d: hexToB64(testKey.d_hex),
      p: hexToB64(testKey.p_hex),
      q: hexToB64(testKey.q_hex),
      dp: hexToB64(testKey.dP_hex),
      dq: hexToB64(testKey.dQ_hex),
      qi: hexToB64(testKey.qi_hex)
    }, { private: true })
  };
  const header = { p: p, u: u };
  const options = { excludetag: true };
  const buf = await cose.sign.create(header, plaintext, signer, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create rsa-pkcs-01 Sync', async () => {
  const example = loadExample('test/rsa-pkcs-examples/rsa-pkcs-01.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const testKey = example.input.sign0.key;
  const signer = {
    key: jwkToPem({
      kty: testKey.kty,
      n: hexToB64(testKey.n_hex),
      e: hexToB64(testKey.e_hex),
      d: hexToB64(testKey.d_hex),
      p: hexToB64(testKey.p_hex),
      q: hexToB64(testKey.q_hex),
      dp: hexToB64(testKey.dP_hex),
      dq: hexToB64(testKey.dQ_hex),
      qi: hexToB64(testKey.qi_hex)
    }, { private: true })
  };
  const header = { p: p, u: u };
  const options = { excludetag: true };
  const buf = await cose.sign.create(header, plaintext, signer, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify rsa-pkcs-01', async () => {
  const example = loadExample('test/rsa-pkcs-examples/rsa-pkcs-01.json');

  const testKey = example.input.sign0.key;

  const verifier = {
    key: jwkToPem({
      kty: testKey.kty,
      n: hexToB64(testKey.n_hex),
      e: hexToB64(testKey.e_hex)
    })
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const options = { defaultType: cose.sign.Sign1Tag };
  const buf = await cose.sign.verify(signature, verifier, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify rsa-pkcs-01 Sync', async () => {
  const example = loadExample('test/rsa-pkcs-examples/rsa-pkcs-01.json');

  const testKey = example.input.sign0.key;

  const verifier = {
    key: jwkToPem({
      kty: testKey.kty,
      n: hexToB64(testKey.n_hex),
      e: hexToB64(testKey.e_hex)
    })
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  const options = { defaultType: cose.sign.Sign1Tag };
  const buf = await cose.sign.verify(signature, verifier, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

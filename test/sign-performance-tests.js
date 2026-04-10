/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cbor = require('cbor');
const { loadExample, b64url } = require('./util.js');

test('create and verify really huge payload', async () => {
  // uses the keys from here but it has nothing to do with the test
  const example = loadExample('test/Examples/sign-tests/ecdsa-01.json');
  const BIG_LENGHT = 100 * 1000;
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const signers = [{
    key: {
      d: b64url(example.input.sign.signers[0].key.d)
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];
  const plaintext = Buffer.from('a'.repeat(BIG_LENGHT));

  const verifier = {
    key: {
      x: b64url(example.input.sign.signers[0].key.x),
      y: b64url(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const actual = await cbor.decodeFirst(buf);
  assert.strictEqual(actual.value[2].length, BIG_LENGHT);

  const verifiedBuf = await cose.sign.verify(buf, verifier);
  assert.ok(Buffer.isBuffer(verifiedBuf));
  assert.ok(verifiedBuf.length > 0);
  assert.strictEqual(verifiedBuf.toString('utf8'), plaintext.toString('utf8'));
});

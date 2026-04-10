/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cbor = require('cbor');
const { deepEqual, loadExample, b64url } = require('./util.js');

test('create HMac-01', async () => {
  const example = loadExample('test/Examples/mac0-tests/HMac-01.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p, u: u };
  const recipents = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify HMac-01', async () => {
  const example = loadExample('test/Examples/mac0-tests/HMac-01.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('create mac-pass-01', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-pass-01.json');

  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const header = { u: u };
  const recipents = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create mac-pass-02', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-pass-02.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const external = Buffer.from(example.input.mac0.external, 'hex');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = { encodep: 'empty' };

  const header = { p: p, u: u };
  const recipents = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipents, external, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create mac-pass-03', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-pass-03.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = { encodep: 'empty', excludetag: true };

  const recipents = { key: key };
  const header = { p: p, u: u };
  const external = null;
  const buf = await cose.mac.create(header, plaintext, recipents, external, options);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify mac-pass-01', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-pass-01.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify mac-pass-02', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-pass-02.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const external = Buffer.from(example.input.mac0.external, 'hex');

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key, external);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify mac-pass-03', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-pass-03.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify mac-fail-01', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-fail-01.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.mac.read(data, key), { message: 'Unexpected cbor tag, \'992\'' });
});

test('verify mac-fail-02', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-fail-02.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

test('verify mac-fail-03', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-fail-03.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.mac.read(data, key), { message: 'Unknown algorithm, -999' });
});

test('verify mac-fail-04', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-fail-04.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.mac.read(data, key), { message: 'Unknown algorithm, Unknown' });
});

test('verify mac-fail-06', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-fail-06.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

test('verify mac-fail-07', async () => {
  const example = loadExample('test/Examples/mac0-tests/mac-fail-07.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

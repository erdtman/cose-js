/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cbor = require('cbor');
const { deepEqual, loadExample, b64url } = require('./util.js');

test('create HMac-enc-01', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-01.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const header = { p: p, u: u };
  const recipeient = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipeient);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create HMac-enc-02', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-02.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const header = { p: p, u: u };
  const recipient = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipient);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create HMac-enc-03', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-03.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const header = { p: p, u: u };
  const recipient = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipient);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

// HMac-enc-04 is a negative test and cannot be recreated

test('create HMac-enc-05', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-05.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const header = { p: p, u: u };
  const recipeint = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipeint);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify HMac-enc-01', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-01.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify HMac-enc-02', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-02.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify HMac-enc-03', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-03.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify HMac-enc-04', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-04.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

test('verify HMac-enc-05', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-enc-05.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('create HMac-01', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-01.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const recipents = [{ key: key, u: u }];
  const header = { p: p };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create HMac-02', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-02.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const recipents = [{ key: key, u: u }];
  const header = { p: p };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create HMac-03', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-03.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const recipents = [{ key: key, u: u }];
  const header = { p: p };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

// HMac-04 is a negative test and cannot be recreated

test('create HMac-05', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-05.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const recipents = [{ key: key, u: u }];
  const header = { p: p };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify HMac-01', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-01.json');
  const key = b64url(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify HMac-02', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-02.json');
  const key = b64url(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify HMac-03', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-03.json');
  const key = b64url(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify HMac-04', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-04.json');
  const key = b64url(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

test('verify HMac-05', async () => {
  const example = loadExample('test/Examples/hmac-examples/HMac-05.json');
  const key = b64url(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

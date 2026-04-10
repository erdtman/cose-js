/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cbor = require('cbor');
const { deepEqual, loadExample, b64url } = require('./util.js');

test('create cbc-mac-01', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-01.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipents = [{ key: key, u: u }];
  const buf = await cose.mac.create(header, plaintext, recipents);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-02', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-02.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipents = [{ key: key, u: u }];
  const buf = await cose.mac.create(header, plaintext, recipents);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-03', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-03.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipents = [{ key: key, u: u }];
  const buf = await cose.mac.create(header, plaintext, recipents);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-04', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-04.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = b64url(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipents = [{ key: key, u: u }];
  const buf = await cose.mac.create(header, plaintext, recipents);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-enc-01', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-01.json');
  const p = example.input.mac0.protected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipents = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipents);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-enc-02', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-02.json');
  const p = example.input.mac0.protected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipent = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipent);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-enc-03', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-03.json');
  const p = example.input.mac0.protected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipent = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipent);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('create cbc-mac-enc-04', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-04.json');
  const p = example.input.mac0.protected;
  const key = b64url(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  const header = { p: p };
  const recipent = { key: key };
  const buf = await cose.mac.create(header, plaintext, recipent);

  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);

  assert.ok(deepEqual(actual, expected));
});

test('verify cbc-mac-01', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-01.json');
  const key = b64url(example.input.mac.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-02', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-02.json');
  const key = b64url(example.input.mac.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-03', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-03.json');
  const key = b64url(example.input.mac.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-04', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-04.json');
  const key = b64url(example.input.mac.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-enc-01', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-02.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-enc-02', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-02.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-enc-03', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-03.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify cbc-mac-enc-04', async () => {
  const example = loadExample('test/Examples/cbc-mac-examples/cbc-mac-enc-04.json');
  const key = b64url(example.input.mac0.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

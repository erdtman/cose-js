/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');
const deepEqual = require('./util.js').deepEqual;

test('create HMac-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/HMac-01.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
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
  const example = jsonfile.readFileSync('test/Examples/mac-tests/HMac-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('create mac-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-01.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.unprotected;
  const ru = example.input.mac.recipients[0].unprotected;
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const recipents = [{ key: key, u: ru }];
  const header = { p: p, u: u };
  const buf = await cose.mac.create(header, plaintext, recipents);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('hex'), example.output.cbor.toLowerCase());
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create mac-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-02.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.unprotected;
  const ru = example.input.mac.recipients[0].unprotected;
  const external = Buffer.from(example.input.mac.external, 'hex');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = { encodep: 'empty' };
  const header = { p: p, u: u };
  const recipents = [{ key: key, u: ru }];
  const buf = await cose.mac.create(header, plaintext, recipents, external, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create mac-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-03.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.unprotected;
  const ru = example.input.mac.recipients[0].unprotected;
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = { encodep: 'empty', excludetag: true };
  const header = { p: p, u: u };
  const recipents = [{ key: key, u: ru }];
  const external = null;
  const buf = await cose.mac.create(header, plaintext, recipents, external, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify mac-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify mac-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-02.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const external = Buffer.from(example.input.mac.external, 'hex');
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key, external);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify mac-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-03.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const options = { defaultType: cose.mac.MACTag };
  const external = null;
  const data = example.output.cbor;
  const buf = await cose.mac.read(data, key, external, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify mac-fail-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Expecting Array of lenght 4' });
});

test('verify mac-fail-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-02.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

test('verify mac-fail-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-03.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Unknown algorithm, -999' });
});

test('verify mac-fail-04', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-04.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Unknown algorithm, Unknown' });
});

test('verify mac-fail-06', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-06.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

test('verify mac-fail-07', async () => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-07.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.mac.read(data, key), { message: 'Tag mismatch' });
});

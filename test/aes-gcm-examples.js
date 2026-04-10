/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cbor = require('cbor');
const { deepEqual, loadExample, b64url } = require('./util.js');

function randomSource (bytes) {
  if (bytes === 12) {
    return Buffer.from('02D1F7E6F26C43D4868D87CE', 'hex');
  } else {
    return Buffer.from('61A7', 'hex');
  }
}

test('create aes-gcm-01', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-01.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: b64url(example.input.enveloped.recipients[0].key.k),
    u: example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipients, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create aes-gcm-02', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-02.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: b64url(example.input.enveloped.recipients[0].key.k),
    u: example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipients, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create aes-gcm-03', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-03.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: b64url(example.input.enveloped.recipients[0].key.k),
    u: example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipients, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

// aes-gcm-04 is an error example and cannot be recreated

test('create aes-gcm-05', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-05.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: b64url(example.input.enveloped.recipients[0].key.k),
    u: example.input.enveloped.recipients[0].unprotected
  }];

  example.input.enveloped.unprotected.Partial_IV = Buffer.from(example.input.enveloped.unprotected.partialIV_hex, 'hex');
  delete example.input.enveloped.unprotected.partialIV_hex;

  const contextIv = Buffer.from(example.input.enveloped.unsent.IV_hex, 'hex');
  contextIv[10] = 0;
  contextIv[11] = 0;

  const options = {
    randomSource: randomSource,
    contextIv: contextIv
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipients, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('decrypt aes-gcm-01', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-01.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt aes-gcm-02', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-02.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt aes-gcm-03', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-03.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt aes-gcm-04', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-04.json');
  const key = b64url(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unsupported state or unable to authenticate data' });
});

test('decrypt aes-gcm-05', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-05.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  const contextIv = Buffer.from(example.input.enveloped.unsent.IV_hex, 'hex');
  contextIv[10] = 0;
  contextIv[11] = 0;
  const options = { contextIv: contextIv };
  const buf = await cose.encrypt.read(data, key, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('create aes-gcm-enc-01', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-01.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    key: b64url(example.input.encrypted.recipients[0].key.k),
    u: example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipient, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create aes-gcm-enc-02', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-02.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    key: b64url(example.input.encrypted.recipients[0].key.k),
    u: example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipient, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create aes-gcm-enc-03', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-03.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    key: b64url(example.input.encrypted.recipients[0].key.k),
    u: example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    randomSource: randomSource
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipient, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

// create aes-gcm-enc-04 is an error example and cannot be recreated

test('decrypt aes-gcm-enc-01', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-01.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.encrypted.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt aes-gcm-enc-02', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-02.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.encrypted.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt aes-gcm-enc-03', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-03.json');
  const plaintext = example.input.plaintext;
  const key = b64url(example.input.encrypted.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt aes-gcm-enc-04', async () => {
  const example = loadExample('test/Examples/aes-gcm-examples/aes-gcm-enc-04.json');
  const key = b64url(example.input.encrypted.recipients[0].key.k);
  const data = example.output.cbor;
  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unsupported state or unable to authenticate data' });
});

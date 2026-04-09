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

function randomSource (bytes) {
  if (bytes === 12) {
    return Buffer.from('02D1F7E6F26C43D4868D87CE', 'hex');
  } else {
    return Buffer.from('61A7', 'hex');
  }
}

test('create aes-gcm-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/aes-gcm-01.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
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

test('create env-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-01.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
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

test('create env-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-02.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    u: example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    randomSource: randomSource,
    externalAAD: Buffer.from(example.input.enveloped.external, 'hex')
  };
  const header = { p: p, u: u };
  const buf = await cose.encrypt.create(header, plaintext, recipients, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create env-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-03.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    key: base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    u: example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    randomSource: randomSource,
    excludetag: true,
    encodep: 'empty'
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
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/aes-gcm-01.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt enc-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-01.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt enc-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-02.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const options = {
    externalAAD: Buffer.from(example.input.enveloped.external, 'hex')
  };
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt enc-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-03.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;
  const buf = await cose.encrypt.read(data, key);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), plaintext);
});

test('decrypt enc-fail-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-01.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unexpected cbor tag, \'995\'' });
});

test('decrypt enc-fail-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-02.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unsupported state or unable to authenticate data' });
});

test('decrypt enc-fail-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-03.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unknown or unsupported algorithm -999' });
});

test('decrypt enc-fail-04', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-04.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unknown or unsupported algorithm Unknown' });
});

test('decrypt enc-fail-06', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-06.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unsupported state or unable to authenticate data' });
});

test('decrypt enc-fail-07', async () => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-07.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const data = example.output.cbor;

  await assert.rejects(() => cose.encrypt.read(data, key), { message: 'Unsupported state or unable to authenticate data' });
});

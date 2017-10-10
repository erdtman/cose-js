/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');

test('create HMac-enc-01', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-01.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('create HMac-enc-02', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-02.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('create HMac-enc-03', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-03.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

// TODO create HMac-enc-04

test('create HMac-enc-05', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-05.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    {'p': p, 'u': u},
    plaintext,
    [{'key': key}])
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);

    const actual = cbor.decode(buf).value;
    const expected = cbor.decode(example.output.cbor).value;

    const expectedP = (expected[0].length === 0) ? {} : cbor.decode(expected[0]);
    const actualP = (actual[0].length === 0) ? {} : cbor.decode(actual[0]);

    t.deepEqual(expectedP[0], actualP[0], 'protected header missmatch');
    t.deepEqual(expected[1], actual[1], 'unprotected header missmatch');
    t.is(expected[2].toString('hex'), actual[2].toString('hex'), 'payload missmatch');
    t.is(expected[3].toString('hex'), actual[3].toString('hex'), 'tag header missmatch');
  });
});

test('verify HMac-enc-01', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-enc-02', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-02.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-enc-03', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-03.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

// TODO verify HMac-enc-04

test('verify HMac-enc-05', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-enc-05.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

// TODO create HMac-01
// TODO create HMac-02
// TODO create HMac-03
// TODO create HMac-04
// TODO create HMac-05

test('verify HMac-01', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-02', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-02.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-03', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-03.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

test('verify HMac-04', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-04.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(false);
  }).catch((error) => {
    t.is(error.message, 'Tag mismatch');
  });
});

test('verify HMac-05', t => {
  const example = jsonfile.readFileSync('test/Examples/hmac-examples/HMac-05.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    t.is(buf.toString('utf8'), example.input.plaintext);
  });
});

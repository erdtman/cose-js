/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');
const deepEqual = require('./util.js').deepEqual;

test('create HMac-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/HMac-01.json');
  const p = example.input.mac0.protected;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    { 'p': p, 'u': u },
    plaintext,
    { 'key': key })
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('verify HMac-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/HMac-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('create mac-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-01.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  return cose.mac.create(
    { 'p': p, 'u': u },
    plaintext,
    { 'key': key })
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create mac-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-02.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const external = Buffer.from(example.input.mac0.external, 'hex');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = { 'encodep': 'empty' };

  return cose.mac.create(
    { 'p': p, 'u': u },
    plaintext,
    { 'key': key },
    external,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create mac-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-03.json');
  const p = undefined;
  const u = example.input.mac0.unprotected;
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = {
    'encodep': 'empty',
    'excludetag': true
  };

  return cose.mac.create(
    { 'p': p, 'u': u },
    plaintext,
    { 'key': key },
    null,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('verify mac-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify mac-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-02.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);
  const external = Buffer.from(example.input.mac0.external, 'hex');

  return cose.mac.read(example.output.cbor,
    key,
    external)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify mac-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-pass-03.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify mac-fail-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-01.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unexpected cbor tag, \'992\'');
    });
});

test('verify mac-fail-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-02.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Tag mismatch');
    });
});

test('verify mac-fail-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-03.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, -999');
    });
});

test('verify mac-fail-04', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-04.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, Unknown');
    });
});

test('verify mac-fail-06', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-06.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Tag mismatch');
    });
});

test('verify mac-fail-07', t => {
  const example = jsonfile.readFileSync('test/Examples/mac0-tests/mac-fail-07.json');
  const key = base64url.toBuffer(example.input.mac0.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Tag mismatch');
    });
});

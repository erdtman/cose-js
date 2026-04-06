/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const { test } = require('node:test');
const assert = require('node:assert/strict');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');
const { deepEqual } = require('./util.js');

test('create sign-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = {
    key: {
      d: base64url.toBuffer(example.input.sign0.key.d)
    }
  };

  const header = { u: u };
  const buf = await cose.sign.create(header, plaintext, signer);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create sign-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = {
    key: {
      d: base64url.toBuffer(example.input.sign0.key.d)
    },
    externalAAD: Buffer.from(example.input.sign0.external, 'hex')
  };

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signer);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create sign-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = {
    key: {
      d: base64url.toBuffer(example.input.sign0.key.d)
    }
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

test('verify sign-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    },
    externalAAD: Buffer.from(example.input.sign0.external, 'hex')
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const options = { defaultType: cose.sign.Sign1Tag };
  const buf = await cose.sign.verify(signature, verifier, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-fail-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Unexpected cbor tag, \'998\'' });
});

test('verify sign-fail-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-02.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Signature missmatch' });
});

test('verify sign-fail-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-03.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Unknown algorithm, -999' });
});

test('verify sign-fail-04', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-04.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Unknown algorithm, unknown' });
});

test('verify sign-fail-06', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-06.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Signature missmatch' });
});

test('verify sign-fail-07', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-07.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Signature missmatch' });
});

/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');
const deepEqual = require('./util.js').deepEqual;

test('create sign-pass-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = {
    'key': {
      'd': base64url.toBuffer(example.input.sign0.key.d)
    }
  };

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signer
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create sign-pass-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = {
    'key': {
      'd': base64url.toBuffer(example.input.sign0.key.d)
    },
    'externalAAD': Buffer.from(example.input.sign0.external, 'hex')
  };

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signer
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create sign-pass-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = {
    'key': {
      'd': base64url.toBuffer(example.input.sign0.key.d)
    }
  };

  return cose.sign.create(
    { 'p': p, 'u': u },
    plaintext,
    signer,
    {
      'excludetag': true
    }
  )
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('verify sign-pass-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify sign-pass-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    },
    'externalAAD': Buffer.from(example.input.sign0.external, 'hex')
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify sign-pass-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier,
    {
      'defaultType': cose.sign.Sign1Tag
    })
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify sign-fail-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-01.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unexpected cbor tag, \'998\'');
    });
});

test('verify sign-fail-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-02.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature missmatch');
    });
});

test('verify sign-fail-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-03.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, -999');
    });
});

test('verify sign-fail-04', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-04.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, unknown');
    });
});

test('verify sign-fail-06', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-06.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature missmatch');
    });
});

test('verify sign-fail-07', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-07.json');

  const verifier = {
    'key': {
      'x': base64url.toBuffer(example.input.sign0.key.x),
      'y': base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature missmatch');
    });
});

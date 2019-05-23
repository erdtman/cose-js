/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
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

test('create aes-gcm-01', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/aes-gcm-01.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipients,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create env-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-01.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipients,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create env-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-02.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource,
    'externalAAD': Buffer.from(example.input.enveloped.external, 'hex')
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipients,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create env-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-03.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipients = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource,
    'excludetag': true,
    'encodep': 'empty'
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipients,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('decrypt aes-gcm-01', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/aes-gcm-01.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt enc-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-01.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt enc-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-02.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);
  const options = {
    'externalAAD': Buffer.from(example.input.enveloped.external, 'hex')
  };
  return cose.encrypt.read(example.output.cbor,
    key,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt enc-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-pass-03.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt enc-fail-01', te => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-01.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      te.true(false);
    }).catch((error) => {
      te.is(error.message, 'Unknown tag, 995');
    });
});

test('decrypt enc-fail-02', te => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-02.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      te.true(false);
    }).catch((error) => {
      te.is(error.message, 'Unsupported state or unable to authenticate data');
    });
});

test('decrypt enc-fail-03', te => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-03.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      te.true(false);
    }).catch((error) => {
      te.is(error.message, 'Unknown or unsupported algorithm -999');
    });
});

test('decrypt enc-fail-04', te => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-04.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      te.true(false);
    }).catch((error) => {
      te.is(error.message, 'Unknown or unsupported algorithm Unknown');
    });
});

test('decrypt enc-fail-06', te => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-06.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      te.true(false);
    }).catch((error) => {
      te.is(error.message, 'Unsupported state or unable to authenticate data');
    });
});

test('decrypt enc-fail-07', te => {
  const example = jsonfile.readFileSync('test/Examples/enveloped-tests/env-fail-07.json');
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      te.true(false);
    }).catch((error) => {
      te.is(error.message, 'Unsupported state or unable to authenticate data');
    });
});

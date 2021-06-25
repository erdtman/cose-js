import * as cose from '../lib/index';
import test from 'ava';
import jsonfile from 'jsonfile';
import base64url from 'base64url';
import * as cbor from 'cbor-web';
import { bufferEqual, deepEqual } from './util';

test('create HMac-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/HMac-01.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.recipients[0].unprotected;
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);

  return cose.mac.create(
    { p: p },
    plaintext,
    [{
      key: key,
      u: u
    }])
    .then((buf) => {
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('verify HMac-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/HMac-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('create mac-pass-01', async t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-01.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.unprotected;
  const ru = example.input.mac.recipients[0].unprotected;
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = new TextEncoder().encode(example.input.plaintext);
  const buf = await cose.mac.create({ p, u }, plaintext, [{ key, u: ru }]);
  const read_back = await cose.mac.read(buf, key);
  bufferEqual(t, read_back, plaintext);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  bufferEqual(t, actual.value[2], expected.value[2]);
});

test('create mac-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-02.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.unprotected;
  const ru = example.input.mac.recipients[0].unprotected;
  const external = Buffer.from(example.input.mac.external, 'hex');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = {
    encodep: 'empty'
  };
  return cose.mac.create(
    { p: p, u: u },
    plaintext,
    [{
      key: key,
      u: ru
    }],
    external, options)
    .then((buf) => {
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create mac-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-03.json');
  const p = example.input.mac.protected;
  const u = example.input.mac.unprotected;
  const ru = example.input.mac.recipients[0].unprotected;
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const plaintext = Buffer.from(example.input.plaintext);
  const options = {
    encodep: 'empty',
    excludetag: true
  };
  return cose.mac.create(
    { p: p, u: u },
    plaintext,
    [{
      key: key,
      u: ru
    }], null, options)
    .then((buf) => {
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('verify mac-pass-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify mac-pass-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-02.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const external = Buffer.from(example.input.mac.external, 'hex');

  return cose.mac.read(example.output.cbor,
    key,
    external)
    .then((buf) => {
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify mac-pass-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-pass-03.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);
  const options = { defaultType: cose.mac.MACTag };

  return cose.mac.read(example.output.cbor,
    key,
    undefined,
    options)
    .then((buf) => {
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
});

test('verify mac-fail-01', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-01.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Expecting Array of lenght 4');
    });
});

test('verify mac-fail-02', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-02.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Tag mismatch');
    });
});

test('verify mac-fail-03', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-03.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, -999');
    });
});

test('verify mac-fail-04', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-04.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unknown algorithm, Unknown');
    });
});

test('verify mac-fail-06', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-06.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Tag mismatch');
    });
});

test('verify mac-fail-07', t => {
  const example = jsonfile.readFileSync('test/Examples/mac-tests/mac-fail-07.json');
  const key = base64url.toBuffer(example.input.mac.recipients[0].key.k);

  return cose.mac.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Tag mismatch');
    });
});

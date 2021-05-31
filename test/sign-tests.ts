import * as cose from '../lib/index';
import test from 'ava';
import { readSigningTestData } from './util'

test('create ecdsa-01', async (t) => {
  const { verifier, plaintext, headers, signers } = await readSigningTestData('test/Examples/sign-tests/ecdsa-01.json');
  const buf = await cose.sign.create(headers, plaintext, signers);
  const decoded = await cose.sign.verify(buf, verifier);
  t.deepEqual(decoded, plaintext);
});

test('verify ecdsa-01', async (t) => {
  const { verifier, signature, plaintext } = await readSigningTestData('test/Examples/sign-tests/ecdsa-01.json');
  const buf = await cose.sign.verify(signature, verifier);
  t.deepEqual(buf, plaintext);
});


for (const i of [1, 2, 3]) {
  test(`create sign-pass-0${i}`, async (t) => {
    const { verifier, plaintext, headers, signers } = await readSigningTestData(`test/Examples/sign-tests/sign-pass-0${i}.json`);
    const buf = await cose.sign.create(headers, plaintext, signers);
    const decoded = await cose.sign.verify(buf, verifier);
    t.deepEqual(decoded, plaintext);
  });

  test(`verify sign-pass-0${i}`, async (t) => {
    const { verifier, signature, plaintext } = await readSigningTestData(`test/Examples/sign-tests/sign-pass-0${i}.json`);
    const buf = await cose.sign.verify(signature, verifier);
    t.deepEqual(buf, plaintext);
  });
}


test('verify sign-fail-01', async (t) => {
  const { verifier, signature } = await readSigningTestData('test/Examples/sign-tests/sign-fail-01.json');
  await t.throwsAsync(cose.sign.verify(signature, verifier), { message: 'Unexpected cbor tag, \'998\'' });
});


test('verify sign-fail-02', async (t) => {
  const { verifier, signature } = await readSigningTestData('test/Examples/sign-tests/sign-fail-02.json');
  await t.throwsAsync(cose.sign.verify(signature, verifier), { message: 'Signature mismatch' });
});

// TODO: ADAPT ALL TESTS
/*
test('verify sign-fail-03', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-03.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
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
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-04.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
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
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-06.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature mismatch');
    });
});

test('verify sign-fail-07', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-07.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier)
    .then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Signature mismatch');
    });
});
*/
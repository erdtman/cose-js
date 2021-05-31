import * as cose from '../lib/index';
import test from 'ava';
import jsonfile from 'jsonfile';
import base64url from 'base64url';
import cbor from 'cbor';
import { deepEqual } from './util';
import webcrypto from 'isomorphic-webcrypto';

test('create ecdsa-01', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/ecdsa-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signer = example.input.sign.signers[0];
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["sign"]);
  const signers = [{
    key,
    u: signer.unprotected,
    p: signer.protected
  }];
  const buf = await cose.sign.create(
    { p: p, u: u },
    plaintext,
    signers
  );
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  t.true(deepEqual(actual, expected));
});

test('verify ecdsa-01', async (t) => {
  const { verifier, signature, plaintext } = await readTestData('test/Examples/sign-tests/ecdsa-01.json');
  const buf = await cose.sign.verify(signature, verifier);
  t.deepEqual(buf, new TextEncoder().encode(plaintext));
});

test('create sign-pass-01', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signer = example.input.sign.signers[0];
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["sign"]);
  const signers = [{
    key,
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];
  const buf = await cose.sign.create(
    { p: p, u: u },
    plaintext,
    signers
  )
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  t.true(deepEqual(actual, expected));
});

test('create sign-pass-02', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-02.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = example.input.sign.signers[0];
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["sign"]);

  const signers = [{
    key,
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected,
    externalAAD: Buffer.from(example.input.sign.signers[0].external, 'hex')
  }];
  const buf = await cose.sign.create(
    { p: p, u: u },
    plaintext,
    signers,
    { encodep: 'empty' }
  )
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  t.true(deepEqual(actual, expected));
});

test('create sign-pass-03', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-03.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signer = example.input.sign.signers[0];
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["sign"]);

  const signers = [{
    key,
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];

  const buf = await cose.sign.create(
    { p, u },
    plaintext,
    signers,
    {
      encodep: 'empty', excludetag: true
    }
  )
  t.true(Buffer.isBuffer(buf));
  t.true(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  t.true(deepEqual(actual, expected));
});

async function readTestData(f: string) {
  const example = jsonfile.readFileSync(f);
  const signer = example.input.sign.signers[0];
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["verify"]);
  const externalAAD = signer.external && Buffer.from(signer.external, 'hex');
  const verifier = { key, kid: signer.key.kid, externalAAD };
  const signature = Buffer.from(example.output.cbor, 'hex');
  const plaintext = example.input.plaintext;
  return { verifier, signature, plaintext };
}

for (const i in [1, 2, 3]) {
  test(`verify sign-pass-0${i}`, async (t) => {
    const { verifier, signature, plaintext } = await readTestData(`test/Examples/sign-tests/sign-pass-0${i}.json`);
    const buf = await cose.sign.verify(signature, verifier);
    t.deepEqual(buf, new TextEncoder().encode(plaintext));
  });
}


test('verify sign-fail-01', async (t) => {
  const { verifier, signature } = await readTestData('test/Examples/sign-tests/sign-fail-01.json');
  t.throwsAsync(cose.sign.verify(signature, verifier), { message: 'Unexpected cbor tag, \'998\'' });
});

// TODO: ADAPT ALL TESTS
/*
test('verify sign-fail-02', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-02.json');

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
import * as cose from '../lib/index';
import test from 'ava';
import jsonfile from 'jsonfile';
import base64url from 'base64url';
import webcrypto from "isomorphic-webcrypto";

test('create sign-pass-01', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signer = example.input.sign0;
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["sign", "verify"]);
  const buf = await cose.sign.create({ p, u }, plaintext, { key });
  const decoded = await cose.sign.verify(buf, { key, kid: signer.key.kid });
  t.deepEqual(decoded, plaintext);
});

test('create sign-pass-02', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-02.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signer = example.input.sign0;
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, false, ["sign", "verify"]);
  const externalAAD = Buffer.from(example.input.sign0.external, 'hex');
  const buf = await cose.sign.create({ p, u }, plaintext, { key, externalAAD });
  const decoded = await cose.sign.verify(buf, { key, externalAAD });
  t.deepEqual(decoded, plaintext);
});

test('create sign-pass-03', async (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-03.json');
  const p = example.input.sign0.protected;
  const u = example.input.sign0.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signer = example.input.sign0;
  const key = await webcrypto.subtle.importKey("jwk", signer.key, { name: "ECDSA", namedCurve: signer.key.crv }, true, ["sign", "verify"]);
  const buf = await cose.sign.create({ p, u }, plaintext, { key });
  const decoded = await cose.sign.verify(buf, { key });
  t.deepEqual(decoded, plaintext);
});

/* Todo: adapt all tests

test('verify sign-pass-01', (t) => {
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-pass-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    },
    externalAAD: Buffer.from(example.input.sign0.external, 'hex')
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
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  return cose.sign.verify(
    signature,
    verifier,
    {
      defaultType: cose.sign.Sign1Tag
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
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-03.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
  const example = jsonfile.readFileSync('test/Examples/sign1-tests/sign-fail-07.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign0.key.x),
      y: base64url.toBuffer(example.input.sign0.key.y)
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
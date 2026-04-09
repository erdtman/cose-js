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

test('ecdsa-examples verify ecdsa-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/ecdsa-examples/ecdsa-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('ecdsa-examples verify ecdsa-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/ecdsa-examples/ecdsa-02.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('create ecdsa-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/ecdsa-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signers = [{
    key: {
      d: base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('sign+verify rsa-pss-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/rsa-pss-examples/rsa-pss-01.json');
  const p = example.input.sign.protected;

  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signers = [{
    key: {
      n: Buffer.from(example.input.sign.signers[0].key.n_hex, 'hex'),
      d: Buffer.from(example.input.sign.signers[0].key.d_hex, 'hex'),
      p: Buffer.from(example.input.sign.signers[0].key.p_hex, 'hex'),
      q: Buffer.from(example.input.sign.signers[0].key.q_hex, 'hex'),
      dp: Buffer.from(example.input.sign.signers[0].key.dP_hex, 'hex'),
      dq: Buffer.from(example.input.sign.signers[0].key.dQ_hex, 'hex'),
      qi: Buffer.from(example.input.sign.signers[0].key.qi_hex, 'hex'),
      e: Buffer.from(example.input.sign.signers[0].key.e_hex, 'hex'),
      kid: example.input.sign.signers[0].key.kid
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];
  signers[0].p.alg = 'PS256';

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const verifiedBuf = await cose.sign.verify(buf, signers[0]);
  assert.ok(Buffer.isBuffer(verifiedBuf));
  assert.ok(verifiedBuf.length > 0);
  assert.strictEqual(verifiedBuf.toString('utf8'), example.input.plaintext);
});

test('sign+verify rsa-pss-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/rsa-pss-examples/rsa-pss-02.json');
  const p = example.input.sign.protected;

  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signers = [{
    key: {
      n: Buffer.from(example.input.sign.signers[0].key.n_hex, 'hex'),
      d: Buffer.from(example.input.sign.signers[0].key.d_hex, 'hex'),
      p: Buffer.from(example.input.sign.signers[0].key.p_hex, 'hex'),
      q: Buffer.from(example.input.sign.signers[0].key.q_hex, 'hex'),
      dp: Buffer.from(example.input.sign.signers[0].key.dP_hex, 'hex'),
      dq: Buffer.from(example.input.sign.signers[0].key.dQ_hex, 'hex'),
      qi: Buffer.from(example.input.sign.signers[0].key.qi_hex, 'hex'),
      e: Buffer.from(example.input.sign.signers[0].key.e_hex, 'hex'),
      kid: example.input.sign.signers[0].key.kid
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];
  signers[0].p.alg = 'PS384';

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const verifiedBuf = await cose.sign.verify(buf, signers[0]);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(verifiedBuf.length > 0);
  assert.strictEqual(verifiedBuf.toString('utf8'), example.input.plaintext);
});
test('sign+verify rsa-pss-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/rsa-pss-examples/rsa-pss-03.json');
  const p = example.input.sign.protected;

  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);
  const signers = [{
    key: {
      n: Buffer.from(example.input.sign.signers[0].key.n_hex, 'hex'),
      d: Buffer.from(example.input.sign.signers[0].key.d_hex, 'hex'),
      p: Buffer.from(example.input.sign.signers[0].key.p_hex, 'hex'),
      q: Buffer.from(example.input.sign.signers[0].key.q_hex, 'hex'),
      dp: Buffer.from(example.input.sign.signers[0].key.dP_hex, 'hex'),
      dq: Buffer.from(example.input.sign.signers[0].key.dQ_hex, 'hex'),
      qi: Buffer.from(example.input.sign.signers[0].key.qi_hex, 'hex'),
      e: Buffer.from(example.input.sign.signers[0].key.e_hex, 'hex'),
      kid: example.input.sign.signers[0].key.kid
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];
  signers[0].p.alg = 'PS512';

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);

  const verifiedBuf = await cose.sign.verify(buf, signers[0]);
  assert.ok(Buffer.isBuffer(verifiedBuf));
  assert.ok(verifiedBuf.length > 0);
  assert.strictEqual(verifiedBuf.toString('utf8'), example.input.plaintext);
});

test('verify ecdsa-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/ecdsa-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('create sign-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    key: {
      d: base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create sign-pass-01 Sync', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    key: {
      d: base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];

  const header = { p: p, u: u };
  const buf = await cose.sign.create(header, plaintext, signers);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create sign-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-02.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    key: { d: base64url.toBuffer(example.input.sign.signers[0].key.d) },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected,
    externalAAD: Buffer.from(example.input.sign.signers[0].external, 'hex')
  }];

  const header = { p: p, u: u };
  const options = { encodep: 'empty' };
  const buf = await cose.sign.create(header, plaintext, signers, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('create sign-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-03.json');
  const p = example.input.sign.protected;
  const u = example.input.sign.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const signers = [{
    key: {
      d: base64url.toBuffer(example.input.sign.signers[0].key.d)
    },
    u: example.input.sign.signers[0].unprotected,
    p: example.input.sign.signers[0].protected
  }];

  const header = { p: p, u: u };
  const options = { encodep: 'empty', excludetag: true };
  const buf = await cose.sign.create(header, plaintext, signers, options);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  const actual = cbor.decodeFirstSync(buf);
  const expected = cbor.decodeFirstSync(example.output.cbor);
  assert.ok(deepEqual(actual, expected));
});

test('verify sign-pass-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-01 Sync', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-02.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    },
    externalAAD: Buffer.from(example.input.sign.signers[0].external, 'hex')
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-pass-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-pass-03.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify sign-fail-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-01.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Unexpected cbor tag, \'998\'' });
});

test('verify sign-fail-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-02.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Signature mismatch' });
});

test('verify sign-fail-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-03.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Unknown algorithm, -999' });
});

test('verify sign-fail-04', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-04.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Unknown algorithm, unknown' });
});

test('verify sign-fail-06', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-06.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Signature mismatch' });
});

test('verify sign-fail-07', async () => {
  const example = jsonfile.readFileSync('test/Examples/sign-tests/sign-fail-07.json');

  const verifier = {
    key: {
      x: base64url.toBuffer(example.input.sign.signers[0].key.x),
      y: base64url.toBuffer(example.input.sign.signers[0].key.y),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');
  await assert.rejects(() => cose.sign.verify(signature, verifier), { message: 'Signature mismatch' });
});

test('verify rsa-pss-01', async () => {
  const example = jsonfile.readFileSync('test/Examples/rsa-pss-examples/rsa-pss-01.json');

  const verifier = {
    key: {
      n: Buffer.from(example.input.sign.signers[0].key.n_hex, 'hex'),
      e: Buffer.from(example.input.sign.signers[0].key.e_hex, 'hex'),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify rsa-pss-02', async () => {
  const example = jsonfile.readFileSync('test/Examples/rsa-pss-examples/rsa-pss-02.json');

  const verifier = {
    key: {
      n: Buffer.from(example.input.sign.signers[0].key.n_hex, 'hex'),
      e: Buffer.from(example.input.sign.signers[0].key.e_hex, 'hex'),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

test('verify rsa-pss-03', async () => {
  const example = jsonfile.readFileSync('test/Examples/rsa-pss-examples/rsa-pss-03.json');

  const verifier = {
    key: {
      n: Buffer.from(example.input.sign.signers[0].key.n_hex, 'hex'),
      e: Buffer.from(example.input.sign.signers[0].key.e_hex, 'hex'),
      kid: example.input.sign.signers[0].key.kid
    }
  };

  const signature = Buffer.from(example.output.cbor, 'hex');

  const buf = await cose.sign.verify(signature, verifier);
  assert.ok(Buffer.isBuffer(buf));
  assert.ok(buf.length > 0);
  assert.strictEqual(buf.toString('utf8'), example.input.plaintext);
});

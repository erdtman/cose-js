import test from 'ava';
import jsonfile from 'jsonfile';
import webcrypto from 'isomorphic-webcrypto';

function hexToB64(hex) {
  return Buffer.from(hex, 'hex').toString('base64');
}

async function makeKey(key: any, usage: "verify" | "sign") {
  if (key.kty === "EC") {
    const { kty, crv, x, y, d } = key;
    var keyType = { name: "ECDSA", namedCurve: crv };
    var params: any = { kty, crv, x, y, d: usage === "sign" ? d : undefined };
  } else if (key.kty === "RSA") {
    var params: any = {
      kty: key.kty,
      n: hexToB64(key.n_hex),
      e: hexToB64(key.e_hex),

    };
    if (usage === "sign") params = {
      ...params,
      d: hexToB64(key.d_hex), p: hexToB64(key.p_hex), q: hexToB64(key.q_hex),
      dp: hexToB64(key.dP_hex), dq: hexToB64(key.dQ_hex), qi: hexToB64(key.qi_hex)
    };

  } else throw new Error("unsupported key type");
  return await webcrypto.subtle.importKey("jwk", params, keyType, true, [usage]);
}

export async function readEllipticSigningTestData(filePath: string) {
  const example = jsonfile.readFileSync(filePath);
  const signer = example.input.sign.signers[0];
  const { kty, crv, x, y, d } = signer.key;
  const keyType = { name: "ECDSA", namedCurve: crv };
  const publicKey = await webcrypto.subtle.importKey("jwk", { kty, crv, x, y }, keyType, true, ["verify"]);
  const privateKey = await webcrypto.subtle.importKey("jwk", { kty, crv, x, y, d }, keyType, true, ["sign"]);
  const externalAAD = signer.external && Buffer.from(signer.external, 'hex');
  const verifier = { key: publicKey, kid: signer.key.kid, externalAAD };
  const headers = { u: signer.unprotected, p: signer.protected, };
  const signers = [{ key: privateKey, externalAAD, ...headers }];
  const signature = Buffer.from(example.output.cbor, 'hex');
  const plaintext = Buffer.from(example.input.plaintext, "utf-8");
  return { verifier, signature, plaintext, signers, headers };
}

function isObject(item) {
  return item && typeof item === 'object' && !Array.isArray(item);
}

function mapDeepEqual(actual, expected, depth) {
  const sortedActualKeys = [...actual.keys()].sort();
  const sortedExpectedKeys = [...expected.keys()].sort();
  if (sortedActualKeys.length !== sortedExpectedKeys.length) {
    return false;
  }
  for (let i = 0; i < sortedActualKeys.length; i++) {
    const actualKey = sortedActualKeys[i];
    const expectedKey = sortedExpectedKeys[i];
    if (actualKey !== expectedKey) {
      return false;
    }
    if (!deepEqual(actual.get(actualKey), expected.get(expectedKey), depth + 1)) {
      return false;
    }
  }
  return true;
}

function objectDeepEqual(actual, expected, depth) {
  const sortedActualKeys = Object.keys(actual).sort();
  const sortedExpectedKeys = Object.keys(expected).sort();
  if (sortedActualKeys.length !== sortedExpectedKeys.length) {
    return false;
  }
  for (let i = 0; i < sortedActualKeys.length; i++) {
    const actualKey = sortedActualKeys[i];
    const expectedKey = sortedExpectedKeys[i];
    if (actualKey !== expectedKey) {
      return false;
    }
    if (!deepEqual(actual[actualKey], expected[expectedKey], depth + 1)) {
      return false;
    }
  }
  return true;
}

function arrayDeepEqual(actual, expected, depth) {
  if (actual.length !== expected.length) {
    return false;
  }
  for (let i = 0; i < actual.length; i++) {
    if (!deepEqual(actual[i], expected[i], depth + 1)) {
      return false;
    }
  }
  return true;
}

export function deepEqual(actual, expected, depth?) {
  const currentDepth = (depth !== undefined ? depth : 0);
  if (currentDepth === 50) {
    throw new Error('Structure is to deeply nested.');
  }

  if (actual instanceof Map && expected instanceof Map) {
    return mapDeepEqual(actual, expected, currentDepth);
  } else if (actual instanceof Set && expected instanceof Set) {
    throw new Error('Set is not supported.');
  } else if (isObject(actual) && isObject(expected)) {
    return objectDeepEqual(actual, expected, currentDepth);
  } else if (Array.isArray(actual) && Array.isArray(expected)) {
    return arrayDeepEqual(actual, expected, currentDepth);
  } else {
    return actual === expected;
  }
}

test('deep equal array', (t) => {
  const actual = [1, 2, 3, '4', [1, 2, 3], { hello: 'world', world: 'hello' }];
  const expected = [1, 2, 3, '4', [1, 2, 3], { hello: 'world', world: 'hello' }];
  t.true(deepEqual(actual, expected));
  expected.push(4);
  t.false(deepEqual(actual, expected));
});

test('deep equal deep array', (t) => {
  const actual = [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, 1]]]]]]]]]]]]];
  const expected = [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, [1, 1]]]]]]]]]]]]];
  t.true(deepEqual(actual, expected));
});

test('deep equal objects', (t) => {
  const actual: any = {
    world: 'hello',
    hello: 'world',
    complex: {
      world: 'hello',
      hello: 'world'
    }
  };
  const expected: any = {
    hello: 'world',
    world: 'hello',
    complex: {
      hello: 'world',
      world: 'hello'
    }
  };
  t.true(deepEqual(actual, expected));
  expected.test = 'test';
  t.false(deepEqual(actual, expected));
});

test('deep equal Map', (t) => {
  const actual = new Map();
  actual.set(1, 1);
  actual.set('hello', 'world');
  actual.set('object', { hello: 'world', world: 'hello' });
  const expected = new Map();
  expected.set(1, 1);
  expected.set('hello', 'world');
  expected.set('object', { hello: 'world', world: 'hello' });
  t.true(deepEqual(actual, expected));
  expected.set(2, 2);
  t.false(deepEqual(actual, expected));
});

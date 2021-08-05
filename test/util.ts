import test, { ExecutionContext } from 'ava';
import jsonfile from 'jsonfile';
import {webcrypto} from '../lib/sign';

function hexToB64url(hex: string) {
  return Buffer.from(hex, 'hex').toString('base64url');
}

function hexToArray(hex: string) {
  return new Uint8Array(Buffer.from(hex, 'hex'));
}

async function makeKey(key: any, usage: "verify" | "sign") {
  if (key.kty === "EC") {
    const { kty, crv, x, y, d } = key;
    var keyType: EcKeyImportParams | RsaHashedImportParams = { name: "ECDSA", namedCurve: crv };
    var params: any = { kty, crv, x, y, d: usage === "sign" ? d : undefined };
  } else if (key.kty === "RSA") {
    var params: any = {
      kty: key.kty,
      n: hexToB64url(key.n_hex),
      e: hexToB64url(key.e_hex),
    };
    if (usage === "sign") params = {
      ...params,
      d: hexToB64url(key.d_hex), p: hexToB64url(key.p_hex), q: hexToB64url(key.q_hex),
      dp: hexToB64url(key.dP_hex), dq: hexToB64url(key.dQ_hex), qi: hexToB64url(key.qi_hex)
    };
    var keyType: EcKeyImportParams | RsaHashedImportParams = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  } else throw new Error("unsupported key type");
  return await webcrypto.subtle.importKey("jwk", params, keyType, true, [usage]);
}

export async function readSigningTestData(filePath: string) {
  const example = jsonfile.readFileSync(filePath);
  const signer = "sign0" in example.input
    ? example.input.sign0
    : example.input.sign.signers[0];
  const publicKey = await makeKey(signer.key, "verify");
  const privateKey = await makeKey(signer.key, "sign");
  const externalAAD = signer.external && hexToArray(signer.external).buffer;
  const verifier = { key: publicKey, kid: signer.key.kid, externalAAD };
  const headers = { u: signer.unprotected, p: signer.protected, };
  const signer0 = { key: privateKey, externalAAD, ...headers };
  const signers = "sign0" in example.input ? signer0 : [signer0];
  const signature = hexToArray(example.output.cbor);
  const plaintext = new TextEncoder().encode(example.input.plaintext);
  return { verifier, signature, plaintext, signers, headers };
}

export function bufferEqual(t: ExecutionContext, b1: Uint8Array, b2: Uint8Array) {
  if (!(b1 instanceof Uint8Array && b2 instanceof Uint8Array))
    throw new Error(`cannot compare as buffers ${b1} and ${b2}`);
  t.deepEqual(
    Buffer.from(Array.from(b1)).toString('hex'),
    Buffer.from(Array.from(b2)).toString('hex'),
  )
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

import * as cose from '../lib/index';
import test from 'ava';
import jsonfile from 'jsonfile';
import cbor from 'cbor';
import { deepEqual, readSigningTestData } from './util';
import jwkToPem from 'jwk-to-pem';

function hexToB64(hex) {
  return Buffer.from(hex, 'hex').toString('base64');
}

test('create rsa-pkcs-01', async (t) => {
  let { verifier, plaintext, headers, signers } = await readSigningTestData('test/rsa-pkcs-examples/rsa-pkcs-01.json');
  if (!Array.isArray(signers)) signers = [signers];
  const buf = await cose.sign.create(headers, plaintext, signers, { excludetag: true });
  const decoded = await cose.sign.verify(buf, verifier);
  t.deepEqual(decoded, plaintext);
});


test('verify rsa-pkcs-01', async (t) => {
  const { verifier, plaintext, signature } = await readSigningTestData('test/rsa-pkcs-examples/rsa-pkcs-01.json');
  const decoded = await cose.sign.verify(signature, verifier, { defaultType: cose.sign.Sign1Tag });
  t.deepEqual(decoded, plaintext);
});

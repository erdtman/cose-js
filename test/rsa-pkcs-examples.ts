import * as cose from '../lib/index';
import test from 'ava';
import { bufferEqual, readSigningTestData } from './util';

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
  bufferEqual(t, decoded, plaintext);
});

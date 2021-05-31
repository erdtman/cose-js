import * as cose from '../lib/index';
import test from 'ava';
import { readSigningTestData } from './util'

const TEST_NAMES = ['ecdsa-01', 'sign-pass-01', 'sign-pass-02', 'sign-pass-03'];
for (const name of TEST_NAMES) {
  test(`create ${name}`, async (t) => {
    const { verifier, plaintext, headers, signers } = await readSigningTestData(`test/Examples/sign-tests/${name}.json`);
    const buf = await cose.sign.create(headers, plaintext, signers);
    const decoded = await cose.sign.verify(buf, verifier);
    t.deepEqual(decoded, plaintext);
  });

  test(`verify ${name}`, async (t) => {
    const { verifier, signature, plaintext } = await readSigningTestData(`test/Examples/sign-tests/${name}.json`);
    const buf = await cose.sign.verify(signature, verifier);
    t.deepEqual(buf, plaintext);
  });
}


[
  { name: 'sign-fail-01', message: 'Unexpected cbor tag, \'998\'', },
  { name: 'sign-fail-02', message: 'Signature mismatch', },
  { name: 'sign-fail-03', message: 'Unknown algorithm, -999', },
  { name: 'sign-fail-04', message: 'Unknown algorithm, unknown', },
  { name: 'sign-fail-06', message: 'Signature mismatch', },
  { name: 'sign-fail-07', message: 'Signature mismatch', },
].forEach(({ name, message }, i) => {
  test('verify ' + name, async (t) => {
    const { verifier, signature } = await readSigningTestData(`test/Examples/sign-tests/${name}.json`);
    await t.throwsAsync(cose.sign.verify(signature, verifier), { message });
  });
})
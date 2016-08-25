const cbor = require('cbor');
const cose = require('../');
const test = require('ava');
const node_webcrypto_ossl = require('node-webcrypto-ossl');
const crypto = new node_webcrypto_ossl();

test('basic sign', (t) => {
  var data = new Uint8Array(4);
  data[0] = 42;
  data[1] = 43;
  data[2] = 44;

  return crypto.subtle.generateKey({
      name: "ECDSA",
      namedCurve: "P-256"
    },
    false, //whether the key is extractable (i.e. can be used in exportKey)
    ["sign", "verify"] //can be any combination of "sign" and "verify"
  )
  .then((key) => {
    //returns a keypair object
    t.truthy(key);
    const publicKey = key.publicKey;
    t.truthy(publicKey);
    var payload = cbor.encode({"hello": "world"});
    return cose.COSE_Sign.create({
        prot: {
          "content_type": 5,
          "alg": 4
        },
        unprot:{}
      },
      payload,
      key);
  })
  .then((signed) => {
    t.truthy(signed);
    return cbor.decodeFirst(signed);
  })
  .then((sig) => {
    t.true(Array.isArray(sig));
    t.is(sig.length, 4);
  });
});

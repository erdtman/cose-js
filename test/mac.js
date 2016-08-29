const cbor = require('cbor');
const cose = require('../');
const test = require('ava');

var hProtected = {
  "alg": "SHA-256",
  "content_type": 5,
};
var key = "secret"
var payload = {"hello": "world"};
var hUnprotected = {};

test('basic mac', t => {
  return cose.mac.create(hProtected,
                              hUnprotected,
                              cbor.encode(payload),
                              key)
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    return cose.mac.read(buf, key);
  })
  .then((buf) => {
    t.true(Buffer.isBuffer(buf));
    t.true(buf.length > 0);
    return cbor.decodeFirst(buf);
  })
  .then((obj) => {
    t.deepEqual(obj, payload);
  });
});

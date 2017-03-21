// const cbor = require('cbor');
const cose = require('../');
const test = require('ava');
const fs = require('fs');
// const utils = require('../test-helpers/failures.js');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
let files;
if (fs.existsSync('Examples')) {
  files = ['Examples/aes-gcm-examples/aes-gcm-01.json',
    'Examples/aes-gcm-examples/aes-gcm-02.json',
    'Examples/aes-gcm-examples/aes-gcm-03.json'];
} else {
  files = ['test/Examples/aes-gcm-examples/aes-gcm-01.json',
    'test/Examples/aes-gcm-examples/aes-gcm-02.json',
    'test/Examples/aes-gcm-examples/aes-gcm-03.json'];
}

function randomSource (bytes) {
  return new Buffer('02D1F7E6F26C43D4868D87CE', 'hex');
}

files.forEach(function (file) {
  const example = jsonfile.readFileSync(file);

  test('CREATE: ' + example.title, t => {
    const recipients = [{
      'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
      'u': example.input.enveloped.recipients[0].unprotected
    }];
    return cose.encrypt.create({p: example.input.enveloped.protected,
      u: example.input.enveloped.unprotected},
      Buffer.from(example.input.plaintext),
      recipients,
      undefined,
      randomSource)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('hex'), example.output.cbor.toLowerCase());
    });
  });

  test('READ: ' + example.title, t => {
    return cose.encrypt.read(example.output.cbor,
    base64url.toBuffer(example.input.enveloped.recipients[0].key.k))
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
  });
});

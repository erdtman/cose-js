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
    'test/Examples/aes-gcm-examples/aes-gcm-03.json',
    'test/Examples/aes-gcm-examples/aes-gcm-05.json'];
}

function randomSource (bytes) {
  if (bytes === 12) {
    return new Buffer('02D1F7E6F26C43D4868D87CE', 'hex');
  } else {
    return new Buffer('61A7', 'hex');
  }
}

files.forEach(function (file) {
  const example = jsonfile.readFileSync(file);

  test('CREATE: ' + example.title, t => {
    const recipients = [{
      'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
      'u': example.input.enveloped.recipients[0].unprotected
    }];

    if (example.input.enveloped.unprotected && example.input.enveloped.unprotected.partialIV_hex) {
      example.input.enveloped.unprotected.Partial_IV = Buffer.from(example.input.enveloped.unprotected.partialIV_hex, 'hex');
      delete example.input.enveloped.unprotected.partialIV_hex;
    }

    let contextIv;
    if (example.input.enveloped.unsent && example.input.enveloped.unsent.IV_hex) {
      contextIv = Buffer.from(example.input.enveloped.unsent.IV_hex, 'hex');
      contextIv[10] = 0;
      contextIv[11] = 0;
    }

    const options = {
      'randomSource': randomSource,
      'externalAAD': undefined,
      'contextIv': contextIv
    };
    return cose.encrypt.create({p: example.input.enveloped.protected,
      u: example.input.enveloped.unprotected},
      Buffer.from(example.input.plaintext),
      recipients,
      options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('hex'), example.output.cbor.toLowerCase());
    });
  });

  test('READ: ' + example.title, t => {
    let contextIv;
    if (example.input.enveloped.unsent && example.input.enveloped.unsent.IV_hex) {
      contextIv = Buffer.from(example.input.enveloped.unsent.IV_hex, 'hex');
      contextIv[10] = 0;
      contextIv[11] = 0;
    }

    return cose.encrypt.read(example.output.cbor,
      base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
      {'contextIv': contextIv})
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
  });
});

const failExample = jsonfile.readFileSync('test/Examples/aes-gcm-examples/aes-gcm-04.json');
test('FAIL: ' + failExample.title, t => {
  cose.encrypt.read(failExample.output.cbor,
    base64url.toBuffer(failExample.input.enveloped.recipients[0].key.k)).then((buf) => {
      t.true(false);
    }).catch((error) => {
      t.is(error.message, 'Unsupported state or unable to authenticate data');
    });
});

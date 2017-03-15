const cbor = require('cbor');
const cose = require('../');
const test = require('ava');
const fs = require('fs');
const utils = require('../test-helpers/failures.js');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
let files;
if (fs.existsSync('Examples')) {
  files = ['Examples/mac0-tests/mac-pass-01.json',
    'Examples/mac0-tests/mac-pass-02.json',
    'Examples/mac0-tests/mac-pass-03.json'];
} else {
  files = ['test/Examples/mac0-tests/mac-pass-01.json',
    'test/Examples/mac0-tests/mac-pass-02.json',
    'test/Examples/mac0-tests/mac-pass-03.json'];
}

files.forEach(function (file) {
  const example = jsonfile.readFileSync(file);
  let external = example.input.mac0.external;
  external = external ? new Buffer(external, 'hex') : undefined;

  test('CREATE: ' + example.title, t => {
    return cose.mac.create({p: example.input.mac0.protected,
      u: example.input.mac0.unprotected},
      Buffer.from(example.input.plaintext),
      [{'key': base64url.toBuffer(example.input.mac0.recipients[0].key.k)}],
      external)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      for (let failure in example.input.failures) {
        if (!utils[failure]) {
          continue;
        }
        buf = utils[failure](buf, example.input.failures[failure]);
      }
      t.is(buf.toString('hex'), example.output.cbor.toLowerCase());
    });
  });

  test('READ: ' + example.title, t => {
    return cose.mac.read(example.output.cbor,
      base64url.toBuffer(example.input.mac0.recipients[0].key.k),
      external)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), example.input.plaintext);
    });
  });
});

test('errors', t => {
  t.throws(() => {
    cose.mac.create({});
  });
  t.throws(() => cose.mac.create({'alg': 'fizzle blorp'}));
  t.throws(cose.mac.read(cbor.encode('foo'), 'key'));
});

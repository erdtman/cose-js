/* jshint esversion: 6 */
/* jslint node: true */
'use strict';

const cose = require('../');
const test = require('ava');
const jsonfile = require('jsonfile');
const base64url = require('base64url');
const cbor = require('cbor');
const deepEqual = require('./util.js').deepEqual;

function randomSource (bytes) {
  if (bytes === 12) {
    return Buffer.from('02D1F7E6F26C43D4868D87CE', 'hex');
  } else if (bytes === 2) {
    return Buffer.from('61A7', 'hex');
  } else if (bytes === 13) {
    return Buffer.from('89F52F65A1C580933B5261A72F', 'hex');
  } else if (bytes === 7) {
    return Buffer.from('89F52F65A1C580', 'hex');
  }
}

test('create aes-ccm-enc-01', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-01.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-02', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-02.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-03', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-03.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-04', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-04.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-05', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-05.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-06', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-06.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-07', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-07.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-enc-08', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-08.json');
  const p = example.input.encrypted.protected;
  const u = example.input.encrypted.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = {
    'key': base64url.toBuffer(example.input.encrypted.recipients[0].key.k),
    'u': example.input.encrypted.recipients[0].unprotected
  };

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('decrypt aes-ccm-enc-01', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-01.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-02', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-02.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-03', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-03.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-04', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-04.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-05', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-05.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-06', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-06.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-07', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-07.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-enc-08', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-enc-08.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.encrypted.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('create aes-ccm-01', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-01.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('hex'), example.output.cbor.toLowerCase());
    });
});

test('create aes-ccm-02', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-02.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-03', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-03.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-04', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-04.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-05', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-05.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-06', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-06.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-07', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-07.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('create aes-ccm-08', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-08.json');
  const p = example.input.enveloped.protected;
  const u = example.input.enveloped.unprotected;
  const plaintext = Buffer.from(example.input.plaintext);

  const recipient = [{
    'key': base64url.toBuffer(example.input.enveloped.recipients[0].key.k),
    'u': example.input.enveloped.recipients[0].unprotected
  }];

  const options = {
    'randomSource': randomSource
  };

  return cose.encrypt.create(
    { p: p, u: u },
    plaintext,
    recipient,
    options)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      const actual = cbor.decodeFirstSync(buf);
      const expected = cbor.decodeFirstSync(example.output.cbor);
      t.true(deepEqual(actual, expected));
    });
});

test('decrypt aes-ccm-01', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-01.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-02', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-02.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-03', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-03.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-04', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-04.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-05', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-05.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-06', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-06.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-07', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-07.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

test('decrypt aes-ccm-08', t => {
  const example = jsonfile.readFileSync('test/Examples/aes-ccm-examples/aes-ccm-08.json');
  const plaintext = example.input.plaintext;
  const key = base64url.toBuffer(example.input.enveloped.recipients[0].key.k);

  return cose.encrypt.read(example.output.cbor,
    key)
    .then((buf) => {
      t.true(Buffer.isBuffer(buf));
      t.true(buf.length > 0);
      t.is(buf.toString('utf8'), plaintext);
    });
});

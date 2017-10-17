[![Build Status](https://travis-ci.org/erdtman/cose-js.svg?branch=master)](https://travis-ci.org/erdtman/cose-js)
[![Coverage Status](https://coveralls.io/repos/github/erdtman/cose-js/badge.svg?branch=master)](https://coveralls.io/github/erdtman/cose-js?branch=master)
# cose-js
JavaScript implementation of [COSE](https://tools.ietf.org/html/draft-ietf-cose-msg)

## Install
```
npm install cose-js --save
```
## Test
```
npm test
```
## Use
### MAC
#### Do MAC
```js
const cose = require('../');

const plaintext = 'Secret message!';
const headers = {
  'p': {'alg': 'A128GCM'},
  'u': {'kid':'our-secret'}
};
const recipients = [{
  'key': Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex')
}];

return cose.encrypt.create(
  headers,
  plaintext,
  recipients
).then((buf) => {
  console.log('Encrypted message: ' + buf.toString('hex'));
}).catch((error)=>{
  console.log(error);
});
```
#### Verify
TBD
### Sign
#### Do Sign
```js
const cose = require('../');

const plaintext = "Important message!";
const headers = {
  'p': {'alg': 'ES256'},
  'u': {'kid': '11'}
};
const signer = {
  'key': {
    'd': Buffer.from('6c1382765aec5358f117733d281c1c7bdc39884d04a45a1e6c67c858bc206c19', 'hex')
  }
};

return cose.sign.create(
  headers,
  plaintext,
  signer
)
.then((buf) => {
  console.log('Signed message: ' + buf.toString('hex'));
}).catch((error)=>{
  console.log(error);
});
```
#### Verify
TBD
### Encrypt
```js
const cose = require('../');

const plaintext = 'Secret message!';
const headers = {
  'p': {'alg': 'A128GCM'},
  'u': {'kid':'our-secret'}
};
const recipients = [{
  'key': Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex')
}];

return cose.encrypt.create(
  headers,
  plaintext,
  recipients
).then((buf) => {
  console.log('Encrypted message: ' + buf.toString('hex'));
}).catch((error)=>{
  console.log(error);
});
```
#### Decrypt
TBD

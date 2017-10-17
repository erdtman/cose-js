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

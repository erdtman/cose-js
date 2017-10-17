const cose = require('../');

const plaintext = "Important message!"
const headers = {
  'p': {'alg': 'SHA-256_64'},
  'u': {'kid':'our-secret'}
};
const recipent = {
  'key': Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex')
};

return cose.mac.create(
  headers,
  plaintext,
  recipent)
.then((buf) => {
  console.log('MACed message: ' + buf.toString('hex'));
}).catch((error)=>{
  console.log(error);
});

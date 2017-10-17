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

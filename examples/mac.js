const cose = require('../');

async function run () {
  try {
    const plaintext = 'Important message!';
    const headers = {
      'p': { 'alg': 'SHA-256_64' },
      'u': { 'kid': 'our-secret' }
    };
    const recipent = {
      'key': Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex')
    };
    const maced = await cose.mac.create(headers, plaintext, recipent);
    console.log('MACed message: ' + maced.toString('hex'));

    const key = Buffer.from('231f4c4d4d3051fdc2ec0a3851d5b383', 'hex');
    const COSEMessage = Buffer.from('d18443a10104a1044a6f75722d73656372657472496d706f7274616e74206d65737361676521488894981d4aa5d614', 'hex');
    const verified = await cose.mac.read(COSEMessage, key);
    console.log('Verified message: ' + verified.toString('utf8'));
  } catch (error) {
    console.log(error);
  }
}
run();

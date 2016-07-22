var cbor = require('cbor');
var COSE_Mac = require('./COSE_Mac.js');



var protected = {
  "alg": "SHA-256",
  "content_type": 5,
  "kid": "s_kid",
};
var external_aad = null;
var key = "secret"
var payload = cbor.encode({"hello": "world"});
var unprotected = {};

COSE_Mac.create(protected, unprotected, payload, key, external_aad).then(function(cose_mac){
  console.log(cose_mac.toString('hex'));
  return COSE_Mac.read(cose_mac, key, external_aad)
}).then(function(data) {
  cbor.decodeFirst(data, function(error, obj) {
      console.log(obj);
  });
}).fail(function(error) {
  console.log(error);
});

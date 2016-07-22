var cbor = require('cbor');
var Q = require('q');
var COSE_Mac = require('./COSE_Mac.js');

var claim_labels = {
  "iss": 1, // 3
  "sub": 2, // 3
  "aud": 3, // 3
  "exp": 4, // 6 tag value 1
  "nbf": 5, // 6 tag value 1
  "iat": 6, // 6 tag value 1
  "cti": 7, // 2
}

function CWT(claims) {
  var payload = new Map();
  for(var param in claims) {
     if(!claim_labels[param]) {
       throw new Error("Unknown claim, " + param);
     }
     payload.set(claim_labels[param], claims[param]);
  }

  // TODO verify types

  return {
    COSE_Mac(key, alg, kid) {
      var protected = {
        "alg": alg,
        "content_type": 61, // TODO uppdate with correct IANA value
        "kid": kid,
      };
      var unprotected = {};
      var external_aad = null;
      return COSE_Mac.create(protected, unprotected, payload, external_aad, key);
    }
  }
}

CWT.read = function(cwt, key) {
  let deferred = Q.defer();
  if (MAC) { // TODO check cbor tag
    var out_mac = COSE_Mac.read(mac, key)
    cbor.decodeAll(out_mac.payload, function(error, obj) {
      if (err) {
        return deferred.reject(error);
      }
      deferred.resolve(new CWT(obj));
    });
  } else if(SIGNATUER) {

  }
  return deferred.promise;
}

exports=CWT;

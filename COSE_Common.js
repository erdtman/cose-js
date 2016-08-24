/*jshint esversion: 6 */
/*jslint node: true */
'use strict';


let header_parameters = {
  "alg": 1,
  "crit": 2,
  "content_type": 3,
  "kid": 4,
  "IV": 5,
  "Partial_IV": 6,
  "counter_signature": 7
};

exports.translate_headers = function(header) {
  let result = new Map();
  for(var param in header) {
     if(!header_parameters[param]) {
       throw new Error("Unknown parameter, " + param);
     }
     result.set(header_parameters[param], header[param]);
  }
  return result;
}

exports.header_parameters = header_parameters;

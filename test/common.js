/* jshint esversion: 6 */
/* jslint node: true */
'use strict';
const test = require('ava');
const cose = require('../');

test('translate headers', (t) => {
  let h = cose.common.TranslateHeaders({});
  t.is(h.constructor.name, 'Map');
  h = cose.common.TranslateHeaders({alg: 'SHA-256', crit: 2});
  t.is(h.constructor.name, 'Map');
  t.is(h.size, 2);
  t.is(h.get(cose.common.HeaderParameters.alg), 5);
  t.is(h.get(cose.common.HeaderParameters.crit), 2);
});

test('invalid', (t) => {
  t.throws(() => {
    cose.common.TranslateHeaders({'fizzle stomp': 12});
  });
});

/* jshint esversion: 6 */
/* jslint node: true */
'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const cose = require('../');

test('translate headers', () => {
  let h = cose.common.TranslateHeaders({});
  assert.strictEqual(h.constructor.name, 'Map');
  h = cose.common.TranslateHeaders({ alg: 'SHA-256', crit: 2 });
  assert.strictEqual(h.constructor.name, 'Map');
  assert.strictEqual(h.size, 2);
  assert.strictEqual(h.get(cose.common.HeaderParameters.alg), 5);
  assert.strictEqual(h.get(cose.common.HeaderParameters.crit), 2);
});

/*
test('translate headers', () => {
  const result = cose.common.TranslateHeaders({
    'ephemeral_key': Buffer.from('beef', 'hex'),
    'partyUNonce': Buffer.from('dead', 'hex'),
    'kid': Buffer.from('0b0b', 'hex'),
  });
  console.log(result);
});
*/

test('invalid', () => {
  assert.throws(() => {
    cose.common.TranslateHeaders({ 'fizzle stomp': 12 });
  });
});

test('xor1', () => {
  const a = Buffer.from('00ff0f', 'hex');
  const b = Buffer.from('f0f0', 'hex');
  const actual = cose.common.xor(a, b);
  const expected = '000fff';
  assert.strictEqual(actual.toString('hex'), expected);
});

test('xor2', () => {
  const a = Buffer.from('f0f0', 'hex');
  const b = Buffer.from('00ff0f', 'hex');
  const actual = cose.common.xor(a, b);
  const expected = '000fff';
  assert.strictEqual(actual.toString('hex'), expected);
});

test('xor3', () => {
  const a = Buffer.from('f0f0f0', 'hex');
  const b = Buffer.from('00ff0f', 'hex');
  const actual = cose.common.xor(a, b);
  const expected = 'f00fff';
  assert.strictEqual(actual.toString('hex'), expected);
});

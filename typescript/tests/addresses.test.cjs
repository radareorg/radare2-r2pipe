const assert = require('node:assert/strict');
const { test } = require('node:test');
const { parseAddress, parseJson } = require('../dist/index.js');

test('addresses accept legacy numbers/bigints and exact hexadecimal uint64 strings', () => {
  for (const value of [0n, 17n, 9007199254740991n, 9007199254740993n, 9223372036854775809n, 18446744073709551615n]) {
    assert.equal(parseAddress('0x' + value.toString(16)), value);
    assert.equal(parseAddress(parseJson(value.toString())), value);
  }
  assert.equal(parseJson('"0xffffffffffffffff"'), '0xffffffffffffffff');
});

test('addresses reject rounded numbers, invalid syntax and uint64 overflow', () => {
  for (const value of [true, null, {}, 1.5, -1, 9007199254740992, '', '17', '0x', '-0x1', '0x10000000000000000', '0x1junk']) {
    assert.throws(() => parseAddress(value));
  }
});

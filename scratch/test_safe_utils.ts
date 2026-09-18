import {
  safeString,
  safeLower,
  safeUpper,
  safeTrim,
  safeReplace,
  safeUrl,
  safeArray,
  safeRecord
} from '../lib/safe-utils';

function assert(condition: boolean, msg: string) {
  if (!condition) {
    console.error(`FAILED: ${msg}`);
    process.exit(1);
  }
  console.log(`PASSED: ${msg}`);
}

console.log('Starting Defensive safe-utils.ts Test Suite...\n');

// 1. safeString tests
assert(safeString(null) === '', 'safeString(null) returns empty string');
assert(safeString(undefined) === '', 'safeString(undefined) returns empty string');
assert(safeString('hello') === 'hello', 'safeString("hello") returns "hello"');
assert(safeString(123) === '123', 'safeString(123) returns "123"');
assert(safeString(true) === 'true', 'safeString(true) returns "true"');
assert(safeString(BigInt(42)) === '42', 'safeString(BigInt(42)) returns "42"');
assert(safeString(Symbol('test')) === 'test', 'safeString(Symbol) returns description');
assert(safeString({ a: 1 }) === '{"a":1}', 'safeString({a:1}) returns JSON string');

// Circular object test for safeString
const circular: any = {};
circular.self = circular;
assert(safeString(circular, 'fallback') === 'fallback', 'safeString handles circular references gracefully');

// 2. safeLower tests
assert(safeLower(null) === '', 'safeLower(null) returns ""');
assert(safeLower(undefined) === '', 'safeLower(undefined) returns ""');
assert(safeLower('FOO_BAR') === 'foo_bar', 'safeLower("FOO_BAR") returns "foo_bar"');
assert(safeLower(123) === '123', 'safeLower(123) returns "123"');

// 3. safeUpper tests
assert(safeUpper(null) === '', 'safeUpper(null) returns ""');
assert(safeUpper('foo_bar') === 'FOO_BAR', 'safeUpper("foo_bar") returns "FOO_BAR"');

// 4. safeTrim tests
assert(safeTrim(null) === '', 'safeTrim(null) returns ""');
assert(safeTrim('  hello world  ') === 'hello world', 'safeTrim trims whitespace');
assert(safeTrim(undefined) === '', 'safeTrim(undefined) returns empty');
assert(safeTrim(undefined, 'default') === 'default', 'safeTrim(undefined, "default") returns fallback');

// 5. safeReplace tests
assert(safeReplace(null, 'foo', 'bar') === '', 'safeReplace(null) returns ""');
assert(safeReplace(undefined, /a/g, 'b') === '', 'safeReplace(undefined) returns ""');
assert(safeReplace('hello-world', '-', '_') === 'hello_world', 'safeReplace string pattern');
assert(safeReplace('hello-123', /\d+/, 'num') === 'hello-num', 'safeReplace regex pattern');
assert(safeReplace('abc', 'b', (m) => m.toUpperCase()) === 'aBc', 'safeReplace with replacer function');

// 6. safeUrl tests
assert(safeUrl(null) === '', 'safeUrl(null) returns ""');
assert(safeUrl(undefined) === '', 'safeUrl(undefined) returns ""');
assert(safeUrl('github.com/owner/repo') === 'https://github.com/owner/repo', 'safeUrl prefixes https:// if missing');
assert(safeUrl('https://example.com/api') === 'https://example.com/api', 'safeUrl preserves https://');
assert(safeUrl('invalid url with spaces @@@', 'fallback') === 'fallback', 'safeUrl returns fallback for invalid url');

// 7. safeArray tests
assert(Array.isArray(safeArray(null)), 'safeArray(null) returns array');
assert(safeArray(null).length === 0, 'safeArray(null) is empty');
assert(safeArray([1, 2, 3]).length === 3, 'safeArray valid array unchanged');
assert(safeArray('not-an-array').length === 0, 'safeArray non-array returns empty array');

// 8. safeRecord tests
assert(typeof safeRecord(null) === 'object' && safeRecord(null) !== null, 'safeRecord(null) returns record');
assert(Object.keys(safeRecord(null)).length === 0, 'safeRecord(null) is empty object');
assert(safeRecord({ key: 'val' }).key === 'val', 'safeRecord valid object unchanged');
assert(Object.keys(safeRecord([1, 2])).length === 0, 'safeRecord on array returns empty object');

console.log('\nALL DEFENSIVE UNIT TESTS PASSED WITH 100% SUCCESS!\n');

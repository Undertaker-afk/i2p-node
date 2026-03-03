/**
 * Test that the bsip library integration produces correct SipHash-2-4 results.
 * This test uses official test vectors from https://github.com/veorq/SipHash
 */

const { Crypto } = await import('./dist/crypto/index.js');

console.log('Testing SipHash-2-4 implementation using bsip library...\n');

// Test vectors from official SipHash reference implementation
// Key: 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f
// The test vectors show the expected output in little-endian byte order

const key1 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
const key2 = new Uint8Array([0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);

// Test vector 0: Empty message
// Expected bytes (LE): 31 0e 0e dd 47 db 6f 72
const emptyData = new Uint8Array([]);
const result0 = Crypto.siphash24(key1, key2, emptyData);
const expected0 = 0x726fdb47dd0e0e31n;

console.log('Test 0: Empty message');
console.log('  Result:  ', result0.toString(16).padStart(16, '0'));
console.log('  Expected:', expected0.toString(16).padStart(16, '0'));
console.log('  Status:  ', result0 === expected0 ? '✓ PASS' : '✗ FAIL');

// Test vector 1: Single byte (0x00)
// Expected bytes (LE): fd 67 dc 93 c5 39 f8 74
const data1 = new Uint8Array([0x00]);
const result1 = Crypto.siphash24(key1, key2, data1);
const expected1 = 0x74f839c593dc67fdn;

console.log('\nTest 1: Single byte (0x00)');
console.log('  Result:  ', result1.toString(16).padStart(16, '0'));
console.log('  Expected:', expected1.toString(16).padStart(16, '0'));
console.log('  Status:  ', result1 === expected1 ? '✓ PASS' : '✗ FAIL');

// Test vector 8: 8-byte message (00 01 02 03 04 05 06 07)
// Expected bytes (LE): 62 24 93 9a 79 f5 f5 93
const data8 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
const result8 = Crypto.siphash24(key1, key2, data8);
const expected8 = 0x93f5f5799a932462n;

console.log('\nTest 8: 8-byte message (00 01 02 03 04 05 06 07)');
console.log('  Result:  ', result8.toString(16).padStart(16, '0'));
console.log('  Expected:', expected8.toString(16).padStart(16, '0'));
console.log('  Status:  ', result8 === expected8 ? '✓ PASS' : '✗ FAIL');

// Test vector 15: 15-byte message (00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e)
// Expected bytes (LE): e5 45 be 49 61 ca 29 a1
const data15 = new Uint8Array([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e]);
const result15 = Crypto.siphash24(key1, key2, data15);
const expected15 = 0xa129ca6149be45e5n;

console.log('\nTest 15: 15-byte message');
console.log('  Result:  ', result15.toString(16).padStart(16, '0'));
console.log('  Expected:', expected15.toString(16).padStart(16, '0'));
console.log('  Status:  ', result15 === expected15 ? '✓ PASS' : '✗ FAIL');

// Summary
const allPassed = result0 === expected0 && result1 === expected1 && result8 === expected8 && result15 === expected15;
console.log('\n' + '='.repeat(50));
console.log('Overall: ', allPassed ? '✓ ALL TESTS PASSED' : '✗ SOME TESTS FAILED');
console.log('='.repeat(50));

if (!allPassed) {
  process.exit(1);
}

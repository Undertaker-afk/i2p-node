#!/usr/bin/env node
/**
 * Test that our RouterInfo signature verifies correctly.
 * This mimics what i2pd does when it receives our SessionConfirmed.
 */
import { I2PRouter, logger, LogLevel } from './dist/index.js';
import { ed25519 } from '@noble/curves/ed25519';

logger.setLevel(LogLevel.WARN);

const router = new I2PRouter({
  ntcp2Port: 0,
  ssu2Port: 0,
  samPort: 0,
  bandwidthClass: 'L',
  isFloodfill: false,
  logLevel: LogLevel.WARN,
  enableWebUI: false,
  dataDir: './i2p-test-data'
});

await router.start();

// Access the wire RI
const ri = router.wireRouterInfo;
if (!ri || !Buffer.isBuffer(ri)) {
  console.error('ERROR: wireRouterInfo not available');
  router.stop();
  process.exit(1);
}

console.log(`RI total length: ${ri.length}`);
console.log(`RI hex (first 50 bytes): ${ri.subarray(0, 50).toString('hex')}`);
console.log(`RI hex (last 70 bytes): ${ri.subarray(ri.length - 70).toString('hex')}`);

// Parse identity structure
const certType = ri.readUInt8(384);
const certLen = ri.readUInt16BE(385);
console.log(`\nIdentity cert type: ${certType} (expected 5=KEY)`);
console.log(`Identity cert len: ${certLen} (expected 4)`);

if (certType === 5 && certLen === 4) {
  const sigType = ri.readUInt16BE(387);
  const cryptoType = ri.readUInt16BE(389);
  console.log(`Signing key type: ${sigType} (expected 7=Ed25519)`);
  console.log(`Crypto key type: ${cryptoType} (expected 4=X25519)`);
}

const identityLen = 387 + certLen; // standardIdentity + extended
console.log(`Identity full length: ${identityLen} (expected 391)`);

// Extract Ed25519 public key (right-aligned in signingKey[128], offset 256+96=352)
const edPub = ri.subarray(352, 384);
console.log(`Ed25519 pubkey: ${edPub.toString('hex')}`);

// Extract X25519 public key (first 32 bytes of publicKey[256])
const x25519Pub = ri.subarray(0, 32);
console.log(`X25519 pubkey: ${x25519Pub.toString('hex')}`);

// Published timestamp
const pubMs = Number(ri.readBigUInt64BE(identityLen));
console.log(`\nPublished timestamp: ${pubMs} (${new Date(pubMs).toISOString()})`);
console.log(`Age: ${Math.floor((Date.now() - pubMs) / 1000)} seconds`);

// Address count
const addrCount = ri.readUInt8(identityLen + 8);
console.log(`Address count: ${addrCount}`);

// Parse addresses for inspection
let offset = identityLen + 9;
for (let i = 0; i < addrCount; i++) {
  const cost = ri.readUInt8(offset); offset += 1;
  const dateMs = Number(ri.readBigUInt64BE(offset)); offset += 8;
  const styleLen = ri.readUInt8(offset); offset += 1;
  const style = ri.subarray(offset, offset + styleLen).toString('ascii'); offset += styleLen;
  const optLen = ri.readUInt16BE(offset); offset += 2;
  const optBytes = ri.subarray(offset, offset + optLen); offset += optLen;
  
  // Parse options
  const opts = {};
  let oOff = 0;
  while (oOff < optBytes.length) {
    const kLen = optBytes.readUInt8(oOff); oOff += 1;
    const key = optBytes.subarray(oOff, oOff + kLen).toString('ascii'); oOff += kLen;
    oOff += 1; // skip '='
    const vLen = optBytes.readUInt8(oOff); oOff += 1;
    const val = optBytes.subarray(oOff, oOff + vLen).toString('ascii'); oOff += vLen;
    oOff += 1; // skip ';'
    opts[key] = val;
  }
  console.log(`\nAddress ${i}: style=${style} cost=${cost} dateMs=${dateMs}`);
  console.log(`  options:`, opts);
  
  // Check if 'i' option is present (should NOT be for unpublished)
  if (opts.i) console.log(`  WARNING: 'i' option present → will be treated as published!`);
  if (!opts.host && !opts.port && !opts.i) console.log(`  ✓ Looks unpublished (no host/port/i)`);
}

// Peer count
const peerCount = ri.readUInt8(offset); offset += 1;
console.log(`\nPeer count: ${peerCount}`);
offset += peerCount * 32;

// Properties
const propsLen = ri.readUInt16BE(offset); offset += 2;
const propsBytes = ri.subarray(offset, offset + propsLen); offset += propsLen;
console.log(`Properties length: ${propsLen}`);

// Parse properties
const props = {};
let pOff = 0;
while (pOff < propsBytes.length) {
  const kLen = propsBytes.readUInt8(pOff); pOff += 1;
  const key = propsBytes.subarray(pOff, pOff + kLen).toString('ascii'); pOff += kLen;
  pOff += 1; // skip '='
  const vLen = propsBytes.readUInt8(pOff); pOff += 1;
  const val = propsBytes.subarray(pOff, pOff + vLen).toString('ascii'); pOff += vLen;
  pOff += 1; // skip ';'
  props[key] = val;
}
console.log('Properties:', props);

// Signature verification
const sigLen = 64; // Ed25519
const unsigned = ri.subarray(0, ri.length - sigLen);
const sig = ri.subarray(ri.length - sigLen);

console.log(`\nUnsigned data length: ${unsigned.length}`);
console.log(`Signature length: ${sig.length}`);
console.log(`Signature: ${sig.toString('hex')}`);

// Verify with @noble/curves
try {
  const valid = ed25519.verify(sig, unsigned, edPub);
  console.log(`\n=== Ed25519 Signature Verification: ${valid ? '✓ VALID' : '✗ INVALID'} ===`);
} catch (e) {
  console.error(`Signature verification ERROR: ${e.message}`);
}

// Also verify that the data after signature ends exactly at the RI boundary
console.log(`\nOffset after properties: ${offset}`);
console.log(`RI length minus sig: ${ri.length - 64}`);
console.log(`Match: ${offset === ri.length - 64 ? '✓ YES' : '✗ NO (off by ' + (offset - (ri.length - 64)) + ')'}`);

router.stop();
setTimeout(() => process.exit(0), 200);

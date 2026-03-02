#!/usr/bin/env node
/**
 * Test RI signature with both @noble/curves AND Node.js crypto (OpenSSL).
 */
import { I2PRouter, logger, LogLevel } from './dist/index.js';
import { ed25519 } from '@noble/curves/ed25519';
import { createPublicKey, verify as cryptoVerify, createPrivateKey, sign as cryptoSign } from 'crypto';

logger.setLevel(LogLevel.WARN);

const router = new I2PRouter({
  ntcp2Port: 0, ssu2Port: 0, samPort: 0,
  bandwidthClass: 'L', isFloodfill: false,
  logLevel: LogLevel.WARN, enableWebUI: false,
  dataDir: './i2p-test-data'
});

await router.start();

const ri = router.wireRouterInfo;
console.log(`RI length: ${ri.length}`);

// Extract Ed25519 pubkey from identity
const edPub = ri.subarray(352, 384);
const unsigned = ri.subarray(0, ri.length - 64);
const sig = ri.subarray(ri.length - 64);

console.log(`\nEd25519 pubkey: ${edPub.toString('hex')}`);
console.log(`Unsigned length: ${unsigned.length}`);
console.log(`Signature: ${sig.toString('hex')}`);

// Test 1: Verify with @noble/curves
try {
  const ok1 = ed25519.verify(sig, unsigned, edPub);
  console.log(`\n@noble/curves verify: ${ok1 ? '✓ VALID' : '✗ INVALID'}`);
} catch (e) {
  console.log(`@noble/curves verify ERROR: ${e.message}`);
}

// Test 2: Verify with Node.js crypto (OpenSSL)
try {
  const pubKeyObj = createPublicKey({
    key: Buffer.concat([
      // Ed25519 public key in DER format (PKCS#8)
      Buffer.from('302a300506032b6570032100', 'hex'), // DER prefix for Ed25519 pubkey
      edPub
    ]),
    format: 'der',
    type: 'spki'
  });
  const ok2 = cryptoVerify(null, unsigned, pubKeyObj, sig);
  console.log(`Node.js crypto verify: ${ok2 ? '✓ VALID' : '✗ INVALID'}`);
} catch (e) {
  console.log(`Node.js crypto verify ERROR: ${e.message}`);
}

// Test 3: Sign with Node.js crypto and verify with @noble/curves
console.log('\n--- Cross-compatibility test ---');
const identity = router.identity;
if (identity) {
  const sigPrivKey = identity.signingPrivateKey;
  console.log(`Signing private key (seed) length: ${sigPrivKey.length}`);
  
  // Sign with Node.js crypto
  try {
    const privKeyObj = createPrivateKey({
      key: Buffer.concat([
        // Ed25519 private key in DER format (PKCS#8)
        Buffer.from('302e020100300506032b657004220420', 'hex'), // DER prefix for Ed25519 privkey
        Buffer.from(sigPrivKey)
      ]),
      format: 'der',
      type: 'pkcs8'
    });
    const nodeSig = cryptoSign(null, unsigned, privKeyObj);
    console.log(`Node.js crypto signature: ${Buffer.from(nodeSig).toString('hex')}`);
    console.log(`@noble/curves signature: ${sig.toString('hex')}`);
    console.log(`Signatures match: ${Buffer.from(nodeSig).equals(sig) ? '✓ YES' : '✗ NO'}`);
    
    // If different, verify the Node.js signature with @noble/curves
    if (!Buffer.from(nodeSig).equals(sig)) {
      const ok3 = ed25519.verify(nodeSig, unsigned, edPub);
      console.log(`Node.js sig verified by @noble/curves: ${ok3 ? '✓ VALID' : '✗ INVALID'}`);
    }
  } catch (e) {
    console.log(`Cross-sign test ERROR: ${e.message}`);
  }
}

router.stop();
setTimeout(() => process.exit(0), 200);

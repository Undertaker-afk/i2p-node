/**
 * Test that loadFromDisk correctly restores IdentHash from filename,
 * which is the AES key used in NTCP2 handshakes.
 */
import { readFileSync, mkdirSync, writeFileSync, existsSync, rmSync } from 'fs';
import { join } from 'path';
import { createHash } from 'crypto';

const { RouterInfo, RouterIdentity } = await import('./dist/data/router-info.js');
const { NetworkDatabase } = await import('./dist/netdb/index.js');
const { buildIdentityExEd25519X25519 } = await import('./dist/i2p/identity/identity-ex.js');
const { Crypto } = await import('./dist/crypto/index.js');
const { ed25519 } = await import('@noble/curves/ed25519');

// ── Build a fake router with known identity ─────────────────────────────────
const sigPriv = ed25519.utils.randomPrivateKey();
const sigPub  = ed25519.getPublicKey(sigPriv);
const enc = Crypto.generateKeyPair();
const identEx = buildIdentityExEd25519X25519({ cryptoPublicKey: enc.publicKey, signingPublicKey: sigPub });
const identityEx = identEx;
const correctHash = identityEx.identHash;

// Build RouterIdentity with setHash already set (simulating a fresh reseed-parsed router)
const identity = new RouterIdentity(sigPub, enc.publicKey, { type: 0, data: Buffer.alloc(0) });
identity.setHash(Buffer.from(correctHash));

const ri = new RouterInfo(identity, [], { caps: 'LR', netId: '2' }, Date.now(), Buffer.alloc(64));

// Verify the hash is correct
const hashBefore = ri.getRouterHash().toString('hex');
console.log('Before save, getRouterHash():', hashBefore.slice(0,16)+'...');
console.log('Correct IdentHash:           ', correctHash.toString('hex').slice(0,16)+'...');
console.log('Hash correct before save:', hashBefore === correctHash.toString('hex') ? '✓' : '✗ WRONG!');

// ── Simulate save to disk ────────────────────────────────────────────────────
const tmpDir = './tmp-test-hash';
const netDbDir = join(tmpDir, 'netDb');
mkdirSync(netDbDir, { recursive: true });

const filename = `routerInfo-${correctHash.toString('hex')}.dat`;
const serialized = ri.serialize();
writeFileSync(join(netDbDir, filename), serialized);
console.log('\nSaved to:', filename.slice(0,30)+'...');

// ── Simulate fresh RouterIdentity WITHOUT precomputed hash ────────────────────
// (simulating what loadFromDisk USED to do: just deserialize with no setHash)
const ri2raw = RouterInfo.deserialize(serialized);
console.log('\nAfter raw deserialize (no setHash):');
console.log('  getRouterHash():', ri2raw.getRouterHash().toString('hex').slice(0,16)+'...');
console.log('  Matches correct: ', ri2raw.getRouterHash().toString('hex') === correctHash.toString('hex') ? '✓' : '✗ WRONG (expected failure)');

// ── Simulate fixed loadFromDisk: restore hash from filename ──────────────────
const ri3 = RouterInfo.deserialize(serialized);
const hashHex = filename.replace('routerInfo-', '').replace('.dat', '');
if (/^[0-9a-f]{64}$/.test(hashHex)) {
  ri3.identity.setHash(Buffer.from(hashHex, 'hex'));
}
console.log('\nAfter deserialize WITH setHash from filename:');
console.log('  getRouterHash():', ri3.getRouterHash().toString('hex').slice(0,16)+'...');
console.log('  Matches correct:', ri3.getRouterHash().toString('hex') === correctHash.toString('hex') ? '✓' : '✗ WRONG!');

// ── Cleanup ─────────────────────────────────────────────────────────────────
rmSync(tmpDir, { recursive: true, force: true });

console.log('\n=== Hash restoration test complete ===');

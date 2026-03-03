/**
 * LeaseSet LS1 + LS2 wire-format parser test.
 *
 * Constructs synthetic LS1 and LS2 payloads that match the i2pd wire format
 * and verifies our parsers round-trip correctly.
 */

import { createHash, randomBytes } from 'crypto';
import { buildIdentityExEd25519X25519 } from '../dist/i2p/identity/identity-ex.js';
import { parseLeaseSetLS1, parseLeaseSetLS2, getSigningKeyInfo } from '../dist/data/lease-set-i2p.js';
import { getIdentityLength } from '../dist/data/router-info-i2p.js';

let pass = 0;
let fail = 0;

function assert(cond, msg) {
  if (!cond) { console.error(`  FAIL: ${msg}`); fail++; }
  else       { console.log(`  PASS: ${msg}`); pass++; }
}

// ── helpers ──────────────────────────────────────────────────────────────

function makeIdentity() {
  const cryptoPub  = randomBytes(32);
  const signingPub = randomBytes(32);
  const { identityBytes, identHash } = buildIdentityExEd25519X25519({ cryptoPublicKey: cryptoPub, signingPublicKey: signingPub });
  return { identityBytes, identHash, signingPub };
}

function makeLease1() {
  const gw = randomBytes(32);
  const tunnelId = 0x12345678;
  const endDate = BigInt(Date.now() + 600_000); // +10 min
  const buf = Buffer.alloc(44);
  gw.copy(buf, 0);
  buf.writeUInt32BE(tunnelId, 32);
  buf.writeBigUInt64BE(endDate, 36);
  return { buf, gw, tunnelId, endDate: Number(endDate) };
}

function makeLease2() {
  const gw = randomBytes(32);
  const tunnelId = 0xABCDEF01;
  const endDateSec = Math.floor(Date.now() / 1000) + 600; // +10 min
  const buf = Buffer.alloc(40);
  gw.copy(buf, 0);
  buf.writeUInt32BE(tunnelId, 32);
  buf.writeUInt32BE(endDateSec, 36);
  return { buf, gw, tunnelId, endDateMs: endDateSec * 1000 };
}

// ── Test 1: identity length helper ──────────────────────────────────────

console.log('\n=== Test 1: getIdentityLength ===');
{
  const { identityBytes } = makeIdentity();
  const len = getIdentityLength(identityBytes);
  assert(len === 391, `Ed25519+X25519 identity should be 391 bytes, got ${len}`);
}

// ── Test 2: getSigningKeyInfo ───────────────────────────────────────────

console.log('\n=== Test 2: getSigningKeyInfo ===');
{
  const { identityBytes } = makeIdentity();
  const info = getSigningKeyInfo(identityBytes);
  assert(info.signingKeyLen === 32, `Ed25519 signing key should be 32, got ${info.signingKeyLen}`);
  assert(info.signatureLen === 64, `Ed25519 signature should be 64, got ${info.signatureLen}`);
}

// ── Test 3: LS1 round-trip ──────────────────────────────────────────────

console.log('\n=== Test 3: LS1 round-trip ===');
{
  const { identityBytes, identHash, signingPub } = makeIdentity();
  const encKey = randomBytes(256);
  const lease1 = makeLease1();
  const lease2 = makeLease1();
  const signature = randomBytes(64);

  // Build wire-format LS1:
  //   identity | encKey(256) | signingKey(32) | numLeases(1) | leases(N*44) | signature(64)
  const numLeases = Buffer.alloc(1);
  numLeases.writeUInt8(2);
  const ls1Wire = Buffer.concat([
    identityBytes,
    encKey,
    signingPub,         // Ed25519 signing public key (32 bytes, NOT the 128-byte padded field)
    numLeases,
    lease1.buf,
    lease2.buf,
    signature
  ]);

  const result = parseLeaseSetLS1(ls1Wire, identHash);
  assert(result !== null, 'parseLeaseSetLS1 should succeed');
  if (result) {
    assert(result.leases.length === 2, `should have 2 leases, got ${result.leases.length}`);
    assert(result.encryptionKey.length === 256, `encKey should be 256 bytes, got ${result.encryptionKey.length}`);
    assert(Buffer.from(result.encryptionKey).equals(encKey), 'encKey should match');
    assert(result.signingKey.length === 32, `sigKey should be 32 bytes, got ${result.signingKey.length}`);
    assert(result.leases[0].tunnelId === lease1.tunnelId, `lease 0 tunnelId should match`);
    assert(result.leases[0].expiration === lease1.endDate, `lease 0 expiration should match`);
    assert(Buffer.from(result.leases[0].tunnelGateway).equals(lease1.gw), `lease 0 gateway should match`);
    assert(result.leases[1].tunnelId === lease2.tunnelId, `lease 1 tunnelId should match`);
    assert(result.signature !== null && result.signature.length === 64, 'signature should be 64 bytes');

    // Hash should match the ident hash
    const hash = result.getHash();
    assert(hash.equals(identHash), 'getHash() should return identity hash');
  }
}

// ── Test 4: LS1 truncation detection ────────────────────────────────────

console.log('\n=== Test 4: LS1 truncation ===');
{
  const { identityBytes, identHash, signingPub } = makeIdentity();
  const truncated = Buffer.concat([identityBytes, randomBytes(100)]); // too short for 256 encKey
  const result = parseLeaseSetLS1(truncated, identHash);
  assert(result === null, 'truncated LS1 should return null');
}

// ── Test 5: LS2 round-trip ──────────────────────────────────────────────

console.log('\n=== Test 5: LS2 round-trip ===');
{
  const { identityBytes, identHash } = makeIdentity();
  const encKeyData = randomBytes(32); // X25519 encryption key (32 bytes for ECIES-X25519-AEAD)
  const lease1 = makeLease2();
  const lease2 = makeLease2();
  const signature = randomBytes(64);

  // Build wire-format LS2:
  //   identity | published(4) | expires(2) | flags(2) |
  //   properties_len(2) | properties(0) |
  //   numKeySections(1) | (keyType(2) + keyLen(2) + key)... |
  //   numLeases(1) | leases(N*40) |
  //   signature(64)

  const publishedSec = Math.floor(Date.now() / 1000);
  const expiresSec   = 600; // 10 min
  const flags        = 0;

  const header = Buffer.alloc(8);
  header.writeUInt32BE(publishedSec, 0);
  header.writeUInt16BE(expiresSec, 4);
  header.writeUInt16BE(flags, 6);

  const propsLen = Buffer.alloc(2);
  propsLen.writeUInt16BE(0);

  // Key section: 1 section, type=4 (ECIES-X25519-AEAD), key=32 bytes
  const numKeys = Buffer.alloc(1);
  numKeys.writeUInt8(1);
  const keySection = Buffer.alloc(4 + 32);
  keySection.writeUInt16BE(4, 0); // keyType = ECIES-X25519-AEAD
  keySection.writeUInt16BE(32, 2);
  encKeyData.copy(keySection, 4);

  const numLeases = Buffer.alloc(1);
  numLeases.writeUInt8(2);

  const ls2Wire = Buffer.concat([
    identityBytes,
    header,
    propsLen,
    numKeys,
    keySection,
    numLeases,
    lease1.buf,
    lease2.buf,
    signature
  ]);

  const result = parseLeaseSetLS2(ls2Wire, identHash);
  assert(result !== null, 'parseLeaseSetLS2 should succeed');
  if (result) {
    assert(result.leases.length === 2, `should have 2 leases, got ${result.leases.length}`);
    assert(result.encryptionKey.length === 32, `encKey should be 32 bytes, got ${result.encryptionKey.length}`);
    assert(Buffer.from(result.encryptionKey).equals(encKeyData), 'encKey should match');
    assert(result.leases[0].tunnelId === lease1.tunnelId, `lease 0 tunnelId`);
    assert(result.leases[0].expiration === lease1.endDateMs, `lease 0 expiration`);
    assert(Buffer.from(result.leases[0].tunnelGateway).equals(lease1.gw), `lease 0 gateway`);
    assert(result.leases[1].tunnelId === lease2.tunnelId, `lease 1 tunnelId`);

    const hash = result.getHash();
    assert(hash.equals(identHash), 'getHash() should return identity hash');
  }
}

// ── Test 6: LS2 with multiple key sections ──────────────────────────────

console.log('\n=== Test 6: LS2 multiple key sections ===');
{
  const { identityBytes, identHash } = makeIdentity();
  const elgKey    = randomBytes(256); // ElGamal key (type 0)
  const x25519Key = randomBytes(32);  // ECIES-X25519 (type 4)
  const lease     = makeLease2();
  const signature = randomBytes(64);

  const header = Buffer.alloc(8);
  header.writeUInt32BE(Math.floor(Date.now() / 1000), 0);
  header.writeUInt16BE(600, 4);
  header.writeUInt16BE(0, 6);

  const propsLen = Buffer.alloc(2);
  propsLen.writeUInt16BE(0);

  const numKeys = Buffer.alloc(1);
  numKeys.writeUInt8(2);

  // Key section 1: ElGamal (type 0)
  const keySection1 = Buffer.alloc(4 + 256);
  keySection1.writeUInt16BE(0, 0);   // keyType 0
  keySection1.writeUInt16BE(256, 2); // keyLen
  elgKey.copy(keySection1, 4);

  // Key section 2: X25519 (type 4, preferred)
  const keySection2 = Buffer.alloc(4 + 32);
  keySection2.writeUInt16BE(4, 0);
  keySection2.writeUInt16BE(32, 2);
  x25519Key.copy(keySection2, 4);

  const numLeases = Buffer.alloc(1);
  numLeases.writeUInt8(1);

  const ls2Wire = Buffer.concat([
    identityBytes,
    header,
    propsLen,
    numKeys,
    keySection1,
    keySection2,
    numLeases,
    lease.buf,
    signature
  ]);

  const result = parseLeaseSetLS2(ls2Wire, identHash);
  assert(result !== null, 'multi-key LS2 should parse');
  if (result) {
    // The parser should pick the X25519 key (type 4) since it's preferred
    assert(result.encryptionKey.length === 32, `should pick 32-byte X25519 key, got ${result.encryptionKey.length}`);
    assert(Buffer.from(result.encryptionKey).equals(x25519Key), 'should pick X25519 key over ElGamal');
    assert(result.leases.length === 1, 'should have 1 lease');
  }
}

// ── Test 7: LS1 with 0 leases rejected ──────────────────────────────────

console.log('\n=== Test 7: LS1 zero leases ===');
{
  const { identityBytes, identHash, signingPub } = makeIdentity();
  const encKey = randomBytes(256);
  const numLeases = Buffer.alloc(1);
  numLeases.writeUInt8(0);
  const ls1 = Buffer.concat([identityBytes, encKey, signingPub, numLeases, randomBytes(64)]);
  const result = parseLeaseSetLS1(ls1, identHash);
  assert(result === null, 'LS1 with 0 leases should be rejected');
}

// ── Test 8: LeaseSet.getHash() uses ident hash ─────────────────────────

console.log('\n=== Test 8: LeaseSet.getHash() ===');
{
  // Import the LeaseSet class
  const { LeaseSet, Lease } = await import('../dist/data/lease-set.js');
  const { RouterIdentity } = await import('../dist/data/router-info.js');

  const identity = new RouterIdentity(randomBytes(32), randomBytes(32));
  const preHash = randomBytes(32);
  identity.setHash(preHash);

  const ls = new LeaseSet(identity, randomBytes(256), randomBytes(32), [
    new Lease(randomBytes(32), 42, Date.now() + 60000)
  ], randomBytes(64));

  const hash = ls.getHash();
  assert(hash.equals(preHash), 'LeaseSet.getHash() should return destination ident hash, not custom serialize hash');
}

// ── Summary ──────────────────────────────────────────────────────────────

console.log(`\n${'='.repeat(40)}`);
console.log(`Results: ${pass} passed, ${fail} failed`);
if (fail > 0) process.exit(1);
else console.log('All tests passed!');

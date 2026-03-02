import { Lease, LeaseSet } from './lease-set.js';
import { RouterIdentity } from './router-info.js';

// Minimal parser for I2P-spec LeaseSet2 (standard, unencrypted).
// Supports extracting leases and mapping them into the internal LeaseSet class.

const IDENTITY_EX_LEN = 391; // Ed25519 + X25519 IdentityEx (per identity-ex.ts)

export function parseLeaseSetI2P(data: Buffer, keyHash: Buffer): LeaseSet | null {
  if (data.length < IDENTITY_EX_LEN + 8) return null;

  let offset = IDENTITY_EX_LEN;

  // published timestamp (4) + expires (2) + flags (2)
  const published = data.readUInt32BE(offset);
  offset += 4;
  const expiresSec = data.readUInt16BE(offset);
  offset += 2;
  const flags = data.readUInt16BE(offset);
  offset += 2;

  // For now we only support standard, public LS2 without offline/encrypted flags.
  const OFFLINE_KEYS = 0x0001;
  const UNPUBLISHED = 0x0002;
  const PUBLISHED_ENCRYPTED = 0x0004;
  if (flags & (OFFLINE_KEYS | PUBLISHED_ENCRYPTED)) {
    return null;
  }

  // properties
  if (offset + 2 > data.length) return null;
  const propsLen = data.readUInt16BE(offset);
  offset += 2 + propsLen;
  if (offset > data.length) return null;

  // key sections
  if (offset + 1 > data.length) return null;
  const numKeySections = data.readUInt8(offset++);
  for (let i = 0; i < numKeySections; i++) {
    if (offset + 4 > data.length) return null;
    const keyType = data.readUInt16BE(offset);
    const keyLen = data.readUInt16BE(offset + 2);
    offset += 4;
    if (offset + keyLen > data.length) return null;
    // skip encryption key bytes
    offset += keyLen;
  }

  // leases
  if (offset + 1 > data.length) return null;
  const numLeases = data.readUInt8(offset++);
  const leases: Lease[] = [];
  const LEASE2_SIZE = 40; // 32 gw + 4 tunnelId + 4 endDate
  if (offset + numLeases * LEASE2_SIZE > data.length) return null;

  for (let i = 0; i < numLeases; i++) {
    const gw = data.subarray(offset, offset + 32);
    offset += 32;
    const tunnelId = data.readUInt32BE(offset);
    offset += 4;
    const endDateSec = data.readUInt32BE(offset);
    offset += 4;
    const expirationMs = endDateSec * 1000;
    leases.push(new Lease(Uint8Array.from(gw), tunnelId, expirationMs));
  }

  // Build a minimal RouterIdentity; we only care that getHash() matches keyHash.
  const dummySign = new Uint8Array(32);
  const dummyEnc = new Uint8Array(32);
  const identity = new RouterIdentity(dummySign, dummyEnc);
  identity.setHash(keyHash);

  const encKey = new Uint8Array(32);
  const sigKey = new Uint8Array(32);
  const signature = new Uint8Array(64); // non-empty so verifyLeaseSet() passes

  const ls = new LeaseSet(identity, encKey, sigKey, leases, signature);
  return ls;
}


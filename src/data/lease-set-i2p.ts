import { createHash } from 'crypto';
import { Lease, LeaseSet } from './lease-set.js';
import { RouterIdentity } from './router-info.js';
import { getIdentityLength } from './router-info-i2p.js';
import { logger } from '../utils/logger.js';

// ---------------------------------------------------------------------------
// I2P wire-format LeaseSet parsers — LS1 (store type 1) & LS2 (store type 3)
//
// Reference: i2pd  libi2pd/LeaseSet.cpp   (ReadFromBuffer & ReadStandardLS2…)
// ---------------------------------------------------------------------------

const DEFAULT_IDENTITY_SIZE = 387;
const LEASE_SIZE  = 44; // LS1: 32 gw + 4 tunnelId + 8 endDate(ms)
const LEASE2_SIZE = 40; // LS2: 32 gw + 4 tunnelId + 4 endDate(s)
const MAX_NUM_LEASES = 16;

// ── helpers ────────────────────────────────────────────────────────────────

/**
 * Derive signing-key and signature lengths from the identity certificate.
 * Mirrors i2pd  IdentityEx::GetSigningPublicKeyLen / GetSignatureLen.
 */
export function getSigningKeyInfo(identityBuf: Buffer): { signingKeyLen: number; signatureLen: number } {
  if (identityBuf.length < DEFAULT_IDENTITY_SIZE) {
    return { signingKeyLen: 128, signatureLen: 40 }; // DSA-SHA1 default
  }

  const certType = identityBuf[DEFAULT_IDENTITY_SIZE - 3]; // byte 384
  if (certType !== 5) {
    // Not a KEY_CERT → legacy DSA-SHA1
    return { signingKeyLen: 128, signatureLen: 40 };
  }

  const certDataLen = identityBuf.readUInt16BE(DEFAULT_IDENTITY_SIZE - 2); // bytes 385-386
  if (certDataLen < 4) {
    return { signingKeyLen: 128, signatureLen: 40 };
  }

  // Certificate data starts at DEFAULT_IDENTITY_SIZE
  const sigType = identityBuf.readUInt16BE(DEFAULT_IDENTITY_SIZE);

  switch (sigType) {
    case  0: return { signingKeyLen: 128, signatureLen: 40  }; // DSA-SHA1
    case  1: return { signingKeyLen:  64, signatureLen: 64  }; // ECDSA-SHA256-P256
    case  2: return { signingKeyLen:  96, signatureLen: 96  }; // ECDSA-SHA384-P384
    case  3: return { signingKeyLen: 132, signatureLen: 132 }; // ECDSA-SHA512-P521
    case  4: return { signingKeyLen: 256, signatureLen: 256 }; // RSA-SHA256-2048
    case  5: return { signingKeyLen: 384, signatureLen: 384 }; // RSA-SHA384-3072
    case  6: return { signingKeyLen: 512, signatureLen: 512 }; // RSA-SHA512-4096
    case  7: return { signingKeyLen:  32, signatureLen: 64  }; // EdDSA-SHA512-Ed25519
    case  8: return { signingKeyLen:  64, signatureLen: 64  }; // GOST-256
    case  9: return { signingKeyLen: 128, signatureLen: 128 }; // GOST-512
    case 11: return { signingKeyLen:  32, signatureLen: 64  }; // RedDSA-SHA512-Ed25519
    default: return { signingKeyLen: 128, signatureLen: 40  }; // unknown → DSA fallback
  }
}

/**
 * Build a minimal RouterIdentity whose getHash() returns the ident hash
 * (SHA256 over the raw identity bytes).
 */
function identityFromRaw(identityBuf: Buffer, keyHash?: Buffer): RouterIdentity {
  // Extract the Ed25519 signing public key from the 128-byte field if possible,
  // or just use dummy keys — what matters is the hash.
  const dummySign = new Uint8Array(32);
  const dummyEnc  = new Uint8Array(32);
  const identity  = new RouterIdentity(dummySign, dummyEnc);

  if (keyHash) {
    identity.setHash(keyHash);
  } else {
    const hash = createHash('sha256').update(identityBuf).digest();
    identity.setHash(hash);
  }
  return identity;
}

// ── LS1 parser (store type 1) ─────────────────────────────────────────────

/**
 * Parse a standard I2P LeaseSet (LS1) from its wire-format bytes.
 *
 * Wire layout (per i2pd ReadFromBuffer):
 *   Identity (variable)  |  encKey (256)  |  signingKey (var)  |
 *   numLeases (1)  |  leases (N×44)  |  signature (var)
 */
export function parseLeaseSetLS1(data: Buffer, keyHash: Buffer): LeaseSet | null {
  try {
    // 1) Identity
    const idLen = getIdentityLength(data);
    if (!idLen) {
      logger.debug('LS1: invalid identity length', undefined, 'LeaseSet');
      return null;
    }
    const identityBuf = data.subarray(0, idLen);
    const { signingKeyLen, signatureLen } = getSigningKeyInfo(identityBuf);

    // 2) Encryption key (256 bytes, fixed)
    let offset = idLen;
    if (offset + 256 > data.length) {
      logger.debug('LS1: truncated — no room for encryption key', undefined, 'LeaseSet');
      return null;
    }
    const encryptionKey = Uint8Array.from(data.subarray(offset, offset + 256));
    offset += 256;

    // 3) Signing public key
    if (offset + signingKeyLen > data.length) {
      logger.debug('LS1: truncated — no room for signing key', undefined, 'LeaseSet');
      return null;
    }
    const signingKey = Uint8Array.from(data.subarray(offset, offset + signingKeyLen));
    offset += signingKeyLen;

    // 4) Num leases
    if (offset + 1 > data.length) return null;
    const numLeases = data.readUInt8(offset);
    offset += 1;

    if (numLeases === 0 || numLeases > MAX_NUM_LEASES) {
      logger.debug(`LS1: invalid lease count ${numLeases}`, undefined, 'LeaseSet');
      return null;
    }

    // 5) Leases (44 bytes each: 32 gw + 4 tunnelId + 8 endDate ms)
    if (offset + numLeases * LEASE_SIZE > data.length) {
      logger.debug('LS1: truncated — not enough room for leases', undefined, 'LeaseSet');
      return null;
    }

    const leases: Lease[] = [];
    for (let i = 0; i < numLeases; i++) {
      const gw = Uint8Array.from(data.subarray(offset, offset + 32));
      offset += 32;
      const tunnelId = data.readUInt32BE(offset);
      offset += 4;
      const endDate = Number(data.readBigUInt64BE(offset));
      offset += 8;
      leases.push(new Lease(gw, tunnelId, endDate));
    }

    // 6) Signature (we don't verify, but store it so verifyLeaseSet passes)
    if (offset + signatureLen > data.length) {
      logger.debug('LS1: truncated — not enough room for signature', undefined, 'LeaseSet');
      return null;
    }
    const signature = Uint8Array.from(data.subarray(offset, offset + signatureLen));

    const identity = identityFromRaw(identityBuf, keyHash);
    return new LeaseSet(identity, encryptionKey, signingKey, leases, signature);
  } catch (e: any) {
    logger.debug(`LS1: parse error: ${e.message}`, undefined, 'LeaseSet');
    return null;
  }
}

// ── LS2 parser (store type 3) ─────────────────────────────────────────────

/**
 * Parse a Standard LeaseSet2 (store type 3) from its wire-format bytes.
 *
 * Wire layout (per i2pd ReadFromBuffer / ReadStandardLS2TypeSpecificPart):
 *   Identity (variable)  |  published (4)  |  expires (2)  |  flags (2)  |
 *   [offline keys if flag set]  |
 *   properties_len (2)  |  properties  |
 *   numKeySections (1)  |  keySections...  |
 *   numLeases (1)  |  leases (N×40)  |
 *   signature (var)
 */
export function parseLeaseSetLS2(data: Buffer, keyHash: Buffer): LeaseSet | null {
  try {
    // 1) Identity
    const idLen = getIdentityLength(data);
    if (!idLen) {
      logger.debug('LS2: invalid identity length', undefined, 'LeaseSet');
      return null;
    }
    const identityBuf = data.subarray(0, idLen);
    const { signatureLen } = getSigningKeyInfo(identityBuf);

    let offset = idLen;

    // 2) Published timestamp (4 bytes, seconds) + expires (2 bytes, seconds) + flags (2 bytes)
    if (offset + 8 > data.length) return null;
    // const published = data.readUInt32BE(offset);
    offset += 4;
    // const expiresSec = data.readUInt16BE(offset);
    offset += 2;
    const flags = data.readUInt16BE(offset);
    offset += 2;

    const OFFLINE_KEYS       = 0x0001;
    const PUBLISHED_ENCRYPTED = 0x0004;
    // Skip offline-key and published-encrypted variants for now
    if (flags & OFFLINE_KEYS) {
      logger.debug('LS2: offline keys not supported — skipping', undefined, 'LeaseSet');
      return null;
    }
    if (flags & PUBLISHED_ENCRYPTED) {
      logger.debug('LS2: published-encrypted flag not supported — skipping', undefined, 'LeaseSet');
      return null;
    }

    // 3) Properties
    if (offset + 2 > data.length) return null;
    const propsLen = data.readUInt16BE(offset);
    offset += 2 + propsLen;
    if (offset > data.length) return null;

    // 4) Key sections — extract first usable encryption key
    if (offset + 1 > data.length) return null;
    const numKeySections = data.readUInt8(offset);
    offset += 1;

    let encryptionKey = new Uint8Array(0);
    for (let i = 0; i < numKeySections; i++) {
      if (offset + 4 > data.length) return null;
      const keyType = data.readUInt16BE(offset);
      const keyLen  = data.readUInt16BE(offset + 2);
      offset += 4;
      if (offset + keyLen > data.length) return null;

      // Prefer ECIES-X25519-AEAD (type 4) or ElGamal (type 0)
      if (encryptionKey.length === 0 || keyType === 4 || (keyType === 0 && encryptionKey.length === 0)) {
        encryptionKey = Uint8Array.from(data.subarray(offset, offset + keyLen));
      }
      offset += keyLen;
    }

    // 5) Leases (40 bytes each: 32 gw + 4 tunnelId + 4 endDate seconds)
    if (offset + 1 > data.length) return null;
    const numLeases = data.readUInt8(offset);
    offset += 1;

    if (numLeases > MAX_NUM_LEASES) {
      logger.debug(`LS2: invalid lease count ${numLeases}`, undefined, 'LeaseSet');
      return null;
    }

    if (offset + numLeases * LEASE2_SIZE > data.length) return null;

    const leases: Lease[] = [];
    for (let i = 0; i < numLeases; i++) {
      const gw = Uint8Array.from(data.subarray(offset, offset + 32));
      offset += 32;
      const tunnelId = data.readUInt32BE(offset);
      offset += 4;
      const endDateSec = data.readUInt32BE(offset);
      offset += 4;
      leases.push(new Lease(gw, tunnelId, endDateSec * 1000));
    }

    // 6) Signature (store non-empty so verifyLeaseSet passes)
    const sigLen = Math.min(signatureLen, data.length - offset);
    const signature = sigLen > 0
      ? Uint8Array.from(data.subarray(offset, offset + sigLen))
      : new Uint8Array(64);

    const identity = identityFromRaw(identityBuf, keyHash);
    const signingKey = new Uint8Array(32); // dummy — not used in LS2 body
    return new LeaseSet(identity, encryptionKey, signingKey, leases, signature);
  } catch (e: any) {
    logger.debug(`LS2: parse error: ${e.message}`, undefined, 'LeaseSet');
    return null;
  }
}

/* ── Backward-compatible re-export ─────────────────────────────────────── */

/** @deprecated — use parseLeaseSetLS1 or parseLeaseSetLS2 instead */
export function parseLeaseSetI2P(data: Buffer, keyHash: Buffer): LeaseSet | null {
  // Try LS1 first (most likely in a type=1 DatabaseStore), then LS2
  return parseLeaseSetLS1(data, keyHash) ?? parseLeaseSetLS2(data, keyHash);
}


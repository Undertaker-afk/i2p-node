import { createHash, randomBytes as nodeRandomBytes } from 'crypto';

// Mirrors i2pd constants (Identity.h)
export const CERTIFICATE_TYPE_KEY = 5;
export const DEFAULT_IDENTITY_SIZE = 387; // 256 + 128 + 3

// Mirrors i2pd key type constants
export const SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519 = 7;
export const CRYPTO_KEY_TYPE_ECIES_X25519_AEAD = 4;

export interface IdentityExKeys {
  cryptoPublicKey: Uint8Array; // X25519, 32 bytes
  signingPublicKey: Uint8Array; // Ed25519, 32 bytes
}

export interface IdentityExBuildResult {
  identityBytes: Buffer; // 391 bytes (387 + 4)
  identHash: Buffer; // sha256(identityBytes)
}

/**
 * Build an i2pd-compatible IdentityEx for (Ed25519 signing, X25519 crypto).
 *
 * i2pd layout:
 * - StandardIdentity (387):
 *   - publicKey[256]  (X25519 key in first 32 bytes, rest random padding)
 *   - signingKey[128] (Ed25519 pubkey right-aligned: 96 bytes padding + 32 bytes pubkey)
 *   - certificate[3]  (type=KEY, len=4)
 * - ExtendedBuffer (4):
 *   - signingKeyType (2 bytes BE)
 *   - cryptoKeyType  (2 bytes BE)
 */
export function buildIdentityExEd25519X25519(
  keys: IdentityExKeys,
  rnd: (n: number) => Buffer = (n) => nodeRandomBytes(n)
): IdentityExBuildResult {
  if (keys.cryptoPublicKey.length !== 32) throw new Error('cryptoPublicKey must be 32 bytes (X25519)');
  if (keys.signingPublicKey.length !== 32) throw new Error('signingPublicKey must be 32 bytes (Ed25519)');

  const publicKey = Buffer.alloc(256);
  const signingKey = Buffer.alloc(128);

  // X25519: first 32 bytes are pubkey, rest random
  Buffer.from(keys.cryptoPublicKey).copy(publicKey, 0);
  rnd(224).copy(publicKey, 32);

  // Ed25519: right-aligned in 128 with 96 bytes padding
  rnd(96).copy(signingKey, 0);
  Buffer.from(keys.signingPublicKey).copy(signingKey, 96);

  // certificate: type + length(2)
  const certificate = Buffer.alloc(3);
  certificate.writeUInt8(CERTIFICATE_TYPE_KEY, 0);
  certificate.writeUInt16BE(4, 1); // extended len

  const standard = Buffer.concat([publicKey, signingKey, certificate]);
  if (standard.length !== DEFAULT_IDENTITY_SIZE) {
    throw new Error(`Standard identity size mismatch: ${standard.length}`);
  }

  // extended: sigType + cryptoType
  const ext = Buffer.alloc(4);
  ext.writeUInt16BE(SIGNING_KEY_TYPE_EDDSA_SHA512_ED25519, 0);
  ext.writeUInt16BE(CRYPTO_KEY_TYPE_ECIES_X25519_AEAD, 2);

  const identityBytes = Buffer.concat([standard, ext]);
  const identHash = createHash('sha256').update(identityBytes).digest();
  return { identityBytes, identHash };
}


import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export class Crypto {
  static generateKeyPair(): KeyPair {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey, publicKey };
  }

  static generateEphemeralKeyPair(): KeyPair {
    return this.generateKeyPair();
  }

  static x25519DiffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return x25519.getSharedSecret(privateKey, publicKey);
  }

  static sha256(data: Uint8Array): Uint8Array {
    return sha256(data) as Uint8Array;
  }

  static hmacSHA256(key: Uint8Array, data: Uint8Array): Uint8Array {
    return hmac(sha256, key, data) as Uint8Array;
  }

  static hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Uint8Array {
    return this.hmacSHA256(salt, ikm);
  }

  static hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    const okm: number[] = [];
    let previous: Uint8Array = new Uint8Array(0);
    const n = Math.ceil(length / 32);
    
    for (let i = 1; i <= n; i++) {
      const data = new Uint8Array([...Array.from(previous), ...Array.from(info), i]);
      const hmacResult = this.hmacSHA256(prk, data);
      previous = new Uint8Array(hmacResult);
      okm.push(...Array.from(previous));
    }
    
    return new Uint8Array(okm.slice(0, length));
  }

  static hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Uint8Array {
    const prk = this.hkdfExtract(salt, ikm);
    return this.hkdfExpand(prk, info, length);
  }

  static encryptChaCha20Poly1305(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array()
  ): Uint8Array {
    // noble-ciphers may mutate views (e.g. nonce) internally; ensure we don't
    // pass Node Buffers or shared views that could be reused elsewhere.
    const k = Uint8Array.from(key);
    const n = Uint8Array.from(nonce);
    const ad = Uint8Array.from(associatedData);
    const pt = Uint8Array.from(plaintext);
    const cipher = chacha20poly1305(k, n, ad);
    return cipher.encrypt(pt);
  }

  static decryptChaCha20Poly1305(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array()
  ): Uint8Array {
    const k = Uint8Array.from(key);
    const n = Uint8Array.from(nonce);
    const ad = Uint8Array.from(associatedData);
    const ct = Uint8Array.from(ciphertext);
    const cipher = chacha20poly1305(k, n, ad);
    return cipher.decrypt(ct);
  }

  static randomBytes(length: number): Uint8Array {
    return randomBytes(length);
  }

  /**
   * SipHash-2-4 (8-byte output) used by NTCP2 for length obfuscation.
   * Key parts are 8 bytes each, little endian as specified by NTCP2.
   */
  static siphash24(key1: Uint8Array, key2: Uint8Array, data: Uint8Array): bigint {
    if (key1.length !== 8 || key2.length !== 8) throw new Error('SipHash keys must be 8 bytes each');
    const key = new Uint8Array(16);
    key.set(key1, 0);
    key.set(key2, 8);
    return siphash24_64(data, key);
  }

  static aesEncryptCBC(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer {
    const cipher = createCipheriv('aes-256-cbc', key, iv);
    cipher.setAutoPadding(false);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return encrypted;
  }

  static aesDecryptCBC(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer {
    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    decipher.setAutoPadding(false);
    const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return decrypted;
  }
}

export default Crypto;

function readU64LE(b: Uint8Array, off: number): bigint {
  let out = 0n;
  for (let i = 7; i >= 0; i--) out = (out << 8n) | BigInt(b[off + i]!);
  return out;
}

function rotl64(x: bigint, b: bigint): bigint {
  return ((x << b) | (x >> (64n - b))) & 0xffffffffffffffffn;
}

function sipRound(v: [bigint, bigint, bigint, bigint]): void {
  let [v0, v1, v2, v3] = v;
  v0 = (v0 + v1) & 0xffffffffffffffffn;
  v1 = rotl64(v1, 13n);
  v1 ^= v0;
  v0 = rotl64(v0, 32n);
  v2 = (v2 + v3) & 0xffffffffffffffffn;
  v3 = rotl64(v3, 16n);
  v3 ^= v2;
  v0 = (v0 + v3) & 0xffffffffffffffffn;
  v3 = rotl64(v3, 21n);
  v3 ^= v0;
  v2 = (v2 + v1) & 0xffffffffffffffffn;
  v1 = rotl64(v1, 17n);
  v1 ^= v2;
  v2 = rotl64(v2, 32n);
  v[0] = v0;
  v[1] = v1;
  v[2] = v2;
  v[3] = v3;
}

/**
 * SipHash-2-4, 64-bit output.
 * Ported from i2pd `libi2pd/Siphash.h` (little-endian key + message words).
 */
function siphash24_64(msg: Uint8Array, key16: Uint8Array): bigint {
  if (key16.length !== 16) throw new Error('SipHash key must be 16 bytes');

  const k0 = readU64LE(key16, 0);
  const k1 = readU64LE(key16, 8);

  let v0 = 0x736f6d6570736575n ^ k0;
  let v1 = 0x646f72616e646f6dn ^ k1;
  let v2 = 0x6c7967656e657261n ^ k0;
  let v3 = 0x7465646279746573n ^ k1;

  const end = msg.length - (msg.length % 8);
  let b = BigInt(msg.length) << 56n;

  for (let i = 0; i < end; i += 8) {
    const mi = readU64LE(msg, i);
    v3 ^= mi;
    const vs: [bigint, bigint, bigint, bigint] = [v0, v1, v2, v3];
    sipRound(vs);
    sipRound(vs);
    [v0, v1, v2, v3] = vs;
    v0 ^= mi;
  }

  // last partial
  for (let i = msg.length - 1; i >= end; i--) {
    b |= BigInt(msg[i]!) << BigInt((i - end) * 8);
  }

  v3 ^= b;
  {
    const vs: [bigint, bigint, bigint, bigint] = [v0, v1, v2, v3];
    sipRound(vs);
    sipRound(vs);
    [v0, v1, v2, v3] = vs;
  }
  v0 ^= b;

  v2 ^= 0xffn;
  {
    const vs: [bigint, bigint, bigint, bigint] = [v0, v1, v2, v3];
    sipRound(vs);
    sipRound(vs);
    sipRound(vs);
    sipRound(vs);
    [v0, v1, v2, v3] = vs;
  }

  return (v0 ^ v1 ^ v2 ^ v3) & 0xffffffffffffffffn;
}

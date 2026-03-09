import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { chacha20poly1305 } from '@noble/ciphers/chacha';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { siphash } from 'bsip';

export interface KeyPair {
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}

export class Crypto {
  private static readonly CHACHA_NONCE_LEN = 12;
  private static readonly NOISE_N_PROTOCOL_NAME = Buffer.from('Noise_N_25519_ChaChaPoly_SHA256', 'ascii');

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
   * Now using official bsip library from bcoin-org for increased stability.
   */
  static siphash24(key1: Uint8Array, key2: Uint8Array, data: Uint8Array): bigint {
    if (key1.length !== 8 || key2.length !== 8) throw new Error('SipHash keys must be 8 bytes each');
    const key = Buffer.alloc(16);
    key.set(key1, 0);
    key.set(key2, 8);
    const dataBuffer = Buffer.from(data);
    const [hi, lo] = siphash(dataBuffer, key);
    // Convert the result from [hi, lo] 32-bit integers to a 64-bit bigint
    // bsip returns [hi, lo] where hi is the high 32 bits and lo is the low 32 bits
    // hi and lo are signed 32-bit integers, need to convert to unsigned
    const loU = BigInt(lo >>> 0);
    const hiU = BigInt(hi >>> 0);
    return (hiU << 32n) | loU;
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

  static encryptTaggedGarlicReply(
    sessionKey: Uint8Array,
    sessionTag: Uint8Array,
    plaintext: Uint8Array
  ): Buffer {
    if (sessionKey.length !== 32) throw new Error('Tagged garlic session key must be 32 bytes');
    if (sessionTag.length !== 8) throw new Error('Tagged garlic session tag must be 8 bytes');
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    return Buffer.from(this.encryptChaCha20Poly1305(sessionKey, nonce, plaintext, sessionTag));
  }

  static decryptTaggedGarlicReply(
    sessionKey: Uint8Array,
    sessionTag: Uint8Array,
    ciphertext: Uint8Array
  ): Buffer {
    if (sessionKey.length !== 32) throw new Error('Tagged garlic session key must be 32 bytes');
    if (sessionTag.length !== 8) throw new Error('Tagged garlic session tag must be 8 bytes');
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    return Buffer.from(this.decryptChaCha20Poly1305(sessionKey, nonce, ciphertext, sessionTag));
  }

  static encryptNoiseNGarlicReply(
    recipientStaticPublicKey: Uint8Array,
    plaintext: Uint8Array
  ): { ephemeralPublicKey: Buffer; ciphertext: Buffer } {
    if (recipientStaticPublicKey.length !== 32) {
      throw new Error('Noise_N recipient static public key must be 32 bytes');
    }

    const ephemeral = this.generateEphemeralKeyPair();
    const { h, key } = this.deriveNoiseNKey(
      Buffer.from(recipientStaticPublicKey),
      Buffer.from(ephemeral.publicKey),
      this.x25519DiffieHellman(ephemeral.privateKey, recipientStaticPublicKey)
    );
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);

    return {
      ephemeralPublicKey: Buffer.from(ephemeral.publicKey),
      ciphertext: Buffer.from(this.encryptChaCha20Poly1305(key, nonce, plaintext, h))
    };
  }

  static decryptNoiseNGarlicReply(
    recipientStaticPrivateKey: Uint8Array,
    recipientStaticPublicKey: Uint8Array,
    ephemeralPublicKey: Uint8Array,
    ciphertext: Uint8Array
  ): Buffer {
    if (recipientStaticPrivateKey.length !== 32) {
      throw new Error('Noise_N recipient static private key must be 32 bytes');
    }
    if (recipientStaticPublicKey.length !== 32) {
      throw new Error('Noise_N recipient static public key must be 32 bytes');
    }
    if (ephemeralPublicKey.length !== 32) {
      throw new Error('Noise_N ephemeral public key must be 32 bytes');
    }

    const { h, key } = this.deriveNoiseNKey(
      Buffer.from(recipientStaticPublicKey),
      Buffer.from(ephemeralPublicKey),
      this.x25519DiffieHellman(recipientStaticPrivateKey, ephemeralPublicKey)
    );
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    return Buffer.from(this.decryptChaCha20Poly1305(key, nonce, ciphertext, h));
  }

  private static deriveNoiseNKey(
    recipientStaticPublicKey: Buffer,
    ephemeralPublicKey: Buffer,
    sharedSecret: Uint8Array
  ): { h: Buffer; key: Buffer } {
    let h = Buffer.from(this.sha256(this.NOISE_N_PROTOCOL_NAME));
    const ck = Buffer.from(h);
    h = Buffer.from(this.sha256(Buffer.concat([h, recipientStaticPublicKey])));
    h = Buffer.from(this.sha256(Buffer.concat([h, ephemeralPublicKey])));

    const derived = Buffer.from(this.hkdf(ck, sharedSecret, new Uint8Array(0), 64));
    return {
      h,
      key: derived.subarray(32, 64)
    };
  }
}

export default Crypto;

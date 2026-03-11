import { x25519 } from '@noble/curves/ed25519';
import { sha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';
import { chacha20poly1305, chacha20 } from '@noble/ciphers/chacha';
import { randomBytes, createCipheriv, createDecipheriv } from 'crypto';
import { siphash } from 'bsip';

export interface KeyPair {
  privateKey: Buffer;
  publicKey: Buffer;
}

export class NoiseSymmetricState {
  public h: Buffer;
  public ck: Buffer;

  constructor() {
    this.h = Buffer.alloc(32);
    this.ck = Buffer.alloc(64);
  }

  mixHash(data: Uint8Array): void {
    this.h = Crypto.sha256(Buffer.concat([this.h, Buffer.from(data)]));
  }

  mixKey(sharedSecret: Uint8Array): void {
    const derived = Crypto.hkdf(this.ck.subarray(0, 32), sharedSecret, Buffer.alloc(0), 64);
    this.ck.set(derived);
  }

  static InitNoiseNState(noise: NoiseSymmetricState, remoteStaticPubKey: Uint8Array): void {
    noise.h = Crypto.sha256(Buffer.from('Noise_N_25519_ChaChaPoly_SHA256', 'ascii'));
    noise.ck.fill(0);
    noise.ck.set(noise.h.subarray(0, 32));
    noise.mixHash(remoteStaticPubKey);
  }
}

export class Crypto {
  private static readonly CHACHA_NONCE_LEN = 12;

  static generateKeyPair(): KeyPair {
    const privateKey = x25519.utils.randomPrivateKey();
    const publicKey = x25519.getPublicKey(privateKey);
    return { privateKey: Buffer.from(privateKey), publicKey: Buffer.from(publicKey) };
  }

  static generateEphemeralKeyPair(): KeyPair {
    return this.generateKeyPair();
  }

  static x25519DiffieHellman(privateKey: Uint8Array, publicKey: Uint8Array): Buffer {
    return Buffer.from(x25519.getSharedSecret(Uint8Array.from(privateKey), Uint8Array.from(publicKey)));
  }

  static sha256(data: Uint8Array): Buffer {
    return Buffer.from(sha256(Uint8Array.from(data)));
  }

  static hmacSHA256(key: Uint8Array, data: Uint8Array): Buffer {
    return Buffer.from(hmac(sha256, Uint8Array.from(key), Uint8Array.from(data)));
  }

  static hkdfExtract(salt: Uint8Array, ikm: Uint8Array): Buffer {
    return this.hmacSHA256(salt, ikm);
  }

  static hkdfExpand(prk: Uint8Array, info: Uint8Array, length: number): Buffer {
    const okm: number[] = [];
    let previous: Uint8Array = new Uint8Array(0);
    const n = Math.ceil(length / 32);
    for (let i = 1; i <= n; i++) {
      const data = new Uint8Array([...Array.from(previous), ...Array.from(info), i]);
      const hmacResult = this.hmacSHA256(prk, data);
      previous = new Uint8Array(hmacResult);
      okm.push(...Array.from(previous));
    }
    return Buffer.from(okm.slice(0, length));
  }

  static hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, length: number): Buffer {
    const prk = this.hkdfExtract(salt, ikm);
    return this.hkdfExpand(prk, info, length);
  }

  static encryptChaCha20Poly1305(
    key: Uint8Array,
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array()
  ): Buffer {
    const cipher = chacha20poly1305(Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(associatedData));
    return Buffer.from(cipher.encrypt(Uint8Array.from(plaintext)));
  }

  static decryptChaCha20Poly1305(
    key: Uint8Array,
    nonce: Uint8Array,
    ciphertext: Uint8Array,
    associatedData: Uint8Array = new Uint8Array()
  ): Buffer {
    const cipher = chacha20poly1305(Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(associatedData));
    return Buffer.from(cipher.decrypt(Uint8Array.from(ciphertext)));
  }

  static decryptChaCha20(key: Uint8Array, nonce: Uint8Array, ciphertext: Uint8Array): Buffer {
    return Buffer.from(chacha20(Uint8Array.from(key), Uint8Array.from(nonce), Uint8Array.from(ciphertext)));
  }

  static randomBytes(length: number): Buffer {
    return Buffer.from(randomBytes(length));
  }

  static siphash24(key1: Uint8Array, key2: Uint8Array, data: Uint8Array): bigint {
    const key = Buffer.alloc(16);
    key.set(key1, 0);
    key.set(key2, 8);
    const [hi, lo] = siphash(Buffer.from(data), key);
    return (BigInt(hi >>> 0) << 32n) | BigInt(lo >>> 0);
  }

  static aesEncryptCBC(plaintext: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer {
    const cipher = createCipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv));
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  }

  static aesDecryptCBC(ciphertext: Uint8Array, key: Uint8Array, iv: Uint8Array): Buffer {
    const decipher = createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv));
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
  }

  static aesEncryptECB(plaintext: Uint8Array, key: Uint8Array): Buffer {
    const cipher = createCipheriv('aes-256-ecb', Buffer.from(key), null);
    cipher.setAutoPadding(false);
    return Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  }

  static aesDecryptECB(ciphertext: Uint8Array, key: Uint8Array): Buffer {
    const decipher = createDecipheriv('aes-256-ecb', Buffer.from(key), null);
    decipher.setAutoPadding(false);
    return Buffer.concat([decipher.update(Buffer.from(ciphertext)), decipher.final()]);
  }

  static createCipher(key: Uint8Array, iv: Uint8Array): any {
    const cipher = createCipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv));
    cipher.setAutoPadding(false);
    return cipher;
  }

  static createDecipher(key: Uint8Array, iv: Uint8Array): any {
    const decipher = createDecipheriv('aes-256-cbc', Buffer.from(key), Buffer.from(iv));
    decipher.setAutoPadding(false);
    return decipher;
  }

  static encryptTaggedGarlicReply(sessionKey: Uint8Array, sessionTag: Uint8Array, plaintext: Uint8Array): Buffer {
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    return this.encryptChaCha20Poly1305(sessionKey, nonce, plaintext, sessionTag);
  }

  static decryptTaggedGarlicReply(sessionKey: Uint8Array, sessionTag: Uint8Array, ciphertext: Uint8Array): Buffer {
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    try {
      return this.decryptChaCha20Poly1305(sessionKey, nonce, ciphertext, sessionTag);
    } catch (err: any) {
      throw new Error(`AEAD decryption failed: ${err.message}`);
    }
  }

  static decryptNoiseNGarlicReplyDirect(recipientStaticPrivateKey: Uint8Array, ephemeralPublicKey: Uint8Array, ciphertext: Uint8Array): Buffer {
    return this.decryptNoiseNGarlicReply(recipientStaticPrivateKey, Buffer.from(x25519.getPublicKey(Uint8Array.from(recipientStaticPrivateKey))), ephemeralPublicKey, ciphertext);
  }

  static encryptNoiseNGarlicReply(recipientStaticPublicKey: Uint8Array, plaintext: Uint8Array): { ephemeralPublicKey: Buffer; ciphertext: Buffer } {
    const ephemeralKeyPair = this.generateEphemeralKeyPair();
    const { h, key } = this.deriveNoiseNKey(Buffer.from(recipientStaticPublicKey), Buffer.from(ephemeralKeyPair.publicKey), this.x25519DiffieHellman(ephemeralKeyPair.privateKey, recipientStaticPublicKey));
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    return {
      ephemeralPublicKey: Buffer.from(ephemeralKeyPair.publicKey),
      ciphertext: this.encryptChaCha20Poly1305(key, nonce, plaintext, h)
    };
  }

  static decryptNoiseNGarlicReply(recipientStaticPrivateKey: Uint8Array, recipientStaticPublicKey: Uint8Array, ephemeralPublicKey: Uint8Array, ciphertext: Uint8Array): Buffer {
    const { h, key } = this.deriveNoiseNKey(Buffer.from(recipientStaticPublicKey), Buffer.from(ephemeralPublicKey), this.x25519DiffieHellman(recipientStaticPrivateKey, ephemeralPublicKey));
    const nonce = new Uint8Array(this.CHACHA_NONCE_LEN);
    try {
      return this.decryptChaCha20Poly1305(key, nonce, ciphertext, h);
    } catch (err: any) {
      throw new Error(`Noise_N AEAD decryption failed: ${err.message}`);
    }
  }

  private static deriveNoiseNKey(recipientStaticPublicKey: Buffer, ephemeralPublicKey: Buffer, sharedSecret: Uint8Array): { h: Buffer; key: Buffer } {
    const noise = new NoiseSymmetricState();
    NoiseSymmetricState.InitNoiseNState(noise, recipientStaticPublicKey);
    noise.mixHash(ephemeralPublicKey);
    noise.mixKey(sharedSecret);
    return { h: noise.h, key: Buffer.from(noise.ck.subarray(32, 64)) };
  }
}

export default Crypto;

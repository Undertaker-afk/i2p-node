import test from 'node:test';
import assert from 'node:assert/strict';
import { Crypto } from './index.js';

test('tagged garlic reply encryption round-trips', () => {
  const sessionKey = Buffer.from(Crypto.randomBytes(32));
  const sessionTag = Buffer.from(Crypto.randomBytes(8));
  const plaintext = Buffer.from('tagged garlic payload');

  const ciphertext = Crypto.encryptTaggedGarlicReply(sessionKey, sessionTag, plaintext);
  const decrypted = Crypto.decryptTaggedGarlicReply(sessionKey, sessionTag, ciphertext);

  assert.deepEqual(decrypted, plaintext);
});

test('Noise_N garlic reply encryption round-trips', () => {
  const recipient = Crypto.generateKeyPair();
  const plaintext = Buffer.from('noise garlic payload');

  const encrypted = Crypto.encryptNoiseNGarlicReply(recipient.publicKey, plaintext);
  const decrypted = Crypto.decryptNoiseNGarlicReply(
    recipient.privateKey,
    recipient.publicKey,
    encrypted.ephemeralPublicKey,
    encrypted.ciphertext
  );

  assert.deepEqual(decrypted, plaintext);
});

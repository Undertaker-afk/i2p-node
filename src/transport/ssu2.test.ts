import test from 'node:test';
import assert from 'node:assert/strict';
import SSU2Transport from './ssu2.js';
import { Crypto } from '../crypto/index.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519 } from '../i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from '../i2p/routerinfo/writer.js';
import { i2pBase64Encode } from '../i2p/base64.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';

async function buildRouterInfo(host: string, port: number, staticKey: Uint8Array) {
  const signPriv = ed25519.utils.randomPrivateKey();
  const signPub = ed25519.getPublicKey(signPriv);
  const iv = Buffer.from(Crypto.randomBytes(16));
  const { identityBytes } = buildIdentityExEd25519X25519({ cryptoPublicKey: staticKey, signingPublicKey: signPub });
  const opts = makeNtcp2PublishedOptions({ host, port, staticKey, ivB64: i2pBase64Encode(iv), v: '2', caps: 'LR' });
  const wire = writeRouterInfoEd25519({
    identityBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'SSU2', options: opts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66', 'core.version': '0.9.66' },
    signingPrivateKey: signPriv
  });
  const ri = parseI2PRouterInfo(wire);
  if (!ri) throw new Error('failed to parse routerinfo');
  return ri;
}

test('ssu2 local handshake and reliable data flow', { timeout: 15000 }, async () => {
  const bobStatic = Crypto.generateKeyPair();
  const bob = new SSU2Transport({ host: '127.0.0.1', port: 0, staticPrivateKey: bobStatic.privateKey, staticPublicKey: bobStatic.publicKey, netId: 2 });
  await bob.start();
  const bobAddress = (bob as any).socket.address();
  const bobPort = bobAddress.port as number;
  const bobRi = await buildRouterInfo('127.0.0.1', bobPort, bobStatic.publicKey);

  const aliceStatic = Crypto.generateKeyPair();
  const alice = new SSU2Transport({ host: '127.0.0.1', port: 0, staticPrivateKey: aliceStatic.privateKey, staticPublicKey: aliceStatic.publicKey, netId: 2 });
  await alice.start();

  const sid = `127.0.0.1:${bobPort}`;
  const received = new Promise<Buffer>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timeout waiting for data')), 8000);
    bob.on('message', ({ data }) => {
      clearTimeout(timer);
      resolve(data as Buffer);
    });
  });

  await alice.connect('127.0.0.1', bobPort, bobRi);
  alice.send(sid, Buffer.from('hello-ssu2'));

  const data = await received;
  assert.equal(data.toString('utf8'), 'hello-ssu2');

  alice.stop();
  bob.stop();
});

import SSU2Transport from '../transport/ssu2.js';
import { Crypto } from '../crypto/index.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519 } from '../i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from '../i2p/routerinfo/writer.js';
import { i2pBase64Encode } from '../i2p/base64.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';

async function main(): Promise<void> {
  // Bob (server) static keys and RouterInfo (reused IdentityEx + NTCP2-style address just for consistency).
  const bobStatic = Crypto.generateKeyPair();
  const bobSignPriv = ed25519.utils.randomPrivateKey();
  const bobSignPub = ed25519.getPublicKey(bobSignPriv);
  const bobIV = Buffer.from(Crypto.randomBytes(16));
  const { identityBytes: bobIdBytes, identHash: bobRH } = buildIdentityExEd25519X25519({
    cryptoPublicKey: bobStatic.publicKey,
    signingPublicKey: bobSignPub
  });
  const bobAddrOpts = makeNtcp2PublishedOptions({
    host: '127.0.0.1',
    port: 0,
    staticKey: bobStatic.publicKey,
    ivB64: i2pBase64Encode(bobIV),
    v: '2',
    caps: 'LR'
  });
  const bobRouterInfoWire = writeRouterInfoEd25519({
    identityBytes: bobIdBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'SSU2', options: bobAddrOpts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66', 'core.version': '0.9.66' },
    signingPrivateKey: bobSignPriv
  });
  const bobRi = parseI2PRouterInfo(bobRouterInfoWire);
  if (!bobRi) throw new Error('failed to parse bob routerinfo');

  const bob = new SSU2Transport({
    host: '127.0.0.1',
    port: 0,
    staticPrivateKey: bobStatic.privateKey,
    staticPublicKey: bobStatic.publicKey,
    netId: 2
  });
  await bob.start();
  const addr = (bob as any).socket?.address?.();
  const bobPort = addr && typeof addr === 'object' ? addr.port : 0;

  // Alice (client)
  const aliceStatic = Crypto.generateKeyPair();
  const aliceSignPriv = ed25519.utils.randomPrivateKey();
  const aliceSignPub = ed25519.getPublicKey(aliceSignPriv);
  const aliceIV = Buffer.from(Crypto.randomBytes(16));
  const { identityBytes: aliceIdBytes } = buildIdentityExEd25519X25519({
    cryptoPublicKey: aliceStatic.publicKey,
    signingPublicKey: aliceSignPub
  });
  const aliceAddrOpts = makeNtcp2PublishedOptions({
    host: '127.0.0.1',
    port: 12346,
    staticKey: aliceStatic.publicKey,
    ivB64: i2pBase64Encode(aliceIV),
    v: '2',
    caps: 'LR'
  });
  const aliceRouterInfoWire = writeRouterInfoEd25519({
    identityBytes: aliceIdBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'SSU2', options: aliceAddrOpts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66', 'core.version': '0.9.66' },
    signingPrivateKey: aliceSignPriv
  });

  const alice = new SSU2Transport({
    staticPrivateKey: aliceStatic.privateKey,
    staticPublicKey: aliceStatic.publicKey,
    netId: 2
  });
  await alice.start();

  const sessionId = `127.0.0.1:${bobPort}`;

  // Handshake smoke: ensure both sides reach "established".
  const bobEstablished = new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout waiting for SSU2 handshake (Bob)')), 7000);
    (bob as any).on('established', ({ sessionId: sid }: { sessionId: string }) => {
      if (sid === sessionId) {
        clearTimeout(t);
        resolve();
      }
    });
  });

  const aliceEstablished = new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout waiting for SSU2 handshake (Alice)')), 7000);
    (alice as any).on('established', ({ sessionId: sid }: { sessionId: string }) => {
      if (sid === sessionId) {
        clearTimeout(t);
        resolve();
      }
    });
  });

  await alice.connect('127.0.0.1', bobPort, bobRi);
  await Promise.all([bobEstablished, aliceEstablished]);

  (alice as any).stop();
  (bob as any).stop();
  console.log('Local SSU2 handshake smoke test OK');
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


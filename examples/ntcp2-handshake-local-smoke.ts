import NTCP2Transport from '../dist/transport/ntcp2.js';
import { Crypto } from '../dist/crypto/index.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519 } from '../dist/i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from '../dist/i2p/routerinfo/writer.js';
import { i2pBase64Encode } from '../dist/i2p/base64.js';
import { parseI2PRouterInfo } from '../dist/data/router-info-i2p.js';

async function main(): Promise<void> {
  // Bob (server)
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
    port: 0, // not used by handshake validation in this local test
    staticKey: bobStatic.publicKey,
    ivB64: i2pBase64Encode(bobIV),
    v: '2',
    caps: 'LR'
  });
  const bobRouterInfoWire = writeRouterInfoEd25519({
    identityBytes: bobIdBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'NTCP2', options: bobAddrOpts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66', 'core.version': '0.9.66' },
    signingPrivateKey: bobSignPriv
  });
  const bobRi = parseI2PRouterInfo(bobRouterInfoWire);
  if (!bobRi) throw new Error('failed to parse bob routerinfo');

  const bob = new NTCP2Transport({
    host: '127.0.0.1',
    port: 0,
    routerHash: bobRH,
    publishedIV: bobIV,
    staticPrivateKey: bobStatic.privateKey,
    staticPublicKey: bobStatic.publicKey,
    netId: 2
  });
  await bob.start();
  const bobPort = bob.getBoundPort();
  if (!bobPort) throw new Error('bob did not bind');

  // Patch bob routerinfo port to match the bound port for Alice connect()
  bobAddrOpts.port = String(bobPort);
  const bobRouterInfoWire2 = writeRouterInfoEd25519({
    identityBytes: bobIdBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'NTCP2', options: bobAddrOpts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66', 'core.version': '0.9.66' },
    signingPrivateKey: bobSignPriv
  });
  const bobRi2 = parseI2PRouterInfo(bobRouterInfoWire2);
  if (!bobRi2) throw new Error('failed to parse bob routerinfo #2');

  // Alice (client)
  const aliceStatic = Crypto.generateKeyPair();
  const aliceSignPriv = ed25519.utils.randomPrivateKey();
  const aliceSignPub = ed25519.getPublicKey(aliceSignPriv);
  const aliceIV = Buffer.from(Crypto.randomBytes(16));
  const { identityBytes: aliceIdBytes, identHash: aliceRH } = buildIdentityExEd25519X25519({
    cryptoPublicKey: aliceStatic.publicKey,
    signingPublicKey: aliceSignPub
  });
  const aliceAddrOpts = makeNtcp2PublishedOptions({
    host: '127.0.0.1',
    port: 12345,
    staticKey: aliceStatic.publicKey,
    ivB64: i2pBase64Encode(aliceIV),
    v: '2',
    caps: 'LR'
  });
  const aliceRouterInfoWire = writeRouterInfoEd25519({
    identityBytes: aliceIdBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'NTCP2', options: aliceAddrOpts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66', 'core.version': '0.9.66' },
    signingPrivateKey: aliceSignPriv
  });

  const alice = new NTCP2Transport({
    staticPrivateKey: aliceStatic.privateKey,
    staticPublicKey: aliceStatic.publicKey,
    routerInfo: aliceRouterInfoWire,
    routerHash: aliceRH,
    publishedIV: aliceIV,
    netId: 2,
    connectTimeoutMs: 3000
  });

  // Handshake smoke: ensure both sides reach "established".
  const bobEstablished = new Promise<void>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error('timeout waiting for handshake (Bob)')), 7000);
    bob.on('established', () => {
      clearTimeout(t);
      resolve();
    });
  });

  await alice.connect('127.0.0.1', bobPort, bobRi2);
  await bobEstablished;

  alice.stop();
  bob.stop();
  console.log('Local NTCP2 handshake smoke test OK');
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


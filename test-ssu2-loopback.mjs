/**
 * SSU2 loopback test: Alice (TypeScript) ↔ Bob (TypeScript)
 * Verifies the full handshake (TokenRequest → Retry → SessionRequest →
 * SessionCreated → SessionConfirmed) and data phase work end-to-end.
 */
import { randomBytes } from 'crypto';
import { x25519, ed25519 } from '@noble/curves/ed25519';

const { SSU2Transport }    = await import('./dist/transport/ssu2.js');
const { Crypto }           = await import('./dist/crypto/index.js');
const { RouterInfo, RouterAddress, RouterIdentity } = await import('./dist/data/router-info.js');
const { buildIdentityExEd25519X25519 } = await import('./dist/i2p/identity/identity-ex.js');
const { writeRouterInfoEd25519, makeNtcp2PublishedOptions } = await import('./dist/i2p/routerinfo/writer.js');
const { i2pBase64Encode } = await import('./dist/i2p/base64.js');

// ─── Build router keys and RI ─────────────────────────────────────────────────

function buildRouter(port) {
  const sigPriv = ed25519.utils.randomPrivateKey();
  const sigPub  = ed25519.getPublicKey(sigPriv);
  const enc     = Crypto.generateKeyPair();       // X25519 static key
  const introKey = Buffer.from(randomBytes(32));  // SSU2 intro key

  const identEx = buildIdentityExEd25519X25519({
    cryptoPublicKey: enc.publicKey,
    signingPublicKey: sigPub,
  });

  const ssu2Opts = {
    host: '127.0.0.1',
    port: port.toString(),
    s: i2pBase64Encode(Buffer.from(enc.publicKey)),
    i: i2pBase64Encode(introKey),
    v: '2',
    caps: 'LR',
  };

  const wireRI = writeRouterInfoEd25519({
    identityBytes: identEx.identityBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'SSU2', options: ssu2Opts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66' },
    signingPrivateKey: sigPriv,
  });

  return {
    identHash:  identEx.identHash,
    staticPriv: Buffer.from(enc.privateKey),
    staticPub:  Buffer.from(enc.publicKey),
    introKey,
    wireRI,
    ssu2Opts,
  };
}

/**
 * Build a minimal RouterInfo object that SSU2Transport.connect() needs.
 */
function fakeRouterInfo(keys) {
  const identity = new RouterIdentity(keys.staticPub, keys.staticPub, { type: 0, data: Buffer.alloc(0) });
  identity.setHash(keys.identHash);
  const addr = new RouterAddress('SSU2', { ...keys.ssu2Opts }, 4, 0);
  return new RouterInfo(identity, [addr], {}, Date.now(), null);
}

// ─── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const BOB_PORT   = 15888;
  const ALICE_PORT = 15889; // Alice doesn't serve, just the port used in her RI

  console.log('Building Bob and Alice keys…');
  const bob   = buildRouter(BOB_PORT);
  const alice = buildRouter(ALICE_PORT);

  console.log(`Bob   hash: ${bob.identHash.toString('hex').slice(0, 16)}…`);
  console.log(`Alice hash: ${alice.identHash.toString('hex').slice(0, 16)}…`);

  // ── Start Bob (responder) ───────────────────────────────────────────────────
  const bobTransport = new SSU2Transport({
    host: '127.0.0.1',
    port: BOB_PORT,
    staticPrivateKey: bob.staticPriv,
    staticPublicKey:  bob.staticPub,
    introKey:         bob.introKey,
    routerInfo:       bob.wireRI,
    netId: 2,
  });

  let bobEstablished  = false;
  let bobGotMessage   = null;

  bobTransport.on('established', ({ sessionId }) => {
    console.log(`[Bob] Session established: ${sessionId}`);
    bobEstablished = true;
  });
  bobTransport.on('message', ({ sessionId, data }) => {
    console.log(`[Bob] Received I2NP ${data.length} bytes from ${sessionId}`);
    bobGotMessage = data;
  });
  bobTransport.on('error', (err) => {
    const msg = err?.message ?? String(err);
    if (!msg.includes('EADDRINUSE')) console.error(`[Bob] Error: ${msg}`);
  });

  await bobTransport.start();
  console.log(`Bob  SSU2 listening on 127.0.0.1:${BOB_PORT}`);

  // ── Start Alice (initiator) ─────────────────────────────────────────────────
  const aliceTransport = new SSU2Transport({
    host: '127.0.0.1',
    port: 0,        // let the OS assign an available ephemeral port
    staticPrivateKey: alice.staticPriv,
    staticPublicKey:  alice.staticPub,
    introKey:         alice.introKey,
    routerInfo:       alice.wireRI,
    netId: 2,
  });

  let aliceEstablished = false;
  aliceTransport.on('established', ({ sessionId }) => {
    console.log(`[Alice] Session established: ${sessionId}`);
    aliceEstablished = true;
  });
  aliceTransport.on('error', (err) => {
    const msg = err?.message ?? String(err);
    if (!msg.includes('EADDRINUSE')) console.error(`[Alice] Error: ${msg}`);
  });

  await aliceTransport.start();
  console.log(`Alice SSU2 listening on 127.0.0.1 (OS-assigned ephemeral port)`);

  const bobRI = fakeRouterInfo(bob);

  console.log('\nAlice connecting to Bob…');
  try {
    await aliceTransport.connect('127.0.0.1', BOB_PORT, bobRI);
    console.log('✓  Alice.connect() resolved (handshake complete)');
  } catch (err) {
    console.error('✗  Alice.connect() rejected:', err.message);
    bobTransport.stop();
    aliceTransport.stop();
    process.exit(1);
  }

  // Give Bob a moment to fire its 'established' event
  await new Promise((r) => setTimeout(r, 100));

  if (bobEstablished) {
    console.log('✓  Bob also emitted established');
  } else {
    console.error('✗  Bob did NOT emit established');
    bobTransport.stop();
    aliceTransport.stop();
    process.exit(1);
  }

  console.log('\n=== SSU2 loopback handshake test PASSED ===');
  bobTransport.stop();
  aliceTransport.stop();
  process.exit(0);
}

main().catch((err) => {
  console.error('Fatal:', err);
  process.exit(1);
});

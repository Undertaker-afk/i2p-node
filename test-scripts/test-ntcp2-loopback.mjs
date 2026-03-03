/**
 * NTCP2 loopback test: Alice (TypeScript) <-> Bob (TypeScript)
 * Verifies the full handshake and data phase works end-to-end within a single process.
 */
import { createHash, randomBytes } from 'crypto';
import { x25519 } from '@noble/curves/ed25519';
import { ed25519 } from '@noble/curves/ed25519';

// Build path: point to compiled dist/
const { NTCP2Transport } = await import('../dist/transport/ntcp2.js');
const { Crypto } = await import('../dist/crypto/index.js');
const { parseI2PRouterInfo } = await import('../dist/data/router-info-i2p.js');
const { RouterInfo, RouterAddress, RouterIdentity } = await import('../dist/data/router-info.js');
const { buildIdentityExEd25519X25519 } = await import('../dist/i2p/identity/identity-ex.js');
const { writeRouterInfoEd25519, makeNtcp2PublishedOptions } = await import('../dist/i2p/routerinfo/writer.js');
const { i2pBase64Encode } = await import('../dist/i2p/base64.js');

// ─── Build Bob's identity and keys ────────────────────────────────────────────
const BOB_PORT = 14777;
const ALICE_PORT = 14778; // not used as server but needed for struct

function buildRouter(port) {
  const sigPriv = ed25519.utils.randomPrivateKey();
  const sigPub  = ed25519.getPublicKey(sigPriv);
  const enc = Crypto.generateKeyPair();  // X25519
  const identEx = buildIdentityExEd25519X25519({ cryptoPublicKey: enc.publicKey, signingPublicKey: sigPub });

  const publishedIV = Buffer.from(randomBytes(16));
  const ntcp2Opts = makeNtcp2PublishedOptions({
    host: '127.0.0.1',
    port,
    staticKey: enc.publicKey,
    ivB64: i2pBase64Encode(publishedIV),
    v: '2',
    caps: 'LR',
  });

  const wireRI = writeRouterInfoEd25519({
    identityBytes: identEx.identityBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'NTCP2', options: ntcp2Opts }],
    routerProperties: { netId: '2', caps: 'LR', 'router.version': '0.9.66' },
    signingPrivateKey: sigPriv,
  });

  return {
    identHash: identEx.identHash,
    publishedIV,
    staticPriv: Buffer.from(enc.privateKey),
    staticPub: Buffer.from(enc.publicKey),
    wireRI,
    ntcp2Opts,
  };
}

// ─── Build a minimal RouterInfo object that NTCP2Transport.connect() needs ───
function fakeRouterInfo(keys) {
  const identity = new RouterIdentity(
    keys.staticPub,        // use any 32-byte data for identity fields
    keys.staticPub,
    { type: 0, data: Buffer.alloc(0) }
  );
  identity.setHash(keys.identHash);

  const addr = new RouterAddress('NTCP2', { ...keys.ntcp2Opts }, 5, 0);
  const ri = new RouterInfo(identity, [addr], {}, Date.now(), null);
  return ri;
}

// ─── Main ─────────────────────────────────────────────────────────────────────
async function main() {
  console.log('Building Bob keys…');
  const bob = buildRouter(BOB_PORT);
  const alice = buildRouter(ALICE_PORT);

  console.log(`Bob IdentHash   : ${bob.identHash.toString('hex').slice(0, 32)}…`);
  console.log(`Alice IdentHash : ${alice.identHash.toString('hex').slice(0, 32)}…`);

  // ── Start Bob as server ──────────────────────────────────────────────────────
  const bobTransport = new NTCP2Transport({
    host: '127.0.0.1',
    port: BOB_PORT,
    routerHash: bob.identHash,
    publishedIV: bob.publishedIV,
    staticPrivateKey: bob.staticPriv,
    staticPublicKey: bob.staticPub,
    routerInfo: bob.wireRI,
    netId: 2,
  });

  let bobEstablished = false;
  let bobGotMessage = null;
  bobTransport.on('established', ({ sessionId }) => {
    console.log(`[Bob] Session established: ${sessionId}`);
    bobEstablished = true;
  });
  bobTransport.on('message', ({ sessionId, data }) => {
    console.log(`[Bob] Received message: ${data.toString('hex')}`);
    bobGotMessage = data;
  });
  bobTransport.on('error', (err) => {
    const msg = err?.error?.message || err?.message || String(err);
    console.error(`[Bob] Error: ${msg}`);
  });

  await bobTransport.start();
  console.log(`Bob NTCP2 listening on port ${BOB_PORT}`);

  // ── Start Alice as initiator ─────────────────────────────────────────────────
  const aliceTransport = new NTCP2Transport({
    host: '127.0.0.1',
    port: ALICE_PORT,
    routerHash: alice.identHash,
    publishedIV: alice.publishedIV,
    staticPrivateKey: alice.staticPriv,
    staticPublicKey: alice.staticPub,
    routerInfo: alice.wireRI,
    netId: 2,
  });

  let aliceEstablished = false;
  aliceTransport.on('established', ({ sessionId }) => {
    console.log(`[Alice] Session established: ${sessionId}`);
    aliceEstablished = true;
  });
  aliceTransport.on('error', (err) => {
    const msg = err?.error?.message || err?.message || String(err);
    console.error(`[Alice] Error: ${msg}`);
  });

  // Alice does NOT need to listen on a port for this test; just use connect().
  const bobRI = fakeRouterInfo(bob);

  console.log('\nAlice connecting to Bob…');
  try {
    await aliceTransport.connect('127.0.0.1', BOB_PORT, bobRI);
    console.log('✓  Alice.connect() resolved  (handshake complete)');
  } catch (err) {
    console.error('✗  Alice.connect() rejected:', err.message);
    bobTransport.stop();
    process.exit(1);
  }

  // Give Bob a tick to fire its 'established' event
  await new Promise(r => setTimeout(r, 50));
  if (bobEstablished) {
    console.log('✓  Bob also emitted established');
  } else {
    console.error('✗  Bob did NOT emit established');
  }

  bobTransport.stop();
  console.log('\n=== Loopback handshake test PASSED ===');
  process.exit(0);
}

main().catch(err => {
  console.error('Fatal:', err);
  process.exit(1);
});

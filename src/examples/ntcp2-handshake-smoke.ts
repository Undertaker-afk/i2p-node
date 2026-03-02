import NTCP2Transport from '../transport/ntcp2.js';
import { Reseeder } from '../netdb/reseed.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';
import { Crypto } from '../crypto/index.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519 } from '../i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from '../i2p/routerinfo/writer.js';
import { i2pBase64Encode } from '../i2p/base64.js';
import https from 'https';

async function getPublicIPv4(): Promise<string | null> {
  return new Promise((resolve) => {
    const req = https.get('https://api.ipify.org', { timeout: 8000 }, (res) => {
      if (res.statusCode !== 200) {
        res.resume();
        resolve(null);
        return;
      }
      let data = '';
      res.setEncoding('utf8');
      res.on('data', (c) => (data += c));
      res.on('end', () => {
        const ip = data.trim();
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(ip)) resolve(ip);
        else resolve(null);
      });
    });
    req.on('timeout', () => {
      req.destroy();
      resolve(null);
    });
    req.on('error', () => resolve(null));
  });
}

async function main(): Promise<void> {
  const reseeder = new Reseeder({ requestTimeout: 30000 });
  const seeded = await reseeder.bootstrap();
  if (!seeded.length) throw new Error('Reseed returned no routers');

  const candidates = [];
  for (const r of seeded) {
    const ri = parseI2PRouterInfo(r.data);
    if (!ri) continue;
    const addr = ri.addresses.find((a) => a.transportStyle === 'NTCP2' && a.options.host && a.options.port && a.options.s && a.options.i);
    if (!addr) continue;
    const host = addr.options.host;
    const port = Number.parseInt(addr.options.port, 10);
    if (!host || !port || Number.isNaN(port)) continue;
    if (host.includes(':')) continue; // skip IPv6 for this smoke test
    candidates.push({ ri, host, port });
    if (candidates.length >= 25) break;
  }

  if (!candidates.length) throw new Error('No NTCP2 candidates found in reseed set');
  // Shuffle candidates so we can retry quickly
  candidates.sort(() => Math.random() - 0.5);

  // Local keys
  const staticKeys = Crypto.generateKeyPair(); // X25519
  const signingPriv = ed25519.utils.randomPrivateKey(); // 32-byte seed
  const signingPub = ed25519.getPublicKey(signingPriv);

  const { identityBytes, identHash } = buildIdentityExEd25519X25519({
    cryptoPublicKey: staticKeys.publicKey,
    signingPublicKey: signingPub
  });

  const publicIP = (await getPublicIPv4()) ?? '0.0.0.0';
  const publishedIV = Buffer.from(Crypto.randomBytes(16));
  const addrOpts = makeNtcp2PublishedOptions({
    host: publicIP,
    port: 12345,
    staticKey: staticKeys.publicKey,
    ivB64: i2pBase64Encode(publishedIV),
    v: '2',
    caps: 'LR'
  });

  const routerInfo = writeRouterInfoEd25519({
    identityBytes,
    publishedMs: Date.now(),
    addresses: [{ transportStyle: 'NTCP2', options: addrOpts }],
    routerProperties: {
      netId: '2',
      caps: 'LR',
      'router.version': '0.9.66',
      'core.version': '0.9.66'
    },
    signingPrivateKey: signingPriv
  });

  const ntcp2 = new NTCP2Transport({
    staticPrivateKey: staticKeys.privateKey,
    staticPublicKey: staticKeys.publicKey,
    routerInfo,
    routerHash: identHash,
    publishedIV,
    netId: 2,
    connectTimeoutMs: 5000
  });

  let closed = false;
  ntcp2.on('close', ({ sessionId }) => {
    closed = true;
    console.log('closed', sessionId);
  });
  ntcp2.on('error', (e) => {
    console.warn('ntcp2 error', e);
  });

  let lastErr: unknown = null;
  for (const c of candidates.slice(0, 25)) {
    closed = false;
    console.log(`Connecting to ${c.host}:${c.port} ...`);
    try {
      await ntcp2.connect(c.host, c.port, c.ri);
      console.log('Handshake sent, waiting briefly to ensure peer accepts...');
      await new Promise((r) => setTimeout(r, 2000));
      if (closed) throw new Error('Connection closed shortly after handshake (peer likely rejected message3)');
      console.log('Smoke test: handshake completed and connection stayed open for 2s');
      ntcp2.stop();
      return;
    } catch (e) {
      lastErr = e;
      console.log(`Failed: ${(e as Error).message}`);
    }
  }

  ntcp2.stop();
  throw lastErr instanceof Error ? lastErr : new Error('All candidates failed');
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


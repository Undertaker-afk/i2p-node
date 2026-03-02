import fs from 'fs';
import path from 'path';
import NTCP2Transport from '../transport/ntcp2.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';
import { Crypto } from '../crypto/index.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519 } from '../i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from '../i2p/routerinfo/writer.js';
import { i2pBase64Encode } from '../i2p/base64.js';
import { RouterInfo } from '../data/router-info.js';

async function pickRemoteNtcp2Peer(): Promise<{ ri: RouterInfo; host: string; port: number }> {
  const netDbRoot = 'C:\\Users\\floga\\AppData\\Roaming\\i2pd\\netDb';
  const subdirs = await fs.promises.readdir(netDbRoot);
  let inspected = 0;

  for (const sub of subdirs) {
    const fullSub = path.join(netDbRoot, sub);
    const stat = await fs.promises.lstat(fullSub);
    if (!stat.isDirectory()) continue;

    const files = await fs.promises.readdir(fullSub);
    for (const f of files) {
      if (!f.startsWith('routerInfo-') || !f.endsWith('.dat')) continue;
      const fullPath = path.join(fullSub, f);
      try {
        const data = await fs.promises.readFile(fullPath);
        const ri = parseI2PRouterInfo(data);
        if (!ri) continue;

        const addr = ri.addresses.find(
          (a) =>
            a.transportStyle.toUpperCase().startsWith('NTCP') &&
            a.options.host &&
            a.options.port &&
            a.options.s &&
            a.options.i
        );
        if (!addr) continue;

        const host = addr.options.host!;
        const port = parseInt(String(addr.options.port), 10);
        if (!host || !port || Number.isNaN(port)) continue;

        console.log('Using remote NTCP2 peer from netDb:', host, port);
        return { ri, host, port };
      } catch {
        // ignore parse/read errors
      }

      inspected++;
      if (inspected > 200) break;
    }
    if (inspected > 200) break;
  }

  throw new Error('No remote NTCP2 peer with host/port/s/i found in netDb');
}

async function main(): Promise<void> {
  // 1) Pick a remote NTCP2 peer from i2pd netDb (with host/port/s/i)
  const { ri: remoteRi, host, port } = await pickRemoteNtcp2Peer();

  // 2) Build a temporary local identity + RouterInfo for our side of NTCP2
  const staticKeys = Crypto.generateKeyPair(); // X25519
  const signingPriv = ed25519.utils.randomPrivateKey();
  const signingPub = ed25519.getPublicKey(signingPriv);
  const { identityBytes, identHash } = buildIdentityExEd25519X25519({
    cryptoPublicKey: staticKeys.publicKey,
    signingPublicKey: signingPub
  });

  const publishedIV = Buffer.from(Crypto.randomBytes(16));
  const addrOpts = makeNtcp2PublishedOptions({
    host: '127.0.0.1',
    port: 0,
    staticKey: staticKeys.publicKey,
    ivB64: i2pBase64Encode(publishedIV),
    v: '2',
    caps: 'LR'
  });

  const localRouterInfo = writeRouterInfoEd25519({
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

  // 3) Set up NTCP2Transport with our static keys and RouterInfo
  const ntcp2 = new NTCP2Transport({
    staticPrivateKey: staticKeys.privateKey,
    staticPublicKey: staticKeys.publicKey,
    routerInfo: localRouterInfo,
    routerHash: identHash,
    publishedIV,
    netId: 2,
    connectTimeoutMs: 8000
  });

  ntcp2.on('established', ({ sessionId }) => {
    console.log('NTCP2 established with i2pd, sessionId=', sessionId);
  });
  ntcp2.on('error', ({ sessionId, error }) => {
    console.warn('NTCP2 error', sessionId, (error as Error).message);
  });
  ntcp2.on('close', ({ sessionId }) => {
    console.log('NTCP2 closed', sessionId);
  });

  // 4) Connect to the chosen remote NTCP2 peer
  console.log(`Connecting to remote NTCP2 peer at ${host}:${port} ...`);

  try {
    await ntcp2.connect(host, port, remoteRi);
    console.log('connect() returned without throwing');
    // Keep connection around briefly to observe behavior
    await new Promise((resolve) => setTimeout(resolve, 5000));
  } catch (e) {
    console.error('NTCP2 connect failed:', (e as Error).message);
  } finally {
    ntcp2.stop();
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


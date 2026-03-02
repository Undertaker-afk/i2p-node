import fs from 'fs';
import path from 'path';
import SSU2Transport from '../transport/ssu2.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';

async function pickRemoteSsu2Peer(): Promise<{ ri: RouterInfo; host: string; port: number }> {
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
            a.transportStyle === 'SSU2' &&
            a.options.host &&
            a.options.port &&
            a.options.s
        );
        if (!addr) continue;

        const host = addr.options.host!;
        const port = parseInt(String(addr.options.port), 10);
        if (!host || !port || Number.isNaN(port)) continue;

        console.log('Using remote SSU2 peer from netDb:', host, port);
        return { ri, host, port };
      } catch {
        // ignore parse/read errors
      }

      inspected++;
      if (inspected > 200) break;
    }
    if (inspected > 200) break;
  }

  throw new Error('No remote SSU2 peer with host/port/s found in netDb');
}

async function main(): Promise<void> {
  // 1) Pick a remote SSU2 peer from i2pd netDb
  const { ri: remoteRi, host, port } = await pickRemoteSsu2Peer();

  // 2) Create local static keys for SSU2 (X25519)
  const staticKeys = Crypto.generateKeyPair();

  // 3) Set up SSU2Transport with our static keys
  const ssu2 = new SSU2Transport({
    host: '0.0.0.0',
    port: 0, // let OS pick a free UDP port
    staticPrivateKey: staticKeys.privateKey,
    staticPublicKey: staticKeys.publicKey,
    netId: 2
  });

  ssu2.on('established', ({ sessionId }) => {
    console.log('SSU2 established with i2pd, sessionId=', sessionId);
  });
  ssu2.on('error', (error) => {
    console.warn('SSU2 error', (error as Error).message ?? error);
  });
  ssu2.on('message', ({ sessionId, data }) => {
    console.log('SSU2 data from', sessionId, 'len=', data.length);
  });

  await ssu2.start();

  console.log(`Connecting to remote SSU2 peer at ${host}:${port} ...`);

  try {
    await ssu2.connect(host, port, remoteRi);
    console.log('SSU2 connect() returned without throwing');
    // keep socket alive briefly
    await new Promise((resolve) => setTimeout(resolve, 5000));
  } catch (e) {
    console.error('SSU2 connect failed:', (e as Error).message);
  } finally {
    ssu2.stop();
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


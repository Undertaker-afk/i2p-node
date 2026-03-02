import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';
const { parseI2PRouterInfo } = await import('./dist/data/router-info-i2p.js');
const { i2pBase64Decode } = await import('./dist/i2p/base64.js');

const netDbDir = 'c:/Users/floga/Desktop/coding/fun/i2p-node/i2p-test-data/netDb';
const files = readdirSync(netDbDir).filter(f => f.endsWith('.dat')).slice(0, 5);

let parsed = 0, failed = 0, hashMismatch = 0;

for (const fname of files) {
  const expectedHash = fname.replace('routerInfo-', '').replace('.dat', '');
  const data = readFileSync(join(netDbDir, fname));
  const ri = parseI2PRouterInfo(data);
  if (!ri) { console.log('FAIL:', fname); failed++; continue; }
  
  const computedHash = ri.getRouterHash().toString('hex');
  const match = computedHash === expectedHash;
  if (!match) hashMismatch++;

  const ntcp2 = ri.addresses.find(a => a.transportStyle === 'NTCP2' && a.options.s && a.options.i);
  
  console.log('\n--- ' + expectedHash.slice(0,16) + '...');
  console.log('  Hash match:   ', match ? '✓' : `✗ got ${computedHash.slice(0,16)}...`);
  if (ntcp2) {
    const s = i2pBase64Decode(ntcp2.options.s);
    const iv = i2pBase64Decode(ntcp2.options.i);
    console.log('  NTCP2 s len:  ', s.length, s.length===32?'✓':'✗');
    console.log('  NTCP2 i len:  ', iv.length, iv.length===16?'✓':'✗');
    console.log('  NTCP2 host:   ', ntcp2.options.host + ':' + ntcp2.options.port);
    console.log('  s[:8]:        ', s.toString('hex').slice(0,16));
    console.log('  i:            ', iv.toString('hex'));
  } else {
    console.log('  No NTCP2 address with s/i');
    console.log('  Addresses:    ', ri.addresses.map(a=>a.transportStyle+`(s=${!!a.options.s},i=${!!a.options.i})`).join(', '));
  }
  parsed++;
}

console.log(`\nTotal: ${parsed} parsed, ${failed} failed, ${hashMismatch} hash mismatches`);

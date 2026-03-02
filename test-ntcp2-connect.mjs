#!/usr/bin/env node
/**
 * Minimal NTCP2 connect test.
 * Boots the router, picks ONE reseeded peer that has an IPv4 NTCP2 address
 * with s/i keys, and tries to connect with full debug logging.
 *
 * Usage:  NTCP2_DEBUG=1 node test-ntcp2-connect.mjs
 */
import { I2PRouter, logger, LogLevel } from './dist/index.js';

// Force NTCP2_DEBUG so we see hex dumps
process.env.NTCP2_DEBUG = '1';

logger.setLevel(LogLevel.WARN); // suppress noise except our debug output

const router = new I2PRouter({
  ntcp2Port: 0, // let OS pick
  ssu2Port: 0,
  samPort: 0,
  bandwidthClass: 'L',
  isFloodfill: false,
  logLevel: LogLevel.WARN,
  enableWebUI: false,
  dataDir: './i2p-test-data'
});

await router.start();

const netDb = router.getNetworkDatabase();
const allRouters = netDb.getAllRouterInfos();
console.log(`Reseeded ${allRouters.length} routers`);

// Find all peers with usable NTCP2 address, then shuffle and take 30
const allCandidates = [];
for (const ri of allRouters) {
  for (const a of ri.addresses) {
    if (!a.transportStyle.toUpperCase().startsWith('NTCP')) continue;
    const host = a.options.host;
    if (!host || host.includes(':') || host.startsWith('[')) continue;
    if (!a.options.s || !a.options.i || !a.options.port) continue;
    const port = parseInt(a.options.port, 10);
    if (!port || isNaN(port)) continue;
    allCandidates.push({ ri, host, port, s: a.options.s, i: a.options.i });
    break;
  }
}
// Fisher-Yates shuffle
for (let i = allCandidates.length - 1; i > 0; i--) {
  const j = Math.floor(Math.random() * (i + 1));
  [allCandidates[i], allCandidates[j]] = [allCandidates[j], allCandidates[i]];
}
const candidates = allCandidates.slice(0, 30);

if (!candidates.length) {
  console.error('ERROR: no usable NTCP2 peer found');
  router.stop();
  process.exit(1);
}

const ntcp2 = router.ntcp2;
if (!ntcp2) {
  console.error('ERROR: ntcp2 transport not available');
  router.stop();
  process.exit(1);
}

// Try 5 concurrently at a time to speed things up
let successes = 0;
let failures = 0;
const errorCounts = {};
for (let i = 0; i < candidates.length; i += 5) {
  const batch = candidates.slice(i, i + 5);
  const results = await Promise.allSettled(batch.map(async (picked) => {
    try {
      await ntcp2.connect(picked.host, picked.port, picked.ri);
      return { ok: true, host: picked.host, port: picked.port };
    } catch (err) {
      return { ok: false, host: picked.host, port: picked.port, error: err.message };
    }
  }));
  for (const r of results) {
    const v = r.value;
    if (v.ok) {
      console.log(`  ✓ ${v.host}:${v.port}`);
      successes++;
    } else {
      console.log(`  ✗ ${v.host}:${v.port} — ${v.error}`);
      failures++;
      errorCounts[v.error] = (errorCounts[v.error] || 0) + 1;
    }
  }
}

console.log(`\n=== Results: ${successes} succeeded, ${failures} failed out of ${candidates.length} ===`);
console.log('Error breakdown:', errorCounts);

router.stop();
setTimeout(() => process.exit(0), 500);

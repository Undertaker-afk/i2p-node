#!/usr/bin/env node
/**
 * Integration test: boot the I2P router, reseed, connect to peers,
 * and keep querying floodfills until we receive the LeaseSet for
 * notbob.i2p (nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p).
 *
 * Usage:  node test-notbob-lookup.mjs
 *
 * The script exits 0 on success, 1 on timeout (default 5 minutes).
 */

import { execSync } from 'child_process';
import { I2PRouter, logger, LogLevel } from './dist/index.js';
import { base32DecodeToHash } from './dist/i2p/base32.js';
import { I2NPMessages } from './dist/i2np/messages.js';

// ── Config ──────────────────────────────────────────────────────────────

const NOTBOB_B32  = 'nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p';
const NTCP2_PORT  = 12345;
const TIMEOUT_MS  = 5 * 60 * 1000; // 5 minutes
const RETRY_MS    = 10_000;        // retry lookup every 10 s

logger.setLevel(LogLevel.DEBUG);

// ── Port cleanup (Windows) ──────────────────────────────────────────────

if (process.platform === 'win32') {
  try {
    const out = execSync(`netstat -ano | findstr :${NTCP2_PORT}`, { encoding: 'utf8' });
    const pids = new Set();
    for (const line of out.split('\n')) {
      const parts = line.trim().split(/\s+/);
      const pid = Number(parts[parts.length - 1]);
      if (!Number.isNaN(pid) && pid > 0 && pid !== process.pid) pids.add(pid);
    }
    for (const pid of pids) {
      try { execSync(`taskkill /PID ${pid} /F`); } catch {}
    }
  } catch {}
}

// ── Decode the b32 address into a 32-byte hash ─────────────────────────

const targetHash = base32DecodeToHash(NOTBOB_B32);
if (!targetHash) {
  console.error('ERROR: failed to decode b32 address');
  process.exit(1);
}
const targetHex = targetHash.toString('hex');
console.log(`Target: ${NOTBOB_B32}`);
console.log(`Hash  : ${targetHex}`);

// ── Create & start router ───────────────────────────────────────────────

const router = new I2PRouter({
  ntcp2Port: NTCP2_PORT,
  ssu2Port:  12346,
  samPort:   7656,
  bandwidthClass: 'L',
  isFloodfill: false,
  logLevel: LogLevel.DEBUG,
  enableWebUI: true,
  webUIPort: 7070,
  dataDir: './i2p-test-data'
});

console.log('\n========================================');
console.log('  notbob.i2p LeaseSet Lookup Test');
console.log('========================================');
console.log('  Web UI : http://127.0.0.1:7070/');
console.log(`  Timeout: ${TIMEOUT_MS / 1000}s`);
console.log('========================================\n');

// ── Global timeout ──────────────────────────────────────────────────────

const deadline = setTimeout(() => {
  console.error(`\n✗ TIMEOUT after ${TIMEOUT_MS / 1000}s — LeaseSet for notbob.i2p was NOT received.`);
  router.stop().then(() => process.exit(1));
}, TIMEOUT_MS);

// ── Watch for our target LeaseSet ───────────────────────────────────────

let found = false;

router.on('leaseSetStored', ({ hash, leaseSet }) => {
  const hex = hash?.toString?.('hex') ?? '';
  if (hex === targetHex) {
    found = true;
    clearTimeout(deadline);
    console.log(`\n✓ SUCCESS — LeaseSet for notbob.i2p received!`);
    console.log(`  Hash   : ${hex}`);
    console.log(`  Leases : ${leaseSet?.leases?.length ?? 0}`);
    if (leaseSet?.leases) {
      for (const l of leaseSet.leases) {
        const gwHex = Buffer.from(l.tunnelGateway).toString('hex').slice(0, 16);
        const exp = new Date(l.expiration).toISOString();
        console.log(`    gw=${gwHex}…  tunnelId=${l.tunnelId}  expires=${exp}`);
      }
    }
    router.stop().then(() => process.exit(0));
  }
});

// Also log every LeaseSet we get so we can see progress
let lsCount = 0;
router.on('leaseSetStored', ({ hash }) => {
  lsCount++;
  const hex = hash?.toString?.('hex')?.slice(0, 16) ?? '?';
  console.log(`  [LS #${lsCount}] ${hex}…  (looking for ${targetHex.slice(0, 16)}…)`);
});

// ── Periodic targeted lookup ────────────────────────────────────────────

// Track peers we failed to reach so we don't retry
const failedPeers = new Set();

async function sendTargetedLookup() {
  if (found) return;

  const netDb = router.netDb;
  if (!netDb) return;

  // Get ALL floodfills — any floodfill can answer a LeaseSet lookup
  const allFFs = netDb.getFloodfillList();
  if (!allFFs.length) {
    console.log(`  [lookup] no floodfills known yet — waiting for reseed…`);
    return;
  }

  const ntcp2 = router.ntcp2;
  if (!ntcp2) return;

  // Filter to usable IPv4 NTCP2 addresses, exclude already-failed
  const connected = [];
  const notConnected = [];
  for (const ff of allFFs) {
    const addr = ff.addresses.find((a) => {
      const style = a.transportStyle.toUpperCase();
      if (!style.startsWith('NTCP')) return false;
      const host = a.options.host;
      if (!host || host.includes(':') || host.startsWith('[')) return false;
      return a.options.s && a.options.i && a.options.port;
    });
    if (!addr) continue;

    const host = addr.options.host;
    const port = parseInt(addr.options.port, 10);
    if (!host || !port || isNaN(port)) continue;

    const key = `${host}:${port}`;
    if (failedPeers.has(key)) continue;
    if (ntcp2.hasSession(host, port)) {
      connected.push({ ff, host, port });
    } else {
      notConnected.push({ ff, host, port });
    }
  }

  // Shuffle not-yet-connected candidates
  for (let i = notConnected.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [notConnected[i], notConnected[j]] = [notConnected[j], notConnected[i]];
  }

  console.log(`  [lookup] ${connected.length} connected, ${notConnected.length} untried, ${failedPeers.size} blacklisted`);

  // First re-send over any already-connected sessions
  const fromHash = router.routerInfo?.getRouterHash();
  if (!fromHash) return;
  const msg = I2NPMessages.createDatabaseLookup(targetHash, fromHash, 1, []);
  const wire = I2NPMessages.serializeMessage(msg);

  for (const { host, port } of connected) {
    ntcp2.send(`${host}:${port}`, wire);
    console.log(`    → re-sent to ${host}:${port}`);
  }

  // Try batches of 10 new connections until we send to at least 3
  let sentCount = connected.length;
  for (let i = 0; i < notConnected.length && sentCount < 5; i += 10) {
    if (found) return;
    const batch = notConnected.slice(i, Math.min(i + 10, notConnected.length));
    await Promise.allSettled(batch.map(async ({ ff, host, port }) => {
      if (found) return;
      const key = `${host}:${port}`;
      try {
        await ntcp2.connect(host, port, ff);
        ntcp2.send(key, wire);
        console.log(`    → sent to ${host}:${port}`);
        sentCount++;
      } catch (e) {
        failedPeers.add(key);
      }
    }));
  }

  if (sentCount === 0) console.log(`  [lookup] no connections succeeded this round`);
}

// ── Boot ────────────────────────────────────────────────────────────────

router.on('started', () => {
  console.log('[*] Router started');

  // First lookup after 15s (give reseed time to finish)
  setTimeout(sendTargetedLookup, 15_000);

  // Then retry periodically
  const interval = setInterval(() => {
    if (found) { clearInterval(interval); return; }
    sendTargetedLookup();
  }, RETRY_MS);
});

process.on('SIGINT', () => {
  console.log('\nStopping…');
  clearTimeout(deadline);
  router.stop().then(() => process.exit(found ? 0 : 1));
});

process.on('SIGTERM', () => {
  clearTimeout(deadline);
  router.stop().then(() => process.exit(found ? 0 : 1));
});

await router.start();

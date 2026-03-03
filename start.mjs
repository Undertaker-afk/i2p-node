#!/usr/bin/env node
/**
 * Start the I2P router, reseed, and watch for LeaseSets.
 * Run from the i2p-node directory:
 *   node start.mjs
 */

import { execSync } from 'child_process';
import { appendFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { I2PRouter, logger, LogLevel } from './dist/index.js';

logger.setLevel(LogLevel.DEBUG);

const LOG_FILE = process.env.I2P_LOG_FILE || './i2p-test-data/router-debug.log';
mkdirSync(dirname(LOG_FILE), { recursive: true });
logger.addHandler((entry) => {
  const line = JSON.stringify(entry);
  appendFileSync(LOG_FILE, `${line}\n`, 'utf8');
});

const NTCP2_PORT = 12345;

// Kill any leftover process holding the NTCP2 port (Windows only)
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

console.log('================================================');
console.log('  I2P Node Router');
console.log('================================================');
console.log('  Web UI : http://127.0.0.1:7070/');
console.log('  Logs   : http://127.0.0.1:7070/logs');
console.log('  Status : http://127.0.0.1:7070/api/status');
console.log('  NTCP2  : 12345   SSU2: 12346   SAM: 7656');
console.log('================================================');
console.log('Press Ctrl+C to stop');
console.log('');

router.on('started', () => {
  console.log('[*] Router started – waiting for LeaseSet...');
});

router.on('tunnelBuilt', ({ tunnelId, type }) => {
  console.log(`[+] Tunnel ${tunnelId} built (${type})`);
});

// LeaseSet received / stored
router.on('leaseSetStored', ({ hash, leaseSet }) => {
  const dest = hash?.toString?.('hex') ?? hash;
  console.log(`\n[!] LeaseSet stored for ${dest}`);
  if (leaseSet?.leases) {
    console.log(`    Leases: ${leaseSet.leases.length}`);
    for (const l of leaseSet.leases) {
      console.log(`      tunnelGW=${l.tunnelGW?.toString('hex') ?? l.tunnelGW}  tunnelId=${l.tunnelId}`);
    }
  }
});

router.on('stopped', () => {
  console.log('[*] Router stopped');
  process.exit(0);
});

process.on('SIGINT',  () => { console.log('\nStopping...'); router.stop(); });
process.on('SIGTERM', () => router.stop());

await router.start();

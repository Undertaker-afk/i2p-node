#!/usr/bin/env node

/**
 * I2P Router Peer Discovery Test
 * 
 * This script demonstrates the peer discovery mechanism:
 * 1. Starts the router
 * 2. Shows NetDb loading (with reseed if needed)
 * 3. Displays peer connections
 * 4. Shows exploratory peer discovery
 */

import { I2PRouter, logger, LogLevel } from 'i2p-node';

// Enable detailed logging to see peer discovery
logger.setLevel(LogLevel.DEBUG);

console.log('==========================================');
console.log('I2P Router - Peer Discovery Test');
console.log('==========================================');
console.log('');
console.log('This test demonstrates:');
console.log('  1. NetDb loading from disk');
console.log('  2. Reseed if peers < 90 or floodfills < 5');
console.log('  3. Exploratory peer discovery');
console.log('  4. Peer profile management');
console.log('');

// Create router with web UI to monitor
const router = new I2PRouter({
  ntcp2Port: 12345,
  // Let the OS choose a free UDP port for SSU2 to avoid conflicts with other routers/tests.
  ssu2Port: 0,
  samPort: 7656,
  bandwidthClass: 'L',
  isFloodfill: false,
  logLevel: LogLevel.DEBUG,
  enableWebUI: true,
  webUIPort: 7070,
  dataDir: './i2p-test-data'
});

// Track peer discovery
let peerDiscoveryStarted = false;
let peersFound = 0;

router.on('started', () => {
  console.log('');
  console.log('✓ Router started');
  console.log('');
  console.log('Web UI: http://127.0.0.1:7070');
  console.log('');
  console.log('Checking peer status...');
  
  const netDb = router.getNetworkDatabase();
  const stats = router.getStats();
  
  console.log(`  Known Peers: ${stats.knownPeers}`);
  console.log(`  Floodfills: ${stats.floodfillPeers}`);
  console.log(`  Online: ${netDb.isOnline() ? 'YES ✓' : 'NO - Reseed needed'}`);
  console.log('');
  
  if (!netDb.isOnline()) {
    console.log('⚠ Not enough peers - reseed required');
    console.log('  Waiting for reseed to complete...');
  } else {
    console.log('✓ Sufficient peers connected');
  }
  
  peerDiscoveryStarted = true;
});

// Monitor peer additions every 5 seconds
const monitorInterval = setInterval(() => {
  if (!peerDiscoveryStarted) return;
  
  const netDb = router.getNetworkDatabase();
  const stats = router.getStats();
  const profiles = router.getPeerProfiles().getAllProfiles();
  
  console.log(`[${new Date().toLocaleTimeString()}] Peers: ${stats.knownPeers} | Floodfills: ${stats.floodfillPeers} | Online: ${netDb.isOnline() ? 'YES' : 'NO'}`);
  
  if (profiles.length > peersFound) {
    const newPeers = profiles.length - peersFound;
    console.log(`  → ${newPeers} new peer(s) discovered!`);
    peersFound = profiles.length;
  }
}, 5000);

// Handle shutdown
process.on('SIGINT', () => {
  console.log('\n');
  console.log('Shutting down...');
  clearInterval(monitorInterval);
  router.stop();
});

// Safety timeout: auto-shutdown after 60 seconds so automated runs don't hang forever
setTimeout(() => {
  console.log('\n[timeout] Stopping peer discovery test after 60 seconds.');
  clearInterval(monitorInterval);
  router.stop();
  // Give transports a moment to close sockets, then exit.
  setTimeout(() => process.exit(0), 1000);
}, 60000);

// Start
console.log('Starting router...');
console.log('');

await router.start();

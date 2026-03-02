#!/usr/bin/env node

/**
 * I2P Router Library Test Script
 * 
 * This script demonstrates:
 * - Setting log levels
 * - Starting the router with web UI
 * - Viewing logs in real-time
 */

import { I2PRouter, logger, LogLevel } from 'i2p-node';

// Configure logging
logger.setLevel(LogLevel.DEBUG);
console.log('Log level set to DEBUG');

// Create router with web UI enabled
const router = new I2PRouter({
  ntcp2Port: 12345,
  ssu2Port: 12346,
  samPort: 7656,
  bandwidthClass: 'L',
  isFloodfill: false,
  logLevel: LogLevel.DEBUG,
  enableWebUI: true,
  webUIPort: 7070
});

console.log('');
console.log('========================================');
console.log('I2P Router Test with Logging & Web UI');
console.log('========================================');
console.log('');
console.log('Configuration:');
console.log('  Log Level: DEBUG');
console.log('  Web UI: http://127.0.0.1:7070');
console.log('  NTCP2 Port: 12345');
console.log('  SSU2 Port: 12346');
console.log('');
console.log('Web UI Pages:');
console.log('  - Main Status: http://127.0.0.1:7070/');
console.log('  - Logs: http://127.0.0.1:7070/logs');
console.log('  - API Status: http://127.0.0.1:7070/api/status');
console.log('  - API Logs: http://127.0.0.1:7070/api/logs');
console.log('');
console.log('Press Ctrl+C to stop');
console.log('');

// Handle events
router.on('started', () => {
  console.log('Router fully started!');
});

router.on('stopped', () => {
  console.log('Router stopped!');
  process.exit(0);
});

router.on('tunnelBuilt', ({ tunnelId, type }) => {
  console.log(`Tunnel ${tunnelId} built (${type})`);
});

// Start router
await router.start();

// Keep running
process.on('SIGINT', () => {
  console.log('\nStopping router...');
  router.stop();
});

process.on('SIGTERM', () => {
  router.stop();
});

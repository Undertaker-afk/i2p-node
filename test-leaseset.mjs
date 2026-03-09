/**
 * Test script: Start the I2P router and verify at least 1 LeaseSet is received within 120 seconds.
 * Exit code 0 = success, 1 = failure.
 */
import { I2PRouter } from './dist/router.js';
import { LogLevel } from './dist/utils/logger.js';
const TIMEOUT_MS = 120_000;
async function main() {
  const router = new I2PRouter({
    host: '0.0.0.0',
    ntcp2Port: 12345,
    ssu2Port: 12346,
    samPort: 7656,
    isFloodfill: true,
    bandwidthClass: 'X',
    netId: 2,
    dataDir: './test-i2p-data',
    logLevel: LogLevel.DEBUG,
    enableWebUI: false,
  });
  let leaseSetCount = 0;
  let routerInfoCount = 0;
  let searchReplyCount = 0;
  let dbStoreCount = 0;
  router.on('leaseSetStored', ({ hash }) => {
    leaseSetCount++;
    console.log(`[TEST] LeaseSet stored #${leaseSetCount}: ${hash.toString('hex').slice(0, 16)}...`);
  });
  router.on('databaseStore', () => {
    dbStoreCount++;
    if (dbStoreCount % 10 === 1) {
      console.log(`[TEST] DatabaseStore messages received: ${dbStoreCount}`);
    }
  });
  router.on('databaseSearchReply', () => {
    searchReplyCount++;
    console.log(`[TEST] DatabaseSearchReply received (total: ${searchReplyCount})`);
  });
  // Track router info count from netdb
  const netDb = router.getNetworkDatabase();
  netDb.on('routerInfoStored', () => {
    routerInfoCount++;
    if (routerInfoCount % 20 === 0) {
      console.log(`[TEST] RouterInfos stored: ${routerInfoCount}`);
    }
  });
  console.log('[TEST] Starting I2P router...');
  const startTime = Date.now();
  try {
    await router.start();
  } catch (err) {
    console.error('[TEST] Failed to start router:', err.message);
    process.exit(1);
  }
  console.log('[TEST] Router started. Waiting up to 120 seconds for LeaseSet...');
  // Poll every 2 seconds
  const checkInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const stats = router.getStats();
    const lsCount = netDb.getLeaseSetCount();
    const riCount = netDb.getRouterInfoCount();
    const ffCount = netDb.getFloodfillCount();
    console.log(
      `[TEST] t=${elapsed}s | peers=${riCount} ff=${ffCount} ls=${lsCount} ` +
      `sent=${stats.messagesSent} recv=${stats.messagesReceived} ` +
      `dbStore=${dbStoreCount} searchReply=${searchReplyCount}`
    );
    if (lsCount > 0) {
      clearInterval(checkInterval);
      console.log(`\n[TEST] SUCCESS: Received ${lsCount} LeaseSet(s) after ${elapsed}s`);
      router.stop();
      process.exit(0);
    }
  }, 2000);
  // Timeout
  setTimeout(() => {
    clearInterval(checkInterval);
    const stats = router.getStats();
    const lsCount = netDb.getLeaseSetCount();
    const riCount = netDb.getRouterInfoCount();
    const ffCount = netDb.getFloodfillCount();
    console.log(
      `\n[TEST] TIMEOUT after 120s | peers=${riCount} ff=${ffCount} ls=${lsCount} ` +
      `sent=${stats.messagesSent} recv=${stats.messagesReceived} ` +
      `dbStore=${dbStoreCount} searchReply=${searchReplyCount}`
    );
    if (lsCount > 0) {
      console.log(`[TEST] SUCCESS: Received ${lsCount} LeaseSet(s)`);
      router.stop();
      process.exit(0);
    } else {
      console.log('[TEST] FAIL: No LeaseSets received within 120 seconds');
      router.stop();
      process.exit(1);
    }
  }, TIMEOUT_MS);
}
main().catch((err) => {
  console.error('[TEST] Unhandled error:', err);
  process.exit(1);
});

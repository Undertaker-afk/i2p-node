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
  let lsType1 = 0, lsType3 = 0, riCount = 0;
  let rejectedCount = 0;

  // Log router hash and floodfill list at startup
  const netDb = router.getNetworkDatabase();
  console.log('[TEST] Router identity:', router.getRouterInfo().getRouterHash().toString('hex').slice(0, 16) + '...');

  router.on('leaseSetStored', ({ hash }) => {
    leaseSetCount++;
    const storeType = router.getNetworkDatabase().lookupLeaseSet(hash)?.storeType;
    console.log(`[TEST] LeaseSet stored #${leaseSetCount}: ${hash.toString('hex').slice(0, 16)}... (storeType=${storeType})`);
  });

  // Log rejected LeaseSets with reasons
  netDb.on('leaseSetRejected', ({ hash, leaseSet, fromFloodfill }) => {
    rejectedCount++;
    const leases = leaseSet?.leases?.length ?? 0;
    const expiration = leaseSet?.getExpiration() ? new Date(leaseSet.getExpiration()).toISOString() : 'unknown';
    console.log(`[TEST] LeaseSet rejected #${rejectedCount}: ${hash.toString('hex').slice(0, 16)}... (leases=${leases}, fromFloodfill=${fromFloodfill}, expires=${expiration})`);
  });

  router.on('databaseStore', (evt) => {
    dbStoreCount++;
    if (evt.data) {
      const type = evt.data.storeType;
      if (type === 1) lsType1++;
      else if (type === 3) lsType3++;
      else if (type === 0) riCount++;
      if (dbStoreCount % 20 === 1) {
        console.log(`[TEST] DatabaseStore: LS1=${lsType1} LS2=${lsType3} RI=${riCount} total=${dbStoreCount}`);
      }
    }
  });

  router.on('databaseSearchReply', () => {
    searchReplyCount++;
  });

  netDb.on('routerInfoStored', () => {
    routerInfoCount++;
    if (routerInfoCount % 50 === 0) {
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

  // Periodic lookup logging every 10s
  const periodicLogger = setInterval(() => {
    const stats = router.getStats();
    const lsCount = netDb.getLeaseSetCount();
    const riCount = netDb.getRouterInfoCount();
    const ffCount = netDb.getFloodfillCount();
    console.log(
      `[TEST] Periodic: t=${Math.floor((Date.now() - startTime) / 1000)}s | peers=${riCount} ff=${ffCount} ls=${lsCount} ` +
      `sent=${stats.messagesSent} recv=${stats.messagesReceived} | rejected=${rejectedCount}`
    );
  }, 10000);

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
      clearInterval(periodicLogger);
      console.log(`\n[TEST] SUCCESS: Received ${lsCount} LeaseSet(s) after ${elapsed}s`);
      router.stop();
      process.exit(0);
    }
  }, 2000);

  // Timeout
  setTimeout(() => {
    clearInterval(checkInterval);
    clearInterval(periodicLogger);
    const stats = router.getStats();
    const lsCount = netDb.getLeaseSetCount();
    const riCount = netDb.getRouterInfoCount();
    const ffCount = netDb.getFloodfillCount();
    console.log(
      `\n[TEST] TIMEOUT after 120s | peers=${riCount} ff=${ffCount} ls=${lsCount} ` +
      `sent=${stats.messagesSent} recv=${stats.messagesReceived} ` +
      `dbStore=${dbStoreCount} searchReply=${searchReplyCount} | rejected=${rejectedCount}`
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

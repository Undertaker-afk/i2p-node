/**
 * Test script: Start the I2P router and verify at least 1 LeaseSet is received within 120 seconds.
 * Exit code 0 = success, 1 = failure.
 */
import { I2PRouter } from './dist/router.js';
import { LogLevel } from './dist/utils/logger.js';
const TIMEOUT_MS = 120_000;
const DB_STORE_TYPE_NAMES = { 0: 'RouterInfo', 1: 'LS1', 3: 'LS2', 5: 'EncryptedLS2', 7: 'MetaLS2' };
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
  let ls1Count = 0;
  let ls2Count = 0;
  let riDbStoreCount = 0;
  let leaseSetRejections = [];
  let rejectionReasonCounts = {};
  let lsLookupSent = 0;
  let lsLookupSucceeded = 0;
  let lsLookupFailed = 0;
  router.on('leaseSetStored', ({ hash }) => {
    leaseSetCount++;
    lsLookupSucceeded++;
    console.log(`[TEST] LeaseSet stored #${leaseSetCount}: ${hash.toString('hex').slice(0, 16)}...`);
  });
  router.on('databaseStore', ({ message }) => {
    dbStoreCount++;
    const buf = message.payload;
    let typeName = 'unknown';
    if (buf && buf.length > 32) {
      const typeByte = buf.readUInt8(32);
      typeName = DB_STORE_TYPE_NAMES[typeByte] || `type=${typeByte}`;
      if (typeByte === 0) riDbStoreCount++;
      else if (typeByte === 1) ls1Count++;
      else if (typeByte === 3) ls2Count++;
    }
    console.log(`[TEST] DatabaseStore #${dbStoreCount}: ${typeName}`);
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
  netDb.on('leaseSetRejected', ({ hash, leaseSet, fromFloodfill }) => {
    const hashHex = hash.toString('hex').slice(0, 16);
    let reason;
    // Derive reason matching verifyLeaseSet logic in src/netdb/index.ts
    if (!leaseSet.signature || leaseSet.signature.length === 0) {
      reason = fromFloodfill ? 'missing signature (floodfill path)' : 'missing signature';
    } else {
      const leases = leaseSet.leases;
      const leaseCount = leases ? leases.length : 0;
      const expiration = leaseSet.getExpiration ? leaseSet.getExpiration() : 0;
      const now = Date.now();
      const expirationDelta = expiration - now;
      if (leaseCount === 0 && leaseSet.storeType !== 3) {
        reason = `no leases (storeType=${leaseSet.storeType})`;
      } else if (leaseCount > 16) {
        reason = `too many leases (${leaseCount})`;
      } else if (expiration <= now) {
        reason = `already expired (delta=${expirationDelta}ms, leases=${leaseCount})`;
      } else if (expiration > now + 15 * 60 * 1000) {
        reason = `expiration too far in future (delta=${expirationDelta}ms, leases=${leaseCount})`;
      } else {
        reason = `unknown (storeType=${leaseSet.storeType}, leases=${leaseCount}, sigLen=${leaseSet.signature?.length ?? 0})`;
      }
    }
    const entry = { hash: hashHex, reason, fromFloodfill };
    leaseSetRejections.push(entry);
    rejectionReasonCounts[reason] = (rejectionReasonCounts[reason] || 0) + 1;
    console.log(`[TEST] LeaseSet REJECTED: ${hashHex}... reason=${reason} (fromFloodfill=${fromFloodfill})`);
  });
  netDb.on('leaseSetLookup', ({ targetHash, lookupType }) => {
    lsLookupSent++;
    if (lsLookupSent % 5 === 1) {
      console.log(`[TEST] LeaseSet lookup #${lsLookupSent}: target=${targetHash.toString('hex').slice(0, 16)}... type=${lookupType}`);
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
  // Log router hash and floodfill status at startup
  const routerInfo = router.getRouterInfo();
  const routerHash = routerInfo?.getRouterHash();
  const routerHashHex = routerHash ? routerHash.toString('hex') : 'N/A';
  console.log(`[TEST] Router hash: ${routerHashHex}`);
  console.log(`[TEST] Floodfill enabled: true`);
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
      `dbStore=${dbStoreCount} (LS1=${ls1Count} LS2=${ls2Count} RI=${riDbStoreCount}) ` +
      `searchReply=${searchReplyCount} lsLookupsSent=${lsLookupSent}`
    );
    if (lsCount > 0) {
      clearInterval(checkInterval);
      console.log(`\n[TEST] SUCCESS: Received ${lsCount} LeaseSet(s) after ${elapsed}s`);
      router.stop();
      process.exit(0);
    }
  }, 2000);
  // Periodic lookup count logging every 10 seconds
  const lookupLogInterval = setInterval(() => {
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    console.log(
      `[TEST] Lookup summary at t=${elapsed}s: sent=${lsLookupSent} succeeded=${lsLookupSucceeded} ` +
      `failed=${lsLookupFailed} rejections=${leaseSetRejections.length}`
    );
  }, 10000);
  // Timeout
  setTimeout(() => {
    clearInterval(checkInterval);
    clearInterval(lookupLogInterval);
    const stats = router.getStats();
    const lsCount = netDb.getLeaseSetCount();
    const riCount = netDb.getRouterInfoCount();
    const ffCount = netDb.getFloodfillCount();
    lsLookupFailed = lsLookupSent - lsLookupSucceeded;
    console.log(
      `\n[TEST] TIMEOUT after 120s | peers=${riCount} ff=${ffCount} ls=${lsCount} ` +
      `sent=${stats.messagesSent} recv=${stats.messagesReceived} ` +
      `dbStore=${dbStoreCount} (LS1=${ls1Count} LS2=${ls2Count} RI=${riDbStoreCount}) ` +
      `searchReply=${searchReplyCount}`
    );
    console.log(`[TEST] LS lookup summary: sent=${lsLookupSent} succeeded=${lsLookupSucceeded} failed=${lsLookupFailed}`);
    if (Object.keys(rejectionReasonCounts).length > 0) {
      console.log('[TEST] Rejection reason breakdown:');
      for (const [reason, count] of Object.entries(rejectionReasonCounts)) {
        console.log(`[TEST]   ${reason}: ${count}`);
      }
    }
    if (leaseSetRejections.length > 0) {
      console.log(`[TEST] LeaseSet rejections (${leaseSetRejections.length}):`);
      for (const r of leaseSetRejections) {
        console.log(`[TEST]   ${r.hash}... reason=${r.reason} fromFloodfill=${r.fromFloodfill}`);
      }
    } else {
      console.log('[TEST] No LeaseSet rejections recorded');
    }
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

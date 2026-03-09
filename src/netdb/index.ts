import { EventEmitter } from 'events';
import { createHash } from 'crypto';
import { RouterInfo, RouterIdentity, RouterAddress } from '../data/router-info.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';
import { LeaseSet } from '../data/lease-set.js';
import { Reseeder } from './reseed.js';
import { logger } from '../utils/logger.js';

export interface NetDbEntry {
  key: Buffer;
  data: RouterInfo | LeaseSet;
  type: 'routerInfo' | 'leaseSet';
  timestamp: number;
  source?: string;
}

export interface NetDbOptions {
  maxRouterInfos?: number;
  maxLeaseSets?: number;
  isFloodfill?: boolean;
  enableReseed?: boolean;
  dataDir?: string;
}

/**
 * Minimum numbers for considering the router "online"
 */
const MIN_ROUTERS = 90;
const MIN_FLOODFILLS = 5;
const MIN_TRANSPORTS = 10;

export class NetworkDatabase extends EventEmitter {
  private routerInfos: Map<string, NetDbEntry> = new Map();
  private leaseSets: Map<string, NetDbEntry> = new Map();
  private floodfillPeers: Set<string> = new Set();
  private options: NetDbOptions;
  private reseeder: Reseeder;
  private isRunning = false;
  private exploratoryTimer: NodeJS.Timeout | null = null;
  private maintenanceTimer: NodeJS.Timeout | null = null;
  private startedAt = 0;
  private lastLeaseSetLookupAt = 0;

  constructor(options: NetDbOptions = {}) {
    super();
    this.options = {
      maxRouterInfos: 3000,
      maxLeaseSets: 10000,
      isFloodfill: false,
      enableReseed: true,
      dataDir: './i2p-data',
      ...options
    };
    
    this.reseeder = new Reseeder();
    
    logger.debug('NetworkDatabase created', { options: this.options }, 'NetDb');
  }

  /**
   * Start the NetDb - loads from disk and triggers reseed if needed
   */
  async start(): Promise<void> {
    if (this.isRunning) return;
    
    logger.info('Starting NetworkDatabase...', undefined, 'NetDb');
    this.isRunning = true;

    // Try to load from disk first
    await this.loadFromDisk();
    
    const routerCount = this.routerInfos.size;
    const floodfillCount = this.floodfillPeers.size;
    
    logger.info(`Loaded ${routerCount} routers (${floodfillCount} floodfills) from disk`, undefined, 'NetDb');

    // Check if reseeding is needed
    if (this.options.enableReseed && this.reseeder.isReseedNeeded(routerCount, floodfillCount)) {
      logger.warn(`Reseed needed: ${routerCount}/${MIN_ROUTERS} routers, ${floodfillCount}/${MIN_FLOODFILLS} floodfills`, undefined, 'NetDb');
      
      try {
        const routers = await this.reseeder.bootstrap();
        
        let added = 0;
        for (const routerData of routers) {
          const routerInfo = parseI2PRouterInfo(routerData.data);
          if (!routerInfo) {
            logger.warn('Failed to parse reseeded router info (I2P format)', undefined, 'NetDb');
            continue;
          }
          if (this.storeRouterInfo(routerInfo)) {
            added++;
          }
        }
        
        logger.info(`Reseed added ${added} routers`, undefined, 'NetDb');
      } catch (err) {
        logger.error('Reseed failed', { error: (err as Error).message }, 'NetDb');
        
        // On total reseed failure we currently do not fabricate peers.
      }
    }

    // Start exploratory peer discovery
    this.startedAt = Date.now();
    this.startExploratory();
    this.startMaintenance();
    
    logger.info('NetworkDatabase started', undefined, 'NetDb');
    this.emit('started');
  }

  // Placeholder helper removed: we now use a real I2P RouterInfo parser.

  /**
   * Stop the NetDb
   */
  stop(): void {
    if (!this.isRunning) return;
    
    logger.info('Stopping NetworkDatabase...', undefined, 'NetDb');
    this.isRunning = false;
    
    if (this.exploratoryTimer) {
      clearTimeout(this.exploratoryTimer);
      this.exploratoryTimer = null;
    }
    
    if (this.maintenanceTimer) {
      clearInterval(this.maintenanceTimer);
      this.maintenanceTimer = null;
    }
    
    // Save to disk
    this.saveToDisk();
    
    logger.info('NetworkDatabase stopped', undefined, 'NetDb');
    this.emit('stopped');
  }

  /**
   * Check if we have enough peers to be considered "online"
   */
  isOnline(): boolean {
    const transports = this.getConnectedTransportCount();
    return this.routerInfos.size >= MIN_ROUTERS && 
           this.floodfillPeers.size >= MIN_FLOODFILLS &&
           transports >= MIN_TRANSPORTS;
  }

  /**
   * Get count of routers we can actually connect to (have transports)
   */
  private getConnectedTransportCount(): number {
    let count = 0;
    for (const entry of this.routerInfos.values()) {
      const router = entry.data as RouterInfo;
      if (router.addresses.length > 0) {
        count++;
      }
    }
    return count;
  }

  /**
   * Start exploratory peer discovery
   * This periodically requests router infos from connected peers
   */
  private startExploratory(): void {
    // Explore immediately on start, then use adaptive interval:
    // - During bootstrap (first 60s): every 5 seconds
    // - After bootstrap: every 30 seconds
    this.exploreNewPeers();

    const tick = () => {
      this.exploreNewPeers();
      const bootstrapping = (Date.now() - this.startedAt) < 60_000;
      const nextMs = bootstrapping ? 5_000 : 30_000;
      this.exploratoryTimer = setTimeout(tick, nextMs);
    };
    this.exploratoryTimer = setTimeout(tick, 5_000);
    
    logger.debug('Started exploratory peer discovery', undefined, 'NetDb');
  }

  /**
   * Explore new peers by requesting random router hashes
   */
  private exploreNewPeers(): void {
    if (!this.isRunning) return;
    
    // Pick a random floodfill to query
    const floodfills = this.getFloodfillList();
    if (floodfills.length === 0) {
      logger.debug('No floodfills available for exploration', undefined, 'NetDb');
      return;
    }
    
    // Generate a random hash to search for
    const randomHash = createHash('sha256').update(Math.random().toString()).digest();
    
    // Find closest floodfills — try more during bootstrap for faster peer discovery
    const bootstrapping = (Date.now() - this.startedAt) < 60_000;
    const closestFloodfills = this.findClosestFloodfills(randomHash, bootstrapping ? 10 : 3);
    
    logger.debug(`Exploring peers near ${randomHash.toString('hex').slice(0, 16)}...`, {
      closestFloodfills: closestFloodfills.length
    }, 'NetDb');
    
    // Emit event to request lookup
    for (const floodfill of closestFloodfills) {
      this.emit('exploratoryLookup', {
        targetHash: randomHash,
        floodfill: floodfill
      });
    }

    // Also do normal (type 0) lookups for random hashes to discover LeaseSets.
    // Keep this aggressive during bootstrap, then back off to one lookup every
    // 30s until we receive at least one LeaseSet.
    const now = Date.now();
    const shouldLookupLeaseSets =
      this.leaseSets.size === 0 &&
      (bootstrapping || (now - this.lastLeaseSetLookupAt) >= 30_000);

    if (shouldLookupLeaseSets) {
      const lsHash = createHash('sha256').update(Date.now().toString() + Math.random().toString()).digest();
      const lsFloodfills = this.findClosestFloodfills(lsHash, bootstrapping ? 3 : 1);
      for (const ff of lsFloodfills) {
        this.emit('leaseSetLookup', { targetHash: lsHash, floodfill: ff });
      }
      this.lastLeaseSetLookupAt = now;
    }
  }

  /**
   * Start maintenance tasks (cleanup, expiration)
   */
  private startMaintenance(): void {
    this.maintenanceTimer = setInterval(() => {
      this.performMaintenance();
    }, 60000); // Every minute
    
    logger.debug('Started NetDb maintenance', undefined, 'NetDb');
  }

  /**
   * Perform maintenance tasks
   */
  private performMaintenance(): void {
    if (!this.isRunning) return;
    
    logger.debug('Performing NetDb maintenance', undefined, 'NetDb');
    
    // Cleanup expired entries
    this.cleanupRouterInfos();
    this.cleanupLeaseSets();
    
    // Save to disk
    this.saveToDisk();
    
    // Log stats
    logger.info(`NetDb stats: ${this.routerInfos.size} routers, ${this.floodfillPeers.size} floodfills, ${this.leaseSets.size} leasesets`, undefined, 'NetDb');
  }

  /**
   * Load router infos from disk
   */
  private async loadFromDisk(): Promise<void> {
    try {
      const fs = await import('fs');
      const path = await import('path');
      const netDbPath = path.join(this.options.dataDir!, 'netDb');
      
      if (!fs.existsSync(netDbPath)) {
        logger.debug('NetDb directory does not exist, creating...', undefined, 'NetDb');
        fs.mkdirSync(netDbPath, { recursive: true });
        return;
      }
      
      // Read router info files
      const files = await fs.promises.readdir(netDbPath);
      let loaded = 0;
      
      for (const file of files) {
        if (!file.endsWith('.dat')) continue;
        
        try {
          const data = await fs.promises.readFile(path.join(netDbPath, file));
          const routerInfo = RouterInfo.deserialize(data);

          // Restore the correct IdentHash from the filename.
          // When saved to disk, the filename is routerInfo-<identHash>.dat where
          // identHash was computed correctly at save-time.  The custom serialization
          // format does NOT embed the raw identity bytes so getHash() would otherwise
          // recompute from the custom layout and return a wrong value — breaking AES key
          // derivation in NTCP2 handshakes.
          const hashHex = file.replace('routerInfo-', '').replace('.dat', '');
          if (/^[0-9a-f]{64}$/.test(hashHex)) {
            routerInfo.identity.setHash(Buffer.from(hashHex, 'hex'));
          }

          this.storeRouterInfo(routerInfo);
          loaded++;
        } catch (err) {
          logger.warn(`Failed to load router info from ${file}`, undefined, 'NetDb');
        }
      }
      
      logger.info(`Loaded ${loaded} router infos from disk`, undefined, 'NetDb');
    } catch (err) {
      logger.error('Failed to load from disk', { error: (err as Error).message }, 'NetDb');
    }
  }

  /**
   * Save router infos to disk
   */
  private async saveToDisk(): Promise<void> {
    try {
      const fs = await import('fs');
      const path = await import('path');
      const netDbPath = path.join(this.options.dataDir!, 'netDb');
      
      // Ensure directory exists
      fs.mkdirSync(netDbPath, { recursive: true });
      
      // Save router infos
      for (const [key, entry] of this.routerInfos) {
        try {
          const filePath = path.join(netDbPath, `routerInfo-${key}.dat`);
          const data = (entry.data as RouterInfo).serialize();
          await fs.promises.writeFile(filePath, data);
        } catch (err) {
          logger.warn(`Failed to save router info ${key}`, undefined, 'NetDb');
        }
      }
      
      logger.debug(`Saved ${this.routerInfos.size} router infos to disk`, undefined, 'NetDb');
    } catch (err) {
      logger.error('Failed to save to disk', { error: (err as Error).message }, 'NetDb');
    }
  }

  storeRouterInfo(routerInfo: RouterInfo, fromFloodfill = false): boolean {
    const hash = routerInfo.getRouterHash();
    const key = hash.toString('hex');
    
    if (this.routerInfos.has(key)) {
      const existing = this.routerInfos.get(key)!;
      if (existing.timestamp >= routerInfo.published) {
        return false;
      }
    }
    
    if (!this.verifyRouterInfo(routerInfo)) {
      return false;
    }
    
    this.routerInfos.set(key, {
      key: hash,
      data: routerInfo,
      type: 'routerInfo',
      timestamp: routerInfo.published
    });
    
    if (this.isFloodfillRouter(routerInfo)) {
      this.floodfillPeers.add(key);
    }
    
    if (fromFloodfill && this.options.isFloodfill) {
      this.floodToClosestPeers(hash, routerInfo);
    }
    
    logger.debug(`Stored router info ${key.slice(0, 16)}...`, {
      isFloodfill: this.isFloodfillRouter(routerInfo),
      addresses: routerInfo.addresses.length
    }, 'NetDb');
    
    this.emit('routerInfoStored', { hash, routerInfo });
    
    return true;
  }

  storeLeaseSet(leaseSet: LeaseSet, fromFloodfill = false): boolean {
    const hash = leaseSet.getHash();
    const key = hash.toString('hex');
    
    if (this.leaseSets.has(key)) {
      const existing = this.leaseSets.get(key)!;
      const newExpiration = leaseSet.getExpiration();
      const existingExpiration = (existing.data as LeaseSet).getExpiration();
      
      if (existingExpiration >= newExpiration) {
        return false;
      }
    }
    
    if (!this.verifyLeaseSet(leaseSet)) {
      return false;
    }
    
    this.leaseSets.set(key, {
      key: hash,
      data: leaseSet,
      type: 'leaseSet',
      timestamp: Date.now()
    });
    
    if (fromFloodfill && this.options.isFloodfill) {
      this.floodToClosestPeers(hash, leaseSet);
    }
    
    logger.debug(`Stored lease set ${key.slice(0, 16)}...`, undefined, 'NetDb');
    this.emit('leaseSetStored', { hash, leaseSet });
    
    return true;
  }

  lookupRouterInfo(hash: Buffer): RouterInfo | null {
    const key = hash.toString('hex');
    const entry = this.routerInfos.get(key);
    return entry ? entry.data as RouterInfo : null;
  }

  lookupLeaseSet(hash: Buffer): LeaseSet | null {
    const key = hash.toString('hex');
    const entry = this.leaseSets.get(key);
    return entry ? entry.data as LeaseSet : null;
  }

  findClosestFloodfills(targetKey: Buffer, count: number): RouterInfo[] {
    const floodfills: { hash: Buffer; distance: Buffer; routerInfo: RouterInfo }[] = [];
    
    for (const ffKey of this.floodfillPeers) {
      const entry = this.routerInfos.get(ffKey);
      if (!entry) continue;
      
      const hash = Buffer.from(ffKey, 'hex');
      const distance = this.xorDistance(hash, targetKey);
      
      floodfills.push({
        hash,
        distance,
        routerInfo: entry.data as RouterInfo
      });
    }
    
    floodfills.sort((a, b) => a.distance.compare(b.distance));
    
    return floodfills.slice(0, count).map(f => f.routerInfo);
  }

  private xorDistance(a: Buffer, b: Buffer): Buffer {
    const result = Buffer.alloc(32);
    for (let i = 0; i < 32; i++) {
      result[i] = a[i] ^ b[i];
    }
    return result;
  }

  private verifyRouterInfo(routerInfo: RouterInfo): boolean {
    if (!routerInfo.signature || routerInfo.signature.length === 0) {
      return false;
    }
    
    return true;
  }

  private verifyLeaseSet(leaseSet: LeaseSet): boolean {
    if (!leaseSet.signature || leaseSet.signature.length === 0) {
      logger.debug('LeaseSet rejected: missing signature', undefined, 'NetDb');
      return false;
    }

    // Validate lease count (per i2pd: MAX_NUM_LEASES = 16)
    const leases = leaseSet.leases;
    if (!leases || leases.length === 0) {
      logger.debug('LeaseSet rejected: no leases', undefined, 'NetDb');
      return false;
    }
    if (leases.length > 16) {
      logger.debug(`LeaseSet rejected: too many leases (${leases.length})`, undefined, 'NetDb');
      return false;
    }

    // Validate expiration: reject already-expired LeaseSets
    const expiration = leaseSet.getExpiration();
    const now = Date.now();
    if (expiration <= now) {
      logger.debug('LeaseSet rejected: already expired', undefined, 'NetDb');
      return false;
    }

    // Reject LeaseSets with expiration too far in the future (> 11 minutes per i2pd)
    const maxFuture = 11 * 60 * 1000; // 11 minutes
    if (expiration > now + maxFuture) {
      logger.debug('LeaseSet rejected: expiration too far in the future', undefined, 'NetDb');
      return false;
    }

    return true;
  }

  private isFloodfillRouter(routerInfo: RouterInfo): boolean {
    const caps = routerInfo.options.caps || '';
    return caps.includes('f');
  }

  private floodToClosestPeers(key: Buffer, data: RouterInfo | LeaseSet): void {
    const routingKey = this.getRoutingKey(key);
    const closestFloodfills = this.findClosestFloodfills(routingKey, 3);
    
    for (const floodfill of closestFloodfills) {
      this.emit('flood', {
        target: floodfill,
        key,
        data
      });
    }
  }

  private getRoutingKey(key: Buffer): Buffer {
    const date = new Date();
    const dateStr = date.toISOString().slice(0, 10).replace(/-/g, '');
    const dateBuf = Buffer.from(dateStr, 'ascii');
    
    return createHash('sha256').update(Buffer.concat([key, dateBuf])).digest();
  }

  private cleanupRouterInfos(): void {
    const now = Date.now();
    const expirationTime = 72 * 60 * 60 * 1000; // 72 hours
    
    for (const [key, entry] of this.routerInfos.entries()) {
      if (now - entry.timestamp > expirationTime) {
        this.routerInfos.delete(key);
        this.floodfillPeers.delete(key);
        logger.debug(`Expired router info ${key.slice(0, 16)}...`, undefined, 'NetDb');
      }
    }
  }

  private cleanupLeaseSets(): void {
    const now = Date.now();
    
    for (const [key, entry] of this.leaseSets.entries()) {
      const leaseSet = entry.data as LeaseSet;
      if (leaseSet.getExpiration() < now) {
        this.leaseSets.delete(key);
        logger.debug(`Expired lease set ${key.slice(0, 16)}...`, undefined, 'NetDb');
      }
    }
  }

  getFloodfillList(): RouterInfo[] {
    const floodfills: RouterInfo[] = [];
    for (const key of this.floodfillPeers) {
      const entry = this.routerInfos.get(key);
      if (entry) {
        floodfills.push(entry.data as RouterInfo);
      }
    }
    return floodfills;
  }

  getAllRouterInfos(): RouterInfo[] {
    return Array.from(this.routerInfos.values()).map(e => e.data as RouterInfo);
  }

  getAllLeaseSets(): LeaseSet[] {
    return Array.from(this.leaseSets.values()).map(e => e.data as LeaseSet);
  }

  getFloodfillCount(): number {
    return this.floodfillPeers.size;
  }

  getRouterInfoCount(): number {
    return this.routerInfos.size;
  }

  getLeaseSetCount(): number {
    return this.leaseSets.size;
  }
}

export default NetworkDatabase;

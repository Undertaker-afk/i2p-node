import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';

/**
 * Tracks a single pending NetDb lookup request.
 * Modeled after i2pd's RequestedDestination.
 */
export interface PendingRequest {
  destination: Buffer;
  isExploratory: boolean;
  excludedPeers: Set<string>;
  creationTime: number;
  lastRequestTime: number;
  numAttempts: number;
  isActive: boolean;
  callbacks: Array<(router: Buffer | null) => void>;
}

const MAX_NUM_REQUEST_ATTEMPTS = 5;
const MAX_REQUEST_TIME = 30000; // 30 seconds
const MIN_REQUEST_INTERVAL = 1200; // ms between retry attempts
const MAX_EXPLORATORY_REQUEST_TIME = 30000; // 30 seconds
const MANAGE_REQUESTS_INTERVAL = 2000; // 2 seconds
const DISCOVERED_REQUEST_DELAY = 360; // ms delay before requesting discovered routers

/**
 * Manages pending NetDb lookup requests, retries, and discovered router tracking.
 * Modeled after i2pd's NetDbRequests.
 */
export class NetDbRequests extends EventEmitter {
  private requests: Map<string, PendingRequest> = new Map();
  private discoveredRouterHashes: Buffer[] = [];
  private manageTimer: NodeJS.Timeout | null = null;
  private discoveredTimer: NodeJS.Timeout | null = null;
  private isRunning = false;

  start(): void {
    if (this.isRunning) return;
    this.isRunning = true;
    this.manageTimer = setInterval(() => this.manageRequests(), MANAGE_REQUESTS_INTERVAL);
    logger.debug('NetDbRequests started', undefined, 'NetDbReq');
  }

  stop(): void {
    if (!this.isRunning) return;
    this.isRunning = false;
    if (this.manageTimer) {
      clearInterval(this.manageTimer);
      this.manageTimer = null;
    }
    if (this.discoveredTimer) {
      clearTimeout(this.discoveredTimer);
      this.discoveredTimer = null;
    }
    // Fail all active requests
    for (const [, req] of this.requests) {
      if (req.isActive) {
        req.isActive = false;
        for (const cb of req.callbacks) cb(null);
      }
    }
    this.requests.clear();
    this.discoveredRouterHashes = [];
    logger.debug('NetDbRequests stopped', undefined, 'NetDbReq');
  }

  /**
   * Create a new request for a destination hash.
   * Returns the PendingRequest if newly created, or null if it already exists.
   */
  createRequest(
    destination: Buffer,
    isExploratory: boolean,
    callback?: (router: Buffer | null) => void
  ): PendingRequest | null {
    const key = destination.toString('hex');

    const existing = this.requests.get(key);
    if (existing) {
      if (callback) {
        if (existing.isActive) {
          existing.callbacks.push(callback);
        } else {
          callback(null);
        }
      }
      return null; // already requested
    }

    const req: PendingRequest = {
      destination: Buffer.from(destination),
      isExploratory,
      excludedPeers: new Set(),
      creationTime: Date.now(),
      lastRequestTime: 0,
      numAttempts: 0,
      isActive: true,
      callbacks: callback ? [callback] : []
    };

    this.requests.set(key, req);
    return req;
  }

  /**
   * Mark a request as successfully completed.
   */
  requestComplete(ident: Buffer, success: boolean): void {
    const key = ident.toString('hex');
    const req = this.requests.get(key);
    if (!req) return;

    if (req.isExploratory) {
      this.requests.delete(key);
    }

    if (req.isActive) {
      req.isActive = false;
      for (const cb of req.callbacks) {
        cb(success ? ident : null);
      }
      req.callbacks = [];
    }
  }

  /**
   * Find an active request for the given ident.
   */
  findRequest(ident: Buffer): PendingRequest | null {
    const key = ident.toString('hex');
    const req = this.requests.get(key);
    return (req && req.isActive) ? req : null;
  }

  /**
   * Check if a request exists (active or cached) for this ident.
   */
  hasRequest(ident: Buffer): boolean {
    return this.requests.has(ident.toString('hex'));
  }

  /**
   * Handle a DatabaseSearchReply: track discovered routers and schedule requests.
   * Per i2pd: if exploratory, postpone router requests; otherwise request immediately.
   */
  handleSearchReply(
    key: Buffer,
    routerHashes: Buffer[],
    isExploratory: boolean
  ): void {
    const keyHex = key.toString('hex').slice(0, 16);
    logger.debug(
      `DatabaseSearchReply for ${keyHex}... num=${routerHashes.length}`,
      undefined,
      'NetDbReq'
    );

    const req = this.findRequest(key);
    if (req) {
      if (!isExploratory && (routerHashes.length > 0 || req.numAttempts < 3)) {
        // Try next floodfill
        this.emit('sendNextRequest', req);
      } else {
        this.requestComplete(key, false);
      }
    }

    // Process discovered router hashes
    for (const hash of routerHashes) {
      if (isExploratory) {
        // Postpone: batch discovered routers and request later
        this.discoveredRouterHashes.push(Buffer.from(hash));
      } else {
        // Request immediately
        this.emit('requestRouter', hash);
      }
    }

    // If exploratory, schedule the batch request
    if (isExploratory && this.discoveredRouterHashes.length > 0) {
      this.scheduleDiscoveredRoutersRequest();
    }
  }

  /**
   * Schedule a delayed batch request for discovered routers.
   * Mirrors i2pd's ScheduleDiscoveredRoutersRequest.
   */
  private scheduleDiscoveredRoutersRequest(): void {
    if (this.discoveredTimer) return; // already scheduled

    this.discoveredTimer = setTimeout(() => {
      this.discoveredTimer = null;
      const hashes = this.discoveredRouterHashes.splice(0);
      for (const hash of hashes) {
        this.emit('requestRouter', hash);
      }
    }, DISCOVERED_REQUEST_DELAY);
  }

  /**
   * Periodic management of pending requests: retry or expire.
   */
  private manageRequests(): void {
    const now = Date.now();

    for (const [key, req] of this.requests) {
      if (!req.isActive && now > req.creationTime + MAX_REQUEST_TIME + 40000) {
        // Expired cache entry
        this.requests.delete(key);
        continue;
      }

      if (!req.isActive) continue;

      if (req.isExploratory) {
        if (now >= req.creationTime + MAX_EXPLORATORY_REQUEST_TIME) {
          this.requestComplete(req.destination, false);
        }
        continue;
      }

      // Regular request
      if (now >= req.creationTime + MAX_REQUEST_TIME) {
        // Timed out
        this.requestComplete(req.destination, false);
        continue;
      }

      if (now > req.lastRequestTime + MIN_REQUEST_INTERVAL) {
        if (req.numAttempts < MAX_NUM_REQUEST_ATTEMPTS) {
          this.emit('sendNextRequest', req);
        } else {
          this.requestComplete(req.destination, false);
        }
      }
    }
  }

  /**
   * Record that a request attempt was made.
   */
  recordAttempt(ident: Buffer, excludedPeer?: Buffer): void {
    const key = ident.toString('hex');
    const req = this.requests.get(key);
    if (!req) return;
    req.numAttempts++;
    req.lastRequestTime = Date.now();
    if (excludedPeer) {
      req.excludedPeers.add(excludedPeer.toString('hex'));
    }
  }

  getRequestCount(): number {
    return this.requests.size;
  }

  getActiveRequestCount(): number {
    let count = 0;
    for (const req of this.requests.values()) {
      if (req.isActive) count++;
    }
    return count;
  }
}

export default NetDbRequests;

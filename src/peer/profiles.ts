import { EventEmitter } from 'events';
import { RouterInfo } from '../data/router-info.js';

export interface PeerStats {
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
  connectionAttempts: number;
  successfulConnections: number;
  failedConnections: number;
  lastSeen: number;
  lastFailed: number;
}

export interface PeerProfile {
  routerHash: string;
  routerInfo: RouterInfo;
  stats: PeerStats;
  isFloodfill: boolean;
  capacity: number;
  integrationTime: number;
}

export interface PeerSelectionCriteria {
  minCapacity?: number;
  requireFloodfill?: boolean;
  excludeHashes?: string[];
  maxFailures?: number;
}

export class PeerProfileManager extends EventEmitter {
  private profiles: Map<string, PeerProfile> = new Map();
  private maxProfiles: number;

  constructor(maxProfiles = 5000) {
    super();
    this.maxProfiles = maxProfiles;
  }

  addPeer(routerInfo: RouterInfo): PeerProfile {
    const hash = routerInfo.getRouterHash().toString('hex');
    
    if (this.profiles.has(hash)) {
      const existing = this.profiles.get(hash)!;
      existing.routerInfo = routerInfo;
      return existing;
    }
    
    const caps = routerInfo.options.caps || '';
    const profile: PeerProfile = {
      routerHash: hash,
      routerInfo,
      stats: {
        messagesSent: 0,
        messagesReceived: 0,
        bytesSent: 0,
        bytesReceived: 0,
        connectionAttempts: 0,
        successfulConnections: 0,
        failedConnections: 0,
        lastSeen: 0,
        lastFailed: 0
      },
      isFloodfill: caps.includes('f'),
      capacity: this.parseCapacity(caps),
      integrationTime: Date.now()
    };
    
    this.profiles.set(hash, profile);
    
    if (this.profiles.size > this.maxProfiles) {
      this.cleanupOldProfiles();
    }
    
    this.emit('peerAdded', { hash, profile });
    return profile;
  }

  getProfile(hash: string): PeerProfile | undefined {
    return this.profiles.get(hash);
  }

  updateStats(hash: string, updates: Partial<PeerStats>): void {
    const profile = this.profiles.get(hash);
    if (!profile) return;
    
    Object.assign(profile.stats, updates);
    
    if (updates.successfulConnections) {
      profile.stats.lastSeen = Date.now();
    }
    
    if (updates.failedConnections) {
      profile.stats.lastFailed = Date.now();
    }
  }

  recordMessageSent(hash: string, bytes: number): void {
    const profile = this.profiles.get(hash);
    if (!profile) return;
    
    profile.stats.messagesSent++;
    profile.stats.bytesSent += bytes;
  }

  recordMessageReceived(hash: string, bytes: number): void {
    const profile = this.profiles.get(hash);
    if (!profile) return;
    
    profile.stats.messagesReceived++;
    profile.stats.bytesReceived += bytes;
    profile.stats.lastSeen = Date.now();
  }

  recordConnectionAttempt(hash: string): void {
    const profile = this.profiles.get(hash);
    if (!profile) return;
    
    profile.stats.connectionAttempts++;
  }

  recordConnectionSuccess(hash: string): void {
    const profile = this.profiles.get(hash);
    if (!profile) return;
    
    profile.stats.successfulConnections++;
    profile.stats.lastSeen = Date.now();
  }

  recordConnectionFailure(hash: string): void {
    const profile = this.profiles.get(hash);
    if (!profile) return;
    
    profile.stats.failedConnections++;
    profile.stats.lastFailed = Date.now();
  }

  selectPeers(count: number, criteria: PeerSelectionCriteria = {}): PeerProfile[] {
    let candidates = Array.from(this.profiles.values());
    
    if (criteria.minCapacity !== undefined) {
      candidates = candidates.filter(p => p.capacity >= criteria.minCapacity!);
    }
    
    if (criteria.requireFloodfill) {
      candidates = candidates.filter(p => p.isFloodfill);
    }
    
    if (criteria.excludeHashes) {
      const excludeSet = new Set(criteria.excludeHashes);
      candidates = candidates.filter(p => !excludeSet.has(p.routerHash));
    }
    
    if (criteria.maxFailures !== undefined) {
      candidates = candidates.filter(p => p.stats.failedConnections <= criteria.maxFailures!);
    }
    
    candidates.sort((a, b) => this.calculateScore(b) - this.calculateScore(a));
    
    const shuffled = candidates
      .slice(0, Math.min(count * 2, candidates.length))
      .sort(() => Math.random() - 0.5);
    
    return shuffled.slice(0, count);
  }

  private calculateScore(profile: PeerProfile): number {
    const totalConnections = profile.stats.successfulConnections + profile.stats.failedConnections;
    const successRate = totalConnections > 0 ? profile.stats.successfulConnections / totalConnections : 0.5;
    
    const lastSeenHours = (Date.now() - profile.stats.lastSeen) / 3600000;
    const recencyFactor = Math.max(0, 1 - lastSeenHours / 24);
    
    return profile.capacity * successRate * recencyFactor;
  }

  private parseCapacity(caps: string): number {
    if (caps.includes('K')) return 12;
    if (caps.includes('L')) return 48;
    if (caps.includes('M')) return 64;
    if (caps.includes('N')) return 128;
    if (caps.includes('O')) return 256;
    if (caps.includes('P')) return 2000;
    if (caps.includes('X')) return 2001;
    return 12;
  }

  private cleanupOldProfiles(): void {
    const profiles = Array.from(this.profiles.entries());
    profiles.sort((a, b) => a[1].stats.lastSeen - b[1].stats.lastSeen);
    
    const toDelete = profiles.slice(0, Math.floor(this.maxProfiles * 0.1));
    for (const [hash] of toDelete) {
      this.profiles.delete(hash);
    }
  }

  getAllProfiles(): PeerProfile[] {
    return Array.from(this.profiles.values());
  }

  getProfileCount(): number {
    return this.profiles.size;
  }

  removePeer(hash: string): boolean {
    return this.profiles.delete(hash);
  }

  getFloodfillPeers(): PeerProfile[] {
    return this.getAllProfiles().filter(p => p.isFloodfill);
  }
}

export default PeerProfileManager;

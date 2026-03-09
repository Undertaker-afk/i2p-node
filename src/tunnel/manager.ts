import { EventEmitter } from 'events';
import { Crypto } from '../crypto/index.js';
import { encryptTunnelMessage } from './message.js';
import { RouterInfo } from '../data/router-info.js';
import { LeaseSet, Lease } from '../data/lease-set.js';
import { NetworkDatabase } from '../netdb/index.js';

export enum TunnelType {
  INBOUND = 'inbound',
  OUTBOUND = 'outbound'
}

export interface TunnelHop {
  routerHash: Uint8Array;
  routerInfo: RouterInfo;
  tunnelId: number;
  layerKey: Uint8Array;
  ivKey: Uint8Array;
  replyKey?: Uint8Array;
}

export interface Tunnel {
  id: number;
  type: TunnelType;
  hops: TunnelHop[];
  gateway: RouterInfo;
  endpoint: RouterInfo;
  created: number;
  expiration: number;
  messagesSent: number;
  messagesReceived: number;
}

export interface TunnelBuildRequest {
  tunnelId: number;
  replyMessageId: number;
  hops: { routerHash: Uint8Array; tunnelId: number }[];
  replyTunnelId: number;
  replyGateway: Uint8Array;
}

export interface TunnelBuildRecord {
  toPeer: Uint8Array;
  replyToken: number;
  replyGateway: Uint8Array;
  replyTunnelId: number;
  layerKey: Uint8Array;
  ivKey: Uint8Array;
  nextTunnelId: number;
  nextRouterHash: Uint8Array;
}

export class TunnelManager extends EventEmitter {
  private tunnels: Map<number, Tunnel> = new Map();
  private pendingBuilds: Map<number, TunnelBuildRequest> = new Map();
  private netDb: NetworkDatabase;
  private localRouterInfo: RouterInfo;
  private nextTunnelId: number = 1;

  constructor(netDb: NetworkDatabase, localRouterInfo: RouterInfo) {
    super();
    this.netDb = netDb;
    this.localRouterInfo = localRouterInfo;
  }

  async buildTunnel(type: TunnelType, numHops = 3): Promise<Tunnel | null> {
    const tunnelId = this.nextTunnelId++;
    const replyMessageId = Math.floor(Math.random() * 0xFFFFFFFF);
    const hops: TunnelHop[] = [];
    if (numHops > 0) {
      const hopRouters = this.selectHopRouters(numHops);
      if (hopRouters.length < numHops) {
        this.emit('error', { tunnelId, error: 'Not enough routers available' });
        return null;
      }

      hops.push(...hopRouters.map((router, index) => ({
        routerHash: router.getRouterHash(),
        routerInfo: router,
        tunnelId: this.nextTunnelId++,
        layerKey: Crypto.randomBytes(32),
        ivKey: Crypto.randomBytes(32),
        replyKey: index === 0 ? Crypto.randomBytes(32) : undefined
      })));
    }
    
    const buildRequest: TunnelBuildRequest = {
      tunnelId,
      replyMessageId,
      hops: hops.map(h => ({
        routerHash: h.routerHash,
        tunnelId: h.tunnelId
      })),
      replyTunnelId: 0,
      replyGateway: this.localRouterInfo.getRouterHash()
    };
    
    this.pendingBuilds.set(replyMessageId, buildRequest);
    
    const tunnel: Tunnel = {
      id: tunnelId,
      type,
      hops,
      gateway: type === TunnelType.OUTBOUND || hops.length === 0 ? this.localRouterInfo : hops[0].routerInfo,
      endpoint: type === TunnelType.INBOUND || hops.length === 0 ? this.localRouterInfo : hops[hops.length - 1].routerInfo,
      created: Date.now(),
      expiration: Date.now() + 600000,
      messagesSent: 0,
      messagesReceived: 0
    };

    // TODO: Implement full ECIES-X25519 build messages over the network.
    // For now we mark the tunnel as built locally without sending records.
    // Zero-hop tunnels are fully local and intentionally skip network build records.
    // await this.sendTunnelBuildMessage(tunnel, hops);
    
    this.tunnels.set(tunnelId, tunnel);
    this.emit('tunnelBuilt', { tunnelId, type, numHops });
    
    return tunnel;
  }

  private selectHopRouters(numHops: number): RouterInfo[] {
    const allRouters = this.netDb.getAllRouterInfos();
    
    const eligibleRouters = allRouters.filter(router => {
      const caps = router.options.caps || '';
      if (caps.includes('H')) return false;
      
      const bw = this.parseBandwidth(caps);
      return bw >= 12;
    });
    
    if (eligibleRouters.length < numHops) {
      return eligibleRouters;
    }
    
    const shuffled = [...eligibleRouters].sort(() => Math.random() - 0.5);
    return shuffled.slice(0, numHops);
  }

  private parseBandwidth(caps: string): number {
    if (caps.includes('K')) return 12;
    if (caps.includes('L')) return 48;
    if (caps.includes('M')) return 64;
    if (caps.includes('N')) return 128;
    if (caps.includes('O')) return 256;
    if (caps.includes('P')) return 2000;
    if (caps.includes('X')) return 2001;
    return 12;
  }

  private async sendTunnelBuildMessage(tunnel: Tunnel, hops: TunnelHop[]): Promise<void> {
    const records: Buffer[] = [];
    
    for (let i = 0; i < hops.length; i++) {
      const hop = hops[i];
      const nextHop = i < hops.length - 1 ? hops[i + 1] : null;
      
      const record = this.buildTunnelRecord(
        hop,
        nextHop,
        i === 0 ? tunnel.id : 0
      );
      
      records.push(record);
    }
    
    this.emit('sendTunnelBuild', {
      tunnelId: tunnel.id,
      firstHop: hops[0].routerInfo,
      records
    });
  }

  private buildTunnelRecord(
    hop: TunnelHop,
    nextHop: TunnelHop | null,
    replyTunnelId: number
  ): Buffer {
    const record = Buffer.alloc(528);
    let pos = 0;
    
    record.writeUInt8(0, pos++);
    
    record.set(hop.routerHash, pos);
    pos += 32;
    
    record.writeUInt32BE(hop.tunnelId, pos);
    pos += 4;
    
    record.set(hop.layerKey, pos);
    pos += 32;
    
    record.set(hop.ivKey, pos);
    pos += 32;
    
    if (nextHop) {
      record.writeUInt32BE(nextHop.tunnelId, pos);
      pos += 4;
      record.set(nextHop.routerHash, pos);
      pos += 32;
    } else {
      record.writeUInt32BE(0, pos);
      pos += 4;
      record.fill(0, pos, pos + 32);
      pos += 32;
    }
    
    record.writeUInt32BE(replyTunnelId, pos);
    pos += 4;
    
    record.fill(0, pos, 528);
    
    return record;
  }

  handleTunnelBuildReply(messageId: number, success: boolean): void {
    const buildRequest = this.pendingBuilds.get(messageId);
    if (!buildRequest) return;
    
    this.pendingBuilds.delete(messageId);
    
    if (!success) {
      this.tunnels.delete(buildRequest.tunnelId);
      this.emit('tunnelBuildFailed', { tunnelId: buildRequest.tunnelId });
    } else {
      this.emit('tunnelBuildSuccess', { tunnelId: buildRequest.tunnelId });
    }
  }

  getTunnel(tunnelId: number): Tunnel | undefined {
    return this.tunnels.get(tunnelId);
  }

  getAllTunnels(): Tunnel[] {
    return Array.from(this.tunnels.values());
  }

  getInboundTunnels(): Tunnel[] {
    return this.getAllTunnels().filter(t => t.type === TunnelType.INBOUND);
  }

  getOutboundTunnels(): Tunnel[] {
    return this.getAllTunnels().filter(t => t.type === TunnelType.OUTBOUND);
  }

  destroyTunnel(tunnelId: number): boolean {
    const tunnel = this.tunnels.get(tunnelId);
    if (!tunnel) return false;
    
    this.tunnels.delete(tunnelId);
    this.emit('tunnelDestroyed', { tunnelId });
    return true;
  }

  cleanupExpiredTunnels(): void {
    const now = Date.now();
    
    for (const [id, tunnel] of this.tunnels.entries()) {
      if (tunnel.expiration < now) {
        this.tunnels.delete(id);
        this.emit('tunnelExpired', { tunnelId: id });
      }
    }
  }

  createLeaseSet(tunnelIds: number[]): LeaseSet {
    const leases: Lease[] = [];
    
    for (const tunnelId of tunnelIds) {
      const tunnel = this.getTunnel(tunnelId);
      if (!tunnel || tunnel.type !== TunnelType.INBOUND) continue;

      const firstHop = tunnel.hops[0];
      leases.push(new Lease(
        firstHop?.routerHash ?? this.localRouterInfo.getRouterHash(),
        firstHop?.tunnelId ?? tunnel.id,
        tunnel.expiration
      ));
    }
    
    const encryptionKey = Crypto.randomBytes(32);
    const signingKey = Crypto.randomBytes(32);
    
    return new LeaseSet(
      this.localRouterInfo.identity,
      encryptionKey,
      signingKey,
      leases
    );
  }

  /**
   * Minimal helper to wrap an I2NP message in a single ECIES tunnel message
   * for a given outbound tunnel. This is LOCAL delivery-only and unfragmented.
   */
  encryptForTunnel(tunnelId: number, msg: Buffer): Buffer[] {
    const tunnel = this.tunnels.get(tunnelId);
    if (!tunnel) throw new Error(`Unknown tunnel ${tunnelId}`);
    if (tunnel.hops.length === 0) {
      return [Buffer.from(msg)];
    }
    const firstHop = tunnel.hops[0];
    const wire = encryptTunnelMessage(firstHop.tunnelId, firstHop.layerKey, msg);
    return [wire];
  }
}

export default TunnelManager;

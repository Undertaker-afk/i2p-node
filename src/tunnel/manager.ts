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
  replyKey: Uint8Array;
  replyIV: Uint8Array;
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
  recordOrder: number[];
  numRecords: number;
  hopReplyKeys: { replyKey: Uint8Array; replyIV: Uint8Array }[];
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
  private static readonly TUNNEL_BUILD_EXPIRATION_S = 600;

  private tunnels: Map<number, Tunnel> = new Map();
  private pendingTunnels: Map<number, Tunnel> = new Map();
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
        replyKey: Crypto.randomBytes(32),
        replyIV: Crypto.randomBytes(16)
      })));
    }
    
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

    // Zero-hop tunnels are fully local and intentionally skip network build records.
    if (hops.length > 0) {
      const buildRequest: TunnelBuildRequest = {
        tunnelId,
        replyMessageId,
        hops: hops.map(h => ({
          routerHash: h.routerHash,
          tunnelId: h.tunnelId
        })),
        replyTunnelId: 0,
        replyGateway: this.localRouterInfo.getRouterHash(),
        recordOrder: [],
        numRecords: 0,
        hopReplyKeys: hops.map((h) => ({ replyKey: h.replyKey, replyIV: h.replyIV }))
      };
      this.pendingBuilds.set(replyMessageId, buildRequest);
      this.pendingTunnels.set(tunnelId, tunnel);
      await this.sendTunnelBuildMessage(tunnel, hops);
    } else {
      this.tunnels.set(tunnelId, tunnel);
      this.emit('tunnelBuilt', { tunnelId, type, numHops });
    }
    
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
    const numRecords = Math.max(4, Math.min(8, hops.length));
    const records: Buffer[] = Array.from({ length: numRecords }, () => Buffer.from(Crypto.randomBytes(528)));
    const order = this.shuffleIndices(numRecords).slice(0, hops.length);

    for (let i = 0; i < hops.length; i++) {
      const hop = hops[i];
      const nextHop = i < hops.length - 1 ? hops[i + 1] : null;
      const clear = this.buildTunnelBuildRequestRecord(tunnel, hop, nextHop, i);
      const encrypted = this.encryptBuildRecordForHop(hop, clear);
      const toPeer = Buffer.from(hop.routerHash).subarray(0, 16);
      records[order[i]] = Buffer.concat([toPeer, encrypted]);
    }

    // garlic/tunnel build record peeling with per-hop reply keys (i2pd style)
    for (let i = hops.length - 2; i >= 0; i--) {
      for (let j = i + 1; j < hops.length; j++) {
        const rec = records[order[j]];
        const peeled = Crypto.aesEncryptCBC(rec.subarray(16), hops[i].replyKey, hops[i].replyIV);
        records[order[j]] = Buffer.concat([rec.subarray(0, 16), peeled]);
      }
    }

    for (const pending of this.pendingBuilds.values()) {
      if (pending.tunnelId !== tunnel.id) continue;
      pending.recordOrder = order;
      pending.numRecords = numRecords;
      break;
    }

    this.emit('sendTunnelBuild', {
      tunnelId: tunnel.id,
      firstHop: hops[0].routerInfo,
      messageId: this.getPendingBuildMessageId(tunnel.id),
      records
    });
  }

  private getPendingBuildMessageId(tunnelId: number): number {
    for (const [messageId, pending] of this.pendingBuilds.entries()) {
      if (pending.tunnelId === tunnelId) return messageId;
    }
    return tunnelId;
  }

  private shuffleIndices(count: number): number[] {
    const values = Array.from({ length: count }, (_, i) => i);
    for (let i = values.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [values[i], values[j]] = [values[j], values[i]];
    }
    return values;
  }

  private buildTunnelBuildRequestRecord(
    tunnel: Tunnel,
    hop: TunnelHop,
    nextHop: TunnelHop | null,
    hopIndex: number
  ): Buffer {
    const clear = Buffer.alloc(464);
    let pos = 0;

    const receiveTunnelId = hop.tunnelId >>> 0;
    clear.writeUInt32BE(receiveTunnelId, pos); pos += 4;

    const nextTunnelId = nextHop ? nextHop.tunnelId >>> 0 : 0;
    clear.writeUInt32BE(nextTunnelId, pos); pos += 4;

    const nextIdent = nextHop ? Buffer.from(nextHop.routerHash) : Buffer.alloc(32);
    nextIdent.copy(clear, pos); pos += 32;

    Buffer.from(hop.layerKey).copy(clear, pos); pos += 32;
    Buffer.from(hop.ivKey).copy(clear, pos); pos += 32;
    Buffer.from(hop.replyKey).copy(clear, pos); pos += 32;
    Buffer.from(hop.replyIV).copy(clear, pos); pos += 16;

    let flag = 0;
    if (hopIndex === 0) flag |= 0x80;
    if (!nextHop) flag |= 0x40;
    clear.writeUInt8(flag, pos); pos += 1;

    clear.fill(0x00, pos, pos + 3); pos += 3;

    const requestTime = Math.floor(Date.now() / 60000) >>> 0;
    clear.writeUInt32BE(requestTime, pos); pos += 4;
    clear.writeUInt32BE(TunnelManager.TUNNEL_BUILD_EXPIRATION_S, pos); pos += 4;

    // sendMsgID: use tunnel id as a stable local correlation id
    clear.writeUInt32BE(tunnel.id >>> 0, pos); pos += 4;

    if (pos < clear.length) {
      Buffer.from(Crypto.randomBytes(clear.length - pos)).copy(clear, pos);
    }

    return clear;
  }

  private encryptBuildRecordForHop(hop: TunnelHop, clear: Buffer): Buffer {
    const staticPub = Buffer.from(hop.routerInfo.identity.encryptionPublicKey);
    if (staticPub.length !== 32) {
      throw new Error('Hop static encryption key must be 32 bytes (X25519)');
    }

    const ephemeral = Crypto.generateEphemeralKeyPair();
    const state = Crypto.initNoiseNState(staticPub);
    Crypto.mixHash(state, Buffer.from(ephemeral.publicKey));
    const shared = Crypto.x25519DiffieHellman(ephemeral.privateKey, staticPub);
    Crypto.mixKey(state, shared);

    const nonce = Buffer.alloc(12);
    const ciphertext = Buffer.from(Crypto.encryptChaCha20Poly1305(state.key, nonce, clear, state.h));
    Crypto.mixHash(state, ciphertext);

    return Buffer.concat([Buffer.from(ephemeral.publicKey), ciphertext]);
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


  handleVariableTunnelBuildReply(messageId: number, reply: Buffer): void {
    if (reply.length < 1) return;
    const count = reply.readUInt8(0);
    if (reply.length < 1 + count * 528) return;

    const pending = this.pendingBuilds.get(messageId);
    if (!pending) return;

    const records: Buffer[] = [];
    let offset = 1;
    for (let i = 0; i < count; i++) {
      records.push(Buffer.from(reply.subarray(offset, offset + 528)));
      offset += 528;
    }

    // reverse-peel to reveal each hop record status
    for (let i = pending.hopReplyKeys.length - 2; i >= 0; i--) {
      for (let j = i + 1; j < pending.hopReplyKeys.length; j++) {
        const recordIndex = pending.recordOrder[j] ?? j;
        const rec = records[recordIndex];
        const decrypted = Crypto.aesDecryptCBC(
          rec.subarray(16),
          pending.hopReplyKeys[i].replyKey,
          pending.hopReplyKeys[i].replyIV
        );
        records[recordIndex] = Buffer.concat([rec.subarray(0, 16), decrypted]);
      }
    }

    let success = true;
    for (let i = 0; i < pending.hopReplyKeys.length; i++) {
      const recordIndex = pending.recordOrder[i] ?? i;
      const record = records[recordIndex];
      const retCode = record.readUInt8(527);
      if (retCode !== 0) {
        success = false;
        break;
      }
    }

    this.pendingBuilds.delete(messageId);
    if (success) {
      const tunnel = this.pendingTunnels.get(pending.tunnelId);
      if (tunnel) {
        this.pendingTunnels.delete(pending.tunnelId);
        this.tunnels.set(pending.tunnelId, tunnel);
        this.emit('tunnelBuilt', { tunnelId: pending.tunnelId, type: tunnel.type, numHops: tunnel.hops.length });
      }
    } else {
      this.pendingTunnels.delete(pending.tunnelId);
      this.tunnels.delete(pending.tunnelId);
      this.emit('tunnelBuildFailed', { tunnelId: pending.tunnelId });
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

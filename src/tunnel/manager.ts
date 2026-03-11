import { EventEmitter } from 'events';
import { Crypto, NoiseSymmetricState } from '../crypto/index.js';
import { encryptTunnelMessage } from './message.js';
import { RouterInfo } from '../data/router-info.js';
import { LeaseSet, Lease } from '../data/lease-set.js';
import { NetworkDatabase } from '../netdb/index.js';
import { I2NPMessages, I2NPMessageType } from '../i2np/messages.js';
import { logger } from '../utils/logger.js';

export enum TunnelType {
  INBOUND = 'inbound',
  OUTBOUND = 'outbound',
}

export interface TunnelHop {
  routerHash: Uint8Array;
  routerInfo: RouterInfo;
  tunnelId: number;
  layerKey: Uint8Array;
  ivKey: Uint8Array;
  replyKey: Uint8Array;
  replyIV: Uint8Array;
  noise?: NoiseSymmetricState;
  recordIndex?: number;
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
  hopRecordIndices: number[];
}

export class TunnelManager extends EventEmitter {
  private tunnels: Map<number, Tunnel> = new Map();
  private buildingTunnels: Map<number, Tunnel> = new Map();
  private pendingBuilds: Map<number, TunnelBuildRequest> = new Map();
  private netDb: NetworkDatabase;
  private localRouterInfo: RouterInfo;
  private nextTunnelId: number = Math.floor(Math.random() * 0x7fffffff) + 1;

  constructor(netDb: NetworkDatabase, localRouterInfo: RouterInfo) {
    super();
    this.netDb = netDb;
    this.localRouterInfo = localRouterInfo;
  }

  async buildTunnel(type: TunnelType, numHops = 3): Promise<Tunnel | null> {
    const tunnelId = this.nextTunnelId++;
    const replyMessageId = Math.floor(Math.random() * 0xffffffff);
    const hops: TunnelHop[] = [];

    if (numHops > 0) {
      const hopRouters = this.selectHopRouters(numHops);
      if (hopRouters.length < numHops) {
        this.emit('error', { tunnelId, error: 'Not enough routers' });
        return null;
      }
      for (const router of hopRouters) {
        hops.push({
          routerHash: router.getRouterHash(),
          routerInfo: router,
          tunnelId: Math.floor(Math.random() * 0xffffffff) + 1,
          layerKey: Crypto.randomBytes(32),
          ivKey: Crypto.randomBytes(32),
          replyKey: Crypto.randomBytes(32),
          replyIV: Crypto.randomBytes(16),
        });
      }
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
      messagesReceived: 0,
    };

    if (numHops > 0) {
      const buildRequest: TunnelBuildRequest = {
        tunnelId,
        replyMessageId,
        hops: hops.map((h) => ({ routerHash: h.routerHash, tunnelId: h.tunnelId })),
        replyTunnelId: 0,
        replyGateway: this.localRouterInfo.getRouterHash(),
        hopRecordIndices: [],
      };
      this.pendingBuilds.set(replyMessageId, buildRequest);
      this.buildingTunnels.set(tunnelId, tunnel);
      logger.info(
        `Starting build for ${type} tunnel ${tunnelId} via ${hops[0].routerInfo
          .getRouterHash()
          .toString('hex')
          .slice(0, 16)}`,
        undefined,
        'Tunnel',
      );
      await this.sendVariableTunnelBuild(tunnel, buildRequest);
    } else {
      this.tunnels.set(tunnelId, tunnel);
      this.emit('tunnelBuilt', { tunnelId, type, numHops: 0 });
    }
    return tunnel;
  }

  private async sendVariableTunnelBuild(tunnel: Tunnel, buildRequest: TunnelBuildRequest): Promise<void> {
    const numHops = tunnel.hops.length;
    const numRecords = 8;
    const records: Buffer[] = [];

    for (let i = 0; i < numHops; i++) {
      const hop = tunnel.hops[i];
      const nextHop = i < numHops - 1 ? tunnel.hops[i + 1] : null;
      const cleartext = Buffer.alloc(464);
      cleartext.writeUInt32BE(hop.tunnelId, 0);

      if (nextHop) {
        cleartext.writeUInt32BE(nextHop.tunnelId, 4);
        cleartext.set(nextHop.routerHash, 8);
      } else if (tunnel.type === TunnelType.INBOUND) {
        cleartext.writeUInt32BE(tunnel.id, 4);
        cleartext.set(this.localRouterInfo.getRouterHash(), 8);
      } else {
        cleartext.writeUInt32BE(0, 4);
        cleartext.set(this.localRouterInfo.getRouterHash(), 8);
      }

      cleartext.set(hop.layerKey, 40);
      cleartext.set(hop.ivKey, 72);
      cleartext.set(hop.replyKey, 104);
      cleartext.set(hop.replyIV, 136);

      let flag = 0;
      if (i === 0) flag |= 0x80;
      if (i === numHops - 1) flag |= 0x40;
      cleartext.writeUInt8(flag, 152);

      cleartext.writeUInt32BE(Math.floor(Date.now() / 60000), 156);
      cleartext.writeUInt32BE(600, 160);
      cleartext.writeUInt32BE(buildRequest.replyMessageId, 164);

      const noise = new NoiseSymmetricState();
      NoiseSymmetricState.InitNoiseNState(noise, hop.routerInfo.identity.encryptionPublicKey);

      const eph = Crypto.generateKeyPair();
      const sharedSecret = Crypto.x25519DiffieHellman(eph.privateKey, hop.routerInfo.identity.encryptionPublicKey);
      const encryptedRecord = Buffer.alloc(512);
      encryptedRecord.set(eph.publicKey, 0);
      noise.mixHash(eph.publicKey);
      noise.mixKey(sharedSecret);

      const ciphertext = Crypto.encryptChaCha20Poly1305(noise.ck.subarray(32, 64), new Uint8Array(12), cleartext, noise.h);
      encryptedRecord.set(ciphertext, 32);
      noise.mixHash(ciphertext);
      hop.noise = noise;

      const record = Buffer.alloc(528);
      record.set(hop.routerHash.subarray(0, 16), 0);
      record.set(encryptedRecord, 16);
      records.push(record);
    }

    while (records.length < numRecords) {
      records.push(Buffer.from(Crypto.randomBytes(528)));
    }

    const recordIndices = Array.from({ length: numRecords }, (_, i) => i);
    for (let i = recordIndices.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [recordIndices[i], recordIndices[j]] = [recordIndices[j], recordIndices[i]];
      [records[i], records[j]] = [records[j], records[i]];
    }

    for (let i = 0; i < numHops; i++) {
      buildRequest.hopRecordIndices[i] = recordIndices.indexOf(i);
    }

    for (let i = numHops - 2; i >= 0; i--) {
      const hop = tunnel.hops[i];
      const myRecordIdx = buildRequest.hopRecordIndices[i];
      for (let j = 0; j < numRecords; j++) {
        if (j !== myRecordIdx) {
          const peeled = Crypto.aesDecryptCBC(records[j].subarray(16), hop.replyKey, hop.replyIV);
          peeled.copy(records[j], 16);
        }
      }
    }
    this.emit('sendTunnelBuild', {
      tunnelId: tunnel.id,
      firstHop: tunnel.hops[0].routerInfo,
      message: I2NPMessages.createVariableTunnelBuild(records, buildRequest.replyMessageId),
    });
  }

  private selectHopRouters(numHops: number): RouterInfo[] {
    const eligibleRouters = this.netDb
      .getAllRouterInfos()
      .filter(
        (router) =>
          !router.getRouterHash().equals(this.localRouterInfo.getRouterHash()) &&
          !(router.options.caps || '').includes('H') &&
          this.parseBandwidth(router.options.caps || '') >= 0,
      );
    if (eligibleRouters.length < numHops) return eligibleRouters;
    return [...eligibleRouters].sort(() => Math.random() - 0.5).slice(0, numHops);
  }

  private parseBandwidth(caps: string): number {
    if (caps.includes('X')) return 2001;
    if (caps.includes('P')) return 2000;
    if (caps.includes('O')) return 256;
    if (caps.includes('N')) return 128;
    if (caps.includes('M')) return 64;
    if (caps.includes('L')) return 48;
    if (caps.includes('K')) return 12;
    return 12;
  }

  handleVariableTunnelBuildReply(messageId: number, records: Buffer[]): void {
    const buildRequest = this.pendingBuilds.get(messageId);
    if (!buildRequest) return;
    this.pendingBuilds.delete(messageId);
    const tunnel = this.buildingTunnels.get(buildRequest.tunnelId);
    if (!tunnel) return;
    this.buildingTunnels.delete(buildRequest.tunnelId);

    for (let i = 0; i < tunnel.hops.length; i++) {
      const hop = tunnel.hops[i];
      for (let j = 0; j < records.length; j++) {
        const peeled = Crypto.aesDecryptCBC(records[j].subarray(16), hop.replyKey, hop.replyIV);
        peeled.copy(records[j], 16);
      }
    }

    let accepted = true;
    for (let i = 0; i < tunnel.hops.length; i++) {
      const hop = tunnel.hops[i];
      const recordIdx = buildRequest.hopRecordIndices[i];
      if (recordIdx === undefined || recordIdx >= records.length || !hop.noise) {
        accepted = false;
        break;
      }
      try {
        const decryptedReply = Crypto.decryptChaCha20Poly1305(
          hop.noise.ck.subarray(32, 64),
          new Uint8Array(12),
          records[recordIdx].subarray(16 + 32),
          hop.noise.h,
        );
        if (decryptedReply[463] !== 0) {
          logger.info(`Hop ${i} rejected build: ${decryptedReply[463]}`, undefined, 'Tunnel');
          accepted = false;
          break;
        }
        logger.info(`Hop ${i} accepted build`, undefined, 'Tunnel');
      } catch (err: any) {
        logger.warn(`Hop ${i} decrypt fail: ${err.message}`, undefined, 'Tunnel');
        accepted = false;
        break;
      }
    }

    if (accepted) {
      logger.info(`Tunnel ${tunnel.id} (${tunnel.type}) BUILT successfully`, undefined, 'Tunnel');
      this.tunnels.set(tunnel.id, tunnel);
      this.emit('tunnelBuilt', { tunnelId: tunnel.id, type: tunnel.type, numHops: tunnel.hops.length });
    } else {
      logger.info(`Tunnel ${tunnel.id} (${tunnel.type}) BUILD FAILED`, undefined, 'Tunnel');
      this.emit('tunnelBuildFailed', { tunnelId: tunnel.id });
    }
  }

  getTunnel(id: number): Tunnel | undefined {
    return this.tunnels.get(id);
  }

  getAllTunnels(): Tunnel[] {
    return Array.from(this.tunnels.values());
  }

  getInboundTunnels(): Tunnel[] {
    return this.getAllTunnels().filter((t) => t.type === TunnelType.INBOUND);
  }

  getOutboundTunnels(): Tunnel[] {
    return this.getAllTunnels().filter((t) => t.type === TunnelType.OUTBOUND);
  }

  destroyTunnel(id: number): boolean {
    if (!this.tunnels.has(id)) return false;
    this.tunnels.delete(id);
    this.emit('tunnelDestroyed', { tunnelId: id });
    return true;
  }

  cleanupExpiredTunnels(): void {
    const now = Date.now();
    for (const [id, t] of this.tunnels.entries()) {
      if (t.expiration < now) {
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
      leases.push(
        new Lease(
          firstHop?.routerHash ?? this.localRouterInfo.getRouterHash(),
          firstHop?.tunnelId ?? tunnel.id,
          tunnel.expiration,
        ),
      );
    }
    return new LeaseSet(
      this.localRouterInfo.identity,
      Crypto.randomBytes(32),
      Crypto.randomBytes(32),
      leases,
    );
  }

  encryptForTunnel(id: number, msg: Buffer): Buffer[] {
    const t = this.tunnels.get(id);
    if (!t) throw new Error(`Unknown tunnel ${id}`);
    return t.hops.length === 0
      ? [Buffer.from(msg)]
      : [encryptTunnelMessage(t.hops[0].tunnelId, t.hops, msg)];
  }
}
export default TunnelManager;

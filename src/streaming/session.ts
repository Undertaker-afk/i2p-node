import { EventEmitter } from 'events';
import { TunnelManager, TunnelType, Tunnel } from '../tunnel/manager.js';
import { NetworkDatabase } from '../netdb/index.js';
import { LeaseSet } from '../data/lease-set.js';
import { base32DecodeToHash } from '../i2p/base32.js';
import { encryptTunnelMessage } from '../tunnel/message.js';

export interface StreamOptions {
  idleTimeoutMs?: number;
  retransmitTimeoutMs?: number;
  maxInFlight?: number;
}

export class Stream extends EventEmitter {
  readonly id: number;
  private readonly tunnelManager: TunnelManager;
  private readonly outboundTunnel: Tunnel;
  private readonly remoteLease: LeaseSet;
  private readonly options: Required<StreamOptions>;

  private seqSend = 0;
  private seqRecv = 0;
  private inFlight: Map<number, { payload: Buffer; timestamp: number }> = new Map();
  private closed = false;

  constructor(
    id: number,
    tunnelManager: TunnelManager,
    outboundTunnel: Tunnel,
    remoteLease: LeaseSet,
    options: StreamOptions = {}
  ) {
    super();
    this.id = id;
    this.tunnelManager = tunnelManager;
    this.outboundTunnel = outboundTunnel;
    this.remoteLease = remoteLease;
    this.options = {
      idleTimeoutMs: options.idleTimeoutMs ?? 60000,
      retransmitTimeoutMs: options.retransmitTimeoutMs ?? 5000,
      maxInFlight: options.maxInFlight ?? 8
    };
  }

  send(data: Buffer): void {
    if (this.closed) return;
    if (this.inFlight.size >= this.options.maxInFlight) return;
    const seq = this.seqSend++;
    const hdr = Buffer.alloc(9);
    hdr.writeUInt32BE(this.id >>> 0, 0);
    hdr.writeUInt32BE(seq >>> 0, 4);
    hdr.writeUInt8(0x00, 8);
    const frame = Buffer.concat([hdr, data]);

    const gatewayTunnelId = this.outboundTunnel.hops.length > 0 ? this.outboundTunnel.hops[0].tunnelId : this.outboundTunnel.id;
    const tunnelMsg = encryptTunnelMessage(gatewayTunnelId, this.outboundTunnel.hops, frame);

    this.inFlight.set(seq, { payload: frame, timestamp: Date.now() });
    this.emit('sendRaw', tunnelMsg);
  }

  handleFragment(fragment: Buffer): void {
    if (fragment.length < 9) return;
    const streamId = fragment.readUInt32BE(0);
    if (streamId !== (this.id >>> 0)) return;
    const seq = fragment.readUInt32BE(4);
    const flags = fragment.readUInt8(8);
    const payload = fragment.subarray(9);

    if (flags & 0x80) {
      this.inFlight.delete(seq);
      return;
    }

    if (seq !== this.seqRecv) return;
    this.seqRecv++;
    this.emit('data', payload);

    const hdr = Buffer.alloc(9);
    hdr.writeUInt32BE(this.id >>> 0, 0);
    hdr.writeUInt32BE(seq >>> 0, 4);
    hdr.writeUInt8(0x80, 8);
    const gatewayTunnelId = this.outboundTunnel.hops.length > 0 ? this.outboundTunnel.hops[0].tunnelId : this.outboundTunnel.id;
    const ackMsg = encryptTunnelMessage(gatewayTunnelId, this.outboundTunnel.hops, hdr);
    this.emit('sendRaw', ackMsg);
  }

  tick(): void {
    if (this.closed) return;
    const now = Date.now();
    for (const [seq, entry] of this.inFlight.entries()) {
      if (now - entry.timestamp > this.options.retransmitTimeoutMs) {
        const gatewayTunnelId = this.outboundTunnel.hops.length > 0 ? this.outboundTunnel.hops[0].tunnelId : this.outboundTunnel.id;
        const tunnelMsg = encryptTunnelMessage(gatewayTunnelId, this.outboundTunnel.hops, entry.payload);
        this.inFlight.set(seq, { payload: entry.payload, timestamp: now });
        this.emit('sendRaw', tunnelMsg);
      }
    }
  }

  close(): void {
    this.closed = true;
    this.inFlight.clear();
    this.emit('close');
  }
}

export class StreamingManager {
  private readonly tunnelManager: TunnelManager;
  private readonly netDb: NetworkDatabase;
  private nextStreamId = 1;

  constructor(tunnelManager: TunnelManager, netDb: NetworkDatabase) {
    this.tunnelManager = tunnelManager;
    this.netDb = netDb;
  }

  async openStreamToBase32(host: string): Promise<Stream | null> {
    const hash = base32DecodeToHash(host);
    if (!hash) return null;
    const leaseSet = this.netDb.lookupLeaseSet(hash);
    if (!leaseSet || leaseSet.leases.length === 0) return null;

    const outbound = await this.ensureOutboundTunnel();
    if (!outbound) return null;

    const streamId = this.nextStreamId++;
    const stream = new Stream(streamId, this.tunnelManager, outbound, leaseSet);
    return stream;
  }

  private async ensureOutboundTunnel(): Promise<Tunnel | null> {
    const existing = this.tunnelManager.getOutboundTunnels()[0];
    if (existing) return existing;
    return this.tunnelManager.buildTunnel(TunnelType.OUTBOUND, 1);
  }
}

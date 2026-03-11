import { EventEmitter } from 'events';
import { gunzipSync, gzipSync } from 'zlib';
import { Crypto } from './crypto/index.js';
import { RouterIdentity, RouterInfo, RouterAddress } from './data/router-info.js';
import { LeaseSet } from './data/lease-set.js';
import { parseLeaseSetLS1, parseLeaseSetLS2 } from './data/lease-set-i2p.js';
import { parseI2PRouterInfo } from './data/router-info-i2p.js';
import { I2NPMessages, I2NPMessageType } from './i2np/messages.js';
import { NetworkDatabase } from './netdb/index.js';
import { TunnelManager, TunnelType } from './tunnel/manager.js';
import { PeerProfileManager } from './peer/profiles.js';
import { NTCP2Transport } from './transport/ntcp2.js';
import { SSU2Transport } from './transport/ssu2.js';
import { SAMProtocol } from './sam/protocol.js';
import { logger, LogLevel } from './utils/logger.js';
import { SimpleWebUI } from './webui/simple-server.js';
import { StreamingManager } from './streaming/session.js';
import { NetDbRequests, PendingRequest } from './netdb/requests.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519, IdentityExBuildResult } from './i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from './i2p/routerinfo/writer.js';
import { i2pBase64Encode } from './i2p/base64.js';

export interface I2PRouterOptions {
  host?: string; ntcp2Port?: number; ssu2Port?: number; samPort?: number;
  isFloodfill?: boolean; bandwidthClass?: 'K' | 'L' | 'M' | 'N' | 'O' | 'P' | 'X';
  sharePercentage?: number; netId?: number; dataDir?: string; logLevel?: LogLevel;
  enableWebUI?: boolean; webUIPort?: number;
}

interface PendingLeaseSetRequest {
  targetHash: Buffer; excluded: Set<string>; attempts: number; createdAt: number;
  candidateFloodfills: string[]; eciesTags: Set<string>; retryTimer: NodeJS.Timeout | null;
}

interface PendingEciesReply { sessionKey: Buffer; targetHash: string; createdAt: number; }

const MAX_LEASESET_FLOODFILLS_PER_REQUEST = 7;
const LEASESET_REQUEST_TIMEOUT_MS = 15000;
const LEASESET_RETRY_DELAY_MS = 2500;
const ECIES_REPLY_TTL_MS = 5 * 60 * 1000;

export interface RouterStats {
  startTime: number; messagesSent: number; messagesReceived: number;
  bytesSent: number; bytesReceived: number; tunnelBuildSuccesses: number;
  tunnelBuildFailures: number; knownPeers: number; activePeers: number;
  floodfillPeers: number; activeTunnels: number;
}

export class I2PRouter extends EventEmitter {
  private identity: { identity: RouterIdentity; signingPrivateKey: Uint8Array; encryptionPrivateKey: Uint8Array } | null = null;
  private routerInfo: RouterInfo | null = null; private netDb: NetworkDatabase; private tunnelManager: TunnelManager | null = null;
  private peerProfiles: PeerProfileManager; private ntcp2: NTCP2Transport | null = null; private ssu2: SSU2Transport | null = null;
  private sam: SAMProtocol | null = null; private webUI: SimpleWebUI | null = null; private streaming: StreamingManager | null = null;
  private netDbRequests: NetDbRequests; private options: I2PRouterOptions; private stats: RouterStats;
  private running = false; private maintenanceInterval: NodeJS.Timeout | null = null; private identityEx: IdentityExBuildResult | null = null;
  private wireRouterInfo: Buffer | null = null; private ntcp2PublishedIV: Buffer | null = null;
  private pendingLeaseSetRequests: Map<string, PendingLeaseSetRequest> = new Map();
  private pendingEciesReplies: Map<string, PendingEciesReply> = new Map();

  constructor(options: I2PRouterOptions = {}) {
    super();
    this.options = { host: '0.0.0.0', ntcp2Port: 12345, ssu2Port: 12346, samPort: 7656, isFloodfill: false, bandwidthClass: 'L', sharePercentage: 80, netId: 2, dataDir: './i2p-data', logLevel: LogLevel.INFO, enableWebUI: false, webUIPort: 7070, ...options };
    logger.setLevel(this.options.logLevel!);
    this.stats = { startTime: 0, messagesSent: 0, messagesReceived: 0, bytesSent: 0, bytesReceived: 0, tunnelBuildSuccesses: 0, tunnelBuildFailures: 0, knownPeers: 0, activePeers: 0, floodfillPeers: 0, activeTunnels: 0 };
    this.netDb = new NetworkDatabase({ isFloodfill: this.options.isFloodfill, enableReseed: true, dataDir: this.options.dataDir });
    this.peerProfiles = new PeerProfileManager(); this.netDbRequests = new NetDbRequests();
    this.setupNetDbListeners(); this.setupNetDbRequestListeners(); this.setupLogging();
  }

  private setupNetDbListeners(): void {
    this.netDb.on('routerInfoStored', ({ hash, routerInfo }) => {
      this.peerProfiles.addPeer(routerInfo); this.netDbRequests.requestComplete(hash, true);
      this.stats.knownPeers = this.netDb.getRouterInfoCount(); this.stats.floodfillPeers = this.netDb.getFloodfillCount();
      const storedHex = hash.toString('hex');
      for (const req of this.pendingLeaseSetRequests.values()) if (req.candidateFloodfills.includes(storedHex)) this.tryNextLeaseSetLookup(req.targetHash);
    });
    this.netDb.on('leaseSetStored', (evt) => this.emit('leaseSetStored', evt));
    this.netDb.on('exploratoryLookup', ({ targetHash, floodfill }) => { this.netDbRequests.createRequest(targetHash, true); this.sendExploratoryLookup(targetHash, floodfill).catch(() => {}); });
    this.netDb.on('leaseSetLookup', ({ targetHash, floodfill }) => this.sendLeaseSetLookup(targetHash, floodfill).catch(() => {}));
  }

  private setupNetDbRequestListeners(): void {
    this.netDbRequests.on('requestRouter', (hash) => { if (this.netDb.lookupRouterInfo(hash) || this.netDbRequests.hasRequest(hash)) return; const req = this.netDbRequests.createRequest(hash, false); if (req) this.sendNextLookupRequest(req).catch(() => {}); });
    this.netDbRequests.on('sendNextRequest', (req) => this.sendNextLookupRequest(req).catch(() => {}));
  }

  private async sendNextLookupRequest(req: PendingRequest): Promise<void> {
    const floodfills = this.netDb.findClosestFloodfills(req.destination, 5);
    const ff = floodfills.find(f => !req.excludedPeers.has(f.getRouterHash().toString('hex')));
    if (!ff) { this.netDbRequests.requestComplete(req.destination, false); return; }
    this.netDbRequests.recordAttempt(req.destination, ff.getRouterHash());
    await this.sendDatabaseLookup(req.destination, ff, req.isExploratory ? 3 : 2);
  }

  private setupLogging(): void {
    this.on('error', ({ transport, error }) => {
      const msg = error?.message ?? '', isExpected = msg === 'connect timeout' || msg.includes('ECONNRESET') || msg.includes('ECONNREFUSED') || msg.includes('socket closed before handshake');
      if (isExpected) logger.warn(`${transport} connection failed`, { error: msg }, transport);
      else logger.error(`Error in ${transport}`, { message: msg, stack: error.stack }, transport);
    });
  }

  async start(): Promise<void> {
    if (this.running) return;
    try {
      await this.generateIdentity(); await this.createRouterInfo(); await this.netDb.start(); this.netDbRequests.start(); await this.startTransports(); await this.startSAM();
      this.tunnelManager = new TunnelManager(this.netDb, this.routerInfo!); this.setupTunnelListeners(); this.streaming = new StreamingManager(this.tunnelManager, this.netDb);
      this.tunnelManager.buildTunnel(TunnelType.INBOUND, 1).catch(() => {}); this.tunnelManager.buildTunnel(TunnelType.OUTBOUND, 1).catch(() => {});
      this.startMaintenance();
      if (this.options.enableWebUI) { this.webUI = new SimpleWebUI({ port: this.options.webUIPort, host: this.options.host, router: this as any }); await this.webUI.start(); }
      this.stats.startTime = Date.now(); this.running = true; this.emit('started');
    } catch (err) { logger.fatal('Failed to start router', { error: (err as Error).message }, 'Router'); throw err; }
  }

  stop(): void { if (!this.running) return; this.running = false; if (this.maintenanceInterval) clearInterval(this.maintenanceInterval); this.netDbRequests?.stop(); this.netDb?.stop(); this.ntcp2?.stop(); this.ssu2?.stop(); this.sam?.stop(); this.webUI?.stop(); this.emit('stopped'); }

  private async generateIdentity(): Promise<void> {
    const signingPrivateKey = ed25519.utils.randomPrivateKey(), signingPublicKey = ed25519.getPublicKey(signingPrivateKey), encryptionKeys = Crypto.generateKeyPair();
    const identity = new RouterIdentity(signingPublicKey, encryptionKeys.publicKey);
    this.identityEx = buildIdentityExEd25519X25519({ cryptoPublicKey: encryptionKeys.publicKey, signingPublicKey });
    identity.setHash(this.identityEx.identHash); this.identity = { identity, signingPrivateKey, encryptionPrivateKey: encryptionKeys.privateKey };
  }

  private async createRouterInfo(): Promise<void> {
    const host = this.options.host || '0.0.0.0', ntcp2Port = this.options.ntcp2Port || 12345, ssu2Port = this.options.ssu2Port || 12346;
    const addresses = [new RouterAddress('NTCP2', { host, port: ntcp2Port.toString(), v: '2' }, 5), new RouterAddress('SSU2', { host, port: ssu2Port.toString(), v: '2' }, 6)];
    const caps = this.buildCaps(), netId = this.options.netId || 2;
    this.routerInfo = new RouterInfo(this.identity!.identity, addresses, { caps, netId: netId.toString(), 'router.version': '0.9.66', 'core.version': '0.9.66', stat_uptime: '90m' }, Date.now());
    this.netDb.storeRouterInfo(this.routerInfo); this.ntcp2PublishedIV = Crypto.randomBytes(16);
    const isPublished = host !== '0.0.0.0' && host !== '::' && ntcp2Port > 0;
    let ntcp2Opts = isPublished ? makeNtcp2PublishedOptions({ host, port: ntcp2Port, staticKey: this.identity!.identity.encryptionPublicKey, ivB64: i2pBase64Encode(this.ntcp2PublishedIV), v: '2', caps }) : { s: i2pBase64Encode(Buffer.from(this.identity!.identity.encryptionPublicKey)), v: '2', caps: caps.includes('4') || !caps.includes('6') ? '4' : '6' };
    this.wireRouterInfo = writeRouterInfoEd25519({ identityBytes: this.identityEx!.identityBytes, publishedMs: Date.now(), addresses: [{ transportStyle: 'NTCP2', cost: isPublished ? 3 : 14, dateMs: 0, options: ntcp2Opts }], routerProperties: { netId: netId.toString(), caps, 'router.version': '0.9.66', 'core.version': '0.9.66' }, signingPrivateKey: this.identity!.signingPrivateKey });
    this.routerInfo!.setWireFormatData(this.wireRouterInfo);
  }

  private buildCaps(): string { let caps = this.options.bandwidthClass!; if (this.options.isFloodfill) caps += 'f'; return caps + 'R'; }

  private async startTransports(): Promise<void> {
    this.ntcp2 = new NTCP2Transport({ host: this.options.host, port: this.options.ntcp2Port, routerHash: this.identityEx!.identHash, publishedIV: this.ntcp2PublishedIV!, staticPrivateKey: this.identity!.encryptionPrivateKey, staticPublicKey: this.identity!.identity.encryptionPublicKey, routerInfo: this.wireRouterInfo!, netId: this.options.netId ?? 2, connectTimeoutMs: 5000 });
    this.ntcp2.on('message', ({ sessionId, data }) => this.handleTransportMessage(sessionId, data));
    this.ntcp2.on('error', (err) => this.emit('error', { transport: 'NTCP2', error: err.error || err }));
    await this.ntcp2.start();
    this.ssu2 = new SSU2Transport({ host: this.options.host, port: this.options.ssu2Port, staticPrivateKey: Buffer.from(this.identity!.encryptionPrivateKey), staticPublicKey: Buffer.from(this.identity!.identity.encryptionPublicKey), netId: this.options.netId });
    this.ssu2.on('message', ({ data }) => this.handleTransportMessage('ssu2', data));
    this.ssu2.on('error', (err) => this.emit('error', { transport: 'SSU2', error: err }));
    await this.ssu2.start();
  }

  private async startSAM(): Promise<void> { this.sam = new SAMProtocol({ host: '127.0.0.1', port: this.options.samPort }); await this.sam.start(); }
  private handleTransportMessage(sessionId: string, data: Buffer): void { this.stats.messagesSent++; this.stats.bytesReceived += data.length; try { this.handleI2NPMessage(sessionId, I2NPMessages.parseMessage(data)); } catch (err) { this.emit('error', { error: err, data }); } }

  private handleI2NPMessage(sessionId: string, message: any): void {
    switch (message.type) {
      case I2NPMessageType.DATABASE_STORE: this.handleDatabaseStore(sessionId, message); break;
      case I2NPMessageType.DATABASE_LOOKUP: this.handleDatabaseLookup(sessionId, message); break;
      case I2NPMessageType.DATABASE_SEARCH_REPLY: this.handleDatabaseSearchReply(sessionId, message); break;
      case I2NPMessageType.DELIVERY_STATUS: this.emit('deliveryStatus', { sessionId, message }); break;
      case I2NPMessageType.GARLIC: this.handleGarlic(sessionId, message); break;
      case I2NPMessageType.TUNNEL_DATA: case I2NPMessageType.TUNNEL_GATEWAY: this.handleTunnelMessage(sessionId, message); break;
      case I2NPMessageType.VARIABLE_TUNNEL_BUILD_REPLY: this.handleTunnelBuildReply(sessionId, message); break;
    }
  }

  private handleDatabaseStore(sessionId: string, message: any): void {
    const buf = message.payload; if (buf.length < 37) return;
    const key = buf.subarray(0, 32), type = buf.readUInt8(32), replyToken = buf.readUInt32BE(33);
    let offset = 37;
    if (replyToken > 0 && buf.length >= offset + 36) {
      const replyTunnelId = buf.readUInt32BE(offset); offset += 4; const _replyGateway = buf.subarray(offset, offset + 32); offset += 32;
      if (replyToken !== 0xFFFFFFFF && this.ntcp2) { const dsWire = I2NPMessages.serializeMessage(I2NPMessages.createDeliveryStatus(replyToken, Date.now())); this.ntcp2.send(replyTunnelId === 0 && _replyGateway ? (this.ntcp2.findSessionIdByRouterHash(_replyGateway) || sessionId) : sessionId, dsWire); }
    }
    const data = buf.subarray(offset);
    if (type === 0 && data.length >= 2) { try { const ri = parseI2PRouterInfo(gunzipSync(data.subarray(2, 2 + data.readUInt16BE(0)))); if (ri) this.netDb.storeRouterInfo(ri); } catch (err) {} }
    else if (type === 1 || type === 3) { const ls = type === 1 ? parseLeaseSetLS1(data, key) : parseLeaseSetLS2(data, key); if (ls) { this.netDb.storeLeaseSet(ls); this.clearPendingLeaseSetRequest(key.toString('hex')); } }
    this.emit('databaseStore', { sessionId, message });
  }

  private handleDatabaseLookup(sessionId: string, message: any): void {
    const buf = message.payload; if (buf.length < 65) return;
    const key = buf.subarray(0, 32), fromHash = buf.subarray(32, 64), flags = buf.readUInt8(64);
    const hasDelivery = (flags & 0x01) !== 0, hasEcies = (flags & 0x10) !== 0;
    let offset = 65, replyTunnelId: number | undefined; if (hasDelivery) { replyTunnelId = buf.readUInt32BE(offset); offset += 4; }
    const numExcluded = buf.readUInt16BE(offset); offset += 2 + numExcluded * 32;
    let eciesSessionKey: Buffer | undefined, eciesSessionTag: Buffer | undefined; if (hasEcies && buf.length >= offset + 41) { eciesSessionKey = buf.subarray(offset, offset + 32); offset += 33; eciesSessionTag = buf.subarray(offset, offset + 8); }
    const lookupType = (flags >> 2) & 0x03; let replied = false;
    if (lookupType === 0 || lookupType === 2) { const ri = this.netDb.lookupRouterInfo(key), riWire = ri?.getWireFormatData() || (this.routerInfo && key.equals(this.routerInfo.getRouterHash()) ? this.wireRouterInfo : null); if (riWire) { const c = gzipSync(riWire), d = Buffer.concat([Buffer.alloc(2), c]); d.writeUInt16BE(c.length, 0); this.sendDatabaseLookupReply(sessionId, fromHash, replyTunnelId, I2NPMessages.createDatabaseStore(key, d, 0, this.routerInfo!.getRouterHash()), eciesSessionKey, eciesSessionTag); replied = true; } }
    if (!replied && (lookupType === 0 || lookupType === 1)) { const ls = this.netDb.lookupLeaseSet(key); if (ls?.getWireFormatData()) { this.sendDatabaseLookupReply(sessionId, fromHash, replyTunnelId, I2NPMessages.createDatabaseStore(key, ls.getWireFormatData()!, 0, this.routerInfo!.getRouterHash(), ls.storeType), eciesSessionKey, eciesSessionTag); replied = true; } }
    if (!replied && this.ntcp2) { const ffs = this.netDb.findClosestFloodfills(key, 3).map(f => f.getRouterHash()); this.sendDatabaseLookupReply(sessionId, fromHash, replyTunnelId, I2NPMessages.createDatabaseSearchReply(key, ffs, this.routerInfo!.getRouterHash()), eciesSessionKey, eciesSessionTag); }
  }

  private handleDatabaseSearchReply(sessionId: string, message: any): void {
    const parsed = I2NPMessages.parseDatabaseSearchReply(message.payload); if (!parsed) return;
    this.netDbRequests.handleSearchReply(parsed.key, parsed.routerHashes, this.netDbRequests.findRequest(parsed.key)?.isExploratory || false);
    const keyHex = parsed.key.toString('hex'), req = this.pendingLeaseSetRequests.get(keyHex);
    if (req) { req.excluded.add(parsed.from.toString('hex')); for (const h of parsed.routerHashes) { const hHex = h.toString('hex'); if (!req.excluded.has(hHex) && !req.candidateFloodfills.includes(hHex)) req.candidateFloodfills.push(hHex); } this.tryNextLeaseSetLookup(parsed.key); }
    this.emit('databaseSearchReply', { sessionId, message });
  }

  private handleGarlic(sessionId: string, message: any): void {
    const parsed = I2NPMessages.parseGarlicOuterMessage(message.payload); if (!parsed || parsed.body.length < 24) return;
    const possibleTag = parsed.body.subarray(0, 8), tagHex = possibleTag.toString('hex'), pending = this.pendingEciesReplies.get(tagHex);
    let plaintext: Buffer | null = null;
    if (pending) { try { plaintext = Crypto.decryptTaggedGarlicReply(pending.sessionKey, possibleTag, parsed.body.subarray(8)); } catch (err) {} }
    if (!plaintext && this.identity && parsed.body.length >= 48) { try { plaintext = Crypto.decryptNoiseNGarlicReplyDirect(this.identity.encryptionPrivateKey, parsed.body.subarray(0, 32), parsed.body.subarray(32)); } catch (err) {} }
    if (!plaintext) return;
    if (pending) this.clearPendingEciesReply(tagHex);
    const cloves = I2NPMessages.parseGarlicCloveMessages(plaintext); if (!cloves) return;
    for (const clove of cloves) this.handleI2NPMessage(sessionId, clove.message);
  }

  private async handleTunnelMessage(sessionId: string, message: any): Promise<void> {
    if (message.payload.length < 5 || !this.tunnelManager) return;
    const tunnelId = message.payload.readUInt32BE(0), tunnel = this.tunnelManager.getTunnel(tunnelId); if (!tunnel || tunnel.type !== TunnelType.INBOUND) return;
    const data = message.payload.subarray(4);
    if (tunnel.hops.length === 0) { try { if (data.length >= 8 && data[4] === 0x00) this.handleI2NPMessage(sessionId, I2NPMessages.parseMessage(data.subarray(8))); } catch (err) {} return; }
    if (data.length !== 1024) return;
    const { decryptHop } = await import('./tunnel/message.js'); let decrypted = data;
    for (let i = tunnel.hops.length - 1; i >= 0; i--) decrypted = decryptHop(decrypted, tunnel.hops[i].layerKey, tunnel.hops[i].ivKey);
    const offset = decrypted.readUInt16BE(0); if (offset > 1022) return;
    try { const frag = decrypted.subarray(offset + 2); if (frag.length < 3) return; const type = frag[0], size = frag.readUInt16BE(1); if (frag.length >= 3 + size) this.handleI2NPMessage(sessionId, I2NPMessages.parseMessage(frag.subarray(0, 3 + size) as any)); } catch (e) {} }

  private handleTunnelBuildReply(sessionId: string, message: any): void { if (this.tunnelManager) { const records = message.type === I2NPMessageType.VARIABLE_TUNNEL_BUILD_REPLY ? I2NPMessages.parseVariableTunnelBuildReply(message.payload) : null; if (records) this.tunnelManager.handleVariableTunnelBuildReply(message.uniqueId, records); } this.emit('tunnelBuildReply', { sessionId, message }); }
  private getNtcpEndpoint(ri: RouterInfo): { host: string; port: number } | null { const addr = ri.addresses.find(a => a.transportStyle.toUpperCase().startsWith('NTCP') && a.options.host && !a.options.host.includes(':') && a.options.s && a.options.i && a.options.port); if (!addr) return null; const host = addr.options.host.trim().replace(/^\[|\]$/g, ''), port = parseInt(addr.options.port, 10); return !host || isNaN(port) || port <= 0 || port > 65535 ? null : { host, port }; }
  private setupTunnelListeners(): void { if (!this.tunnelManager) return; this.tunnelManager.on('tunnelBuilt', ({ tunnelId, type }) => { this.stats.tunnelBuildSuccesses++; this.emit('tunnelBuilt', { tunnelId, type }); this.updateStats(); }); this.tunnelManager.on('tunnelBuildFailed', ({ tunnelId }) => { this.stats.tunnelBuildFailures++; this.emit('tunnelBuildFailed', { tunnelId }); }); this.tunnelManager.on('sendTunnelBuild', ({ firstHop, message }) => this.sendI2NPDirect(firstHop, message).catch(() => {})); }
  private startMaintenance(): void { this.maintenanceInterval = setInterval(() => { this.cleanupPendingLeaseSetRequests(); this.cleanupPendingEciesReplies(); if (this.tunnelManager) { this.tunnelManager.cleanupExpiredTunnels(); if (this.tunnelManager.getInboundTunnels().length === 0) this.tunnelManager.buildTunnel(TunnelType.INBOUND, 1).catch(() => {}); if (this.tunnelManager.getOutboundTunnels().length === 0) this.tunnelManager.buildTunnel(TunnelType.OUTBOUND, 1).catch(() => {}); } this.publishRouterInfo(); this.updateStats(); this.emit('maintenance', { stats: this.getStats() }); }, 60000); }
  private async sendExploratoryLookup(targetHash: Buffer, floodfill: RouterInfo): Promise<void> { await this.sendI2NPDirect(floodfill, I2NPMessages.createDatabaseLookup(targetHash, this.routerInfo!.getRouterHash(), 3)); }
  private async sendI2NPDirect(peer: RouterInfo, msg: any): Promise<void> { const wire = I2NPMessages.serializeMessage(msg); if (!this.ntcp2) return; const endpoint = this.getNtcpEndpoint(peer); if (endpoint) { try { await this.ntcp2.connect(endpoint.host, endpoint.port, peer); this.ntcp2.send(`${endpoint.host}:${endpoint.port}`, wire); this.stats.messagesSent++; this.stats.bytesSent += wire.length; } catch (err) {} } }
  private publishRouterInfo(): void { if (!this.routerInfo || !this.wireRouterInfo) return; const ffs = this.netDb.findClosestFloodfills(this.routerInfo.getRouterHash(), 3), ourHash = this.routerInfo.getRouterHash(), c = gzipSync(this.wireRouterInfo), data = Buffer.concat([Buffer.alloc(2), c]); data.writeUInt16BE(c.length, 0); const storeMsg = I2NPMessages.createDatabaseStore(ourHash, data, 0, ourHash); for (const ff of ffs) this.sendI2NPDirect(ff, storeMsg).catch(() => {}); }
  private updateStats(): void { this.stats.knownPeers = this.netDb.getRouterInfoCount(); this.stats.activePeers = this.peerProfiles.getProfileCount(); this.stats.floodfillPeers = this.netDb.getFloodfillCount(); this.stats.activeTunnels = this.tunnelManager?.getAllTunnels().length || 0; }
  getStats(): RouterStats { return { ...this.stats }; }
  getNetworkDatabase(): NetworkDatabase { return this.netDb; }
  getRouterInfo(): RouterInfo | null { return this.routerInfo; }
  getPeerProfiles(): PeerProfileManager { return this.peerProfiles; }
  isRunning(): boolean { return this.running; }
  private async sendLeaseSetLookup(targetHash: Buffer, floodfill: RouterInfo): Promise<void> { const keyHex = targetHash.toString('hex'); let req = this.pendingLeaseSetRequests.get(keyHex); if (!req) { req = this.createPendingLeaseSetRequest(targetHash, keyHex); this.pendingLeaseSetRequests.set(keyHex, req); } const ffHash = floodfill.getRouterHash().toString('hex'); if (req.excluded.has(ffHash)) return; req.excluded.add(ffHash); req.candidateFloodfills = req.candidateFloodfills.filter(c => c !== ffHash); req.attempts++; this.scheduleLeaseSetRetry(req); await this.sendDatabaseLookup(targetHash, floodfill, 1, Array.from(req.excluded, v => Buffer.from(v, 'hex')), req); }
  private tryNextLeaseSetLookup(targetHash: Buffer): void {
    const keyHex = targetHash.toString('hex'), req = this.pendingLeaseSetRequests.get(keyHex); if (!req || this.netDb.lookupLeaseSet(targetHash) || Date.now() - req.createdAt >= LEASESET_REQUEST_TIMEOUT_MS || req.attempts >= MAX_LEASESET_FLOODFILLS_PER_REQUEST) { this.clearPendingLeaseSetRequest(keyHex); return; }
    let next: RouterInfo | undefined; while (req.candidateFloodfills.length > 0 && !next) { const cHash = req.candidateFloodfills.shift()!; if (!req.excluded.has(cHash)) next = this.netDb.lookupRouterInfo(Buffer.from(cHash, 'hex')) || undefined; }
    if (!next) next = this.netDb.findClosestFloodfills(targetHash, MAX_LEASESET_FLOODFILLS_PER_REQUEST).find(ff => !req.excluded.has(ff.getRouterHash().toString('hex')));
    if (!next) { this.clearPendingLeaseSetRequest(keyHex); return; } this.sendLeaseSetLookup(targetHash, next).catch(() => {});
  }
  private async sendDatabaseLookup(targetHash: Buffer, floodfill: RouterInfo, lookupType: number, excludedPeers: Buffer[] = [], leaseSetRequest?: PendingLeaseSetRequest): Promise<void> {
    const opts: any = {}; let fromHash = this.routerInfo!.getRouterHash();
    if (lookupType === 1) { const replyTunnel = await this.ensureLeaseSetReplyTunnel(); if (!replyTunnel) throw new Error('No reply tunnel'); fromHash = replyTunnel.gatewayHash; opts.replyTunnelId = replyTunnel.tunnelId; opts.eciesSessionKey = Crypto.randomBytes(32); opts.eciesSessionTag = Crypto.randomBytes(8); const tagHex = opts.eciesSessionTag.toString('hex'); this.pendingEciesReplies.set(tagHex, { sessionKey: opts.eciesSessionKey as any, targetHash: targetHash.toString('hex'), createdAt: Date.now() }); leaseSetRequest?.eciesTags.add(tagHex); }
    const wire = I2NPMessages.serializeMessage(I2NPMessages.createDatabaseLookup(targetHash, fromHash, lookupType as any, excludedPeers, opts));
    const obTunnel = this.tunnelManager?.getOutboundTunnels().find(t => t.hops.length > 0);
    if (obTunnel) {
      const payload = this.tunnelManager!.encryptForTunnel(obTunnel.id, wire)[0], firstHop = obTunnel.hops[0], ep = this.getNtcpEndpoint(firstHop.routerInfo);
      if (ep && this.ntcp2) {
        const wireMsg = I2NPMessages.serializeMessage({ type: I2NPMessageType.TUNNEL_DATA, uniqueId: Math.floor(Math.random() * 0xFFFFFFFF), expiration: Date.now() + 30000, payload: payload as any });
        await this.ntcp2.connect(ep.host, ep.port, firstHop.routerInfo); this.ntcp2.send(`${ep.host}:${ep.port}`, wireMsg); this.stats.messagesSent++; this.stats.bytesSent += wireMsg.length;
      }
    } else await this.sendI2NPDirect(floodfill, I2NPMessages.createDatabaseLookup(targetHash, fromHash, lookupType as any, excludedPeers, opts));
  }
  private sendDatabaseLookupReply(sessionId: string, replyGatewayHash: Buffer, replyTunnelId: number | undefined, innerMsg: any, sessionKey?: Buffer, sessionTag?: Buffer): void {
    if (!this.ntcp2) return; let replyMsg = innerMsg;
    if (sessionKey && sessionTag) { const ciphertext = Crypto.encryptTaggedGarlicReply(sessionKey, sessionTag, I2NPMessages.createGarlicClovePayload([innerMsg])), body = Buffer.concat([sessionTag, ciphertext]), lenBuf = Buffer.alloc(4); lenBuf.writeUInt32BE(body.length, 0); replyMsg = { type: I2NPMessageType.GARLIC, uniqueId: Math.floor(Math.random() * 0xFFFFFFFF), expiration: Date.now() + 30000, payload: Buffer.concat([lenBuf, body]) }; }
    const wire = I2NPMessages.serializeMessage(replyMsg); let finalWire = wire; if (replyTunnelId && replyTunnelId > 0) { const h = Buffer.alloc(4); h.writeUInt32BE(replyTunnelId, 0); finalWire = I2NPMessages.serializeMessage({ type: I2NPMessageType.TUNNEL_GATEWAY, uniqueId: Math.floor(Math.random() * 0xFFFFFFFF), expiration: Date.now() + 30000, payload: Buffer.concat([h, wire]) }); }
    this.ntcp2.send(this.ntcp2.findSessionIdByRouterHash(replyGatewayHash) || sessionId, finalWire as any); this.stats.messagesSent++; this.stats.bytesSent += finalWire.length;
  }
  private createPendingLeaseSetRequest(targetHash: Buffer, targetHex: string, timeoutMs = LEASESET_REQUEST_TIMEOUT_MS): PendingLeaseSetRequest { return { targetHash: Buffer.from(targetHash), excluded: new Set(), attempts: 0, createdAt: Date.now(), candidateFloodfills: [], eciesTags: new Set(), retryTimer: setTimeout(() => this.clearPendingLeaseSetRequest(targetHex), timeoutMs) }; }
  private clearPendingLeaseSetRequest(targetHex: string): void { const req = this.pendingLeaseSetRequests.get(targetHex); if (!req) return; if (req.retryTimer) clearTimeout(req.retryTimer); for (const t of req.eciesTags) this.pendingEciesReplies.delete(t); this.pendingLeaseSetRequests.delete(targetHex); }
  private scheduleLeaseSetRetry(req: PendingLeaseSetRequest): void { if (req.retryTimer) clearTimeout(req.retryTimer); req.retryTimer = setTimeout(() => this.tryNextLeaseSetLookup(req.targetHash), LEASESET_RETRY_DELAY_MS); }
  private cleanupPendingLeaseSetRequests(): void { for (const [t, r] of this.pendingLeaseSetRequests.entries()) if (Date.now() - r.createdAt >= LEASESET_REQUEST_TIMEOUT_MS || r.attempts >= MAX_LEASESET_FLOODFILLS_PER_REQUEST) this.clearPendingLeaseSetRequest(t); }
  private cleanupPendingEciesReplies(): void { const now = Date.now(); for (const [t, p] of this.pendingEciesReplies.entries()) if (now - p.createdAt >= ECIES_REPLY_TTL_MS) this.clearPendingEciesReply(t); }
  private clearPendingEciesReply(tag: string): void { this.pendingEciesReplies.delete(tag); for (const r of this.pendingLeaseSetRequests.values()) r.eciesTags.delete(tag); }
  private async ensureLeaseSetReplyTunnel(): Promise<{ tunnelId: number; gatewayHash: Buffer } | null> { if (!this.tunnelManager || !this.routerInfo) return null; let t = this.tunnelManager.getInboundTunnels().find(c => c.hops.length >= 1); if (!t) t = (await this.tunnelManager.buildTunnel(TunnelType.INBOUND, 1)) ?? undefined; return t ? { tunnelId: (t as any).hops[0]?.tunnelId ?? t.id, gatewayHash: (t as any).hops[0]?.routerHash ?? (this.routerInfo as any).getRouterHash() } : null; }
}
export default I2PRouter;

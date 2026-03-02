import { EventEmitter } from 'events';
import { Crypto } from './crypto/index.js';
import { RouterIdentity, RouterInfo, RouterAddress } from './data/router-info.js';
import { LeaseSet } from './data/lease-set.js';
import { parseLeaseSetI2P } from './data/lease-set-i2p.js';
import { I2NPMessages, I2NPMessageType } from './i2np/messages.js';
import { NetworkDatabase } from './netdb/index.js';
import { TunnelManager, TunnelType } from './tunnel/manager.js';
import { PeerProfileManager } from './peer/profiles.js';
import { NTCP2Transport } from './transport/ntcp2.js';
import { SSU2Transport } from './transport/ssu2.js';
import { SAMProtocol } from './sam/protocol.js';
import { logger, LogLevel } from './utils/logger.js';
import { SimpleWebUI } from './webui/simple-server.js';
import { StreamingManager, Stream } from './streaming/session.js';
import { base32DecodeToHash } from './i2p/base32.js';
import { ed25519 } from '@noble/curves/ed25519';
import { buildIdentityExEd25519X25519, IdentityExBuildResult } from './i2p/identity/identity-ex.js';
import { writeRouterInfoEd25519, makeNtcp2PublishedOptions } from './i2p/routerinfo/writer.js';
import { i2pBase64Encode } from './i2p/base64.js';

export interface I2PRouterOptions {
  host?: string;
  ntcp2Port?: number;
  ssu2Port?: number;
  samPort?: number;
  isFloodfill?: boolean;
  bandwidthClass?: 'K' | 'L' | 'M' | 'N' | 'O' | 'P' | 'X';
  sharePercentage?: number;
  netId?: number;
  dataDir?: string;
  logLevel?: LogLevel;
  enableWebUI?: boolean;
  webUIPort?: number;
}

export interface RouterStats {
  startTime: number;
  messagesSent: number;
  messagesReceived: number;
  bytesSent: number;
  bytesReceived: number;
  tunnelBuildSuccesses: number;
  tunnelBuildFailures: number;
  knownPeers: number;
  activePeers: number;
  floodfillPeers: number;
  activeTunnels: number;
}

export class I2PRouter extends EventEmitter {
  private identity: { identity: RouterIdentity; signingPrivateKey: Uint8Array; encryptionPrivateKey: Uint8Array } | null = null;
  private routerInfo: RouterInfo | null = null;
  private netDb: NetworkDatabase;
  private tunnelManager: TunnelManager | null = null;
  private peerProfiles: PeerProfileManager;
  private ntcp2: NTCP2Transport | null = null;
  private ssu2: SSU2Transport | null = null;
  private sam: SAMProtocol | null = null;
  private webUI: SimpleWebUI | null = null;
  private streaming: StreamingManager | null = null;
  private options: I2PRouterOptions;
  private stats: RouterStats;
  private running = false;
  private maintenanceInterval: NodeJS.Timeout | null = null;
  // I2P-spec identity + RouterInfo (wire format) used by NTCP2/SSU2 and for interoperability.
  private identityEx: IdentityExBuildResult | null = null;
  private wireRouterInfo: Buffer | null = null;
  private ntcp2PublishedIV: Buffer | null = null;

  constructor(options: I2PRouterOptions = {}) {
    super();
    this.options = {
      host: '0.0.0.0',
      ntcp2Port: 12345,
      ssu2Port: 12346,
      samPort: 7656,
      isFloodfill: false,
      bandwidthClass: 'L',
      sharePercentage: 80,
      netId: 2,
      dataDir: './i2p-data',
      logLevel: LogLevel.INFO,
      enableWebUI: false,
      webUIPort: 7070,
      ...options
    };

    // Configure logger
    logger.setLevel(this.options.logLevel!);
    logger.info('I2P Router instance created', { options: this.options }, 'Router');

    this.stats = {
      startTime: 0,
      messagesSent: 0,
      messagesReceived: 0,
      bytesSent: 0,
      bytesReceived: 0,
      tunnelBuildSuccesses: 0,
      tunnelBuildFailures: 0,
      knownPeers: 0,
      activePeers: 0,
      floodfillPeers: 0,
      activeTunnels: 0
    };

    this.netDb = new NetworkDatabase({ 
      isFloodfill: this.options.isFloodfill,
      enableReseed: true,
      dataDir: this.options.dataDir
    });
    this.peerProfiles = new PeerProfileManager();
    
    this.setupNetDbListeners();
    this.setupLogging();
  }

  private setupNetDbListeners(): void {
    // Listen for new router infos and add to peer profiles
    this.netDb.on('routerInfoStored', ({ hash, routerInfo }: { hash: Buffer; routerInfo: RouterInfo }) => {
      logger.debug(`New router info stored: ${hash.toString('hex').slice(0, 16)}...`, undefined, 'Router');
      
      // Add to peer profiles
      this.peerProfiles.addPeer(routerInfo);
      
      // Update stats
      this.stats.knownPeers = this.netDb.getRouterInfoCount();
      this.stats.floodfillPeers = this.netDb.getFloodfillCount();
    });

    // Listen for exploratory lookups and trigger DatabaseLookup messages
    this.netDb.on('exploratoryLookup', ({ targetHash, floodfill }: { targetHash: Buffer; floodfill: RouterInfo }) => {
      logger.debug(
        `Exploratory lookup for ${targetHash.toString('hex').slice(0, 16)}... via ${floodfill.getRouterHash().toString('hex').slice(0, 16)}...`,
        undefined,
        'Router'
      );

      // Fire and forget: connect to the floodfill over NTCP2 and send a DatabaseLookup
      this.sendExploratoryLookup(targetHash, floodfill).catch((err) => {
        logger.warn('Failed exploratory lookup send', { error: (err as Error).message }, 'Router');
      });
    });
  }

  private setupLogging(): void {
    // Log all events
    this.on('started', () => {
      logger.info('Router started successfully', undefined, 'Router');
    });

    this.on('stopped', () => {
      logger.info('Router stopped', undefined, 'Router');
    });

    this.on('tunnelBuilt', ({ tunnelId, type }: { tunnelId: number; type: string }) => {
      logger.info(`Tunnel ${tunnelId} built (${type})`, { tunnelId, type }, 'Tunnel');
    });

    this.on('tunnelBuildFailed', ({ tunnelId }: { tunnelId: number }) => {
      logger.warn(`Tunnel ${tunnelId} build failed`, { tunnelId }, 'Tunnel');
    });

    this.on('tunnelExpired', ({ tunnelId }: { tunnelId: number }) => {
      logger.info(`Tunnel ${tunnelId} expired`, { tunnelId }, 'Tunnel');
    });

    this.on('error', ({ transport, error }: { transport: string; error: Error }) => {
      logger.error(`Error in ${transport}`, { message: error.message, stack: error.stack }, transport);
    });
  }

  async start(): Promise<void> {
    if (this.running) {
      logger.warn('Router already running', undefined, 'Router');
      return;
    }

    logger.info('Starting I2P Router...', undefined, 'Router');

    try {
      await this.generateIdentity();
      logger.debug('Identity generated', undefined, 'Router');

      await this.createRouterInfo();
      logger.info('RouterInfo created', { 
        hash: this.routerInfo?.getRouterHash().toString('hex').slice(0, 16) 
      }, 'Router');

      // Start NetDb (loads from disk and reseeds if needed)
      await this.netDb.start();
      
      await this.startTransports();
      await this.startSAM();
      
      this.tunnelManager = new TunnelManager(this.netDb, this.routerInfo!);
      this.setupTunnelListeners();
      this.streaming = new StreamingManager(this.tunnelManager, this.netDb);

      this.startMaintenance();
      
      // Start Web UI if enabled
      if (this.options.enableWebUI) {
        this.webUI = new SimpleWebUI({ 
          port: this.options.webUIPort, 
          host: this.options.host,
          router: this 
        });
        await this.webUI.start();
      }
      
      this.stats.startTime = Date.now();
      this.running = true;
      
      logger.info('I2P Router started successfully', {
        routerHash: this.routerInfo!.getRouterHash().toString('hex'),
        ntcp2Port: this.options.ntcp2Port,
        ssu2Port: this.options.ssu2Port,
        webUI: this.options.enableWebUI ? `http://${this.options.host}:${this.options.webUIPort}` : 'disabled'
      }, 'Router');
      
      this.emit('started');
      console.log('I2P Router started successfully');
      console.log(`Router Hash: ${this.routerInfo!.getRouterHash().toString('hex').slice(0, 16)}...`);
      if (this.options.enableWebUI) {
        console.log(`Web UI: http://${this.options.host}:${this.options.webUIPort}`);
      }
    } catch (err) {
      logger.fatal('Failed to start router', { error: (err as Error).message }, 'Router');
      throw err;
    }
  }

  stop(): void {
    if (!this.running) {
      logger.warn('Router not running', undefined, 'Router');
      return;
    }

    logger.info('Stopping I2P Router...', undefined, 'Router');

    this.running = false;

    if (this.maintenanceInterval) {
      clearInterval(this.maintenanceInterval);
      this.maintenanceInterval = null;
    }

    this.ntcp2?.stop();
    this.ssu2?.stop();
    this.sam?.stop();
    this.webUI?.stop();

    logger.info('I2P Router stopped', undefined, 'Router');
    this.emit('stopped');
    console.log('I2P Router stopped');
  }

  private async generateIdentity(): Promise<void> {
    const { Crypto } = await import('./crypto/index.js');

    // Ed25519 signing key (32-byte seed) + X25519 encryption key, matching i2pd layout.
    const signingPrivateKey = ed25519.utils.randomPrivateKey();
    const signingPublicKey = ed25519.getPublicKey(signingPrivateKey);
    const encryptionKeys = Crypto.generateKeyPair(); // X25519

    const identity = new RouterIdentity(signingPublicKey, encryptionKeys.publicKey);

    // Build I2P-spec IdentityEx bytes + identHash and bind it to RouterIdentity.
    this.identityEx = buildIdentityExEd25519X25519({
      cryptoPublicKey: encryptionKeys.publicKey,
      signingPublicKey
    });
    identity.setHash(this.identityEx.identHash);

    this.identity = {
      identity,
      signingPrivateKey,
      encryptionPrivateKey: encryptionKeys.privateKey
    };
  }

  private async createRouterInfo(): Promise<void> {
    const addresses: RouterAddress[] = [];
    const host = this.options.host || '0.0.0.0';
    const ntcp2Port = this.options.ntcp2Port || 12345;
    const ssu2Port = this.options.ssu2Port || 12346;

    // Internal RouterInfo view (non-wire format, used by NetDb/tunnel manager).
    addresses.push(
      new RouterAddress(
        'NTCP2',
        {
          host: host,
          port: ntcp2Port.toString(),
          v: '2'
        },
        5
      )
    );

    addresses.push(
      new RouterAddress(
        'SSU2',
        {
          host: host,
          port: ssu2Port.toString(),
          v: '2'
        },
        6
      )
    );

    const caps = this.buildCaps();
    const netId = this.options.netId || 2;

    this.routerInfo = new RouterInfo(
      this.identity!.identity,
      addresses,
      {
        caps,
        netId: netId.toString(),
        'router.version': '0.9.66',
        'core.version': '0.9.66',
        stat_uptime: '90m'
      },
      Date.now()
    );

    this.netDb.storeRouterInfo(this.routerInfo);

    // Also build a spec-compliant wire-format RouterInfo for NTCP2 handshakes.
    if (!this.identityEx) {
      throw new Error('identityEx not initialized');
    }

    const publishedIV = Buffer.from(Crypto.randomBytes(16));
    this.ntcp2PublishedIV = publishedIV;

    const ntcp2Opts = makeNtcp2PublishedOptions({
      host,
      port: ntcp2Port,
      staticKey: this.identity!.identity.encryptionPublicKey,
      ivB64: i2pBase64Encode(publishedIV),
      v: '2',
      caps
    });

    const addressesWire = [
      {
        transportStyle: 'NTCP2',
        options: ntcp2Opts
      }
    ];

    this.wireRouterInfo = writeRouterInfoEd25519({
      identityBytes: this.identityEx.identityBytes,
      publishedMs: Date.now(),
      addresses: addressesWire,
      routerProperties: {
        netId: netId.toString(),
        caps,
        'router.version': '0.9.66',
        'core.version': '0.9.66'
      },
      signingPrivateKey: this.identity!.signingPrivateKey
    });
  }

  private buildCaps(): string {
    let caps = this.options.bandwidthClass!;
    
    if (this.options.isFloodfill) {
      caps += 'f';
    }
    
    caps += 'R';
    
    return caps;
  }

  private async startTransports(): Promise<void> {
    if (!this.identity || !this.identityEx || !this.routerInfo || !this.wireRouterInfo || !this.ntcp2PublishedIV) {
      throw new Error('Router identity/RouterInfo not fully initialized before starting transports');
    }

    this.ntcp2 = new NTCP2Transport({
      host: this.options.host,
      port: this.options.ntcp2Port,
      routerHash: this.identityEx.identHash,
      publishedIV: this.ntcp2PublishedIV,
      staticPrivateKey: Buffer.from(this.identity.encryptionPrivateKey),
      staticPublicKey: Buffer.from(this.identity.identity.encryptionPublicKey),
      routerInfo: this.wireRouterInfo,
      netId: this.options.netId ?? 2,
      connectTimeoutMs: 8000
    });

    this.ntcp2.on('message', ({ sessionId, data }) => {
      this.handleTransportMessage(sessionId, data);
    });

    this.ntcp2.on('error', (err) => {
      this.emit('error', { transport: 'NTCP2', error: err });
    });

    await this.ntcp2.start();
    console.log(`NTCP2 transport started on port ${this.options.ntcp2Port}`);

    this.ssu2 = new SSU2Transport({
      host: this.options.host,
      port: this.options.ssu2Port,
      staticPrivateKey: Buffer.from(this.identity!.encryptionPrivateKey),
      staticPublicKey: Buffer.from(this.identity!.identity.encryptionPublicKey),
      netId: this.options.netId
    });

    this.ssu2.on('message', ({ data }) => {
      this.handleTransportMessage('ssu2', data);
    });

    this.ssu2.on('error', (err) => {
      this.emit('error', { transport: 'SSU2', error: err });
    });

    await this.ssu2.start();
    console.log(`SSU2 transport started on port ${this.options.ssu2Port}`);
  }

  private async startSAM(): Promise<void> {
    this.sam = new SAMProtocol({
      host: '127.0.0.1',
      port: this.options.samPort
    });

    this.sam.on('sessionCreate', ({ sessionId, style, destination }) => {
      this.emit('samSession', { sessionId, style, destination });
    });

    this.sam.on('streamConnect', ({ destination }) => {
      this.emit('samStreamConnect', { destination });
    });

    this.sam.on('error', (err) => {
      this.emit('error', { transport: 'SAM', error: err });
    });

    await this.sam.start();
    console.log(`SAM protocol started on port ${this.options.samPort}`);
  }

  private handleTransportMessage(sessionId: string, data: Buffer): void {
    this.stats.messagesReceived++;
    this.stats.bytesReceived += data.length;

    try {
      const message = I2NPMessages.parseMessage(data);
      this.handleI2NPMessage(sessionId, message);
    } catch (err) {
      this.emit('error', { error: err, data });
    }
  }

  private handleI2NPMessage(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    switch (message.type) {
      case I2NPMessageType.DATABASE_STORE:
        this.handleDatabaseStore(sessionId, message);
        break;
      case I2NPMessageType.DATABASE_LOOKUP:
        this.handleDatabaseLookup(sessionId, message);
        break;
      case I2NPMessageType.DATABASE_SEARCH_REPLY:
        this.handleDatabaseSearchReply(sessionId, message);
        break;
      case I2NPMessageType.DELIVERY_STATUS:
        this.handleDeliveryStatus(sessionId, message);
        break;
      case I2NPMessageType.TUNNEL_BUILD:
        this.handleTunnelBuild(sessionId, message);
        break;
      case I2NPMessageType.TUNNEL_BUILD_REPLY:
        this.handleTunnelBuildReply(sessionId, message);
        break;
      default:
        this.emit('unknownMessage', { message });
    }
  }

  private handleDatabaseStore(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    // Spec format (simplified subset):
    // key(32) | type(1) | replyToken(4) |
    // [ reply_tunnelId(4) | reply_gateway(32) if replyToken>0 ] | data...
    const buf = message.payload;
    if (buf.length < 32 + 1 + 4) return;

    const key = buf.subarray(0, 32);
    const type = buf.readUInt8(32);
    const replyToken = buf.readUInt32BE(33);

    let offset = 37;
    if (replyToken > 0) {
      if (buf.length < offset + 4 + 32) return;
      // const replyTunnelId = buf.readUInt32BE(offset);
      offset += 4;
      // const replyGateway = buf.subarray(offset, offset + 32);
      offset += 32;
    }

    const data = buf.subarray(offset);

    if (type === 0) {
      // RouterInfo
      try {
        const routerInfo = RouterInfo.deserialize(data);
        this.netDb.storeRouterInfo(routerInfo);
        logger.debug(
          `DatabaseStore (RouterInfo) for ${key.toString('hex').slice(0, 16)}...`,
          undefined,
          'Router'
        );
      } catch (err) {
        logger.warn('Failed to deserialize RouterInfo from DatabaseStore', { error: (err as Error).message }, 'Router');
      }
    } else if (type === 1) {
      // LeaseSet / LeaseSet2 (parsed into our LeaseSet abstraction)
      let leaseSet: LeaseSet | null = null;
      try {
        // Try classic LeaseSet (LS1) layout first.
        leaseSet = LeaseSet.deserialize(data);
      } catch {
        // Fallback to LS2 parser (standard, unencrypted).
        leaseSet = parseLeaseSetI2P(data, key);
      }

      if (leaseSet) {
        this.netDb.storeLeaseSet(leaseSet);
        logger.debug(
          `DatabaseStore (LeaseSet) for ${key.toString('hex').slice(0, 16)}...`,
          undefined,
          'Router'
        );
      } else {
        logger.warn('Failed to deserialize LeaseSet/LeaseSet2 from DatabaseStore', undefined, 'Router');
      }
    } else {
      logger.debug(`DatabaseStore with unsupported type=${type}`, undefined, 'Router');
    }

    this.emit('databaseStore', { sessionId, message });
  }

  private handleDatabaseLookup(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    // Payload (subset of spec): key(32) | from(32) | flags(1) | size(2) | excluded[size*32]
    const buf = message.payload;
    if (buf.length < 32 + 32 + 1 + 2) return;

    const key = buf.subarray(0, 32);
    // const fromHash = buf.subarray(32, 64);
    const flags = buf.readUInt8(64);
    const size = buf.readUInt16BE(65);

    const lookupTypeBits = (flags >> 2) & 0x03;
    const lookupType = lookupTypeBits;

    logger.debug(
      `DatabaseLookup received for ${key.toString('hex').slice(0, 16)}... (type=${lookupType})`,
      undefined,
      'Router'
    );

    const ri = this.netDb.lookupRouterInfo(key);
    if (ri && this.ntcp2) {
      const data = ri.serialize();
      const fromHash = this.routerInfo!.getRouterHash();
      const replyToken = 0;
      const storeMsg = I2NPMessages.createDatabaseStore(key, data, replyToken, fromHash);
      const wire = I2NPMessages.serializeMessage(storeMsg);
      this.ntcp2.send(sessionId, wire);

      this.stats.messagesSent++;
      this.stats.bytesSent += wire.length;
    }

    this.emit('databaseLookup', { sessionId, message });
  }

  private handleDatabaseSearchReply(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('databaseSearchReply', { sessionId, message });
  }

  private handleDeliveryStatus(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('deliveryStatus', { sessionId, message });
  }

  private handleTunnelBuild(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('tunnelBuild', { sessionId, message });
  }

  private handleTunnelBuildReply(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('tunnelBuildReply', { sessionId, message });
  }

  private setupTunnelListeners(): void {
    if (!this.tunnelManager) return;

    this.tunnelManager.on('tunnelBuilt', ({ tunnelId, type }) => {
      this.stats.tunnelBuildSuccesses++;
      this.emit('tunnelBuilt', { tunnelId, type });
      this.updateStats();
    });

    this.tunnelManager.on('tunnelBuildFailed', ({ tunnelId }) => {
      this.stats.tunnelBuildFailures++;
      this.emit('tunnelBuildFailed', { tunnelId });
    });

    this.tunnelManager.on('tunnelExpired', ({ tunnelId }) => {
      this.emit('tunnelExpired', { tunnelId });
      this.updateStats();
    });
  }

  private startMaintenance(): void {
    this.maintenanceInterval = setInterval(() => {
      this.performMaintenance();
    }, 60000);
  }

  private performMaintenance(): void {
    if (this.tunnelManager) {
      this.tunnelManager.cleanupExpiredTunnels();

      // Ensure at least one inbound and one outbound tunnel exist.
      if (this.tunnelManager.getInboundTunnels().length === 0) {
        this.tunnelManager.buildTunnel(TunnelType.INBOUND, 1).catch(() => {
          /* ignore for now */
        });
      }
      if (this.tunnelManager.getOutboundTunnels().length === 0) {
        this.tunnelManager.buildTunnel(TunnelType.OUTBOUND, 1).catch(() => {
          /* ignore for now */
        });
      }
    }

    this.publishRouterInfo();
    this.updateStats();
    this.emit('maintenance', { stats: this.getStats() });
  }

  /**
   * Connect to a floodfill and send an exploratory DatabaseLookup for a random key.
   * Prefer NTCP2 if the floodfill has a full NTCP/NTCP2 address with host/port/s/i.
   * Fall back to SSU2 if available. Best-effort; failures are logged but not fatal.
   */
  private async sendExploratoryLookup(targetHash: Buffer, floodfill: RouterInfo): Promise<void> {
    const fromHash = this.routerInfo!.getRouterHash();
    const msg = I2NPMessages.createDatabaseLookup(
      targetHash,
      fromHash,
      0, // lookup type: router info
      []
    );
    const wire = I2NPMessages.serializeMessage(msg);

    // 1) Try NTCP2 (or NTCP v=2) if present with full keys (host/port/s/i).
    if (this.ntcp2) {
      // Prefer IPv4 NTCP/NTCP2 addresses with full s/i options; skip IPv6/Ygg/Yggdrasil for now.
      const ntcpAddr = floodfill.addresses.find((a) => {
        const styleOk = a.transportStyle.toUpperCase().startsWith('NTCP');
        const host = a.options.host;
        const hasKeys = a.options.s && a.options.i && a.options.port;
        if (!styleOk || !host || !hasKeys) return false;
        // crude IPv4 detection: no ':' and not bracketed.
        if (host.includes(':') || host.startsWith('[')) return false;
        return true;
      });

      if (ntcpAddr) {
        const host = ntcpAddr.options.host;
        const portNum = parseInt(ntcpAddr.options.port, 10);
        if (!host || !portNum || Number.isNaN(portNum)) {
          logger.debug('Invalid NTCP2 address for floodfill', { host, port: ntcpAddr.options.port }, 'Router');
        } else {
          try {
            await this.ntcp2.connect(host, portNum, floodfill);
            const sessionId = `${host}:${portNum}`;
            this.ntcp2.send(sessionId, wire);
            this.stats.messagesSent++;
            this.stats.bytesSent += wire.length;
            return;
          } catch (err) {
            logger.warn(
              'Exploratory NTCP2 lookup failed, will consider SSU2 fallback',
              { error: (err as Error).message },
              'Router'
            );
          }
        }
      } else {
        logger.debug('No IPv4 NTCP/NTCP2 address with s/i found for floodfill', undefined, 'Router');
      }
    }

    // NOTE: SSU2 fallback is temporarily disabled for exploratory lookups while
    // NTCP2 interop is being hardened; SSU2 is not yet reliably interoperable.
  }

  private publishRouterInfo(): void {
    if (!this.routerInfo) return;
    
    this.routerInfo.published = Date.now();
    
    const floodfills = this.netDb.findClosestFloodfills(
      this.routerInfo.getRouterHash(),
      3
    );
    
    for (const floodfill of floodfills) {
      this.emit('publishRouterInfo', { floodfill });
    }
  }

  private updateStats(): void {
    this.stats.knownPeers = this.netDb.getRouterInfoCount();
    this.stats.activePeers = this.peerProfiles.getProfileCount();
    this.stats.floodfillPeers = this.netDb.getFloodfillCount();
    this.stats.activeTunnels = this.tunnelManager?.getAllTunnels().length || 0;
  }

  getStats(): RouterStats {
    return { ...this.stats };
  }

  getRouterInfo(): RouterInfo | null {
    return this.routerInfo;
  }

  getNetworkDatabase(): NetworkDatabase {
    return this.netDb;
  }

  getTunnelManager(): TunnelManager | null {
    return this.tunnelManager;
  }

  getPeerProfiles(): PeerProfileManager {
    return this.peerProfiles;
  }

  isRunning(): boolean {
    return this.running;
  }

  /**
   * Minimal helper to open a streaming session to a .b32.i2p destination using this router:
   *  - Ensures a LeaseSet is present in NetDb (via targeted DatabaseLookup)
   *  - Ensures an outbound tunnel exists
   *  - Returns a Stream instance (or null on failure)
   */
  async openStreamToBase32(host: string, timeoutMs = 15000): Promise<Stream | null> {
    if (!this.streaming || !this.tunnelManager) return null;
    const hash = base32DecodeToHash(host);
    if (!hash) return null;

    // If no LeaseSet yet, request it from floodfills and wait.
    let leaseSet = this.netDb.lookupLeaseSet(hash);
    if (!leaseSet) {
      leaseSet = await this.fetchLeaseSet(hash, timeoutMs);
      if (!leaseSet) return null;
    }

    // StreamingManager.openStreamToBase32 expects the LeaseSet to be present in NetDb.
    return this.streaming.openStreamToBase32(host);
  }

  /**
   * Send DatabaseLookup for a LeaseSet hash to closest floodfills and wait until a LeaseSet
   * with that hash is stored in NetDb or timeout expires.
   */
  private async fetchLeaseSet(hash: Buffer, timeoutMs: number): Promise<LeaseSet | null> {
    const targetHex = hash.toString('hex');
    const existing = this.netDb.lookupLeaseSet(hash);
    if (existing) return existing;

    const floodfills = this.netDb.findClosestFloodfills(hash, 3);
    if (!floodfills.length) return null;

    // Fire off lookups (LeaseSet type = 1)
    await Promise.all(
      floodfills.map((ff) => this.sendDatabaseLookup(hash, ff, 1).catch(() => undefined))
    );

    return new Promise<LeaseSet | null>((resolve) => {
      const onStored = ({ hash: hs, leaseSet }: { hash: Buffer; leaseSet: LeaseSet }) => {
        if (hs.toString('hex') === targetHex) {
          cleanup();
          resolve(leaseSet);
        }
      };
      const onTimeout = () => {
        cleanup();
        resolve(null);
      };
      const cleanup = () => {
        this.netDb.off('leaseSetStored', onStored as any);
      };
      this.netDb.on('leaseSetStored', onStored as any);
      setTimeout(onTimeout, timeoutMs);
    });
  }

  /**
   * Generic DatabaseLookup sender used for exploratory (routerInfo) and targeted (LeaseSet) lookups.
   */
  private async sendDatabaseLookup(
    targetHash: Buffer,
    floodfill: RouterInfo,
    lookupType: 0 | 1 | 2 | 3
  ): Promise<void> {
    // Prefer IPv4 NTCP2/NTCP with full keys; SSU2 fallback is disabled for now.
    if (this.ntcp2) {
      const ntcpAddr = floodfill.addresses.find((a) => {
        const styleOk = a.transportStyle.toUpperCase().startsWith('NTCP');
        const host = a.options.host;
        const hasKeys = a.options.s && a.options.i && a.options.port;
        if (!styleOk || !host || !hasKeys) return false;
        if (host.includes(':') || host.startsWith('[')) return false;
        return true;
      });
      if (ntcpAddr) {
        const host = ntcpAddr.options.host!;
        const portNum = parseInt(ntcpAddr.options.port, 10);
        if (host && portNum && !Number.isNaN(portNum)) {
          const fromHash = this.routerInfo!.getRouterHash();
          const msg = I2NPMessages.createDatabaseLookup(targetHash, fromHash, lookupType, []);
          const wire = I2NPMessages.serializeMessage(msg);
          await this.ntcp2.connect(host, portNum, floodfill);
          const sessionId = `${host}:${portNum}`;
          this.ntcp2.send(sessionId, wire);
          this.stats.messagesSent++;
          this.stats.bytesSent += wire.length;
          return;
        }
      }
    }

    // SSU2 path intentionally disabled while transport is MVP-only and not
    // interoperable with stock routers yet.
  }

  async buildInboundTunnel(hops = 3): Promise<ReturnType<TunnelManager['buildTunnel']>> {
    if (!this.tunnelManager) return null;
    return this.tunnelManager.buildTunnel(TunnelType.INBOUND, hops);
  }

  async buildOutboundTunnel(hops = 3): Promise<ReturnType<TunnelManager['buildTunnel']>> {
    if (!this.tunnelManager) return null;
    return this.tunnelManager.buildTunnel(TunnelType.OUTBOUND, hops);
  }
}

export default I2PRouter;

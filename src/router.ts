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
import { StreamingManager, Stream } from './streaming/session.js';
import { base32DecodeToHash } from './i2p/base32.js';
import { NetDbRequests, PendingRequest } from './netdb/requests.js';
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

interface PendingLeaseSetRequest {
  targetHash: Buffer;
  excluded: Set<string>;
  attempts: number;
  createdAt: number;
  candidateFloodfills: string[];
  eciesTags: Set<string>;
  retryTimer: NodeJS.Timeout | null;
}

interface PendingEciesReply {
  sessionKey: Buffer;
  targetHash: string;
  createdAt: number;
}

const MAX_LEASESET_FLOODFILLS_PER_REQUEST = 7;
const LEASESET_REQUEST_TIMEOUT_MS = 15000;
const LEASESET_RETRY_DELAY_MS = 2500;
const ECIES_REPLY_TTL_MS = 5 * 60 * 1000;

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
  private netDbRequests: NetDbRequests;
  private options: I2PRouterOptions;
  private stats: RouterStats;
  private running = false;
  private maintenanceInterval: NodeJS.Timeout | null = null;
  // I2P-spec identity + RouterInfo (wire format) used by NTCP2/SSU2 and for interoperability.
  private identityEx: IdentityExBuildResult | null = null;
  private wireRouterInfo: Buffer | null = null;
  private ntcp2PublishedIV: Buffer | null = null;
  private pendingLeaseSetRequests: Map<string, PendingLeaseSetRequest> = new Map();
  private pendingEciesReplies: Map<string, PendingEciesReply> = new Map();

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
    this.netDbRequests = new NetDbRequests();
    
    this.setupNetDbListeners();
    this.setupNetDbRequestListeners();
    this.setupLogging();
  }

  private setupNetDbListeners(): void {
    // Listen for new router infos and add to peer profiles
    this.netDb.on('routerInfoStored', ({ hash, routerInfo }: { hash: Buffer; routerInfo: RouterInfo }) => {
      logger.debug(`New router info stored: ${hash.toString('hex').slice(0, 16)}...`, undefined, 'Router');
      
      // Add to peer profiles
      this.peerProfiles.addPeer(routerInfo);
      
      // Complete any pending request for this router
      this.netDbRequests.requestComplete(hash, true);
      
      // Update stats
      this.stats.knownPeers = this.netDb.getRouterInfoCount();
      this.stats.floodfillPeers = this.netDb.getFloodfillCount();

      const storedHex = hash.toString('hex');
      for (const req of this.pendingLeaseSetRequests.values()) {
        if (req.candidateFloodfills.includes(storedHex)) {
          this.tryNextLeaseSetLookup(req.targetHash);
        }
      }
    });

    // Forward leaseSetStored so callers can subscribe directly on the router
    this.netDb.on('leaseSetStored', (evt: { hash: Buffer; leaseSet: LeaseSet }) => {
      this.emit('leaseSetStored', evt);
    });

    // Listen for exploratory lookups and trigger DatabaseLookup messages
    this.netDb.on('exploratoryLookup', ({ targetHash, floodfill }: { targetHash: Buffer; floodfill: RouterInfo }) => {
      logger.debug(
        `Exploratory lookup for ${targetHash.toString('hex').slice(0, 16)}... via ${floodfill.getRouterHash().toString('hex').slice(0, 16)}...`,
        undefined,
        'Router'
      );

      // Track the exploratory request
      this.netDbRequests.createRequest(targetHash, true);

      // Fire and forget: connect to the floodfill over NTCP2 and send a DatabaseLookup
      this.sendExploratoryLookup(targetHash, floodfill).catch((err) => {
        logger.warn('Failed exploratory lookup send', { error: (err as Error).message }, 'Router');
      });
    });

    // Listen for LeaseSet lookup requests
    this.netDb.on('leaseSetLookup', ({ targetHash, floodfill }: { targetHash: Buffer; floodfill: RouterInfo }) => {
      logger.debug(
        `LeaseSet lookup for ${targetHash.toString('hex').slice(0, 16)}... via ${floodfill.getRouterHash().toString('hex').slice(0, 16)}...`,
        undefined,
        'Router'
      );
      this.sendLeaseSetLookup(targetHash, floodfill).catch((err) => {
        logger.debug(`LeaseSet lookup failed: ${(err as Error).message}`, undefined, 'Router');
      });
    });
  }

  /**
   * Wire up NetDbRequests events to perform actual network lookups.
   */
  private setupNetDbRequestListeners(): void {
    // When NetDbRequests wants to request a new/unknown router's info
    this.netDbRequests.on('requestRouter', (hash: Buffer) => {
      const existing = this.netDb.lookupRouterInfo(hash);
      if (existing) {
        // Already known — skip
        return;
      }
      if (this.netDbRequests.hasRequest(hash)) {
        // Already being requested
        return;
      }

      const req = this.netDbRequests.createRequest(hash, false);
      if (req) {
        this.sendNextLookupRequest(req).catch((err) => {
          logger.debug(`requestRouter lookup failed: ${(err as Error).message}`, undefined, 'NetDbReq');
        });
      }
    });

    // When NetDbRequests wants to retry / send next attempt for a request
    this.netDbRequests.on('sendNextRequest', (req: PendingRequest) => {
      this.sendNextLookupRequest(req).catch((err) => {
        logger.debug(`sendNextRequest failed: ${(err as Error).message}`, undefined, 'NetDbReq');
      });
    });
  }

  /**
   * Send the next DatabaseLookup for a pending request to the closest
   * non-excluded floodfill.
   */
  private async sendNextLookupRequest(req: PendingRequest): Promise<void> {
    const floodfills = this.netDb.findClosestFloodfills(req.destination, 5);
    // Pick the first floodfill not yet excluded
    const ff = floodfills.find(f => !req.excludedPeers.has(f.getRouterHash().toString('hex')));
    if (!ff) {
      logger.debug('No more floodfills for lookup', undefined, 'NetDbReq');
      this.netDbRequests.requestComplete(req.destination, false);
      return;
    }

    const lookupType = req.isExploratory ? 3 : 2; // 3=exploratory, 2=routerInfo
    this.netDbRequests.recordAttempt(req.destination, ff.getRouterHash());
    await this.sendDatabaseLookup(req.destination, ff, lookupType as 0 | 1 | 2 | 3);
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
      // Connectivity failures (timeout, RST, peer close) are expected during bootstrapping
      const msg = error?.message ?? '';
      const isExpectedNetworkError =
        msg === 'connect timeout' ||
        msg.includes('ECONNRESET') ||
        msg.includes('ECONNREFUSED') ||
        msg.includes('socket closed before handshake');
      if (isExpectedNetworkError) {
        logger.warn(`${transport} connection failed`, { error: msg }, transport);
      } else {
        logger.error(`Error in ${transport}`, { message: msg, stack: error.stack }, transport);
      }
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
      this.netDbRequests.start();
      
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

    this.netDbRequests?.stop();
    this.netDb?.stop();
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

    // For outbound-only (unpublished) routers, the NTCP2 address in the RI
    // must contain ONLY s, v, and caps -- NO host, port, or i.
    // If i is present, i2pd treats the address as "published" and checks
    // that our endpoint IP matches the RI host.  With 0.0.0.0 that always
    // fails → eNTCP2Banned.  See NTCP2 spec "Unpublished NTCP2 Address".
    const isPublished = host !== '0.0.0.0' && host !== '::' && ntcp2Port > 0;

    let ntcp2Opts: Record<string, string>;
    if (isPublished) {
      ntcp2Opts = makeNtcp2PublishedOptions({
        host,
        port: ntcp2Port,
        staticKey: this.identity!.identity.encryptionPublicKey,
        ivB64: i2pBase64Encode(publishedIV),
        v: '2',
        caps
      });
    } else {
      // Unpublished: only s and v (and caps for capability advertisement)
      ntcp2Opts = {
        s: i2pBase64Encode(Buffer.from(this.identity!.identity.encryptionPublicKey)),
        v: '2',
      };
      // Advertise IPv4 capability so remote peers know we support v4
      const capStr = caps.includes('4') || !caps.includes('6') ? '4' : '6';
      ntcp2Opts.caps = capStr;
    }

    const addressesWire = [
      {
        transportStyle: 'NTCP2',
        cost: isPublished ? 3 : 14,
        dateMs: 0, // no expiration
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

    this.routerInfo!.setWireFormatData(this.wireRouterInfo);
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
      connectTimeoutMs: 5000
    });

    this.ntcp2.on('message', ({ sessionId, data }) => {
      this.handleTransportMessage(sessionId, data);
    });

    this.ntcp2.on('error', (err) => {
      // Normalize NTCP2 error so logger sees the real Error object.
      const wrapped = (err as any) && (err as any).error ? (err as any).error : err;
      this.emit('error', { transport: 'NTCP2', error: wrapped });
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
      case I2NPMessageType.GARLIC:
        this.handleGarlic(sessionId, message);
        break;
      case I2NPMessageType.TUNNEL_GATEWAY:
      case I2NPMessageType.TUNNEL_DATA:
        this.handleTunnelMessage(sessionId, message);
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
    let replyTunnelId = 0;
    let _replyGateway: Buffer | null = null;
    if (replyToken > 0) {
      if (buf.length < offset + 4 + 32) return;
      replyTunnelId = buf.readUInt32BE(offset);
      offset += 4;
      _replyGateway = buf.subarray(offset, offset + 32);
      offset += 32;

      // Send DeliveryStatus reply (per i2pd HandleDatabaseStoreMsg)
      if (replyToken !== 0xFFFFFFFF && this.ntcp2) {
        const deliveryStatus = I2NPMessages.createDeliveryStatus(replyToken, Date.now());
        const dsWire = I2NPMessages.serializeMessage(deliveryStatus);
        if (replyTunnelId === 0) {
          // Direct reply to the gateway router from DatabaseStore fields.
          const replySessionId = _replyGateway ? this.ntcp2.findSessionIdByRouterHash(_replyGateway) : null;
          if (replySessionId) {
            this.ntcp2.send(replySessionId, dsWire);
          } else {
            logger.debug('DatabaseStore: no established session to reply gateway; falling back to source session', undefined, 'Router');
            this.ntcp2.send(sessionId, dsWire);
          }
        } else {
          // Reply through tunnel — wrap in TunnelGateway
          // For now send directly to the session; full tunnel routing is TODO
          this.ntcp2.send(sessionId, dsWire);
        }
        this.stats.messagesSent++;
        this.stats.bytesSent += dsWire.length;
      }
    }

    const data = buf.subarray(offset);

    if (type === 0) {
      // RouterInfo — format: size(2) + gzip-compressed RouterInfo
      if (data.length < 2) return;
      const compressedSize = data.readUInt16BE(0);
      if (compressedSize > data.length - 2) {
        logger.warn(`DatabaseStore: compressed RI size ${compressedSize} exceeds remaining ${data.length - 2}`, undefined, 'Router');
        return;
      }
      const compressed = data.subarray(2, 2 + compressedSize);
      let uncompressed: Buffer;
      try {
        uncompressed = gunzipSync(compressed);
      } catch (err) {
        logger.warn(`DatabaseStore: gzip decompression failed: ${(err as Error).message}`, undefined, 'Router');
        return;
      }
      const routerInfo = parseI2PRouterInfo(uncompressed);
      if (routerInfo) {
        this.netDb.storeRouterInfo(routerInfo);
        logger.debug(
          `DatabaseStore (RouterInfo) for ${key.toString('hex').slice(0, 16)}...`,
          undefined,
          'Router'
        );
      } else {
        logger.warn('Failed to deserialize RouterInfo from DatabaseStore (I2P parse failed)', undefined, 'Router');
      }
    } else if (type === 1) {
      // LeaseSet (LS1) — standard I2P LeaseSet wire format
      const leaseSet = parseLeaseSetLS1(data, key);

      if (leaseSet) {
        this.netDb.storeLeaseSet(leaseSet);
        this.clearPendingLeaseSetRequest(key.toString('hex'));
        logger.debug(
          `DatabaseStore (LS1) for ${key.toString('hex').slice(0, 16)}...`,
          undefined,
          'Router'
        );
      } else {
        logger.warn('Failed to parse LeaseSet (LS1) from DatabaseStore', undefined, 'Router');
      }
    } else if (type === 3) {
      // Standard LeaseSet2 (LS2) wire format
      const leaseSet = parseLeaseSetLS2(data, key);

      if (leaseSet) {
        this.netDb.storeLeaseSet(leaseSet);
        this.clearPendingLeaseSetRequest(key.toString('hex'));
        logger.debug(
          `DatabaseStore (LS2) for ${key.toString('hex').slice(0, 16)}...`,
          undefined,
          'Router'
        );
      } else {
        logger.warn('Failed to parse LeaseSet2 (LS2) from DatabaseStore', undefined, 'Router');
      }
    } else if (type === 5) {
      // Encrypted LeaseSet2 — not yet implemented
      logger.debug(`DatabaseStore: Encrypted LeaseSet2 for ${key.toString('hex').slice(0, 16)}... (not implemented)`, undefined, 'Router');
    } else if (type === 7) {
      // Meta LeaseSet2 — not yet implemented
      logger.debug(`DatabaseStore: Meta LeaseSet2 for ${key.toString('hex').slice(0, 16)}... (not implemented)`, undefined, 'Router');
    } else {
      logger.debug(`DatabaseStore with unsupported type=${type}`, undefined, 'Router');
    }

    this.emit('databaseStore', { sessionId, message });
  }

  private handleDatabaseLookup(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    // Payload (subset of spec): key(32) | from(32) | flags(1) | [replyTunnelId(4) if delivery flag] | size(2) | excluded[size*32]
    const buf = message.payload;
    if (buf.length < 32 + 32 + 1 + 2) return;

    const key = buf.subarray(0, 32);
    const fromHash = buf.subarray(32, 64);
    const flags = buf.readUInt8(64);

    const hasDeliveryFlag = (flags & 0x01) !== 0;
    const hasEciesFlag = (flags & 0x10) !== 0;
    let excludedOffset = 65;
    let replyTunnelId: number | undefined;
    if (hasDeliveryFlag) {
      if (buf.length < excludedOffset + 4) return;
      replyTunnelId = buf.readUInt32BE(excludedOffset);
      excludedOffset += 4;
    }

    if (buf.length < excludedOffset + 2) return;
    const numExcluded = buf.readUInt16BE(excludedOffset);
    excludedOffset += 2;

    const lookupTypeBits = (flags >> 2) & 0x03;
    // 0=normal, 1=leaseSet, 2=routerInfo, 3=exploratory
    const lookupType = lookupTypeBits;

    logger.debug(
      `DatabaseLookup received for ${key.toString('hex').slice(0, 16)}... (type=${lookupType}, excluded=${numExcluded})`,
      undefined,
      'Router'
    );

    // Build excluded set for search reply
    const excludedSet = new Set<string>();
    for (let i = 0; i < numExcluded && excludedOffset + 32 <= buf.length; i++) {
      excludedSet.add(buf.subarray(excludedOffset, excludedOffset + 32).toString('hex'));
      excludedOffset += 32;
    }

    let eciesSessionKey: Buffer | undefined;
    let eciesSessionTag: Buffer | undefined;
    if (hasEciesFlag) {
      if (buf.length < excludedOffset + 32 + 1 + 8) return;
      eciesSessionKey = buf.subarray(excludedOffset, excludedOffset + 32);
      excludedOffset += 32;
      const numTags = buf.readUInt8(excludedOffset);
      excludedOffset += 1;
      if (numTags < 1 || buf.length < excludedOffset + 8) return;
      eciesSessionTag = buf.subarray(excludedOffset, excludedOffset + 8);
      excludedOffset += 8;
    }

    let replied = false;

    // Try RouterInfo lookup (for normal or routerInfo type)
    if (lookupType === 0 || lookupType === 2) {
      const ri = this.netDb.lookupRouterInfo(key);
      if (ri && this.ntcp2) {
        const riWire = ri.getWireFormatData();
        const fallbackLocalWire = this.routerInfo && ri.getRouterHash().equals(this.routerInfo.getRouterHash())
          ? this.wireRouterInfo
          : null;
        const replyRiWire = riWire ?? fallbackLocalWire;

        if (!replyRiWire) {
          logger.warn(
            `DatabaseLookup: RouterInfo found for ${key.toString('hex').slice(0, 16)}... but no I2P wire bytes available; skipping DatabaseStore reply`,
            undefined,
            'Router'
          );
        } else {
          const compressed = gzipSync(replyRiWire);
          if (compressed.length > 0xFFFF) {
            logger.warn(`DatabaseLookup: compressed RouterInfo too large (${compressed.length} bytes)`, undefined, 'Router');
          } else {
            const size = Buffer.alloc(2);
            size.writeUInt16BE(compressed.length);
            const data = Buffer.concat([size, compressed]);
            const ourHash = this.routerInfo!.getRouterHash();
            const storeMsg = I2NPMessages.createDatabaseStore(key, data, 0, ourHash);
            this.sendDatabaseLookupReply(sessionId, fromHash, replyTunnelId, storeMsg, eciesSessionKey, eciesSessionTag);
            replied = true;
          }
        }
      }
    }

    // Try LeaseSet lookup (for normal or leaseSet type)
    if (!replied && (lookupType === 0 || lookupType === 1)) {
      const ls = this.netDb.lookupLeaseSet(key);
      if (ls && this.ntcp2) {
        const lsData = ls.getWireFormatData();
        if (!lsData) {
          logger.debug('DatabaseLookup: LeaseSet found but original I2P wire bytes unavailable; skipping DatabaseStore reply', undefined, 'Router');
        } else {
          const ourHash = this.routerInfo!.getRouterHash();
          const storeMsg = I2NPMessages.createDatabaseStore(key, lsData, 0, ourHash, ls.storeType);
          this.sendDatabaseLookupReply(sessionId, fromHash, replyTunnelId, storeMsg, eciesSessionKey, eciesSessionTag);
          replied = true;
        }
      }
    }

    // Exploratory: return closest non-floodfill peers (per i2pd)
    // For any lookup type: if we couldn't answer, send DatabaseSearchReply with closest floodfills
    if (!replied && this.ntcp2) {
      const closestFloodfills = this.netDb.findClosestFloodfills(key, 3);
      const routerHashes = closestFloodfills
        .filter(ff => !excludedSet.has(ff.getRouterHash().toString('hex')))
        .map(ff => ff.getRouterHash());
      const ourHash = this.routerInfo!.getRouterHash();
      const searchReply = I2NPMessages.createDatabaseSearchReply(key, routerHashes, ourHash);
      this.sendDatabaseLookupReply(sessionId, fromHash, replyTunnelId, searchReply, eciesSessionKey, eciesSessionTag);
    }

    this.emit('databaseLookup', { sessionId, message });
  }

  private handleDatabaseSearchReply(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    const parsed = I2NPMessages.parseDatabaseSearchReply(message.payload);
    if (!parsed) {
      logger.debug('Failed to parse DatabaseSearchReply', undefined, 'Router');
      return;
    }

    const { key, routerHashes, from: _from } = parsed;
    logger.debug(
      `DatabaseSearchReply for ${key.toString('hex').slice(0, 16)}... with ${routerHashes.length} peers`,
      undefined,
      'Router'
    );

    // Determine if this was an exploratory request
    const pendingReq = this.netDbRequests.findRequest(key);
    const isExploratory = pendingReq ? pendingReq.isExploratory : false;

    // Delegate to NetDbRequests which handles retry logic and discovered router scheduling
    this.netDbRequests.handleSearchReply(key, routerHashes, isExploratory);

    // LeaseSet iterative follow-up (i2pd-style): keep querying next closest floodfills.
    if (this.pendingLeaseSetRequests.has(key.toString('hex'))) {
      const req = this.pendingLeaseSetRequests.get(key.toString('hex'))!;
      for (const h of routerHashes) {
        const routerHex = h.toString('hex');
        if (!req.excluded.has(routerHex) && !req.candidateFloodfills.includes(routerHex)) {
          req.candidateFloodfills.push(routerHex);
        }
      }
      this.tryNextLeaseSetLookup(key);
    }

    this.emit('databaseSearchReply', { sessionId, message });
  }

  private handleDeliveryStatus(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('deliveryStatus', { sessionId, message });
  }

  private handleGarlic(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    const parsed = I2NPMessages.parseGarlicOuterMessage(message.payload);
    if (!parsed || parsed.body.length < 8 + 16) {
      logger.debug('Failed to parse Garlic message', undefined, 'Router');
      return;
    }

    let plaintext: Buffer | null = null;
    let usedTag: string | null = null;

    const possibleTag = parsed.body.subarray(0, 8);
    const pending = this.pendingEciesReplies.get(possibleTag.toString('hex'));
    if (pending) {
      try {
        plaintext = Crypto.decryptTaggedGarlicReply(
          pending.sessionKey,
          possibleTag,
          parsed.body.subarray(8)
        );
        usedTag = possibleTag.toString('hex');
      } catch (err) {
        logger.debug(`Tagged garlic decrypt failed: ${(err as Error).message}`, undefined, 'Router');
      }
    }

    if (!plaintext && this.identity) {
      if (parsed.body.length < 32 + 16) {
        logger.debug('Garlic body too short for router-context decrypt', undefined, 'Router');
        return;
      }
      try {
        plaintext = Crypto.decryptNoiseNGarlicReply(
          this.identity.encryptionPrivateKey,
          this.identity.identity.encryptionPublicKey,
          parsed.body.subarray(0, 32),
          parsed.body.subarray(32)
        );
      } catch (err) {
        logger.debug(`Router-context garlic decrypt failed: ${(err as Error).message}`, undefined, 'Router');
        return;
      }
    }

    if (!plaintext) {
      logger.debug('Garlic message could not be decrypted', undefined, 'Router');
      return;
    }

    if (usedTag) {
      this.clearPendingEciesReply(usedTag);
    }

    const cloves = I2NPMessages.parseGarlicCloveMessages(plaintext);
    if (!cloves) {
      logger.debug('Failed to parse garlic cloves', undefined, 'Router');
      return;
    }

    for (const clove of cloves) {
      this.handleI2NPMessage(sessionId, clove.message);
    }
  }

  private handleTunnelMessage(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    if (message.payload.length < 5 || !this.tunnelManager) {
      return;
    }

    const tunnelId = message.payload.readUInt32BE(0);
    const tunnel = this.tunnelManager.getTunnel(tunnelId);
    if (!tunnel || tunnel.type !== TunnelType.INBOUND || tunnel.hops.length !== 0) {
      return;
    }

    try {
      const inner = I2NPMessages.parseMessage(message.payload.subarray(4));
      this.handleI2NPMessage(sessionId, inner);
    } catch (err) {
      logger.debug(`Failed to unwrap zero-hop tunnel message: ${(err as Error).message}`, undefined, 'Router');
    }
  }

  private handleTunnelBuild(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('tunnelBuild', { sessionId, message });
  }

  private handleTunnelBuildReply(sessionId: string, message: ReturnType<typeof I2NPMessages.parseMessage>): void {
    this.emit('tunnelBuildReply', { sessionId, message });
  }


  /**
   * Pick a usable NTCP/NTCP2 endpoint from RouterInfo.
   * Supports IPv4 and IPv6 literals (bracketed or plain) and requires s/i keys.
   */
  private getNtcpEndpoint(routerInfo: RouterInfo): { host: string; port: number } | null {
    const addr = routerInfo.addresses.find((a) => {
      const styleOk = a.transportStyle.toUpperCase().startsWith('NTCP');
      const host = a.options.host;
      const hasKeys = a.options.s && a.options.i && a.options.port;
      return Boolean(styleOk && host && hasKeys);
    });
    if (!addr?.options.host || !addr.options.port) return null;

    const rawHost = addr.options.host.trim();
    const host = rawHost.startsWith('[') && rawHost.endsWith(']')
      ? rawHost.slice(1, -1)
      : rawHost;

    const port = parseInt(addr.options.port, 10);
    if (!host || Number.isNaN(port) || port <= 0 || port > 65535) {
      return null;
    }

    return { host, port };
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
    this.cleanupPendingLeaseSetRequests();
    this.cleanupPendingEciesReplies();

    if (this.tunnelManager) {
      this.tunnelManager.cleanupExpiredTunnels();

      // Ensure at least one inbound and one outbound tunnel exist.
      if (this.tunnelManager.getInboundTunnels().length === 0) {
        this.tunnelManager.buildTunnel(TunnelType.INBOUND, 0).catch(() => {
          /* ignore for now */
        });
      }
      if (this.tunnelManager.getOutboundTunnels().length === 0) {
        this.tunnelManager.buildTunnel(TunnelType.OUTBOUND, 0).catch(() => {
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
      3, // lookup type 3 = Exploratory (peer discovery mode; floodfills return closest known routers)
      []
    );
    const wire = I2NPMessages.serializeMessage(msg);

    // 1) Try NTCP2 if present with full keys (host/port/s/i).
    if (this.ntcp2) {
      const endpoint = this.getNtcpEndpoint(floodfill);
      if (endpoint) {
        try {
          await this.ntcp2.connect(endpoint.host, endpoint.port, floodfill);
          const sessionId = `${endpoint.host}:${endpoint.port}`;
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
      } else {
        logger.debug('No NTCP/NTCP2 address with s/i found for floodfill', undefined, 'Router');
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

    let req = this.pendingLeaseSetRequests.get(targetHex);
    if (!req) {
      req = this.createPendingLeaseSetRequest(hash, timeoutMs);
      this.pendingLeaseSetRequests.set(targetHex, req);
    }

    this.tryNextLeaseSetLookup(hash);

    return new Promise<LeaseSet | null>((resolve) => {
      const onStored = ({ hash: hs, leaseSet }: { hash: Buffer; leaseSet: LeaseSet }) => {
        if (hs.toString('hex') === targetHex) {
          cleanup();
          resolve(leaseSet);
        }
      };
      const onTimeout = () => {
        cleanup();
        this.clearPendingLeaseSetRequest(targetHex);
        resolve(null);
      };
      const cleanup = () => {
        this.netDb.off('leaseSetStored', onStored as any);
      };
      this.netDb.on('leaseSetStored', onStored as any);
      setTimeout(onTimeout, timeoutMs);
    });
  }

  private async sendLeaseSetLookup(targetHash: Buffer, floodfill: RouterInfo): Promise<void> {
    const keyHex = targetHash.toString('hex');
    let req = this.pendingLeaseSetRequests.get(keyHex);
    if (!req) {
      req = this.createPendingLeaseSetRequest(targetHash);
      this.pendingLeaseSetRequests.set(keyHex, req);
    }
    const floodfillHash = floodfill.getRouterHash().toString('hex');
    if (req.excluded.has(floodfillHash)) {
      return;
    }
    req.excluded.add(floodfillHash);
    req.candidateFloodfills = req.candidateFloodfills.filter((candidate) => candidate !== floodfillHash);
    req.attempts++;
    this.scheduleLeaseSetRetry(req);
    await this.sendDatabaseLookup(targetHash, floodfill, 1, Array.from(req.excluded, (v) => Buffer.from(v, 'hex')), req);
  }

  private tryNextLeaseSetLookup(targetHash: Buffer): void {
    const keyHex = targetHash.toString('hex');
    const req = this.pendingLeaseSetRequests.get(keyHex);
    if (!req) return;
    if (this.netDb.lookupLeaseSet(targetHash)) {
      this.clearPendingLeaseSetRequest(keyHex);
      return;
    }
    if (Date.now() - req.createdAt >= LEASESET_REQUEST_TIMEOUT_MS || req.attempts >= MAX_LEASESET_FLOODFILLS_PER_REQUEST) {
      this.clearPendingLeaseSetRequest(keyHex);
      return;
    }

    let next: RouterInfo | undefined;
    while (req.candidateFloodfills.length > 0 && !next) {
      const candidateHash = req.candidateFloodfills.shift()!;
      if (req.excluded.has(candidateHash)) continue;
      const candidateInfo = this.netDb.lookupRouterInfo(Buffer.from(candidateHash, 'hex'));
      if (candidateInfo) {
        next = candidateInfo;
      }
    }

    if (!next) {
      next = this.netDb
        .findClosestFloodfills(targetHash, MAX_LEASESET_FLOODFILLS_PER_REQUEST)
        .find((ff) => !req.excluded.has(ff.getRouterHash().toString('hex')));
    }

    if (!next) {
      this.clearPendingLeaseSetRequest(keyHex);
      return;
    }
    this.sendLeaseSetLookup(targetHash, next).catch(() => undefined);
  }

  /**
   * Generic DatabaseLookup sender used for exploratory (routerInfo) and targeted (LeaseSet) lookups.
   */
  private async sendDatabaseLookup(
    targetHash: Buffer,
    floodfill: RouterInfo,
    lookupType: 0 | 1 | 2 | 3,
    excludedPeers: Buffer[] = [],
    leaseSetRequest?: PendingLeaseSetRequest
  ): Promise<void> {
    // Prefer NTCP2/NTCP with full keys.
    if (this.ntcp2) {
      const endpoint = this.getNtcpEndpoint(floodfill);
      if (endpoint) {
        const fromHash = this.routerInfo!.getRouterHash();
        const opts: {
          replyTunnelId?: number;
          eciesSessionKey?: Buffer;
          eciesSessionTag?: Buffer;
        } = {};
        let lookupFromHash = fromHash;

        if (lookupType === 1) {
          const replyTunnel = await this.ensureLeaseSetReplyTunnel();
          if (!replyTunnel) {
            throw new Error('No inbound tunnel available for LeaseSet lookup reply');
          }
          lookupFromHash = replyTunnel.gatewayHash;
          opts.replyTunnelId = replyTunnel.tunnelId;
          opts.eciesSessionKey = Buffer.from(Crypto.randomBytes(32));
          opts.eciesSessionTag = Buffer.from(Crypto.randomBytes(8));
          const tagHex = opts.eciesSessionTag.toString('hex');
          this.pendingEciesReplies.set(tagHex, {
            sessionKey: opts.eciesSessionKey,
            targetHash: targetHash.toString('hex'),
            createdAt: Date.now()
          });
          leaseSetRequest?.eciesTags.add(tagHex);
        }

        const msg = I2NPMessages.createDatabaseLookup(targetHash, lookupFromHash, lookupType, excludedPeers, opts);
        const wire = I2NPMessages.serializeMessage(msg);
        await this.ntcp2.connect(endpoint.host, endpoint.port, floodfill);
        const sessionId = `${endpoint.host}:${endpoint.port}`;
        this.ntcp2.send(sessionId, wire);
        this.stats.messagesSent++;
        this.stats.bytesSent += wire.length;
        return;
      }
    }

    // SSU2 path intentionally disabled while transport is MVP-only and not
    // interoperable with stock routers yet.
  }

  private sendDatabaseLookupReply(
    sessionId: string,
    replyGatewayHash: Buffer,
    replyTunnelId: number | undefined,
    innerMessage: ReturnType<typeof I2NPMessages.createDatabaseStore> | ReturnType<typeof I2NPMessages.createDatabaseSearchReply>,
    eciesSessionKey?: Buffer,
    eciesSessionTag?: Buffer
  ): void {
    if (!this.ntcp2) return;

    let replyMessage = innerMessage;
    if (eciesSessionKey && eciesSessionTag) {
      const garlicPayload = I2NPMessages.createGarlicClovePayload([innerMessage]);
      const ciphertext = Crypto.encryptTaggedGarlicReply(eciesSessionKey, eciesSessionTag, garlicPayload);
      const body = Buffer.concat([eciesSessionTag, ciphertext]);
      const lengthBuf = Buffer.alloc(4);
      lengthBuf.writeUInt32BE(body.length);
      replyMessage = {
        type: I2NPMessageType.GARLIC,
        uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
        expiration: Date.now() + 30000,
        payload: Buffer.concat([lengthBuf, body])
      };
    }

    let wire = I2NPMessages.serializeMessage(replyMessage);
    if (replyTunnelId && replyTunnelId > 0) {
      const tunnelHeader = Buffer.alloc(4);
      tunnelHeader.writeUInt32BE(replyTunnelId >>> 0);
      wire = I2NPMessages.serializeMessage({
        type: I2NPMessageType.TUNNEL_GATEWAY,
        uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
        expiration: Date.now() + 30000,
        payload: Buffer.concat([tunnelHeader, wire])
      });
    }

    const gatewaySessionId = this.ntcp2.findSessionIdByRouterHash(replyGatewayHash);
    this.ntcp2.send(gatewaySessionId ?? sessionId, wire);
    this.stats.messagesSent++;
    this.stats.bytesSent += wire.length;
  }

  private createPendingLeaseSetRequest(targetHash: Buffer, timeoutMs = LEASESET_REQUEST_TIMEOUT_MS): PendingLeaseSetRequest {
    return {
      targetHash: Buffer.from(targetHash),
      excluded: new Set(),
      attempts: 0,
      createdAt: Date.now(),
      candidateFloodfills: [],
      eciesTags: new Set(),
      retryTimer: setTimeout(() => {
        this.clearPendingLeaseSetRequest(targetHash.toString('hex'));
      }, timeoutMs)
    };
  }

  private clearPendingLeaseSetRequest(targetHex: string): void {
    const req = this.pendingLeaseSetRequests.get(targetHex);
    if (!req) return;
    if (req.retryTimer) {
      clearTimeout(req.retryTimer);
    }
    for (const tagHex of req.eciesTags) {
      this.clearPendingEciesReply(tagHex);
    }
    this.pendingLeaseSetRequests.delete(targetHex);
  }

  private scheduleLeaseSetRetry(req: PendingLeaseSetRequest): void {
    if (req.retryTimer) {
      clearTimeout(req.retryTimer);
    }
    req.retryTimer = setTimeout(() => {
      this.tryNextLeaseSetLookup(req.targetHash);
    }, LEASESET_RETRY_DELAY_MS);
  }

  private cleanupPendingLeaseSetRequests(): void {
    const now = Date.now();
    for (const [targetHex, req] of this.pendingLeaseSetRequests.entries()) {
      if (now - req.createdAt >= LEASESET_REQUEST_TIMEOUT_MS || req.attempts >= MAX_LEASESET_FLOODFILLS_PER_REQUEST) {
        this.clearPendingLeaseSetRequest(targetHex);
      }
    }
  }

  private clearPendingEciesReply(tagHex: string): void {
    this.pendingEciesReplies.delete(tagHex);
    for (const req of this.pendingLeaseSetRequests.values()) {
      req.eciesTags.delete(tagHex);
    }
  }

  private cleanupPendingEciesReplies(): void {
    const now = Date.now();
    for (const [tagHex, pending] of this.pendingEciesReplies.entries()) {
      if (now - pending.createdAt >= ECIES_REPLY_TTL_MS) {
        this.clearPendingEciesReply(tagHex);
      }
    }
  }

  private async ensureLeaseSetReplyTunnel(): Promise<{ tunnelId: number; gatewayHash: Buffer } | null> {
    if (!this.tunnelManager || !this.routerInfo) return null;

    let tunnel = this.tunnelManager
      .getInboundTunnels()
      .find((candidate) => candidate.hops.length === 0 && candidate.gateway.getRouterHash().equals(this.routerInfo!.getRouterHash()));

    if (!tunnel) {
      tunnel = (await this.tunnelManager.buildTunnel(TunnelType.INBOUND, 0)) ?? undefined;
    }

    if (!tunnel) return null;

    return {
      tunnelId: tunnel.id,
      gatewayHash: tunnel.gateway.getRouterHash()
    };
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

import { createSocket, Socket, RemoteInfo } from 'dgram';
import { AddressInfo } from 'net';
import { EventEmitter } from 'events';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';
import { i2pBase64Decode } from '../i2p/base64.js';
import { logger } from '../utils/logger.js';

const enum SSU2MessageType {
  SessionRequest = 0,
  SessionCreated = 1,
  NewToken = 3,
  SessionConfirmed = 4,
  Ack = 5,
  Data = 6,
  Nack = 7
}

const HANDSHAKE_TIMEOUT_MS = 12000;
const HANDSHAKE_RETRY_DELAYS_MS = [1000, 2000, 3000, 4000, 5000];
const DATA_RETRANSMIT_MS = 800;
const MAX_DATA_RETRANSMITS = 2;
const PENDING_PACKET_TTL_MS = 5000;
const MAX_PENDING_DATA = 256;
const KEY_ROTATION_INTERVAL = 1024;
const REPLAY_WINDOW = 128;
const MAX_ACTIVE_SESSIONS = 1024;
const MAX_SERVER_TOKENS = 2048;
const SESSION_IDLE_MS = 30_000;
const ESTABLISHED_IDLE_MS = 10 * 60_000;
const CLEANUP_INTERVAL_MS = 10_000;
const KEY_DEBUG = process.env.TRANSPORT_KEY_DEBUG === '1' || process.env.SSU2_KEY_DEBUG === '1';

function hex(value?: Uint8Array | Buffer | null): string {
  if (!value) return '';
  return Buffer.from(value).toString('hex');
}

function logSsu2Keys(stage: string, data: Record<string, Uint8Array | Buffer | null | undefined>): void {
  if (!KEY_DEBUG) return;
  const payload: Record<string, string> = {};
  for (const [key, value] of Object.entries(data)) {
    payload[key] = hex(value as Uint8Array | Buffer | null | undefined);
  }
  logger.info(`SSU2 key dump: ${stage}`, payload, 'SSU2');
}

export interface SSU2Options {
  host?: string;
  port?: number;
  staticPrivateKey?: Uint8Array;
  staticPublicKey?: Uint8Array;
  netId?: number;
}

function normalizeHost(host?: string): string | undefined {
  if (!host) return undefined;
  if (host.startsWith('[') && host.endsWith(']')) {
    return host.slice(1, -1).toLowerCase();
  }
  return host.toLowerCase();
}

type SessionState = 'init' | 'request_sent' | 'created_sent' | 'established';

interface HandshakeState {
  k: Uint8Array | null;
  h: Uint8Array;
  ePriv?: Uint8Array;
  ePub?: Uint8Array;
  rs?: Uint8Array;
  timeoutAt?: number;
}

interface SentPacket {
  raw: Buffer;
  retransmits: number;
  createdAt: number;
}

export interface SSU2Session {
  address: string;
  port: number;
  state: SessionState;
  isInitiator: boolean;
  connIdLocal: bigint;
  connIdRemote: bigint;
  hs: HandshakeState;
  sendKey?: Uint8Array;
  recvKey?: Uint8Array;
  sendNonce: number;
  recvNonce: number;
  sendEpoch: number;
  recvEpoch: number;
  token?: bigint;
  handshakeRetries: number;
  handshakeTimer?: NodeJS.Timeout;
  pendingData: Map<number, SentPacket>;
  receivedPackets: Set<number>;
  createdAt: number;
  lastActivity: number;
}

function writeSsu2Header(buf: Buffer, type: SSU2MessageType, connIdDest: bigint, connIdSrc: bigint): void {
  buf.writeUInt8(type, 0);
  buf.writeBigUInt64BE(connIdDest, 1);
  buf.writeBigUInt64BE(connIdSrc, 9);
}

function dumpSsu2HandshakeState(hs: HandshakeState): Record<string, string | number | null | undefined> {
  return {
    k: hex(hs.k),
    h: hex(hs.h),
    ePriv: hex(hs.ePriv),
    ePub: hex(hs.ePub),
    rs: hex(hs.rs),
    timeoutAt: hs.timeoutAt
  };
}

function dumpSentPacket(packet?: SentPacket): Record<string, string | number | undefined> {
  if (!packet) return {};
  return {
    raw: hex(packet.raw),
    retransmits: packet.retransmits,
    createdAt: packet.createdAt,
    rawLen: packet.raw.length
  };
}

function logSsu2InterfaceSnapshot(stage: string, sessionId: string, s: SSU2Session): void {
  if (!KEY_DEBUG) return;
  const pendingPreview = Array.from(s.pendingData.entries())
    .slice(0, 8)
    .map(([packetNumber, packet]) => ({
      packetNumber,
      ...dumpSentPacket(packet)
    }));

  logger.info(
    `SSU2 interface snapshot: ${stage}`,
    {
      sessionId,
      address: s.address,
      port: s.port,
      state: s.state,
      isInitiator: s.isInitiator,
      connIdLocal: s.connIdLocal.toString(),
      connIdRemote: s.connIdRemote.toString(),
      handshake: dumpSsu2HandshakeState(s.hs),
      sendKey: hex(s.sendKey),
      recvKey: hex(s.recvKey),
      sendNonce: s.sendNonce,
      recvNonce: s.recvNonce,
      sendEpoch: s.sendEpoch,
      recvEpoch: s.recvEpoch,
      token: s.token?.toString(),
      handshakeRetries: s.handshakeRetries,
      hasHandshakeTimer: !!s.handshakeTimer,
      pendingDataSize: s.pendingData.size,
      pendingDataPreview: pendingPreview,
      receivedPacketsSize: s.receivedPackets.size,
      receivedPacketsPreview: Array.from(s.receivedPackets).slice(0, 16),
      createdAt: s.createdAt,
      lastActivity: s.lastActivity
    },
    'SSU2'
  );
}

export class SSU2Transport extends EventEmitter {
  private socket: Socket | null = null;
  private sessions: Map<string, SSU2Session> = new Map();
  private serverTokens: Map<string, bigint> = new Map();
  private cleanupTimer: NodeJS.Timeout | null = null;
  private options: Required<Pick<SSU2Options, 'host' | 'port' | 'netId'>> & Omit<SSU2Options, 'host' | 'port' | 'netId'>;

  constructor(options: SSU2Options = {}) {
    super();
    this.options = {
      host: options.host ?? '0.0.0.0',
      port: options.port ?? 12346,
      netId: options.netId ?? 2,
      ...options
    };
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = createSocket('udp4');
      this.socket.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });
      this.socket.on('message', this.handleMessage.bind(this));
      this.socket.bind(this.options.port, this.options.host, () => {
        if (!this.cleanupTimer) {
          this.cleanupTimer = setInterval(() => this.pruneState(), CLEANUP_INTERVAL_MS);
        }
        this.emit('listening', { host: this.options.host, port: this.options.port });
        resolve();
      });
    });
  }

  stop(): void {
    if (this.socket) {
      this.socket.close();
      this.socket = null;
    }
    for (const s of this.sessions.values()) {
      if (s.handshakeTimer) clearTimeout(s.handshakeTimer);
    }
    this.sessions.clear();
    this.serverTokens.clear();
    if (this.cleanupTimer) {
      clearInterval(this.cleanupTimer);
      this.cleanupTimer = null;
    }
  }

  public getListeningAddress(): AddressInfo | null {
    if (!this.socket) return null;
    const addr = this.socket.address();
    return typeof addr === 'string' ? null : addr;
  }

  private sessionKey(address: string, port: number): string {
    return `${address}:${port}`;
  }

  async connect(host: string, port: number, remoteRouterInfo: RouterInfo, timeoutMsOverride?: number): Promise<void> {
    if (!this.options.staticPrivateKey || !this.options.staticPublicKey) {
      throw new Error('SSU2 static keys not configured');
    }

    logger.info('SSU2 connect attempt', { host, port }, 'SSU2');

    const id = this.sessionKey(host, port);
    if (this.sessions.get(id)?.state === 'established') {
      logger.debug('SSU2 session already established', { sessionId: id }, 'SSU2');
      return;
    }

    const hs: HandshakeState = initHandshake();
    const eph = Crypto.generateEphemeralKeyPair();
    hs.ePriv = eph.privateKey;
    hs.ePub = eph.publicKey;
    hs.rs = extractRemoteSsu2StaticKey(remoteRouterInfo, host, port);
    logSsu2Keys('connect-init', {
      localStaticPriv: this.options.staticPrivateKey,
      localStaticPub: this.options.staticPublicKey,
      remoteStaticPub: hs.rs,
      ePriv: hs.ePriv,
      ePub: hs.ePub
    });
    const handshakeTimeoutMs = Math.max(3000, timeoutMsOverride ?? HANDSHAKE_TIMEOUT_MS);
    hs.timeoutAt = Date.now() + handshakeTimeoutMs;

    const session: SSU2Session = {
      address: host,
      port,
      state: 'request_sent',
      isInitiator: true,
      connIdLocal: this.generateConnId(),
      connIdRemote: 0n,
      hs,
      sendNonce: 0,
      recvNonce: 0,
      sendEpoch: 0,
      recvEpoch: 0,
      handshakeRetries: 0,
      token: this.serverTokens.get(id),
      pendingData: new Map(),
      receivedPackets: new Set(),
      createdAt: Date.now(),
      lastActivity: Date.now()
    };

    this.sessions.set(id, session);
    logSsu2InterfaceSnapshot('connect-created', id, session);

    return new Promise((resolve, reject) => {
      let settled = false;
      const cleanup = () => {
        clearTimeout(timeout);
        this.off('established', onEstablished);
      };

      const fail = (err: Error) => {
        if (settled) return;
        settled = true;
        cleanup();
        if (session.handshakeTimer) {
          clearTimeout(session.handshakeTimer);
          session.handshakeTimer = undefined;
        }
        const current = this.sessions.get(id);
        if (current === session && current.state !== 'established') {
          this.sessions.delete(id);
        }
        reject(err);
      };

      const succeed = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve();
      };

      const onEstablished = ({ sessionId }: { sessionId: string }) => {
        if (sessionId === id) {
          succeed();
        }
      };

      const timeout = setTimeout(() => {
        logger.warn('SSU2 connect timeout', { host, port, sessionId: id }, 'SSU2');
        fail(new Error('SSU2 connect timeout'));
      }, handshakeTimeoutMs + 1000);

      this.on('established', onEstablished);

      this.sendHandshakeRequest(session).catch((err) => {
        fail(err instanceof Error ? err : new Error(String(err)));
      });
    });
  }

  send(sessionId: string, data: Buffer): void {
    const s = this.sessions.get(sessionId);
    if (!s || s.state !== 'established' || !s.sendKey || !this.socket) {
      logger.warn('SSU2 send failed: session not ready', { sessionId }, 'SSU2');
      return;
    }
    this.touchSession(s);

    logger.debug('SSU2 send data', { sessionId, size: data.length }, 'SSU2');

    const packetNumber = s.sendNonce;
    if (s.pendingData.size >= MAX_PENDING_DATA) {
      const oldest = s.pendingData.keys().next().value;
      if (oldest !== undefined) s.pendingData.delete(oldest);
    }
    const pkt = this.buildData(s, data);
    s.pendingData.set(packetNumber, { raw: pkt, retransmits: 0, createdAt: Date.now() });
    logSsu2InterfaceSnapshot('data-send-enqueue', sessionId, s);
    this.socket.send(pkt, s.port, s.address);
    setTimeout(() => this.retransmitIfUnacked(sessionId, packetNumber), DATA_RETRANSMIT_MS);
  }

  private retransmitIfUnacked(sessionId: string, packetNumber: number): void {
    const s = this.sessions.get(sessionId);
    if (!s || !this.socket) return;
    const pending = s.pendingData.get(packetNumber);
    if (!pending) return;
    if (Date.now() - pending.createdAt > PENDING_PACKET_TTL_MS) {
      s.pendingData.delete(packetNumber);
      return;
    }
    if (pending.retransmits >= MAX_DATA_RETRANSMITS) {
      s.pendingData.delete(packetNumber);
      return;
    }

    pending.retransmits++;
    this.touchSession(s);
    logSsu2InterfaceSnapshot('data-retransmit', sessionId, s);
    this.socket.send(pending.raw, s.port, s.address);
    setTimeout(() => this.retransmitIfUnacked(sessionId, packetNumber), DATA_RETRANSMIT_MS * 2);
  }

  private async sendRaw(buf: Buffer, host: string, port: number): Promise<void> {
    if (!this.socket) throw new Error('SSU2 socket not started');
    return new Promise((resolve, reject) => {
      this.socket!.send(buf, port, host, (err) => (err ? reject(err) : resolve()));
    });
  }

  private async sendHandshakeRequest(s: SSU2Session): Promise<void> {
    const req = this.buildSessionRequest(s);
    await this.sendRaw(req, s.address, s.port);
    this.scheduleHandshakeRetry(s);
  }

  private scheduleHandshakeRetry(s: SSU2Session): void {
    if (s.handshakeTimer) clearTimeout(s.handshakeTimer);
    if (s.state === 'established' || !s.hs.timeoutAt || Date.now() >= s.hs.timeoutAt) return;
    const delay = HANDSHAKE_RETRY_DELAYS_MS[Math.min(s.handshakeRetries, HANDSHAKE_RETRY_DELAYS_MS.length - 1)];
    s.handshakeTimer = setTimeout(() => {
      if (s.state === 'established' || Date.now() >= (s.hs.timeoutAt ?? 0)) return;
      s.handshakeRetries++;
      this.sendHandshakeRequest(s).catch((err) => {
        logger.warn(`SSU2 handshake retry send failed for ${s.address}:${s.port}`, { error: String(err) }, 'SSU2');
      });
    }, delay);
  }

  private handleMessage(msg: Buffer, rinfo: RemoteInfo): void {
    logger.debug('SSU2 received message', { from: `${rinfo.address}:${rinfo.port}`, size: msg.length }, 'SSU2');

    if (msg.length < 1 + 8 + 8) {
      logger.warn('SSU2 message too short', { size: msg.length }, 'SSU2');
      return;
    }
    const type = msg.readUInt8(0);
    const connIdDest = msg.readBigUInt64BE(1);
    const connIdSrc = msg.readBigUInt64BE(9);
    const id = this.sessionKey(rinfo.address, rinfo.port);

    if (!this.sessions.has(id)) {
      if (type !== SSU2MessageType.SessionRequest) return;
      if (this.sessions.size >= MAX_ACTIVE_SESSIONS) this.pruneState();
      if (this.sessions.size >= MAX_ACTIVE_SESSIONS) return;
      const hs = initHandshake();
      const s: SSU2Session = {
        address: rinfo.address,
        port: rinfo.port,
        state: 'init',
        isInitiator: false,
        connIdLocal: this.generateConnId(),
        connIdRemote: connIdSrc,
        hs,
        sendNonce: 0,
        recvNonce: 0,
        sendEpoch: 0,
        recvEpoch: 0,
        handshakeRetries: 0,
        pendingData: new Map(),
        receivedPackets: new Set(),
        createdAt: Date.now(),
        lastActivity: Date.now()
      };
      this.sessions.set(id, s);
      logSsu2InterfaceSnapshot('incoming-session-created', id, s);
    }

    const s = this.sessions.get(id)!;
    this.touchSession(s);
    if (type === SSU2MessageType.SessionRequest && !s.isInitiator) this.processSessionRequest(s, msg);
    else if (type === SSU2MessageType.NewToken && s.isInitiator) this.processNewToken(s, msg);
    else if (type === SSU2MessageType.SessionCreated && s.isInitiator) this.processSessionCreated(s, msg);
    else if (type === SSU2MessageType.SessionConfirmed && !s.isInitiator) this.processSessionConfirmed(s, msg);
    else if (type === SSU2MessageType.Ack) this.processAck(s, msg);
    else if (type === SSU2MessageType.Nack) this.processNack(s, msg);
    else if (type === SSU2MessageType.Data && (s.state === 'established' || (!s.isInitiator && s.state === 'created_sent'))) this.processData(s, msg);
  }

  private buildSessionRequest(s: SSU2Session): Buffer {
    const hs = s.hs;
    hs.h = Crypto.sha256(new Uint8Array(Buffer.from('SSU2_HANDSHAKE', 'ascii')));
    hs.h = Crypto.sha256(concat(hs.h, hs.ePub!));
    const dh = Crypto.x25519DiffieHellman(hs.ePriv!, hs.rs!);
    const { ck, k } = mixKey(hs.h, dh);
    hs.h = ck;
    hs.k = k;
    logSsu2Keys('session-request', {
      ePriv: hs.ePriv,
      ePub: hs.ePub,
      remoteStaticPub: hs.rs,
      dh,
      ck,
      k,
      h: hs.h
    });

    const plain = Buffer.alloc(2);
    plain.writeUInt8(this.options.netId & 0xff, 0);
    plain.writeUInt8(1, 1);

    const nonce = Buffer.alloc(12);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(hs.k, nonce, plain, hs.h));

    const token = s.token ?? 0n;
    const buf = Buffer.alloc(1 + 8 + 8 + 8 + 32 + ct.length);
    writeSsu2Header(buf, SSU2MessageType.SessionRequest, s.connIdRemote, s.connIdLocal);
    buf.writeBigUInt64BE(token, 17);
    Buffer.from(hs.ePub!).copy(buf, 25);
    ct.copy(buf, 57);
    return buf;
  }

  private processSessionRequest(s: SSU2Session, msg: Buffer): void {
    if (!this.options.staticPrivateKey || !this.options.staticPublicKey) return;
    if (msg.length < 1 + 8 + 8 + 8 + 32 + 16) return;

    const id = this.sessionKey(s.address, s.port);
    const providedToken = msg.readBigUInt64BE(17);
    const expectedToken = this.serverTokens.get(id);
    if (!expectedToken || providedToken !== expectedToken) {
      const newToken = this.generateConnId();
      this.setServerToken(id, newToken);
      const reply = this.buildNewToken(s, newToken);
      this.sendFireAndForget(reply, s.address, s.port, 'NewToken');
      return;
    }

    const eph = msg.subarray(25, 57);
    const ct = msg.subarray(57);
    const hs = s.hs;
    hs.h = Crypto.sha256(new Uint8Array(Buffer.from('SSU2_HANDSHAKE', 'ascii')));
    hs.rs = this.options.staticPublicKey;
    hs.h = Crypto.sha256(concat(hs.h, eph));

    const dh = Crypto.x25519DiffieHellman(this.options.staticPrivateKey, eph);
    const { ck, k } = mixKey(hs.h, dh);
    hs.h = ck;
    hs.k = k;
    logSsu2Keys('session-request-recv', {
      localStaticPriv: this.options.staticPrivateKey,
      localStaticPub: this.options.staticPublicKey,
      remoteEpub: eph,
      dh,
      ck,
      k,
      h: hs.h
    });

    const nonce = Buffer.alloc(12);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(hs.k, nonce, ct, hs.h));
    } catch {
      return;
    }

    if (plain.readUInt8(0) !== (this.options.netId & 0xff) || plain.readUInt8(1) !== 1) return;

    s.state = 'created_sent';
    s.connIdRemote = msg.readBigUInt64BE(9);
    logSsu2InterfaceSnapshot('session-request-accepted', this.sessionKey(s.address, s.port), s);

    const reply = this.buildSessionCreated(s);
    this.sendFireAndForget(reply, s.address, s.port, 'SessionCreated');
  }

  private buildNewToken(s: SSU2Session, token: bigint): Buffer {
    const buf = Buffer.alloc(1 + 8 + 8 + 8);
    writeSsu2Header(buf, SSU2MessageType.NewToken, s.connIdRemote, s.connIdLocal);
    buf.writeBigUInt64BE(token, 17);
    return buf;
  }

  private processNewToken(s: SSU2Session, msg: Buffer): void {
    if (msg.length < 25) return;
    const token = msg.readBigUInt64BE(17);
    const id = this.sessionKey(s.address, s.port);
    this.setServerToken(id, token);
    s.token = token;
    this.sendHandshakeRequest(s).catch((err) => {
      logger.warn(`SSU2 resend with token failed for ${s.address}:${s.port}`, { error: String(err) }, 'SSU2');
    });
  }

  private buildSessionCreated(s: SSU2Session): Buffer {
    const hs = s.hs;
    const { sendKey, recvKey } = deriveDirectionalKeys(hs.k!, false);
    s.sendKey = sendKey;
    s.recvKey = recvKey;
    logSsu2Keys('session-created-send-keys', {
      k: hs.k,
      sendKey: s.sendKey,
      recvKey: s.recvKey
    });

    const plain = Buffer.from('CREATED');
    const nonce = Buffer.alloc(12);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(hs.k!, nonce, plain, hs.h));

    const buf = Buffer.alloc(1 + 8 + 8 + ct.length);
    writeSsu2Header(buf, SSU2MessageType.SessionCreated, s.connIdRemote, s.connIdLocal);
    ct.copy(buf, 17);
    return buf;
  }

  private processSessionCreated(s: SSU2Session, msg: Buffer): void {
    if (s.handshakeTimer) clearTimeout(s.handshakeTimer);
    const hs = s.hs;
    const nonce = Buffer.alloc(12);
    const ct = msg.subarray(17);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(hs.k!, nonce, ct, hs.h));
    } catch {
      return;
    }
    if (plain.toString('utf8') !== 'CREATED') return;

    const connIdSrc = msg.readBigUInt64BE(9);
    if (connIdSrc !== 0n) {
      s.connIdRemote = connIdSrc;
    }

    const { sendKey, recvKey } = deriveDirectionalKeys(hs.k!, true);
    s.sendKey = sendKey;
    s.recvKey = recvKey;
    logSsu2Keys('session-created-recv-keys', {
      k: hs.k,
      sendKey: s.sendKey,
      recvKey: s.recvKey
    });

    const confirmed = this.buildSessionConfirmed(s);
    this.sendFireAndForget(confirmed, s.address, s.port, 'SessionConfirmed');
    s.state = 'established';
    logSsu2InterfaceSnapshot('initiator-established', this.sessionKey(s.address, s.port), s);
    logger.info('SSU2 session established (initiator)', { sessionId: this.sessionKey(s.address, s.port) }, 'SSU2');
    this.emit('established', { sessionId: this.sessionKey(s.address, s.port) });
  }

  private buildSessionConfirmed(s: SSU2Session): Buffer {
    const plain = Buffer.from('CONFIRMED');
    const nonce = Buffer.alloc(12);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, plain));

    const buf = Buffer.alloc(1 + 8 + 8 + ct.length);
    writeSsu2Header(buf, SSU2MessageType.SessionConfirmed, s.connIdRemote, s.connIdLocal);
    ct.copy(buf, 17);
    return buf;
  }

  private processSessionConfirmed(s: SSU2Session, msg: Buffer): void {
    const nonce = Buffer.alloc(12);
    const ct = msg.subarray(17);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(s.recvKey!, nonce, ct));
    } catch {
      return;
    }
    if (plain.toString('utf8') !== 'CONFIRMED') return;

    s.state = 'established';
    logSsu2InterfaceSnapshot('responder-established', this.sessionKey(s.address, s.port), s);
    logSsu2Keys('session-confirmed-established', {
      sendKey: s.sendKey,
      recvKey: s.recvKey
    });
    logger.info('SSU2 session established (responder)', { sessionId: this.sessionKey(s.address, s.port) }, 'SSU2');
    this.emit('established', { sessionId: this.sessionKey(s.address, s.port) });
  }

  private buildData(s: SSU2Session, payload: Buffer): Buffer {
    this.rotateKeysIfNeeded(s);
    const packetNumber = s.sendNonce;
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(packetNumber & 0xffffffff, 8);
    s.sendNonce++;
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, payload));
    const buf = Buffer.alloc(1 + 8 + 8 + 4 + ct.length);
    writeSsu2Header(buf, SSU2MessageType.Data, s.connIdRemote, s.connIdLocal);
    buf.writeUInt32BE(packetNumber >>> 0, 17);
    ct.copy(buf, 21);
    return buf;
  }

  private processData(s: SSU2Session, msg: Buffer): void {
    if (msg.length < 21) return;
    this.rotateKeysIfNeeded(s, true);

    const packetNumber = msg.readUInt32BE(17);
    if (packetNumber + REPLAY_WINDOW < s.recvNonce) return;
    if (s.receivedPackets.has(packetNumber)) {
      this.sendFireAndForget(this.buildAck(s, packetNumber), s.address, s.port, 'Ack-Replay');
      return;
    }
    if (packetNumber > s.recvNonce) {
      const nack = this.buildNack(s, s.recvNonce);
      this.sendFireAndForget(nack, s.address, s.port, 'Nack');
    }

    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(packetNumber & 0xffffffff, 8);
    const ct = msg.subarray(21);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(s.recvKey!, nonce, ct));
    } catch {
      return;
    }

    s.recvNonce = Math.max(s.recvNonce, packetNumber + 1);
    s.receivedPackets.add(packetNumber);
    this.pruneReceivedPackets(s);
    this.sendFireAndForget(this.buildAck(s, packetNumber), s.address, s.port, 'Ack');
    this.emit('message', { sessionId: this.sessionKey(s.address, s.port), data: plain });
  }

  private buildAck(s: SSU2Session, ackedPacketNumber: number): Buffer {
    const nonce = Buffer.from(Crypto.randomBytes(12));
    const plain = Buffer.alloc(4);
    plain.writeUInt32BE(ackedPacketNumber >>> 0, 0);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, plain));

    const buf = Buffer.alloc(1 + 8 + 8 + 12 + ct.length);
    writeSsu2Header(buf, SSU2MessageType.Ack, s.connIdRemote, s.connIdLocal);
    nonce.copy(buf, 17);
    ct.copy(buf, 29);
    return buf;
  }

  private processAck(s: SSU2Session, msg: Buffer): void {
    if (!s.recvKey || msg.length < 49) return;
    const nonce = msg.subarray(17, 29);
    const ct = msg.subarray(29);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(s.recvKey, nonce, ct));
    } catch {
      return;
    }
    const acked = plain.readUInt32BE(0);
    for (const packetNumber of s.pendingData.keys()) {
      if (packetNumber <= acked) s.pendingData.delete(packetNumber);
    }
  }

  private buildNack(s: SSU2Session, expectedPacketNumber: number): Buffer {
    const nonce = Buffer.from(Crypto.randomBytes(12));
    const plain = Buffer.alloc(4);
    plain.writeUInt32BE(expectedPacketNumber >>> 0, 0);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, plain));

    const buf = Buffer.alloc(1 + 8 + 8 + 12 + ct.length);
    writeSsu2Header(buf, SSU2MessageType.Nack, s.connIdRemote, s.connIdLocal);
    nonce.copy(buf, 17);
    ct.copy(buf, 29);
    return buf;
  }

  private processNack(s: SSU2Session, msg: Buffer): void {
    if (!s.recvKey || msg.length < 49 || !this.socket) return;
    const nonce = msg.subarray(17, 29);
    const ct = msg.subarray(29);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(s.recvKey, nonce, ct));
    } catch {
      return;
    }
    const expected = plain.readUInt32BE(0);
    const pending = s.pendingData.get(expected);
    if (pending) this.socket.send(pending.raw, s.port, s.address);
  }

  private sendFireAndForget(buf: Buffer, host: string, port: number, label: string): void {
    this.sendRaw(buf, host, port).catch((err) => {
      logger.warn(`SSU2 send failed (${label}) to ${host}:${port}`, { error: String(err) }, 'SSU2');
    });
  }

  private touchSession(s: SSU2Session): void {
    s.lastActivity = Date.now();
  }

  private pruneReceivedPackets(s: SSU2Session): void {
    const threshold = Math.max(0, s.recvNonce - REPLAY_WINDOW);
    for (const packetNumber of s.receivedPackets) {
      if (packetNumber < threshold) s.receivedPackets.delete(packetNumber);
    }
  }

  private setServerToken(id: string, token: bigint): void {
    this.serverTokens.set(id, token);
    while (this.serverTokens.size > MAX_SERVER_TOKENS) {
      const oldest = this.serverTokens.keys().next().value;
      if (oldest === undefined) break;
      this.serverTokens.delete(oldest);
    }
  }

  private pruneState(): void {
    const now = Date.now();
    for (const [sessionId, session] of this.sessions) {
      const staleEstablished = session.state === 'established' && now - session.lastActivity > ESTABLISHED_IDLE_MS;
      const staleHandshake = session.state !== 'established' && (now - session.lastActivity > SESSION_IDLE_MS || now - session.createdAt > HANDSHAKE_TIMEOUT_MS * 2);
      if (staleEstablished || staleHandshake) {
        if (session.handshakeTimer) clearTimeout(session.handshakeTimer);
        this.sessions.delete(sessionId);
      }
    }

    if (this.sessions.size > MAX_ACTIVE_SESSIONS) {
      const sorted = [...this.sessions.entries()].sort((a, b) => a[1].lastActivity - b[1].lastActivity);
      for (const [sessionId] of sorted) {
        if (this.sessions.size <= MAX_ACTIVE_SESSIONS) break;
        this.sessions.delete(sessionId);
      }
    }

    while (this.serverTokens.size > MAX_SERVER_TOKENS) {
      const oldest = this.serverTokens.keys().next().value;
      if (oldest === undefined) break;
      this.serverTokens.delete(oldest);
    }
  }

  private rotateKeysIfNeeded(s: SSU2Session, inbound = false): void {
    if (!s.sendKey || !s.recvKey) return;

    if (!inbound && s.sendNonce > 0 && s.sendNonce % KEY_ROTATION_INTERVAL === 0) {
      s.sendEpoch++;
      s.sendKey = Crypto.hmacSHA256(s.sendKey, Buffer.from(`rotate-send-${s.sendEpoch}`));
    }
    if (inbound && s.recvNonce > 0 && s.recvNonce % KEY_ROTATION_INTERVAL === 0) {
      s.recvEpoch++;
      s.recvKey = Crypto.hmacSHA256(s.recvKey, Buffer.from(`rotate-recv-${s.recvEpoch}`));
    }
  }

  private generateConnId(): bigint {
    const buf = Crypto.randomBytes(8);
    return BigInt('0x' + Buffer.from(buf).toString('hex'));
  }
}

export default SSU2Transport;

function initHandshake(): HandshakeState {
  return { k: null, h: new Uint8Array(32) };
}

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function mixKey(h: Uint8Array, dh: Uint8Array): { ck: Uint8Array; k: Uint8Array } {
  const temp = Crypto.hmacSHA256(h, dh);
  const ck = Crypto.hmacSHA256(temp, new Uint8Array([0x01]));
  const k = Crypto.hmacSHA256(temp, concat(ck, new Uint8Array([0x02])));
  return { ck, k };
}

function deriveDirectionalKeys(sharedKey: Uint8Array, isInitiator: boolean): { sendKey: Uint8Array; recvKey: Uint8Array } {
  const initiatorToResponder = Crypto.hmacSHA256(sharedKey, Buffer.from('ssu2-initiator-to-responder'));
  const responderToInitiator = Crypto.hmacSHA256(sharedKey, Buffer.from('ssu2-responder-to-initiator'));
  if (isInitiator) {
    return { sendKey: initiatorToResponder, recvKey: responderToInitiator };
  }
  return { sendKey: responderToInitiator, recvKey: initiatorToResponder };
}

function extractRemoteSsu2StaticKey(ri: RouterInfo, hostHint?: string, portHint?: number): Uint8Array {
  const addrs = ri.addresses.filter((a) => a.transportStyle === 'SSU2' && a.options.s);
  if (!addrs.length) throw new Error('remote RouterInfo has no SSU2 address with s');

  let addr = addrs[0];
  if (hostHint && typeof portHint === 'number') {
    const normalizedHint = normalizeHost(hostHint);
    const expectedPort = String(portHint);
    const exact = addrs.find((a) => {
      const addressHost = normalizeHost(a.options.host);
      const addressPort = a.options.port != null ? String(a.options.port) : undefined;
      return addressPort === expectedPort && addressHost === normalizedHint;
    });
    if (exact) {
      addr = exact;
    }
  }

  const s = i2pBase64Decode(addr.options.s);
  if (s.length !== 32) throw new Error('remote SSU2 static key must be 32 bytes');
  return new Uint8Array(s);
}

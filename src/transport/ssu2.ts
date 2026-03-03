import { createSocket, Socket, RemoteInfo } from 'dgram';
import { EventEmitter } from 'events';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';
import { i2pBase64Decode } from '../i2p/base64.js';

const enum SSU2MessageType {
  SessionRequest = 0,
  SessionCreated = 1,
  TokenRequest = 2,
  NewToken = 3,
  SessionConfirmed = 4,
  Ack = 5,
  Data = 6,
  Nack = 7
}

const HANDSHAKE_TIMEOUT_MS = 9000;
const HANDSHAKE_RETRY_DELAYS_MS = [1000, 3000, 7000];
const DATA_RETRANSMIT_MS = 800;
const KEY_ROTATION_INTERVAL = 1024;

export interface SSU2Options {
  host?: string;
  port?: number;
  staticPrivateKey?: Uint8Array;
  staticPublicKey?: Uint8Array;
  netId?: number;
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
}

export class SSU2Transport extends EventEmitter {
  private socket: Socket | null = null;
  private sessions: Map<string, SSU2Session> = new Map();
  private serverTokens: Map<string, bigint> = new Map();
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
  }

  private sessionKey(address: string, port: number): string {
    return `${address}:${port}`;
  }

  async connect(host: string, port: number, remoteRouterInfo: RouterInfo): Promise<void> {
    if (!this.options.staticPrivateKey || !this.options.staticPublicKey) {
      throw new Error('SSU2 static keys not configured');
    }

    const id = this.sessionKey(host, port);
    if (this.sessions.get(id)?.state === 'established') return;

    const hs: HandshakeState = initHandshake();
    const eph = Crypto.generateEphemeralKeyPair();
    hs.ePriv = eph.privateKey;
    hs.ePub = eph.publicKey;
    hs.rs = extractRemoteSsu2StaticKey(remoteRouterInfo);
    hs.timeoutAt = Date.now() + HANDSHAKE_TIMEOUT_MS;

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
      pendingData: new Map()
    };

    this.sessions.set(id, session);
    await this.sendHandshakeRequest(session);

    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.off('established', onEstablished);
        reject(new Error('SSU2 connect timeout'));
      }, HANDSHAKE_TIMEOUT_MS + 1000);
      const onEstablished = ({ sessionId }: { sessionId: string }) => {
        if (sessionId === id) {
          clearTimeout(timeout);
          this.off('established', onEstablished);
          resolve();
        }
      };
      this.on('established', onEstablished);
    });
  }

  send(sessionId: string, data: Buffer): void {
    const s = this.sessions.get(sessionId);
    if (!s || s.state !== 'established' || !s.sendKey || !this.socket) return;

    const packetNumber = s.sendNonce;
    const pkt = this.buildData(s, data);
    s.pendingData.set(packetNumber, { raw: pkt, retransmits: 0 });
    this.socket.send(pkt, s.port, s.address);
    setTimeout(() => this.retransmitIfUnacked(sessionId, packetNumber), DATA_RETRANSMIT_MS);
  }

  private retransmitIfUnacked(sessionId: string, packetNumber: number): void {
    const s = this.sessions.get(sessionId);
    if (!s || !this.socket) return;
    const pending = s.pendingData.get(packetNumber);
    if (!pending || pending.retransmits >= 2) return;

    pending.retransmits++;
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
      this.sendHandshakeRequest(s).catch(() => {});
    }, delay);
  }

  private handleMessage(msg: Buffer, rinfo: RemoteInfo): void {
    if (msg.length < 1 + 8 + 8) return;
    const type = msg.readUInt8(0);
    const connIdDest = msg.readBigUInt64BE(1);
    const connIdSrc = msg.readBigUInt64BE(9);
    const id = this.sessionKey(rinfo.address, rinfo.port);

    if (!this.sessions.has(id)) {
      const hs = initHandshake();
      const s: SSU2Session = {
        address: rinfo.address,
        port: rinfo.port,
        state: 'init',
        isInitiator: false,
        connIdLocal: connIdDest,
        connIdRemote: connIdSrc,
        hs,
        sendNonce: 0,
        recvNonce: 0,
        sendEpoch: 0,
        recvEpoch: 0,
        handshakeRetries: 0,
        pendingData: new Map()
      };
      this.sessions.set(id, s);
    }

    const s = this.sessions.get(id)!;
    if (type === SSU2MessageType.SessionRequest && !s.isInitiator) this.processSessionRequest(s, msg);
    else if (type === SSU2MessageType.NewToken && s.isInitiator) this.processNewToken(s, msg);
    else if (type === SSU2MessageType.SessionCreated && s.isInitiator) this.processSessionCreated(s, msg);
    else if (type === SSU2MessageType.SessionConfirmed && !s.isInitiator) this.processSessionConfirmed(s, msg);
    else if (type === SSU2MessageType.Ack) this.processAck(s, msg);
    else if (type === SSU2MessageType.Nack) this.processNack(s, msg);
    else if (type === SSU2MessageType.Data && s.state === 'established') this.processData(s, msg);
  }

  private buildSessionRequest(s: SSU2Session): Buffer {
    const hs = s.hs;
    hs.h = Crypto.sha256(new Uint8Array(Buffer.from('SSU2_HANDSHAKE', 'ascii')));
    hs.h = Crypto.sha256(concat(hs.h, hs.ePub!));
    const dh = Crypto.x25519DiffieHellman(hs.ePriv!, hs.rs!);
    const { ck, k } = mixKey(hs.h, dh);
    hs.h = ck;
    hs.k = k;

    const plain = Buffer.alloc(2);
    plain.writeUInt8(this.options.netId & 0xff, 0);
    plain.writeUInt8(1, 1);

    const nonce = Buffer.alloc(12);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(hs.k, nonce, plain, hs.h));

    const token = s.token ?? 0n;
    const buf = Buffer.alloc(1 + 8 + 8 + 8 + 32 + ct.length);
    buf.writeUInt8(SSU2MessageType.SessionRequest, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
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
      this.serverTokens.set(id, this.generateConnId());
      const newToken = this.serverTokens.get(id)!;
      const reply = this.buildNewToken(s, newToken);
      this.sendRaw(reply, s.address, s.port).catch(() => {});
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

    const nonce = Buffer.alloc(12);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(hs.k, nonce, ct, hs.h));
    } catch {
      return;
    }

    if (plain.readUInt8(0) !== (this.options.netId & 0xff) || plain.readUInt8(1) !== 1) return;

    s.state = 'created_sent';
    s.connIdRemote = msg.readBigUInt64BE(1);
    s.connIdLocal = msg.readBigUInt64BE(9);

    const reply = this.buildSessionCreated(s);
    this.sendRaw(reply, s.address, s.port).catch(() => {});
  }

  private buildNewToken(s: SSU2Session, token: bigint): Buffer {
    const buf = Buffer.alloc(1 + 8 + 8 + 8);
    buf.writeUInt8(SSU2MessageType.NewToken, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
    buf.writeBigUInt64BE(token, 17);
    return buf;
  }

  private processNewToken(s: SSU2Session, msg: Buffer): void {
    if (msg.length < 25) return;
    const token = msg.readBigUInt64BE(17);
    const id = this.sessionKey(s.address, s.port);
    this.serverTokens.set(id, token);
    s.token = token;
    this.sendHandshakeRequest(s).catch(() => {});
  }

  private buildSessionCreated(s: SSU2Session): Buffer {
    const hs = s.hs;
    const secret = Crypto.hmacSHA256(hs.k!, Buffer.from('ssu2-created'));
    s.sendKey = secret.subarray(0, 32);
    s.recvKey = secret.subarray(0, 32);

    const plain = Buffer.from('CREATED');
    const nonce = Buffer.alloc(12);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(hs.k!, nonce, plain, hs.h));

    const buf = Buffer.alloc(1 + 8 + 8 + ct.length);
    buf.writeUInt8(SSU2MessageType.SessionCreated, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
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

    const secret = Crypto.hmacSHA256(hs.k!, Buffer.from('ssu2-created'));
    s.sendKey = secret.subarray(0, 32);
    s.recvKey = secret.subarray(0, 32);

    const confirmed = this.buildSessionConfirmed(s);
    this.sendRaw(confirmed, s.address, s.port).catch(() => {});
    s.state = 'established';
    this.emit('established', { sessionId: this.sessionKey(s.address, s.port) });
  }

  private buildSessionConfirmed(s: SSU2Session): Buffer {
    const plain = Buffer.from('CONFIRMED');
    const nonce = Buffer.alloc(12);
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, plain));

    const buf = Buffer.alloc(1 + 8 + 8 + ct.length);
    buf.writeUInt8(SSU2MessageType.SessionConfirmed, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
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
    this.emit('established', { sessionId: this.sessionKey(s.address, s.port) });
    const ack = this.buildAck(s, 0);
    this.sendRaw(ack, s.address, s.port).catch(() => {});
  }

  private buildData(s: SSU2Session, payload: Buffer): Buffer {
    this.rotateKeysIfNeeded(s);
    const packetNumber = s.sendNonce;
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(packetNumber & 0xffffffff, 8);
    s.sendNonce++;
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, payload));
    const buf = Buffer.alloc(1 + 8 + 8 + 4 + ct.length);
    buf.writeUInt8(SSU2MessageType.Data, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
    buf.writeUInt32BE(packetNumber >>> 0, 17);
    ct.copy(buf, 21);
    return buf;
  }

  private processData(s: SSU2Session, msg: Buffer): void {
    if (msg.length < 21) return;
    this.rotateKeysIfNeeded(s, true);

    const packetNumber = msg.readUInt32BE(17);
    if (packetNumber > s.recvNonce + 1) {
      const nack = this.buildNack(s, s.recvNonce);
      this.sendRaw(nack, s.address, s.port).catch(() => {});
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
    this.sendRaw(this.buildAck(s, packetNumber), s.address, s.port).catch(() => {});
    this.emit('message', { sessionId: this.sessionKey(s.address, s.port), data: plain });
  }

  private buildAck(s: SSU2Session, ackedPacketNumber: number): Buffer {
    const buf = Buffer.alloc(1 + 8 + 8 + 4);
    buf.writeUInt8(SSU2MessageType.Ack, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
    buf.writeUInt32BE(ackedPacketNumber >>> 0, 17);
    return buf;
  }

  private processAck(s: SSU2Session, msg: Buffer): void {
    if (msg.length < 21) return;
    const acked = msg.readUInt32BE(17);
    for (const packetNumber of s.pendingData.keys()) {
      if (packetNumber <= acked) s.pendingData.delete(packetNumber);
    }
  }

  private buildNack(s: SSU2Session, expectedPacketNumber: number): Buffer {
    const buf = Buffer.alloc(1 + 8 + 8 + 4);
    buf.writeUInt8(SSU2MessageType.Nack, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
    buf.writeUInt32BE(expectedPacketNumber >>> 0, 17);
    return buf;
  }

  private processNack(s: SSU2Session, msg: Buffer): void {
    if (msg.length < 21 || !this.socket) return;
    const expected = msg.readUInt32BE(17);
    const pending = s.pendingData.get(expected);
    if (pending) this.socket.send(pending.raw, s.port, s.address);
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

function extractRemoteSsu2StaticKey(ri: RouterInfo): Uint8Array {
  const addr = ri.addresses.find((a) => a.transportStyle === 'SSU2' && a.options.s);
  if (!addr) throw new Error('remote RouterInfo has no SSU2 address with s');
  const s = i2pBase64Decode(addr.options.s);
  if (s.length !== 32) throw new Error('remote SSU2 static key must be 32 bytes');
  return new Uint8Array(s);
}

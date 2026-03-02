import { createSocket, Socket, RemoteInfo } from 'dgram';
import { EventEmitter } from 'events';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';
import { i2pBase64Decode } from '../i2p/base64.js';

// Very small subset of SSU2 for local smoke testing:
// - Single-packet SessionRequest from Alice, single-packet SessionCreated from Bob.
// - Keys derived via X25519 + HMAC-SHA256 in a Noise-like pattern.
// - Data packets using AEAD ChaCha20-Poly1305 with per-packet nonce.

const enum SSU2MessageType {
  SessionRequest = 0,
  SessionCreated = 1,
  Data = 6
}

export interface SSU2Options {
  host?: string;
  port?: number;

  /** Local static X25519 private key (32 bytes). */
  staticPrivateKey?: Uint8Array;

  /** Local static X25519 public key (32 bytes). */
  staticPublicKey?: Uint8Array;

  /** Local network ID (mainline=2). */
  netId?: number;
}

type SessionState = 'init' | 'request_sent' | 'created_sent' | 'established';

interface HandshakeState {
  k: Uint8Array | null;
  h: Uint8Array;
  ePriv?: Uint8Array;
  ePub?: Uint8Array;
  rs?: Uint8Array; // remote static
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
}

export class SSU2Transport extends EventEmitter {
  private socket: Socket | null = null;
  private sessions: Map<string, SSU2Session> = new Map();
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
    this.sessions.clear();
  }

  private sessionKey(address: string, port: number): string {
    return `${address}:${port}`;
  }

  /**
   * Alice: initiate SSU2 handshake to remote router/endpoint.
   * Host/port must match a published SSU2 address in the given RouterInfo
   * (we extract the static key from that address via option 's').
   */
  async connect(host: string, port: number, remoteRouterInfo: RouterInfo): Promise<void> {
    if (!this.options.staticPrivateKey || !this.options.staticPublicKey) {
      throw new Error('SSU2 static keys not configured');
    }
    const id = this.sessionKey(host, port);
    if (this.sessions.has(id)) {
      const s = this.sessions.get(id)!;
      if (s.state === 'established') return;
    }

    const connIdLocal = this.generateConnId();
    const connIdRemote = 0n;

    // Extract remote static key from SSU2 address (option 's', I2P base64).
    const remoteStatic = extractRemoteSsu2StaticKey(remoteRouterInfo);

    const hs: HandshakeState = initHandshake();
    const eph = Crypto.generateEphemeralKeyPair();
    hs.ePriv = eph.privateKey;
    hs.ePub = eph.publicKey;
    hs.rs = remoteStatic;

    const session: SSU2Session = {
      address: host,
      port,
      state: 'request_sent',
      isInitiator: true,
      connIdLocal,
      connIdRemote,
      hs,
      sendNonce: 0,
      recvNonce: 0
    };
    this.sessions.set(id, session);

    const buf = this.buildSessionRequest(session);
    await this.sendRaw(buf, host, port);

    // Resolve when we see SessionCreated and mark established.
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.off('established', onEstablished);
        reject(new Error('SSU2 connect timeout'));
      }, 7000);
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

  /**
   * Send data over established SSU2 session. For now, wraps the payload into a single Data packet.
   */
  send(sessionId: string, data: Buffer): void {
    const s = this.sessions.get(sessionId);
    if (!s || s.state !== 'established' || !s.sendKey || !this.socket) return;
    const pkt = this.buildData(s, data);
    this.socket.send(pkt, s.port, s.address);
  }

  private async sendRaw(buf: Buffer, host: string, port: number): Promise<void> {
    if (!this.socket) throw new Error('SSU2 socket not started');
    return new Promise((resolve, reject) => {
      this.socket!.send(buf, port, host, (err) => (err ? reject(err) : resolve()));
    });
  }

  private handleMessage(msg: Buffer, rinfo: RemoteInfo): void {
    if (msg.length < 1 + 8 + 8) return;
    const type = msg.readUInt8(0);
    const connIdDest = msg.readBigUInt64BE(1);
    const connIdSrc = msg.readBigUInt64BE(9);
    const id = this.sessionKey(rinfo.address, rinfo.port);

    if (!this.sessions.has(id)) {
      // New inbound session (Bob).
      const hs = initHandshake();
      const s: SSU2Session = {
        address: rinfo.address,
        port: rinfo.port,
        state: 'init',
        isInitiator: false,
        connIdLocal: connIdDest, // Bob's ID
        connIdRemote: connIdSrc,
        hs,
        sendNonce: 0,
        recvNonce: 0
      };
      this.sessions.set(id, s);
    }
    const s = this.sessions.get(id)!;

    if (type === SSU2MessageType.SessionRequest && !s.isInitiator) {
      this.processSessionRequest(s, msg);
    } else if (type === SSU2MessageType.SessionCreated && s.isInitiator) {
      this.processSessionCreated(s, msg);
    } else if (type === SSU2MessageType.Data && s.state === 'established') {
      this.processData(s, msg);
    }
  }

  private buildSessionRequest(s: SSU2Session): Buffer {
    const hs = s.hs;
    const h0 = Crypto.sha256(new Uint8Array(Buffer.from('SSU2_HANDSHAKE', 'ascii')));
    hs.h = h0;
    // rs (remote static) must be set by connect() for initiator.

    // MixHash(ephemeral pub)
    hs.h = Crypto.sha256(concat(hs.h, hs.ePub!));
    // MixKey(DH(e, rs))
    const dh = Crypto.x25519DiffieHellman(hs.ePriv!, hs.rs!);
    const { ck, k } = mixKey(hs.h, dh);
    hs.h = ck; // simple: reuse ck as new h
    hs.k = k;

    // Plaintext payload = [netId(1) | ver(1)]
    const plain = Buffer.alloc(2);
    plain.writeUInt8(this.options.netId & 0xff, 0);
    plain.writeUInt8(1, 1); // handshake version

    const nonce = Buffer.alloc(12); // all zero
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(hs.k, nonce, plain, hs.h));

    const buf = Buffer.alloc(1 + 8 + 8 + 32 + ct.length);
    buf.writeUInt8(SSU2MessageType.SessionRequest, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
    Buffer.from(hs.ePub!).copy(buf, 17);
    ct.copy(buf, 49);
    return buf;
  }

  private processSessionRequest(s: SSU2Session, msg: Buffer): void {
    if (!this.options.staticPrivateKey || !this.options.staticPublicKey) return;
    if (msg.length < 1 + 8 + 8 + 32 + 16) return;
    const eph = msg.subarray(17, 49);
    const ct = msg.subarray(49);

    const hs = s.hs;
    const h0 = Crypto.sha256(new Uint8Array(Buffer.from('SSU2_HANDSHAKE', 'ascii')));
    hs.h = h0;
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
    const netId = plain.readUInt8(0);
    const ver = plain.readUInt8(1);
    if (netId !== (this.options.netId & 0xff) || ver !== 1) return;

    // We are Bob; mark established after we send SessionCreated.
    s.state = 'created_sent';
    // swap local/remote conn IDs
    s.connIdRemote = msg.readBigUInt64BE(1);
    s.connIdLocal = msg.readBigUInt64BE(9);

    const reply = this.buildSessionCreated(s);
    this.sendRaw(reply, s.address, s.port).catch(() => {});
  }

  private buildSessionCreated(s: SSU2Session): Buffer {
    const hs = s.hs;
    // New key for data phase; simple split of k
    const temp = Crypto.hmacSHA256(hs.k!, new Uint8Array());
    const sendKey = temp.subarray(0, 32);
    const recvKey = temp.subarray(0, 32);
    s.sendKey = sendKey;
    s.recvKey = recvKey;
    s.state = 'established';
    this.emit('established', { sessionId: this.sessionKey(s.address, s.port) });

    const plain = Buffer.from('OK');
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
    const hs = s.hs;
    const ct = msg.subarray(17);
    const nonce = Buffer.alloc(12);
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(hs.k!, nonce, ct, hs.h));
    } catch {
      return;
    }
    if (plain.toString('utf8') !== 'OK') return;

    const temp = Crypto.hmacSHA256(hs.k!, new Uint8Array());
    const sendKey = temp.subarray(0, 32);
    const recvKey = temp.subarray(0, 32);
    s.sendKey = sendKey;
    s.recvKey = recvKey;
    s.state = 'established';
    this.emit('established', { sessionId: this.sessionKey(s.address, s.port) });
  }

  private buildData(s: SSU2Session, payload: Buffer): Buffer {
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(s.sendNonce & 0xffffffff, 8);
    s.sendNonce++;
    const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(s.sendKey!, nonce, payload));
    const buf = Buffer.alloc(1 + 8 + 8 + ct.length);
    buf.writeUInt8(SSU2MessageType.Data, 0);
    buf.writeBigUInt64BE(s.connIdLocal, 1);
    buf.writeBigUInt64BE(s.connIdRemote, 9);
    ct.copy(buf, 17);
    return buf;
  }

  private processData(s: SSU2Session, msg: Buffer): void {
    const ct = msg.subarray(17);
    const nonce = Buffer.alloc(12);
    nonce.writeUInt32BE(s.recvNonce & 0xffffffff, 8);
    s.recvNonce++;
    let plain: Buffer;
    try {
      plain = Buffer.from(Crypto.decryptChaCha20Poly1305(s.recvKey!, nonce, ct));
    } catch {
      return;
    }
    const sessionId = this.sessionKey(s.address, s.port);
    this.emit('message', { sessionId, data: plain });
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

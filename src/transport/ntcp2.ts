import { Socket, createServer, Server } from 'net';
import { EventEmitter } from 'events';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';
import { logger } from '../utils/logger.js';
import { i2pBase64Decode } from '../i2p/base64.js';
import { ed25519 } from '@noble/curves/ed25519';

type SessionState = 'init' | 'm1_sent' | 'm2_sent' | 'm2_recv' | 'm3_sent' | 'm3_recv' | 'established';

const DEBUG = process.env.NTCP2_DEBUG === '1';

export interface NTCP2Options {
  host?: string;
  port?: number;

  /** Local router hash (IdentHash) for AES obfuscation on inbound handshakes */
  routerHash?: Uint8Array;

  /** Local published NTCP2 IV (16 bytes) for inbound handshakes */
  publishedIV?: Uint8Array;

  /** Local X25519 static private key (32 bytes). Required to accept inbound handshakes. */
  staticPrivateKey?: Uint8Array;

  /** Local X25519 static public key (32 bytes). Required to initiate handshakes. */
  staticPublicKey?: Uint8Array;

  /** Local RouterInfo (wire format) to send in SessionConfirmed. Required to initiate handshakes. */
  routerInfo?: Buffer;

  /** Network ID (default 2 mainline) */
  netId?: number;

  /** TCP connect timeout for outbound sessions */
  connectTimeoutMs?: number;
}

interface NTCP2Handshake {
  // Noise symmetric state
  h: Buffer;
  ck: Buffer;
  k: Buffer | null;
  nonce: number;

  // initiator ephemeral
  ePriv?: Uint8Array;
  ePub?: Buffer;
  // responder ephemeral
  rPriv?: Uint8Array;
  rPub?: Buffer;

  // remote static
  rs?: Buffer;
  // for inbound, Alice static after msg3p1
  remoteStatic?: Buffer;

  // AES IV chaining from msg1 ciphertext
  aesIV2?: Buffer;

  m3p2Len?: number;
}

interface SipState {
  k1: Buffer; // 8
  k2: Buffer; // 8
  iv: Buffer; // 8 (IV[n], starts at IV[0] from KDF)
}

interface NTCP2DataPhase {
  sendKey: Buffer;
  recvKey: Buffer;
  sendNonce: number;
  recvNonce: number;
  sipSend: SipState;
  sipRecv: SipState;
}

export interface NTCP2Session {
  socket: Socket;
  state: SessionState;
  isInitiator: boolean;
  recvBuffer: Buffer;

  // remote info for outbound
  remoteRouterHash?: Buffer;
  remoteNtcp2IV?: Buffer;
  remoteNtcp2Static?: Buffer;

  hs?: NTCP2Handshake;
  dp?: NTCP2DataPhase;
}

const PROTOCOL_NAME = Buffer.from('Noise_XKaesobfse+hs2+hs3_25519_ChaChaPoly_SHA256', 'ascii');

export class NTCP2Transport extends EventEmitter {
  private server: Server | null = null;
  private sessions: Map<string, NTCP2Session> = new Map();
  private options: Required<Pick<NTCP2Options, 'host' | 'port' | 'netId'>> & Omit<NTCP2Options, 'host' | 'port' | 'netId'>;

  constructor(options: NTCP2Options = {}) {
    super();
    this.setMaxListeners(100); // Many concurrent outbound connections
    this.options = {
      host: options.host ?? '0.0.0.0',
      port: options.port ?? 12345,
      netId: options.netId ?? 2,
      ...options
    };
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer(this.handleConnection.bind(this));
      this.server.on('error', (err) => reject(err));
      this.server.listen(this.options.port, this.options.host, () => {
        const addr = this.server?.address();
        if (addr && typeof addr === 'object') {
          this.emit('listening', { host: addr.address, port: addr.port });
        } else {
          this.emit('listening', { host: this.options.host, port: this.options.port });
        }
        resolve();
      });
    });
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    for (const s of this.sessions.values()) s.socket.destroy();
    this.sessions.clear();
  }

  private handleConnection(socket: Socket): void {
    const sessionId = `${socket.remoteAddress}:${socket.remotePort}`;
    const session: NTCP2Session = {
      socket,
      state: 'init',
      isInitiator: false,
      recvBuffer: Buffer.alloc(0)
    };
    this.sessions.set(sessionId, session);
    socket.on('data', (data) => this.handleData(sessionId, data));
    socket.on('close', () => this.handleClose(sessionId));
    socket.on('error', (err) => this.handleError(sessionId, err));
  }

  /**
   * Outbound connect to a reseeded peer. Requires the peer RouterInfo to contain
   * an NTCP2 address with options: host, port, s, i.
   */
  async connect(host: string, port: number, remoteRouterInfo: RouterInfo): Promise<void> {
    const { s, i } = this.extractRemoteNtcp2Keys(remoteRouterInfo, host, port);
    const remoteRouterHash = Buffer.from(remoteRouterInfo.getRouterHash());

    const sessionId = `${host}:${port}`;

    // If we already have an established session to this peer, reuse it.
    const existing = this.sessions.get(sessionId);
    if (existing && existing.state === 'established' && !existing.socket.destroyed) {
      return;
    }
    // If a previous session exists but isn't established, destroy it first.
    if (existing) {
      existing.socket.destroy();
      this.sessions.delete(sessionId);
    }

    return new Promise((resolve, reject) => {
      const socket = new Socket();
      const timeoutMs = this.options.connectTimeoutMs ?? 8000;
      socket.setTimeout(timeoutMs);
      const session: NTCP2Session = {
        socket,
        state: 'init',
        isInitiator: true,
        recvBuffer: Buffer.alloc(0),
        remoteRouterHash,
        remoteNtcp2IV: i,
        remoteNtcp2Static: s
      };
      this.sessions.set(sessionId, session);

      let settled = false;
      const fail = (err: unknown) => {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err instanceof Error ? err : new Error(String(err)));
      };
      const succeed = () => {
        if (settled) return;
        settled = true;
        cleanup();
        resolve();
      };

      const onClose = () => fail(new Error('socket closed before handshake established'));
      const onError = (err: Error) => fail(err);
      const onTimeout = () => {
        socket.destroy(new Error('connect timeout'));
      };
      const onEstablished = ({ sessionId: sid }: { sessionId: string }) => {
        if (sid === sessionId) succeed();
      };
      const cleanup = () => {
        socket.off('close', onClose);
        socket.off('error', onError);
        socket.off('timeout', onTimeout);
        this.off('established', onEstablished);
      };

      socket.on('close', onClose);
      socket.on('error', onError);
      socket.on('timeout', onTimeout);
      this.on('established', onEstablished);

      socket.on('data', (data) => this.handleData(sessionId, data));
      socket.on('close', () => this.handleClose(sessionId));
      socket.on('error', (err) => this.handleError(sessionId, err));

      socket.connect(port, host, async () => {
        try {
          if (DEBUG) console.log(`NTCP2 TCP connected to ${host}:${port}`);
          await this.sendSessionRequest(sessionId);
        } catch (e) {
          fail(e);
        }
      });
    });
  }

  send(sessionId: string, data: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'established' || !session.dp) return;
    // Wrap raw bytes as an I2NP block (type 3). Proper I2NP header formatting
    // will be implemented in the I2NP checkpoint; for now this validates
    // NTCP2 data-phase framing and AEAD keys end-to-end.
    const framePlain = encodeBlocks([{ type: 3, data }]);
    this.sendDataFrame(session, framePlain);
  }

  /** Check if we have an active established session to a peer */
  hasSession(host: string, port: number): boolean {
    const session = this.sessions.get(`${host}:${port}`);
    return !!session && session.state === 'established' && !session.socket.destroyed;
  }

  /** Find an established session by remote router hash. */
  findSessionIdByRouterHash(routerHash: Uint8Array): string | null {
    const target = Buffer.from(routerHash);
    for (const [sessionId, session] of this.sessions) {
      if (
        session.state === 'established' &&
        session.remoteRouterHash &&
        Buffer.compare(session.remoteRouterHash, target) === 0
      ) {
        return sessionId;
      }
    }
    return null;
  }

  getBoundPort(): number | null {
    const addr = this.server?.address();
    return addr && typeof addr === 'object' ? addr.port : null;
  }

  private handleData(sessionId: string, data: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    session.recvBuffer = Buffer.concat([session.recvBuffer, data]);

    try {
      while (true) {
        if (session.state === 'init' && !session.isInitiator) {
          if (!this.tryProcessSessionRequest(sessionId, session)) break;
          continue;
        }
        if (session.state === 'm1_sent' && session.isInitiator) {
          if (!this.tryProcessSessionCreated(sessionId, session)) break;
          continue;
        }
        if (session.state === 'm2_sent' && !session.isInitiator) {
          if (!this.tryProcessSessionConfirmed(sessionId, session)) break;
          continue;
        }
        if (session.state === 'established') {
          if (!this.tryProcessDataFrames(sessionId, session)) break;
          continue;
        }
        break;
      }
    } catch (err) {
      if (DEBUG) console.log(`NTCP2 processing error [${sessionId}] state=${session.state}:`, (err as Error).message);
      logger.warn('NTCP2 processing error', { error: (err as Error).message, sessionId }, 'NTCP2');
      session.socket.destroy();
      this.sessions.delete(sessionId);
    }
  }

  private async sendSessionRequest(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session) throw new Error('session not found');
    if (!session.remoteRouterHash || !session.remoteNtcp2IV || !session.remoteNtcp2Static) {
      throw new Error('remote NTCP2 keys missing');
    }
    if (!this.options.staticPublicKey || !this.options.staticPrivateKey || !this.options.routerInfo) {
      throw new Error('local static keys and routerInfo required for outbound handshake');
    }

    const hs = initializeHandshakeInitiator(session.remoteNtcp2Static);
    const eph = Crypto.generateEphemeralKeyPair();
    hs.ePriv = eph.privateKey;
    hs.ePub = Buffer.from(eph.publicKey);

    if (DEBUG) {
      console.log('NTCP2 m1 remoteStaticKey (s)', session.remoteNtcp2Static.toString('hex'));
      console.log('NTCP2 m1 remoteRouterHash (AES key)', session.remoteRouterHash.toString('hex'));
      console.log('NTCP2 m1 remoteNtcp2IV (AES iv)', session.remoteNtcp2IV.toString('hex'));
      console.log('NTCP2 m1 ePub (X plaintext)', hs.ePub.toString('hex'));
      console.log('NTCP2 m1 h after init', hs.h.toString('hex'));
      console.log('NTCP2 m1 ck after init', hs.ck.toString('hex'));
    }

    // MixHash(epub)
    hs.h = sha256Concat(hs.h, hs.ePub);

    // AES encrypt X with RH_B and IV from RouterAddress option i
    const encX = Crypto.aesEncryptCBC(hs.ePub, session.remoteRouterHash, session.remoteNtcp2IV);
    hs.aesIV2 = encX.subarray(16, 32);

    if (DEBUG) {
      console.log('NTCP2 m1 encX (AES-CBC output)', encX.toString('hex'));
      console.log('NTCP2 m1 h after MixHash(epub)', hs.h.toString('hex'));
    }

    // MixKey(DH(e, rs))
    const dh = Crypto.x25519DiffieHellman(hs.ePriv, session.remoteNtcp2Static);
    if (DEBUG) console.log('NTCP2 m1 DH result', Buffer.from(dh).toString('hex'));
    mixKey(hs, dh);
    if (DEBUG) console.log('NTCP2 m1 derived k', hs.k?.toString('hex'));
    if (DEBUG) console.log('NTCP2 m1 derived ck', hs.ck.toString('hex'));
    if (DEBUG) console.log('NTCP2 m1 ad h', hs.h.toString('hex'));

    // options block
    const padLen = Math.floor(Math.random() * 32);
    const m3p2Len = this.options.routerInfo.length + 20; // routerinfo + block hdr+flag + MAC
    hs.m3p2Len = m3p2Len;

    const opts = Buffer.alloc(16);
    opts.writeUInt8(this.options.netId & 0xff, 0);
    opts.writeUInt8(2, 1); // ver
    opts.writeUInt16BE(padLen, 2);
    opts.writeUInt16BE(m3p2Len, 4);
    opts.writeUInt16BE(0, 6);
    opts.writeUInt32BE(Math.floor((Date.now() + 500) / 1000), 8);
    opts.writeUInt32BE(0, 12);
    if (DEBUG) console.log('NTCP2 m1 opts', opts.toString('hex'));

    const ct1 = encryptWithAd(hs, opts, hs.h, 0);
    if (DEBUG) console.log('NTCP2 m1 ct1', ct1.toString('hex'));
    if (DEBUG) {
      const round = Buffer.from(Crypto.decryptChaCha20Poly1305(hs.k!, nonce12(0), ct1, hs.h));
      console.log('NTCP2 m1 selfcheck pt', round.toString('hex'));
    }
    hs.h = sha256Concat(hs.h, ct1);

    const padding = padLen ? Buffer.from(Crypto.randomBytes(padLen)) : Buffer.alloc(0);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);

    session.hs = hs;
    session.state = 'm1_sent';
    session.socket.write(Buffer.concat([encX, ct1, padding]));
  }

  private tryProcessSessionRequest(sessionId: string, session: NTCP2Session): boolean {
    if (session.recvBuffer.length < 64) return false;
    if (!this.options.routerHash || !this.options.publishedIV || !this.options.staticPrivateKey || !this.options.staticPublicKey) {
      throw new Error('missing inbound NTCP2 keys (routerHash/publishedIV/static keys)');
    }

    // initialize hs once
    if (!session.hs) session.hs = initializeHandshakeResponder(Buffer.from(this.options.staticPublicKey));
    const hs = session.hs;

    const encX = session.recvBuffer.subarray(0, 32);
    const frame = session.recvBuffer.subarray(32, 64);
    if (DEBUG) console.log('NTCP2 m1 recv frame', frame.toString('hex'));

    const x = Crypto.aesDecryptCBC(encX, this.options.routerHash, this.options.publishedIV);
    hs.ePub = x.subarray(0, 32);
    hs.h = sha256Concat(hs.h, hs.ePub);
    hs.aesIV2 = encX.subarray(16, 32);

    const dh = Crypto.x25519DiffieHellman(this.options.staticPrivateKey, hs.ePub);
    mixKey(hs, dh);
    if (DEBUG) console.log('NTCP2 m1 recv derived k', hs.k?.toString('hex'));
    if (DEBUG) console.log('NTCP2 m1 recv ad h', hs.h.toString('hex'));

    let optsPlain: Buffer;
    try {
      optsPlain = decryptWithAd(hs, frame, hs.h, 0);
    } catch (e) {
      throw new Error(`SessionRequest options AEAD failed: ${(e as Error).message}`);
    }
    hs.h = sha256Concat(hs.h, frame);

    const netId = optsPlain.readUInt8(0);
    const ver = optsPlain.readUInt8(1);
    const padLen = optsPlain.readUInt16BE(2);
    hs.m3p2Len = optsPlain.readUInt16BE(4);
    if (netId !== (this.options.netId & 0xff) || ver !== 2) throw new Error('incompatible netId/ver');

    const totalLen = 64 + padLen;
    if (session.recvBuffer.length < totalLen) return false;

    const padding = session.recvBuffer.subarray(64, totalLen);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);

    session.recvBuffer = session.recvBuffer.subarray(totalLen);

    // respond with SessionCreated
    this.sendSessionCreated(sessionId, session);
    session.state = 'm2_sent';
    return true;
  }

  private sendSessionCreated(sessionId: string, session: NTCP2Session): void {
    if (!session.hs) throw new Error('hs missing');
    const hs = session.hs;
    if (!hs.ePub || !hs.aesIV2) throw new Error('missing X or iv2');
    if (!this.options.routerHash || !this.options.staticPrivateKey) throw new Error('missing local keys');

    // generate Bob ephemeral Y
    const eph = Crypto.generateEphemeralKeyPair();
    hs.rPriv = eph.privateKey;
    hs.rPub = Buffer.from(eph.publicKey);

    // AES encrypt Y using AES state from message1 (iv2)
    const encY = Crypto.aesEncryptCBC(hs.rPub, this.options.routerHash, hs.aesIV2);

    // MixHash(Y)
    hs.h = sha256Concat(hs.h, hs.rPub);

    // MixKey(DH(re, e))
    const dh = Crypto.x25519DiffieHellman(hs.rPriv, hs.ePub);
    mixKey(hs, dh);

    const padLen = Math.floor(Math.random() * 32);
    const opts = Buffer.alloc(16);
    opts.writeUInt16BE(padLen, 2); // padlen at bytes 2-3, rest reserved
    opts.writeUInt32BE(Math.floor((Date.now() + 500) / 1000), 8); // tsB at bytes 8-11 (big endian)

    const ct2 = encryptWithAd(hs, opts, hs.h, 0);
    hs.h = sha256Concat(hs.h, ct2);

    const padding = padLen ? Buffer.from(Crypto.randomBytes(padLen)) : Buffer.alloc(0);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);

    session.socket.write(Buffer.concat([encY, ct2, padding]));
  }

  private tryProcessSessionCreated(sessionId: string, session: NTCP2Session): boolean {
    if (!session.hs) throw new Error('hs missing');
    const hs = session.hs;
    if (session.recvBuffer.length < 64) return false;
    if (!session.remoteRouterHash || !hs.aesIV2 || !hs.ePriv || !hs.ePub) throw new Error('missing initiator state');

    const encY = session.recvBuffer.subarray(0, 32);
    const frame = session.recvBuffer.subarray(32, 64);

    const y = Crypto.aesDecryptCBC(encY, session.remoteRouterHash, hs.aesIV2);
    hs.rPub = y.subarray(0, 32);

    hs.h = sha256Concat(hs.h, hs.rPub);

    const dh = Crypto.x25519DiffieHellman(hs.ePriv, hs.rPub);
    mixKey(hs, dh);

    let optsPlain: Buffer;
    try {
      optsPlain = decryptWithAd(hs, frame, hs.h, 0);
    } catch (e) {
      throw new Error(`SessionCreated options AEAD failed: ${(e as Error).message}`);
    }
    hs.h = sha256Concat(hs.h, frame);

    const padLen = optsPlain.readUInt16BE(2);
    const totalLen = 64 + padLen;
    if (session.recvBuffer.length < totalLen) return false;

    const padding = session.recvBuffer.subarray(64, totalLen);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);
    session.recvBuffer = session.recvBuffer.subarray(totalLen);

    // send SessionConfirmed immediately
    this.sendSessionConfirmed(sessionId, session);
    session.state = 'established';
    // Clear the connect timeout so the socket doesn't fire idle 'timeout' events.
    session.socket.setTimeout(0);
    this.emit('established', { sessionId });
    return true;
  }

  private sendSessionConfirmed(sessionId: string, session: NTCP2Session): void {
    if (!session.hs) throw new Error('hs missing');
    const hs = session.hs;
    if (!hs.rPub) throw new Error('missing Y');
    if (!this.options.staticPrivateKey || !this.options.staticPublicKey || !this.options.routerInfo) {
      throw new Error('missing local static keys/routerinfo');
    }

    // Message 3 part 1: Encrypt static pubkey with current k, nonce = 1 (nonce 0 used for msg2 options)
    if (!hs.k) throw new Error('cipher key missing');
    const ctS = encryptWithAd(hs, Buffer.from(this.options.staticPublicKey), hs.h, 1);
    hs.h = sha256Concat(hs.h, ctS);

    // Message 3 part 2: MixKey(DH(s, re))
    const dh = Crypto.x25519DiffieHellman(this.options.staticPrivateKey, hs.rPub);
    mixKey(hs, dh);

    const ri = this.options.routerInfo;
    if (DEBUG && !(this as any)._riDumped) {
      (this as any)._riDumped = true;
      console.log(`NTCP2 m3 RI length=${ri.length}`);
      // Self-verify: Ed25519 signature is last 64 bytes
      const unsigned = ri.subarray(0, ri.length - 64);
      const sig = ri.subarray(ri.length - 64);
      // Extract Ed25519 pubkey from identity: right-aligned in signingKey[128] at offset 256+96=352
      const edPub = ri.subarray(352, 384);
      try {
        const ok = ed25519.verify(sig, unsigned, edPub);
        console.log(`NTCP2 m3 RI self-verify sig=${ok ? 'VALID' : 'INVALID'}`);
      } catch (e) { console.log(`NTCP2 m3 RI self-verify error: ${(e as Error).message}`); }
      // Dump identity cert type and extended info
      const certType = ri.readUInt8(384);
      const certLen = ri.readUInt16BE(385);
      console.log(`NTCP2 m3 RI identity certType=${certType} certLen=${certLen}`);
      if (certType === 5 && certLen === 4) {
        const sigType = ri.readUInt16BE(387);
        const cryptoType = ri.readUInt16BE(389);
        console.log(`NTCP2 m3 RI sigType=${sigType} cryptoType=${cryptoType}`);
      }
      // Published timestamp 
      const pubMs = Number(ri.readBigUInt64BE(391));
      console.log(`NTCP2 m3 RI publishedMs=${pubMs} age=${Math.floor((Date.now() - pubMs)/1000)}s`);
    }
    const blk = Buffer.alloc(4);
    blk.writeUInt8(2, 0);
    blk.writeUInt16BE(1 + ri.length, 1);
    blk.writeUInt8(0, 3);
    const plain = Buffer.concat([blk, ri]);

    const ct3 = encryptWithAd(hs, plain, hs.h, 0);
    hs.h = sha256Concat(hs.h, ct3);

    // derive data phase
    session.dp = deriveDataPhase(hs.ck, hs.h, true);

    session.socket.write(Buffer.concat([ctS, ct3]));
  }

  private tryProcessSessionConfirmed(sessionId: string, session: NTCP2Session): boolean {
    if (!session.hs) throw new Error('hs missing');
    const hs = session.hs;
    const m3p2Len = hs.m3p2Len ?? 0;
    if (!m3p2Len) throw new Error('missing m3p2Len');
    const need = 48 + m3p2Len;
    if (session.recvBuffer.length < need) return false;
    if (!this.options.staticPrivateKey) throw new Error('missing local static priv');
    if (!hs.rPriv || !hs.rPub) throw new Error('missing responder ephemeral');
    if (!hs.k) throw new Error('missing cipher key');

    const part1 = session.recvBuffer.subarray(0, 48);
    const part2 = session.recvBuffer.subarray(48, 48 + m3p2Len);

    // decrypt Alice static
    let sPub: Buffer;
    try {
      sPub = decryptWithAd(hs, part1, hs.h, 1);
    } catch (e) {
      throw new Error(`SessionConfirmed part1 AEAD failed: ${(e as Error).message}`);
    }
    hs.h = sha256Concat(hs.h, part1);
    hs.remoteStatic = sPub.subarray(0, 32);

    // MixKey(DH(e, rs)) for Bob side == DH(rPriv, sPub)
    const dh = Crypto.x25519DiffieHellman(hs.rPriv, hs.remoteStatic);
    mixKey(hs, dh);

    let plain: Buffer;
    try {
      plain = decryptWithAd(hs, part2, hs.h, 0);
    } catch (e) {
      throw new Error(`SessionConfirmed part2 AEAD failed: ${(e as Error).message}`);
    }
    hs.h = sha256Concat(hs.h, part2);

    // minimal parse: look for RouterInfo block
    const blocks = decodeBlocks(plain);
    const riBlk = blocks.find((b) => b.type === 2);
    if (!riBlk) throw new Error('missing routerinfo block');

    try {
      const remoteRouterInfo = RouterInfo.deserialize(riBlk.data.subarray(1));
      session.remoteRouterHash = Buffer.from(remoteRouterInfo.getRouterHash());
    } catch {
      // Keep session established even if RouterInfo parse fails.
    }

    session.dp = deriveDataPhase(hs.ck, hs.h, false);
    session.state = 'established';
    session.recvBuffer = session.recvBuffer.subarray(need);
    this.emit('established', { sessionId });
    return true;
  }

  private tryProcessDataFrames(sessionId: string, session: NTCP2Session): boolean {
    if (!session.dp) return false;
    if (session.recvBuffer.length < 2) return false;

    const dp = session.dp;

    const obf = session.recvBuffer.readUInt16BE(0);
    const len = deobfuscateLength(dp.sipRecv, obf);
    if (len < 16 || len > 65535) throw new Error('invalid frame length');
    if (session.recvBuffer.length < 2 + len) return false;

    const frame = session.recvBuffer.subarray(2, 2 + len);
    session.recvBuffer = session.recvBuffer.subarray(2 + len);

    const plain = decryptDataFrame(dp, frame);
    const blocks = decodeBlocks(plain);
    for (const b of blocks) {
      if (b.type === 4 && b.data.length >= 9) {
        // Termination block: 8 bytes sequence number + 1 byte reason
        const reason = b.data.readUInt8(8);
        const REASONS = [
          'NormalClose','TerminationReceived','IdleTimeout','RouterShutdown',
          'DataPhaseAEADFailure','IncompatibleOptions','IncompatibleSignatureType',
          'ClockSkew','PaddingViolation','AEADFramingError','PayloadFormatError',
          'Message1Error','Message2Error','Message3Error','IntraFrameReadTimeout',
          'RouterInfoSignatureVerificationFail','IncorrectSParameter','Banned'
        ];
        const reasonStr = REASONS[reason] ?? `Unknown(${reason})`;
        if (DEBUG) console.log(`NTCP2 received Termination [${sessionId}] reason=${reason} (${reasonStr})`);
        logger.warn('NTCP2 termination received', { sessionId, reason, reasonStr }, 'NTCP2');
      }
      if (DEBUG && b.type !== 3 && b.type !== 254) {
        console.log(`NTCP2 data block [${sessionId}] type=${b.type} len=${b.data.length}`);
      }
      if (b.type === 3) this.emit('message', { sessionId, data: b.data });
    }
    return session.recvBuffer.length >= 2;
  }

  private handleClose(sessionId: string): void {
    const session = this.sessions.get(sessionId);
    if (DEBUG && session) console.log(`NTCP2 session closed [${sessionId}] state=${session.state}`);
    this.sessions.delete(sessionId);
    this.emit('close', { sessionId });
  }

  private handleError(sessionId: string, err: Error): void {
    // Only emit if session is still tracked; spurious events can fire after
    // the session has been cleaned up (e.g. destroy() emits error then close).
    if (!this.sessions.has(sessionId)) return;
    this.emit('error', { sessionId, error: err });
  }

  /**
   * Extract the remote router's NTCP2 static key (s) and IV (i).
   *
   * IMPORTANT: When multiple NTCP/NTCP2 addresses are present (IPv4/IPv6/Ygg),
   * we MUST prefer the address that matches the host/port we are actually
   * connecting to. Otherwise we might AES-encrypt X/Y with an IV from a
   * different address than the TCP endpoint, which breaks interop with i2pd.
   */
  private extractRemoteNtcp2Keys(ri: RouterInfo, hostHint?: string, portHint?: number): { s: Buffer; i: Buffer } {
    const addrs = ri.addresses.filter(
      (a) => a.transportStyle.toUpperCase().startsWith('NTCP') && a.options.s && a.options.i
    );
    if (!addrs.length) {
      if (DEBUG) {
        console.log(
          'NTCP2 extractRemoteNtcp2Keys: no address with s/i, got:',
          ri.addresses.map((a) => ({
            style: a.transportStyle,
            opts: a.options
          }))
        );
      }
      throw new Error('remote has no NTCP/NTCP2 address with s/i');
    }

    let addr = addrs[0];

    if (hostHint && typeof portHint === 'number') {
      const portStr = String(portHint);
      const match = addrs.find((a) => {
        const h = a.options.host;
        const p = a.options.port != null ? String(a.options.port) : undefined;
        return h === hostHint && p === portStr;
      });
      if (match) {
        addr = match;
      } else if (DEBUG) {
        console.log('NTCP2 extractRemoteNtcp2Keys: no exact addr match for host/port hint', {
          hostHint,
          portHint,
          candidates: addrs.map((a) => ({ host: a.options.host, port: a.options.port }))
        });
      }
    }

    if (!addr) {
      throw new Error('remote has no NTCP/NTCP2 address with s/i');
    }
    const s = i2pBase64Decode(addr.options.s);
    const i = i2pBase64Decode(addr.options.i);
    if (s.length !== 32) throw new Error('invalid remote ntcp2 static key length');
    if (i.length !== 16) throw new Error('invalid remote ntcp2 iv length');
    return { s, i };
  }

  private sendDataFrame(session: NTCP2Session, plain: Buffer): void {
    const dp = session.dp!;
    const frame = encryptDataFrame(dp, plain);
    const obfLen = obfuscateLength(dp.sipSend, frame.length);
    const lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(obfLen, 0);
    session.socket.write(Buffer.concat([lenBuf, frame]));
  }
}

export default NTCP2Transport;

function sha256Concat(h: Buffer, data: Buffer): Buffer {
  return Buffer.from(Crypto.sha256(Buffer.concat([h, data]))) as Buffer;
}

function initializeHandshakeInitiator(rs: Buffer): NTCP2Handshake {
  let h = (Buffer.from(Crypto.sha256(PROTOCOL_NAME)) as Buffer);
  const ck = Buffer.from(h) as Buffer;
  h = (Buffer.from(Crypto.sha256(h)) as Buffer); // MixHash(null prologue)
  h = sha256Concat(h, rs); // MixHash(rs)
  return { h, ck, k: null, nonce: 0, rs };
}

function initializeHandshakeResponder(localStaticPub: Buffer): NTCP2Handshake {
  let h = (Buffer.from(Crypto.sha256(PROTOCOL_NAME)) as Buffer);
  const ck = Buffer.from(h) as Buffer;
  h = (Buffer.from(Crypto.sha256(h)) as Buffer); // prologue
  h = sha256Concat(h, localStaticPub);
  return { h, ck, k: null, nonce: 0, rs: localStaticPub };
}

function mixKey(hs: NTCP2Handshake, ikm: Uint8Array): void {
  const temp = Buffer.from(Crypto.hmacSHA256(hs.ck, ikm));
  const ck = Buffer.from(Crypto.hmacSHA256(temp, Buffer.from([0x01])));
  const k = Buffer.from(Crypto.hmacSHA256(temp, Buffer.concat([ck, Buffer.from([0x02])])));
  hs.ck = ck;
  hs.k = k;
  hs.nonce = 0;
}

function nonce12(n: number): Uint8Array {
  const out = Buffer.alloc(12);
  out.writeBigUInt64LE(BigInt(n), 4);
  return out;
}

function encryptWithAd(hs: NTCP2Handshake, plaintext: Buffer, ad: Buffer, nonce: number): Buffer {
  if (!hs.k) throw new Error('cipher key not set');
  const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(hs.k, nonce12(nonce), plaintext, ad));
  return ct;
}

function decryptWithAd(hs: NTCP2Handshake, ciphertext: Buffer, ad: Buffer, nonce: number): Buffer {
  if (!hs.k) throw new Error('cipher key not set');
  const pt = Buffer.from(Crypto.decryptChaCha20Poly1305(hs.k, nonce12(nonce), ciphertext, ad));
  return pt;
}

function deriveDataPhase(ck: Buffer, h: Buffer, initiator: boolean): NTCP2DataPhase {
  const zerolen = Buffer.alloc(0);
  const tempKey = Buffer.from(Crypto.hmacSHA256(ck, zerolen));

  const k_ab = Buffer.from(Crypto.hmacSHA256(tempKey, Buffer.from([0x01])));
  const k_ba = Buffer.from(Crypto.hmacSHA256(tempKey, Buffer.concat([k_ab, Buffer.from([0x02])])));

  const askMaster = Buffer.from(Crypto.hmacSHA256(tempKey, Buffer.concat([Buffer.from('ask', 'ascii'), Buffer.from([0x01])])));
  const temp2 = Buffer.from(Crypto.hmacSHA256(askMaster, Buffer.concat([h, Buffer.from('siphash', 'ascii')])));
  const sipMaster = Buffer.from(Crypto.hmacSHA256(temp2, Buffer.from([0x01])));

  const temp3 = Buffer.from(Crypto.hmacSHA256(sipMaster, zerolen));
  const sipkeys_ab = Buffer.from(Crypto.hmacSHA256(temp3, Buffer.from([0x01])));
  const sipkeys_ba = Buffer.from(Crypto.hmacSHA256(temp3, Buffer.concat([sipkeys_ab, Buffer.from([0x02])])));

  const sip_ab: SipState = {
    k1: sipkeys_ab.subarray(0, 8),
    k2: sipkeys_ab.subarray(8, 16),
    iv: sipkeys_ab.subarray(16, 24)
  };
  const sip_ba: SipState = {
    k1: sipkeys_ba.subarray(0, 8),
    k2: sipkeys_ba.subarray(8, 16),
    iv: sipkeys_ba.subarray(16, 24)
  };

  const sendKey = initiator ? k_ab : k_ba;
  const recvKey = initiator ? k_ba : k_ab;
  const sipSend = initiator ? sip_ab : sip_ba;
  const sipRecv = initiator ? sip_ba : sip_ab;

  return { sendKey, recvKey, sendNonce: 0, recvNonce: 0, sipSend: { ...sipSend }, sipRecv: { ...sipRecv } };
}

function nextSipMask(sip: SipState): number {
  // IV[n] = SipHash(IV[n-1]); mask = first 2 bytes of IV[n]
  const digest = Crypto.siphash24(sip.k1, sip.k2, sip.iv);
  const next = Buffer.alloc(8);
  next.writeBigUInt64LE(digest, 0);
  sip.iv = next;
  return next.readUInt16LE(0);
}

function obfuscateLength(sip: SipState, length: number): number {
  const mask = nextSipMask(sip);
  return (length ^ mask) & 0xffff;
}

function deobfuscateLength(sip: SipState, obf: number): number {
  const mask = nextSipMask(sip);
  return (obf ^ mask) & 0xffff;
}

function encryptDataFrame(dp: NTCP2DataPhase, plain: Buffer): Buffer {
  const ct = Buffer.from(Crypto.encryptChaCha20Poly1305(dp.sendKey, nonce12(dp.sendNonce), plain, Buffer.alloc(0)));
  dp.sendNonce++;
  return ct;
}

function decryptDataFrame(dp: NTCP2DataPhase, frame: Buffer): Buffer {
  const pt = Buffer.from(Crypto.decryptChaCha20Poly1305(dp.recvKey, nonce12(dp.recvNonce), frame, Buffer.alloc(0)));
  dp.recvNonce++;
  return pt;
}

type Block = { type: number; data: Buffer };

function encodeBlocks(blocks: Block[]): Buffer {
  const parts: Buffer[] = [];
  for (const b of blocks) {
    const hdr = Buffer.alloc(3);
    hdr.writeUInt8(b.type & 0xff, 0);
    hdr.writeUInt16BE(b.data.length, 1);
    parts.push(hdr, b.data);
  }
  return Buffer.concat(parts);
}

function decodeBlocks(plain: Buffer): Block[] {
  const out: Block[] = [];
  let off = 0;
  while (off + 3 <= plain.length) {
    const type = plain.readUInt8(off);
    const len = plain.readUInt16BE(off + 1);
    off += 3;
    if (off + len > plain.length) break;
    out.push({ type, data: plain.subarray(off, off + len) });
    off += len;
  }
  return out;
}

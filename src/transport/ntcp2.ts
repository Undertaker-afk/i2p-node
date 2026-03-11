import { Socket, createServer, Server } from 'net';
import { EventEmitter } from 'events';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';
import { parseI2PRouterInfo } from '../data/router-info-i2p.js';
import { logger } from '../utils/logger.js';
import { i2pBase64Decode } from '../i2p/base64.js';

type SessionState = 'init' | 'm1_sent' | 'm2_sent' | 'm2_recv' | 'm3_sent' | 'm3_recv' | 'established';

const DEBUG = process.env.NTCP2_DEBUG === '1';

export interface NTCP2Options {
  host?: string;
  port?: number;
  routerHash?: Uint8Array;
  publishedIV?: Uint8Array;
  staticPrivateKey?: Uint8Array;
  staticPublicKey?: Uint8Array;
  routerInfo?: Buffer;
  netId?: number;
  connectTimeoutMs?: number;
}

interface NTCP2Handshake {
  h: Buffer;
  ck: Buffer;
  k: Buffer | null;
  nonce: number;
  ePriv?: Uint8Array;
  ePub?: Buffer;
  rPriv?: Uint8Array;
  rPub?: Buffer;
  rs?: Buffer;
  remoteStatic?: Buffer;
  aesIV2?: Buffer;
  m3p2Len?: number;
}

interface SipState {
  k1: Buffer;
  k2: Buffer;
  iv: Buffer;
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
    this.setMaxListeners(100);
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
    const session: NTCP2Session = { socket, state: 'init', isInitiator: false, recvBuffer: Buffer.alloc(0) };
    this.sessions.set(sessionId, session);
    socket.on('data', (data) => this.handleData(sessionId, data));
    socket.on('close', () => this.handleClose(sessionId));
    socket.on('error', (err) => this.handleError(sessionId, err));
  }

  async connect(host: string, port: number, remoteRouterInfo: RouterInfo): Promise<void> {
    const { s, i } = this.extractRemoteNtcp2Keys(remoteRouterInfo, host, port);
    const remoteRouterHash = Buffer.from(remoteRouterInfo.getRouterHash());
    const sessionId = `${host}:${port}`;
    const existing = this.sessions.get(sessionId);
    if (existing && existing.state === 'established' && !existing.socket.destroyed) return;
    if (existing) { existing.socket.destroy(); this.sessions.delete(sessionId); }

    return new Promise((resolve, reject) => {
      const socket = new Socket();
      const timeoutMs = this.options.connectTimeoutMs ?? 8000;
      socket.setTimeout(timeoutMs);
      const session: NTCP2Session = { socket, state: 'init', isInitiator: true, recvBuffer: Buffer.alloc(0), remoteRouterHash, remoteNtcp2IV: i, remoteNtcp2Static: s };
      this.sessions.set(sessionId, session);

      let settled = false;
      const fail = (err: unknown) => { if (settled) return; settled = true; cleanup(); reject(err instanceof Error ? err : new Error(String(err))); };
      const succeed = () => { if (settled) return; settled = true; cleanup(); resolve(); };

      const onClose = () => fail(new Error('socket closed before handshake established'));
      const onError = (err: Error) => fail(err);
      const onTimeout = () => { socket.destroy(new Error('connect timeout')); };
      const onEstablished = ({ sessionId: sid }: { sessionId: string }) => { if (sid === sessionId) succeed(); };
      const cleanup = () => { socket.off('close', onClose); socket.off('error', onError); socket.off('timeout', onTimeout); this.off('established', onEstablished); };

      socket.on('close', onClose); socket.on('error', onError); socket.on('timeout', onTimeout); this.on('established', onEstablished);
      socket.on('data', (data) => this.handleData(sessionId, data)); socket.on('close', () => this.handleClose(sessionId)); socket.on('error', (err) => this.handleError(sessionId, err));

      socket.connect(port, host, async () => { try { await this.sendSessionRequest(sessionId); } catch (e) { fail(e); } });
    });
  }

  send(sessionId: string, data: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (!session || session.state !== 'established' || !session.dp) return;
    const framePlain = encodeBlocks([{ type: 3, data }]);
    this.sendDataFrame(session, framePlain);
  }

  findSessionIdByRouterHash(routerHash: Uint8Array): string | null {
    const target = Buffer.from(routerHash);
    for (const [sessionId, session] of this.sessions) {
      if (session.state === 'established' && session.remoteRouterHash && Buffer.compare(session.remoteRouterHash, target) === 0) return sessionId;
    }
    return null;
  }

  private handleData(sessionId: string, data: Buffer): void {
    const session = this.sessions.get(sessionId);
    if (!session) return;
    session.recvBuffer = Buffer.concat([session.recvBuffer, data]);
    try {
      while (true) {
        if (session.state === 'init' && !session.isInitiator) { if (!this.tryProcessSessionRequest(sessionId, session)) break; continue; }
        if (session.state === 'm1_sent' && session.isInitiator) { if (!this.tryProcessSessionCreated(sessionId, session)) break; continue; }
        if (session.state === 'm2_sent' && !session.isInitiator) { if (!this.tryProcessSessionConfirmed(sessionId, session)) break; continue; }
        if (session.state === 'established') { if (!this.tryProcessDataFrames(sessionId, session)) break; continue; }
        break;
      }
    } catch (err) { logger.warn('NTCP2 processing error', { error: (err as Error).message, sessionId }, 'NTCP2'); session.socket.destroy(); this.sessions.delete(sessionId); }
  }

  private async sendSessionRequest(sessionId: string): Promise<void> {
    const session = this.sessions.get(sessionId);
    if (!session || !session.remoteRouterHash || !session.remoteNtcp2IV || !session.remoteNtcp2Static) throw new Error('remote keys missing');
    if (!this.options.staticPublicKey || !this.options.staticPrivateKey || !this.options.routerInfo) throw new Error('local keys missing');

    const hs = initializeHandshakeInitiator(session.remoteNtcp2Static);
    const eph = Crypto.generateKeyPair();
    hs.ePriv = eph.privateKey;
    hs.ePub = eph.publicKey;
    hs.h = sha256Concat(hs.h, hs.ePub);
    const encX = Crypto.aesEncryptCBC(hs.ePub, session.remoteRouterHash as any, session.remoteNtcp2IV as any);
    hs.aesIV2 = Buffer.from(encX.subarray(16, 32));
    const dh = Crypto.x25519DiffieHellman(hs.ePriv, session.remoteNtcp2Static as any);
    mixKey(hs, dh);
    const padLen = Math.floor(Math.random() * 32);
    const m3p2Len = this.options.routerInfo.length + 20;
    hs.m3p2Len = m3p2Len;
    const opts = Buffer.alloc(16);
    opts.writeUInt8(this.options.netId & 0xff, 0); opts.writeUInt8(2, 1); opts.writeUInt16BE(padLen, 2); opts.writeUInt16BE(m3p2Len, 4); opts.writeUInt32BE(Math.floor((Date.now() + 500) / 1000), 8);
    const ct1 = encryptWithAd(hs, opts, hs.h, 0);
    hs.h = sha256Concat(hs.h, ct1);
    const padding = padLen ? Crypto.randomBytes(padLen) : Buffer.alloc(0);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);
    session.hs = hs; session.state = 'm1_sent';
    session.socket.write(Buffer.concat([encX, ct1, padding]));
  }

  private tryProcessSessionRequest(sessionId: string, session: NTCP2Session): boolean {
    if (session.recvBuffer.length < 64) return false;
    if (!this.options.routerHash || !this.options.publishedIV || !this.options.staticPrivateKey || !this.options.staticPublicKey) throw new Error('missing inbound keys');
    if (!session.hs) session.hs = initializeHandshakeResponder(Buffer.from(this.options.staticPublicKey));
    const hs = session.hs;
    const encX = session.recvBuffer.subarray(0, 32), frame = session.recvBuffer.subarray(32, 64);
    const x = Crypto.aesDecryptCBC(encX, Buffer.from(this.options.routerHash), Buffer.from(this.options.publishedIV));
    hs.ePub = Buffer.from(x.subarray(0, 32)); hs.h = sha256Concat(hs.h, hs.ePub); hs.aesIV2 = Buffer.from(encX.subarray(16, 32));
    const dh = Crypto.x25519DiffieHellman(Buffer.from(this.options.staticPrivateKey), hs.ePub);
    mixKey(hs, dh);
    let optsPlain: Buffer;
    try { optsPlain = decryptWithAd(hs, frame, hs.h, 0); } catch (e) { throw new Error('SessionRequest AEAD failed'); }
    hs.h = sha256Concat(hs.h, frame);
    const netId = optsPlain.readUInt8(0), ver = optsPlain.readUInt8(1), padLen = optsPlain.readUInt16BE(2);
    hs.m3p2Len = optsPlain.readUInt16BE(4);
    if (netId !== (this.options.netId & 0xff) || ver !== 2) throw new Error('incompatible netId/ver');
    const totalLen = 64 + padLen;
    if (session.recvBuffer.length < totalLen) return false;
    const padding = session.recvBuffer.subarray(64, totalLen);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);
    session.recvBuffer = session.recvBuffer.subarray(totalLen);
    this.sendSessionCreated(sessionId, session);
    session.state = 'm2_sent';
    return true;
  }

  private sendSessionCreated(sessionId: string, session: NTCP2Session): void {
    if (!session.hs || !session.hs.ePub || !session.hs.aesIV2 || !this.options.routerHash || !this.options.staticPrivateKey) throw new Error('hs state missing');
    const hs = session.hs;
    const eph = Crypto.generateKeyPair(); hs.rPriv = eph.privateKey; hs.rPub = eph.publicKey;
    const encY = Crypto.aesEncryptCBC(hs.rPub!, Buffer.from(this.options.routerHash), hs.aesIV2 as any);
    hs.h = sha256Concat(hs.h, hs.rPub!);
    const dh = Crypto.x25519DiffieHellman(hs.rPriv!, hs.ePub!);
    mixKey(hs, dh);
    const padLen = Math.floor(Math.random() * 32), opts = Buffer.alloc(16);
    opts.writeUInt16BE(padLen, 2); opts.writeUInt32BE(Math.floor((Date.now() + 500) / 1000), 8);
    const ct2 = encryptWithAd(hs, opts, hs.h, 0);
    hs.h = sha256Concat(hs.h, ct2);
    const padding = padLen ? Crypto.randomBytes(padLen) : Buffer.alloc(0);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);
    session.socket.write(Buffer.concat([encY, ct2, padding]));
  }

  private tryProcessSessionCreated(sessionId: string, session: NTCP2Session): boolean {
    if (!session.hs) throw new Error('hs missing');
    const hs = session.hs;
    if (session.recvBuffer.length < 64) return false;
    if (!session.remoteRouterHash || !hs.aesIV2 || !hs.ePriv || !hs.ePub) throw new Error('missing initiator state');
    const encY = session.recvBuffer.subarray(0, 32), frame = session.recvBuffer.subarray(32, 64);
    const y = Crypto.aesDecryptCBC(encY, session.remoteRouterHash as any, hs.aesIV2 as any);
    hs.rPub = Buffer.from(y.subarray(0, 32)); hs.h = sha256Concat(hs.h, hs.rPub);
    const dh = Crypto.x25519DiffieHellman(hs.ePriv!, hs.rPub as any);
    mixKey(hs, dh);
    let optsPlain: Buffer;
    try { optsPlain = decryptWithAd(hs, frame, hs.h, 0); } catch (e) { throw new Error('SessionCreated AEAD failed'); }
    hs.h = sha256Concat(hs.h, frame);
    const padLen = optsPlain.readUInt16BE(2), totalLen = 64 + padLen;
    if (session.recvBuffer.length < totalLen) return false;
    const padding = session.recvBuffer.subarray(64, totalLen);
    if (padding.length) hs.h = sha256Concat(hs.h, padding);
    session.recvBuffer = session.recvBuffer.subarray(totalLen);
    this.sendSessionConfirmed(sessionId, session);
    session.state = 'established'; session.socket.setTimeout(0);
    this.emit('established', { sessionId });
    return true;
  }

  private sendSessionConfirmed(sessionId: string, session: NTCP2Session): void {
    if (!session.hs || !session.hs.rPub || !this.options.staticPrivateKey || !this.options.staticPublicKey || !this.options.routerInfo) throw new Error('hs state missing');
    const hs = session.hs;
    const ctS = encryptWithAd(hs, Buffer.from(this.options.staticPublicKey), hs.h, 1);
    hs.h = sha256Concat(hs.h, ctS);
    const dh = Crypto.x25519DiffieHellman(Buffer.from(this.options.staticPrivateKey), hs.rPub as any);
    mixKey(hs, dh);
    const ri = this.options.routerInfo;
    const blk = Buffer.alloc(4); blk.writeUInt8(2, 0); blk.writeUInt16BE(1 + ri.length, 1); blk.writeUInt8(0, 3);
    const plain = Buffer.concat([blk, ri]);
    const ct3 = encryptWithAd(hs, plain, hs.h, 0);
    hs.h = sha256Concat(hs.h, ct3);
    session.dp = deriveDataPhase(hs.ck, hs.h, true);
    session.socket.write(Buffer.concat([ctS, ct3]));
  }

  private tryProcessSessionConfirmed(sessionId: string, session: NTCP2Session): boolean {
    if (!session.hs || session.hs.m3p2Len === undefined || !this.options.staticPrivateKey || !session.hs.rPriv) throw new Error('hs state missing');
    const hs = session.hs, need = 48 + hs.m3p2Len!;
    if (session.recvBuffer.length < need) return false;
    const part1 = session.recvBuffer.subarray(0, 48), part2 = session.recvBuffer.subarray(48, 48 + hs.m3p2Len!);
    let sPub: Buffer;
    try { sPub = decryptWithAd(hs, part1, hs.h, 1); } catch (e) { throw new Error('SessionConfirmed part1 failed'); }
    hs.h = sha256Concat(hs.h, part1); hs.remoteStatic = Buffer.from(sPub.subarray(0, 32));
    const dh = Crypto.x25519DiffieHellman(hs.rPriv!, hs.remoteStatic as any);
    mixKey(hs, dh);
    let plain: Buffer;
    try { plain = decryptWithAd(hs, part2, hs.h, 0); } catch (e) { throw new Error('SessionConfirmed part2 failed'); }
    hs.h = sha256Concat(hs.h, part2);
    const blocks = decodeBlocks(plain), riBlk = blocks.find((b) => b.type === 2);
    if (!riBlk) throw new Error('missing routerinfo block');
    const remoteRouterInfo = parseI2PRouterInfo(riBlk.data.subarray(1));
    if (remoteRouterInfo) session.remoteRouterHash = Buffer.from(remoteRouterInfo.getRouterHash());
    session.dp = deriveDataPhase(hs.ck, hs.h, false);
    session.state = 'established'; session.recvBuffer = session.recvBuffer.subarray(need);
    this.emit('established', { sessionId });
    return true;
  }

  private tryProcessDataFrames(sessionId: string, session: NTCP2Session): boolean {
    if (!session.dp || session.recvBuffer.length < 2) return false;
    const dp = session.dp, obf = session.recvBuffer.readUInt16BE(0), len = deobfuscateLength(dp.sipRecv, obf);
    if (len < 16 || len > 65535) throw new Error('invalid frame length');
    if (session.recvBuffer.length < 2 + len) return false;
    const frame = session.recvBuffer.subarray(2, 2 + len); session.recvBuffer = session.recvBuffer.subarray(2 + len);
    const plain = decryptDataFrame(dp, frame), blocks = decodeBlocks(plain);
    for (const b of blocks) { if (b.type === 3) this.emit('message', { sessionId, data: b.data }); }
    return session.recvBuffer.length >= 2;
  }

  private handleClose(sessionId: string): void { this.sessions.delete(sessionId); this.emit('close', { sessionId }); }
  private handleError(sessionId: string, err: Error): void { if (!this.sessions.has(sessionId)) return; this.emit('error', { sessionId, error: err }); }

  private extractRemoteNtcp2Keys(ri: RouterInfo, hostHint?: string, portHint?: number): { s: Buffer; i: Buffer } {
    const addrs = ri.addresses.filter((a) => a.transportStyle.toUpperCase().startsWith('NTCP') && a.options.s && a.options.i);
    if (!addrs.length) throw new Error('remote has no NTCP2 keys');
    let addr = addrs[0];
    if (hostHint && typeof portHint === 'number') { const portStr = String(portHint); const match = addrs.find((a) => a.options.host === hostHint && String(a.options.port) === portStr); if (match) addr = match; }
    const s = i2pBase64Decode(addr.options.s), i = i2pBase64Decode(addr.options.i);
    return { s: Buffer.from(s), i: Buffer.from(i) };
  }

  private sendDataFrame(session: NTCP2Session, plain: Buffer): void {
    const dp = session.dp!;
    const frame = encryptDataFrame(dp, plain), obfLen = obfuscateLength(dp.sipSend, frame.length), lenBuf = Buffer.alloc(2);
    lenBuf.writeUInt16BE(obfLen, 0); session.socket.write(Buffer.concat([lenBuf, frame]));
  }
}

export default NTCP2Transport;

function sha256Concat(h: Buffer, data: Buffer): Buffer { return Crypto.sha256(Buffer.concat([h, data])); }
function initializeHandshakeInitiator(rs: Buffer): NTCP2Handshake {
  let h = Crypto.sha256(PROTOCOL_NAME); const ck = Buffer.from(h); h = Crypto.sha256(h); h = sha256Concat(h, rs);
  return { h, ck, k: null, nonce: 0, rs };
}
function initializeHandshakeResponder(localStaticPub: Buffer): NTCP2Handshake {
  let h = Crypto.sha256(PROTOCOL_NAME); const ck = Buffer.from(h); h = Crypto.sha256(h); h = sha256Concat(h, localStaticPub);
  return { h, ck, k: null, nonce: 0, rs: localStaticPub };
}
function mixKey(hs: NTCP2Handshake, ikm: Uint8Array): void {
  const temp = Crypto.hmacSHA256(hs.ck, ikm), ck = Crypto.hmacSHA256(temp, Buffer.from([0x01])), k = Crypto.hmacSHA256(temp, Buffer.concat([ck, Buffer.from([0x02])]));
  hs.ck = Buffer.from(ck); hs.k = Buffer.from(k); hs.nonce = 0;
}
function nonce12(n: number): Uint8Array { const out = Buffer.alloc(12); out.writeBigUInt64LE(BigInt(n), 4); return out; }
function encryptWithAd(hs: NTCP2Handshake, plaintext: Buffer, ad: Buffer, nonce: number): Buffer { return Crypto.encryptChaCha20Poly1305(hs.k!, nonce12(nonce), plaintext, ad); }
function decryptWithAd(hs: NTCP2Handshake, ciphertext: Buffer, ad: Buffer, nonce: number): Buffer { return Crypto.decryptChaCha20Poly1305(hs.k!, nonce12(nonce), ciphertext, ad); }
function deriveDataPhase(ck: Buffer, h: Buffer, initiator: boolean): NTCP2DataPhase {
  const zerolen = Buffer.alloc(0), tempKey = Crypto.hmacSHA256(ck, zerolen);
  const k_ab = Crypto.hmacSHA256(tempKey, Buffer.from([0x01])), k_ba = Crypto.hmacSHA256(tempKey, Buffer.concat([k_ab, Buffer.from([0x02])]));
  const askMaster = Crypto.hmacSHA256(tempKey, Buffer.concat([Buffer.from('ask', 'ascii'), Buffer.from([0x01])]));
  const temp2 = Crypto.hmacSHA256(askMaster, Buffer.concat([h, Buffer.from('siphash', 'ascii')])), sipMaster = Crypto.hmacSHA256(temp2, Buffer.from([0x01]));
  const temp3 = Crypto.hmacSHA256(sipMaster, zerolen), sipkeys_ab = Crypto.hmacSHA256(temp3, Buffer.from([0x01])), sipkeys_ba = Crypto.hmacSHA256(temp3, Buffer.concat([sipkeys_ab, Buffer.from([0x02])]));
  const sip_ab = { k1: sipkeys_ab.subarray(0, 8), k2: sipkeys_ab.subarray(8, 16), iv: sipkeys_ab.subarray(16, 24) };
  const sip_ba = { k1: sipkeys_ba.subarray(0, 8), k2: sipkeys_ba.subarray(8, 16), iv: sipkeys_ba.subarray(16, 24) };
  return { sendKey: initiator ? k_ab : k_ba, recvKey: initiator ? k_ba : k_ab, sendNonce: 0, recvNonce: 0, sipSend: { ... (initiator ? sip_ab : sip_ba) } as any, sipRecv: { ... (initiator ? sip_ba : sip_ab) } as any };
}
function nextSipMask(sip: SipState): number {
  const digest = Crypto.siphash24(sip.k1, sip.k2, sip.iv), next = Buffer.alloc(8);
  next.writeBigUInt64LE(digest, 0); sip.iv = next; return next.readUInt16LE(0);
}
function obfuscateLength(sip: SipState, length: number): number { return (length ^ nextSipMask(sip)) & 0xffff; }
function deobfuscateLength(sip: SipState, obf: number): number { return (obf ^ nextSipMask(sip)) & 0xffff; }
function encryptDataFrame(dp: NTCP2DataPhase, plain: Buffer): Buffer { const ct = Crypto.encryptChaCha20Poly1305(dp.sendKey, nonce12(dp.sendNonce++), plain, Buffer.alloc(0)); return ct; }
function decryptDataFrame(dp: NTCP2DataPhase, frame: Buffer): Buffer { const pt = Crypto.decryptChaCha20Poly1305(dp.recvKey, nonce12(dp.recvNonce++), frame, Buffer.alloc(0)); return pt; }
type Block = { type: number; data: Buffer };
function encodeBlocks(blocks: Block[]): Buffer {
  const parts: Buffer[] = [];
  for (const b of blocks) { const hdr = Buffer.alloc(3); hdr.writeUInt8(b.type & 0xff, 0); hdr.writeUInt16BE(b.data.length, 1); parts.push(hdr, b.data); }
  return Buffer.concat(parts);
}
function decodeBlocks(plain: Buffer): Block[] {
  const out: Block[] = []; let off = 0;
  while (off + 3 <= plain.length) { const type = plain.readUInt8(off), len = plain.readUInt16BE(off + 1); off += 3; if (off + len > plain.length) break; out.push({ type, data: plain.subarray(off, off + len) }); off += len; }
  return out;
}

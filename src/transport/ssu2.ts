/**
 * SSU2 (Secure Semi-reliable UDP) Transport — spec-compliant implementation.
 *
 * References:
 *   - https://i2p.net/en/docs/transport/ssu2
 *   - PurpleI2P/i2pd SSU2 implementation
 *
 * Handshake: Noise XK with extensions
 *   protocol = "Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256"
 *
 * Message flow (no cached token):
 *   Alice → Bob: TokenRequest
 *   Bob → Alice: Retry (with token)
 *   Alice → Bob: SessionRequest (with token)
 *   Bob → Alice: SessionCreated
 *   Alice → Bob: SessionConfirmed (with Alice's RouterInfo)
 *   Both ↔ Data packets
 */

import { createSocket, Socket, RemoteInfo } from 'dgram';
import { EventEmitter } from 'events';
import { chacha20 } from '@noble/ciphers/chacha';
import { Crypto } from '../crypto/index.js';
import { RouterInfo } from '../data/router-info.js';
import { i2pBase64Decode } from '../i2p/base64.js';

// ─── Message types ──────────────────────────────────────────────────────────
const MSG_SESSION_REQUEST   = 0;
const MSG_SESSION_CREATED   = 1;
const MSG_SESSION_CONFIRMED = 2;
const MSG_DATA              = 6;
const MSG_RETRY             = 9;
const MSG_TOKEN_REQUEST     = 10;

// ─── Block types ────────────────────────────────────────────────────────────
const BLK_DATETIME          =   0;
const BLK_ROUTERINFO        =   2;
const BLK_I2NP              =   3;
const BLK_TERMINATION       =   6;
const BLK_ACK               =  12;
const BLK_ADDRESS           =  13;
const BLK_NEW_TOKEN         =  17;
const BLK_PADDING           = 254;

// ─── Constants ──────────────────────────────────────────────────────────────
const PROTOCOL_NAME = Buffer.from(
  'Noise_XKchaobfse+hs1+hs2+hs3_25519_ChaChaPoly_SHA256', 'ascii'
);
const PROTOCOL_VERSION = 2;

// Handshake retransmit intervals (ms)
const RETRANSMIT_1 = 1250;
const RETRANSMIT_2 = 2500;
const RETRANSMIT_3 = 5000;
const HANDSHAKE_TIMEOUT = 15000;

// ─── Public types ────────────────────────────────────────────────────────────

export interface SSU2Options {
  host?: string;
  port?: number;
  /** Our X25519 static private key (32 bytes). */
  staticPrivateKey?: Uint8Array;
  /** Our X25519 static public key (32 bytes). */
  staticPublicKey?: Uint8Array;
  /** Our 32-byte introduction key (published in our RI address option 'i'). */
  introKey?: Uint8Array;
  /** Wire-format RouterInfo to send in SessionConfirmed (as Alice). */
  routerInfo?: Buffer;
  /** Network ID (2 = mainline). */
  netId?: number;
}

type SessionState =
  | 'init'
  | 'token_request_sent'
  | 'request_sent'
  | 'created_sent'
  | 'confirmed_sent'
  | 'established';

/** Internal Noise handshake state */
interface NoiseState {
  h: Buffer;        // chaining hash
  ck: Buffer;       // chaining key
  k: Buffer | null; // current AEAD key
  n: number;        // AEAD nonce counter

  ePriv?: Buffer;   // our ephemeral private key
  ePub?: Buffer;    // our ephemeral public key (32 bytes, unobfuscated)
  rEPub?: Buffer;   // remote ephemeral public key

  // saved for SessionConfirmed construction (Alice side)
  kFromSR?: Buffer; // k derived in SessionRequest KDF (used in SC part 1)
  // derived k_header_2 for next message
  kHdr2Next?: Buffer;
}

/** Per-session state */
export interface SSU2Session {
  address: string;
  port: number;
  state: SessionState;
  isInitiator: boolean;

  // Connection IDs
  sendConnId: bigint; // put in Destination field of outgoing packets
  recvConnId: bigint; // expected in Destination field of incoming packets

  // Handshake
  ns: NoiseState;
  remoteStaticKey?: Buffer; // Bob's static pub key (Alice extracts from RI)
  remoteIntroKey?: Buffer;  // remote intro key (used for header protection)

  // Token management
  token: bigint; // current token (0 = none)

  // Data phase
  kSend?: Buffer;      // send key (k_data for our direction)
  kRecv?: Buffer;      // recv key (k_data for their direction)
  kHdr2Send?: Buffer;  // k_header_2 for our outgoing data
  kHdr2Recv?: Buffer;  // k_header_2 for their incoming data
  sendPktNum: number;  // our next outgoing packet number
  recvPktNum: number;  // highest received packet number + 1

  // ACK tracking
  receivedPackets: Set<number>; // packet numbers we've received (for ACK)
  ackedByPeer: Set<number>;     // packet numbers acked by the peer

  // Retransmission
  pendingHandshakePkt?: Buffer; // encrypted handshake packet to retransmit
  retransmitTimer?: ReturnType<typeof setInterval>;
  retransmitCount: number;
  handshakeTimedOut: boolean;
}

// ─── SSU2Transport ──────────────────────────────────────────────────────────

export class SSU2Transport extends EventEmitter {
  private socket: Socket | null = null;
  // sessions keyed by "address:port"
  private sessions: Map<string, SSU2Session> = new Map();
  // lookup by recvConnId (bigint → session key)
  private byRecvConnId: Map<bigint, string> = new Map();

  private opts: {
    host: string;
    port: number;
    staticPrivateKey?: Uint8Array;
    staticPublicKey?: Uint8Array;
    introKey?: Uint8Array;
    routerInfo?: Buffer;
    netId: number;
  };

  // token cache: remote "address:port" → {token, expires}
  private tokenCache: Map<string, { token: bigint; expires: number }> = new Map();

  constructor(options: SSU2Options = {}) {
    super();
    this.opts = {
      host:   options.host   ?? '0.0.0.0',
      port:   options.port   ?? 12346,
      netId:  options.netId  ?? 2,
      staticPrivateKey: options.staticPrivateKey,
      staticPublicKey:  options.staticPublicKey,
      introKey:         options.introKey,
      routerInfo:       options.routerInfo,
    };
  }

  // ── Lifecycle ──────────────────────────────────────────────────────────────

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.socket = createSocket('udp4');
      this.socket.on('error', (err) => { this.emit('error', err); reject(err); });
      this.socket.on('message', (msg, rinfo) => this.handleIncoming(msg, rinfo));
      this.socket.bind(this.opts.port, this.opts.host, () => {
        this.emit('listening', { host: this.opts.host, port: this.opts.port });
        resolve();
      });
    });
  }

  stop(): void {
    for (const s of this.sessions.values()) this.clearRetransmit(s);
    this.sessions.clear();
    this.byRecvConnId.clear();
    this.socket?.close();
    this.socket = null;
  }

  // ── Public send API ────────────────────────────────────────────────────────

  /**
   * Connect to a remote router (Alice side).
   * Returns a promise that resolves when the session is established.
   */
  async connect(host: string, port: number, remoteRI: RouterInfo): Promise<void> {
    if (!this.opts.staticPrivateKey || !this.opts.staticPublicKey) {
      throw new Error('SSU2: static keys not configured');
    }
    const key = sessionKey(host, port);
    const existing = this.sessions.get(key);
    if (existing?.state === 'established') return;

    // Extract remote static key and intro key from RI
    const remoteStatic = extractSsu2Key(remoteRI, 's');
    const remoteIntro  = extractSsu2Key(remoteRI, 'i');

    // Generate our two connection IDs
    const sendConnId = randomConnId();
    const recvConnId = randomConnId() | 1n; // ensure different

    // Init Noise state with Bob's static key
    const ns = initNoiseState(remoteStatic);

    // Look up cached token
    const cached = this.tokenCache.get(key);
    const token = cached && cached.expires > Date.now() ? cached.token : 0n;

    const s: SSU2Session = {
      address: host, port,
      state: 'init',
      isInitiator: true,
      sendConnId, recvConnId,
      ns,
      remoteStaticKey: Buffer.from(remoteStatic),
      remoteIntroKey:  Buffer.from(remoteIntro),
      token,
      sendPktNum: 0,
      recvPktNum: 0,
      receivedPackets: new Set(),
      ackedByPeer: new Set(),
      retransmitCount: 0,
      handshakeTimedOut: false,
    };
    this.storeSession(s);

    // Initiate with TokenRequest → (wait for Retry) → SessionRequest
    await this.sendTokenRequest(s);

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.off('established', onEst);
        reject(new Error(`SSU2 connect timeout to ${host}:${port}`));
      }, HANDSHAKE_TIMEOUT + 5000);

      const onEst = ({ sessionId }: { sessionId: string }) => {
        if (sessionId === key) {
          clearTimeout(timer);
          this.off('established', onEst);
          resolve();
        }
      };
      this.on('established', onEst);
    });
  }

  /**
   * Send an I2NP message over an established session.
   */
  sendI2NP(sessionId: string, i2npMsg: Buffer): void {
    const s = this.sessions.get(sessionId);
    if (!s || s.state !== 'established') return;
    const blk = buildI2NPBlock(i2npMsg);
    this.sendDataPacket(s, [blk]);
  }

  // ── Inbound dispatch ────────────────────────────────────────────────────────

  private handleIncoming(raw: Buffer, rinfo: RemoteInfo): void {
    if (raw.length < 40) return; // min SSU2 packet size

    // Try to find the session by the raw connection ID (before decryption).
    // We can't decrypt yet, but we try the known sessions' keys.
    const peer = sessionKey(rinfo.address, rinfo.port);

    // Determine if this could be a new inbound session or matches a known one.
    // Strategy: try each known session's k_header_1 to decrypt the first byte;
    // the type byte (position 12 after decryption) tells us the message type.
    // Optimisation: for known sessions (outbound), we already know which keys to try.

    const known = this.sessions.get(peer);
    if (known) {
      this.dispatchKnownSession(raw, rinfo, known);
      return;
    }

    // Check byRecvConnId for established sessions where remote address changed
    // (connection migration) - skip for now.

    // Potential new inbound session (Bob side): message must be TokenRequest or SessionRequest
    this.tryInboundSession(raw, rinfo);
  }

  private dispatchKnownSession(raw: Buffer, _rinfo: RemoteInfo, s: SSU2Session): void {
    // Try to decrypt the header to read the message type
    const bik = this.getRemoteIntroKey(s);
    const k2 = s.ns.kHdr2Next ?? bik;

    const pkt = Buffer.from(raw); // working copy
    tryUnprotectHeader(pkt, bik, k2, false);

    const msgType = pkt.readUInt8(12);

    switch (msgType) {
      case MSG_SESSION_CREATED:
        if (s.isInitiator && (s.state === 'request_sent')) {
          this.processSessionCreated(s, raw);
        }
        break;
      case MSG_RETRY:
        if (s.isInitiator && (s.state === 'token_request_sent' || s.state === 'request_sent')) {
          this.processRetry(s, raw);
        }
        break;
      case MSG_DATA:
        if (s.state === 'established') {
          this.processData(s, raw);
        }
        break;
      case MSG_SESSION_CONFIRMED:
        if (!s.isInitiator && s.state === 'created_sent') {
          this.processSessionConfirmed(s, raw);
        }
        break;
      default:
        break;
    }
  }

  private tryInboundSession(raw: Buffer, rinfo: RemoteInfo): void {
    if (!this.opts.staticPrivateKey || !this.opts.introKey) return;

    const bik = Buffer.from(this.opts.introKey);
    const pkt = Buffer.from(raw);
    tryUnprotectHeader(pkt, bik, bik, false);
    const msgType = pkt.readUInt8(12);

    if (msgType === MSG_TOKEN_REQUEST) {
      this.handleTokenRequest(raw, rinfo);
    } else if (msgType === MSG_SESSION_REQUEST) {
      this.handleSessionRequest(raw, rinfo);
    }
  }

  // ── Token Request (Alice → Bob) ────────────────────────────────────────────

  private async sendTokenRequest(s: SSU2Session): Promise<void> {
    const bik = this.getRemoteIntroKey(s);
    if (!bik) return; // can't send without intro key

    // Long header: [sendConnId(8)][pktNum(4)][type=10(1)][ver=2(1)][netId(1)][flags=0(1)][recvConnId(8)][token=0(8)]
    const hdr = buildLongHeader(s.sendConnId, s.recvConnId, MSG_TOKEN_REQUEST,
                                this.opts.netId, 0n, randomU32());

    const payload = Buffer.concat([buildDateTimeBlock()]);
    const payloadWithPad = ensureMinPayload(payload);

    // AEAD: k=bik, n=pktNum(32-bit), ad=hdr(32 bytes)
    const pktNum = hdr.readUInt32BE(8);
    const aead = aesEncAD(bik, pktNum, payloadWithPad, hdr);

    const pkt = Buffer.concat([hdr, aead]);
    protectLongHeader(pkt, bik, bik, false);

    s.state = 'token_request_sent';
    s.pendingHandshakePkt = pkt;
    s.retransmitCount = 0;
    this.setupRetransmit(s, RETRANSMIT_1);

    await this.sendRaw(pkt, s.address, s.port);
  }

  // ── Handle Token Request (Bob side) ────────────────────────────────────────

  private handleTokenRequest(raw: Buffer, rinfo: RemoteInfo): void {
    if (!this.opts.introKey) return;
    const bik = Buffer.from(this.opts.introKey);

    // Decrypt header copy to validate
    const pkt = Buffer.from(raw);
    tryUnprotectHeader(pkt, bik, bik, false);

    const ver   = pkt.readUInt8(13);
    const netId = pkt.readUInt8(14);
    if (ver !== PROTOCOL_VERSION || netId !== this.opts.netId) return;

    const destConnId = pkt.readBigUInt64BE(0);
    const srcConnId  = pkt.readBigUInt64BE(16);
    const pktNum     = pkt.readUInt32BE(8);

    // Verify AEAD — AD is the unencrypted (decrypted) header, not raw
    const hdr32 = pkt.subarray(0, 32);
    const aeadData = raw.subarray(32);
    try {
      aesDecAD(bik, pktNum, aeadData, Buffer.from(hdr32));
    } catch {
      return; // invalid
    }

    // Generate a token and respond with Retry.
    // Retry Destination = Alice's Source (srcConnId), Retry Source = Alice's Destination (destConnId)
    const token = randomConnId();
    this.sendRetry(rinfo.address, rinfo.port, srcConnId, destConnId, token);
  }

  // ── Retry (Bob → Alice) ────────────────────────────────────────────────────

  private sendRetry(host: string, port: number,
                    destConnId: bigint, srcConnId: bigint, token: bigint): void {
    if (!this.opts.introKey) return;
    const bik = Buffer.from(this.opts.introKey);

    const hdr = buildLongHeader(destConnId, srcConnId, MSG_RETRY,
                                this.opts.netId, token, randomU32());

    const pktNum = hdr.readUInt32BE(8);
    const payload = ensureMinPayload(Buffer.concat([
      buildDateTimeBlock(),
      buildAddressBlock(host, port),
    ]));
    const aead = aesEncAD(bik, pktNum, payload, hdr);

    const pkt = Buffer.concat([hdr, aead]);
    protectLongHeader(pkt, bik, bik, false);

    this.sendRaw(pkt, host, port).catch(() => {});
  }

  // ── Process Retry (Alice side) ─────────────────────────────────────────────

  private processRetry(s: SSU2Session, raw: Buffer): void {
    const bik = this.getRemoteIntroKey(s);
    if (!bik) return;

    const pkt = Buffer.from(raw);
    tryUnprotectHeader(pkt, bik, bik, false);

    // Read the token from the decrypted header (bytes 24-31)
    const token  = pkt.readBigUInt64BE(24);
    const pktNum = pkt.readUInt32BE(8);

    // Verify AEAD — AD is the unencrypted (decrypted) header
    try {
      aesDecAD(bik, pktNum, raw.subarray(32), Buffer.from(pkt.subarray(0, 32)));
    } catch {
      return;
    }

    // Cache the token
    this.tokenCache.set(sessionKey(s.address, s.port), {
      token,
      expires: Date.now() + 120_000, // 2 minutes
    });
    s.token = token;

    this.clearRetransmit(s);

    // Re-init Noise state (fresh ephemeral for new SessionRequest)
    if (s.remoteStaticKey) {
      s.ns = initNoiseState(s.remoteStaticKey);
    }
    // Send SessionRequest with the new token
    this.sendSessionRequest(s).catch(() => {});
  }

  // ── Session Request (Alice → Bob) ─────────────────────────────────────────

  private async sendSessionRequest(s: SSU2Session): Promise<void> {
    const bik = this.getRemoteIntroKey(s);
    if (!bik || !s.remoteStaticKey) return;
    if (!this.opts.staticPrivateKey) return;

    const ns = s.ns;

    // Generate ephemeral key pair
    const eph = Crypto.generateEphemeralKeyPair();
    ns.ePriv = Buffer.from(eph.privateKey);
    ns.ePub  = Buffer.from(eph.publicKey);

    // Long header (unencrypted):
    //   destConnId=sendConnId, srcConnId=recvConnId, type=0, token=s.token
    const hdr = buildLongHeader(s.sendConnId, s.recvConnId, MSG_SESSION_REQUEST,
                                this.opts.netId, s.token, randomU32());

    // KDF: MixHash(header)
    ns.h = sha256(Buffer.concat([ns.h, hdr]));

    // MixHash(ePub)
    ns.h = sha256(Buffer.concat([ns.h, ns.ePub]));

    // MixKey(DH(e, rs))
    const dh = Buffer.from(Crypto.x25519DiffieHellman(ns.ePriv, s.remoteStaticKey));
    const mk = mixKey(ns.ck, dh);
    ns.ck = mk.ck;
    ns.k  = mk.k;
    ns.n  = 0;
    // Save k_es (from es DH) before it gets overwritten by ee DH in SessionCreated
    ns.kFromSR = Buffer.from(mk.k);

    // Build payload: DateTime + optional padding
    const plainPayload = ensureMinPayload(buildDateTimeBlock());

    // AEAD: k=ns.k, n=0, ad=ns.h
    const nonce0 = makeNonce(ns.n++);
    const aeadPl = Buffer.from(
      Crypto.encryptChaCha20Poly1305(ns.k, nonce0, plainPayload, ns.h)
    );

    // MixHash(ciphertext)
    ns.h = sha256(Buffer.concat([ns.h, aeadPl]));

    // Compute k_header_2 for the upcoming SessionCreated
    ns.kHdr2Next = hkdf32(ns.ck, Buffer.alloc(0), 'SessCreateHeader');

    // Build raw packet: [hdr(32)][ePub(32)][aeadPayload]
    const pkt = Buffer.concat([hdr, ns.ePub, aeadPl]);

    // Obfuscate header and ephemeral key
    protectLongHeader(pkt, bik, bik, true);

    s.state = 'request_sent';
    s.pendingHandshakePkt = pkt;
    s.retransmitCount = 0;
    this.setupRetransmit(s, RETRANSMIT_1);

    await this.sendRaw(pkt, s.address, s.port);
  }

  // ── Handle Session Request (Bob side) ─────────────────────────────────────

  private handleSessionRequest(raw: Buffer, rinfo: RemoteInfo): void {
    if (!this.opts.staticPrivateKey || !this.opts.staticPublicKey || !this.opts.introKey) return;
    if (raw.length < 88) return;

    const bik = Buffer.from(this.opts.introKey);
    const pkt = Buffer.from(raw);
    // Unprotect header (bytes 16-63 also for SR)
    tryUnprotectHeader(pkt, bik, bik, true);

    const ver   = pkt.readUInt8(13);
    const netId = pkt.readUInt8(14);
    if (ver !== PROTOCOL_VERSION || netId !== this.opts.netId) return;

    const destConnId = pkt.readBigUInt64BE(0);
    const srcConnId  = pkt.readBigUInt64BE(16);
    const token      = pkt.readBigUInt64BE(24);

    // Extract ephemeral key (bytes 32-63 of unprotected packet)
    const ePubRemote = pkt.subarray(32, 64);
    const aeadData   = raw.subarray(64); // rest is AEAD-encrypted payload

    // Init Noise from Bob's side
    const bpk = Buffer.from(this.opts.staticPublicKey);
    const bsk = Buffer.from(this.opts.staticPrivateKey);
    const ns = initNoiseState(bpk);

    // The header (unprotected, before any obfuscation) = original hdr 32 bytes
    const hdrOrig = Buffer.from(pkt.subarray(0, 32));

    // KDF: MixHash(header)
    ns.h = sha256(Buffer.concat([ns.h, hdrOrig]));

    // MixHash(ePub)
    ns.h = sha256(Buffer.concat([ns.h, ePubRemote]));

    // MixKey(DH(e, rs) from Bob's side = DH(bsk, ePubRemote))
    const dh = Buffer.from(Crypto.x25519DiffieHellman(bsk, ePubRemote));
    const mk = mixKey(ns.ck, dh);
    ns.ck = mk.ck;
    ns.k  = mk.k;
    ns.n  = 0;
    // Save k_es (from es DH) for use in SessionConfirmed part 1
    ns.kFromSR = Buffer.from(mk.k);

    // Decrypt payload
    const nonce0 = makeNonce(0);
    let plainPayload: Buffer;
    try {
      plainPayload = Buffer.from(
        Crypto.decryptChaCha20Poly1305(ns.k, nonce0, aeadData, ns.h)
      );
    } catch {
      return; // AEAD failure — send Retry? For simplicity, drop.
    }
    ns.n = 1;

    // MixHash(ciphertext)
    ns.h = sha256(Buffer.concat([ns.h, aeadData]));

    // Compute k_header_2 for SessionCreated
    const kHdr2SC = hkdf32(ns.ck, Buffer.alloc(0), 'SessCreateHeader');
    ns.kHdr2Next  = kHdr2SC;

    // Compute k_header_2 for SessionConfirmed (derived after SC)
    // (derived later from ck after ee step)

    // Create session (Bob perspective: our sendConnId = srcConnId from Alice)
    const peer = sessionKey(rinfo.address, rinfo.port);
    const s: SSU2Session = {
      address:    rinfo.address,
      port:       rinfo.port,
      state:      'init',
      isInitiator: false,
      // Bob sends to Alice using Alice's recvConnId (= srcConnId from SR)
      sendConnId: srcConnId,
      // Bob expects Alice to send to his recvConnId (= destConnId from SR)
      recvConnId: destConnId,
      ns,
      remoteIntroKey: undefined, // will need Alice's intro key for data phase
      token: token,
      sendPktNum: 0,
      recvPktNum: 0,
      receivedPackets: new Set(),
      ackedByPeer: new Set(),
      retransmitCount: 0,
      handshakeTimedOut: false,
    };
    ns.ePriv = Buffer.from(ePubRemote); // placeholder (Bob stores Alice's ePub here)
    ns.ePub  = Buffer.from(ePubRemote); // Alice's ePub, needed for KDF

    this.storeSession(s);
    this.emit('connect', { sessionId: peer, address: rinfo.address, port: rinfo.port });

    // Send SessionCreated
    this.sendSessionCreated(s).catch(() => {});

    void plainPayload; // validated but not used yet
  }

  // ── Session Created (Bob → Alice) ─────────────────────────────────────────

  private async sendSessionCreated(s: SSU2Session): Promise<void> {
    if (!this.opts.staticPrivateKey || !this.opts.introKey) return;

    const bik = Buffer.from(this.opts.introKey);
    const ns  = s.ns;
    const aEPub = ns.ePub!; // Alice's ephemeral key (stored in ns.ePub on Bob's side)

    // Save k_header_2 for THIS message (SC) before the ee DH overwrites ns.kHdr2Next
    // kHdr2Next was set in handleSessionRequest: HKDF(ck_after_es, "SessCreateHeader", 32)
    const kHdr2ForSC = ns.kHdr2Next ?? bik;

    // Generate Bob's ephemeral key pair
    const bEph = Crypto.generateEphemeralKeyPair();
    const bePriv = Buffer.from(bEph.privateKey);
    const bEPub  = Buffer.from(bEph.publicKey);

    // Long header
    const hdr = buildLongHeader(s.sendConnId, s.recvConnId, MSG_SESSION_CREATED,
                                this.opts.netId, 0n, randomU32());

    // KDF: MixHash(header)
    ns.h = sha256(Buffer.concat([ns.h, hdr]));

    // MixHash(bEPub)
    ns.h = sha256(Buffer.concat([ns.h, bEPub]));

    // MixKey(DH(be, ae))
    const dh = Buffer.from(Crypto.x25519DiffieHellman(bePriv, aEPub));
    const mk = mixKey(ns.ck, dh);
    ns.ck = mk.ck;
    ns.k  = mk.k;
    ns.n  = 0;

    // Save bePriv for SessionConfirmed processing (se DH)
    ns.ePriv = bePriv;

    // Build payload: DateTime + Address
    const plainPayload = ensureMinPayload(Buffer.concat([
      buildDateTimeBlock(),
      buildAddressBlock(s.address, s.port),
    ]));

    // AEAD: k=ns.k, n=0, ad=ns.h
    const nonce0 = makeNonce(ns.n++);
    const aeadPl = Buffer.from(
      Crypto.encryptChaCha20Poly1305(ns.k, nonce0, plainPayload, ns.h)
    );

    // MixHash(ciphertext)
    ns.h = sha256(Buffer.concat([ns.h, aeadPl]));

    // Compute k_header_2 for the upcoming SessionConfirmed (derived from ck_after_ee)
    const kHdr2SCF = hkdf32(ns.ck, Buffer.alloc(0), 'SessionConfirmed');
    ns.kHdr2Next   = kHdr2SCF;

    // Build raw packet: [hdr(32)][bEPub(32)][aeadPayload]
    const pkt = Buffer.concat([hdr, bEPub, aeadPl]);
    // k_header_1 = Bob's intro key; k_header_2 = kHdr2ForSC (from SR KDF)
    protectLongHeader(pkt, bik, kHdr2ForSC, true);

    s.state = 'created_sent';
    s.pendingHandshakePkt = pkt;
    s.retransmitCount = 0;
    this.setupRetransmit(s, RETRANSMIT_1);

    await this.sendRaw(pkt, s.address, s.port);
  }

  // ── Process Session Created (Alice side) ───────────────────────────────────

  private processSessionCreated(s: SSU2Session, raw: Buffer): void {
    if (raw.length < 88) return;

    const bik = this.getRemoteIntroKey(s);
    if (!bik) return;

    // k_header_2 for SC = derived from chainKey after SR
    const kHdr2SC = s.ns.kHdr2Next ?? bik;

    const pkt = Buffer.from(raw);
    tryUnprotectHeader(pkt, bik, kHdr2SC, true);

    // Extract Bob's ephemeral key Y (bytes 32-63)
    const bEPub  = Buffer.from(pkt.subarray(32, 64));
    const aeadData = raw.subarray(64);

    const ns = s.ns;

    // KDF: MixHash(header)
    const hdrOrig = Buffer.from(pkt.subarray(0, 32));
    ns.h = sha256(Buffer.concat([ns.h, hdrOrig]));

    // MixHash(bEPub)
    ns.h = sha256(Buffer.concat([ns.h, bEPub]));

    // MixKey(DH(ae, be) from Alice's side)
    const dh = Buffer.from(Crypto.x25519DiffieHellman(ns.ePriv!, bEPub));
    const mk = mixKey(ns.ck, dh);
    ns.ck = mk.ck;
    ns.k  = mk.k;
    ns.n  = 0;

    // Decrypt payload
    const nonce0 = makeNonce(0);
    let plainPayload: Buffer;
    try {
      plainPayload = Buffer.from(
        Crypto.decryptChaCha20Poly1305(ns.k, nonce0, aeadData, ns.h)
      );
    } catch {
      return;
    }
    ns.n = 1;

    // MixHash(ciphertext)
    ns.h = sha256(Buffer.concat([ns.h, aeadData]));

    // Save Bob's ePub for SessionConfirmed (we need it for se DH)
    ns.rEPub = bEPub;

    // kFromSR was saved in sendSessionRequest (k from es DH).
    // Do NOT overwrite it here; it will be used in sendSessionConfirmed part 1.

    // Compute k_header_2 for SessionConfirmed
    ns.kHdr2Next = hkdf32(ns.ck, Buffer.alloc(0), 'SessionConfirmed');

    this.clearRetransmit(s);
    this.sendSessionConfirmed(s, plainPayload).catch(() => {});
  }

  // ── Session Confirmed (Alice → Bob) ────────────────────────────────────────

  private async sendSessionConfirmed(s: SSU2Session, _scPayload: Buffer): Promise<void> {
    if (!this.opts.staticPrivateKey || !this.opts.staticPublicKey || !this.opts.introKey) return;
    if (!this.opts.routerInfo) return;

    const bik = this.getRemoteIntroKey(s);
    if (!bik) return;

    const ns = s.ns;
    const ask = Buffer.from(this.opts.staticPrivateKey);
    const apk = Buffer.from(this.opts.staticPublicKey);

    // Short header (16 bytes): [sendConnId(8)][pktNum=0(4)][type=2(1)][frag=0x01(1)][flags=0(2)]
    const hdr = buildShortHeader(s.sendConnId, 0, MSG_SESSION_CONFIRMED);

    // KDF for SC part 1:
    // MixHash(header)
    ns.h = sha256(Buffer.concat([ns.h, hdr]));

    // s message pattern: ENCRYPT(k_es, n=1, apk, h)
    // k_es was saved in sendSessionRequest as ns.kFromSR (before ee DH overwrote ns.k)
    if (!ns.kFromSR) {
      throw new Error('SSU2: missing k_from_sr — es-derived key was not saved');
    }
    const kPart1 = ns.kFromSR;

    const nonce1 = makeNonce(1);
    const ctApk = Buffer.from(
      Crypto.encryptChaCha20Poly1305(kPart1, nonce1, apk, ns.h)
    );

    // MixHash(ciphertext of apk)
    ns.h = sha256(Buffer.concat([ns.h, ctApk]));

    // se message pattern: MixKey(DH(ask, bEPub))
    const dh2 = Buffer.from(Crypto.x25519DiffieHellman(ask, ns.rEPub!));
    const mk2 = mixKey(ns.ck, dh2);
    ns.ck = mk2.ck;
    ns.k  = mk2.k;
    ns.n  = 0;

    // Build payload for part 2: RouterInfo block
    const riBlk = buildRouterInfoBlock(this.opts.routerInfo);
    const plainPayload = ensureMinPayload(riBlk);

    // AEAD part 2: k=ns.k, n=0, ad=ns.h
    const nonce0 = makeNonce(0);
    const aeadPl = Buffer.from(
      Crypto.encryptChaCha20Poly1305(ns.k, nonce0, plainPayload, ns.h)
    );

    // MixHash(ciphertext part 2)
    ns.h = sha256(Buffer.concat([ns.h, aeadPl]));

    // Derive data phase keys via split()
    this.deriveDataPhaseKeys(s);

    // Build packet: [hdr(16)][ctApk(48)][aeadPl]
    const kHdr2SCF = ns.kHdr2Next ?? bik;
    const pkt = Buffer.concat([hdr, ctApk, aeadPl]);
    // Protect with bik as k_header_1, kHdr2SCF as k_header_2
    protectShortHeader(pkt, bik, kHdr2SCF);

    s.state = 'confirmed_sent';
    s.pendingHandshakePkt = pkt;
    s.retransmitCount = 0;
    this.setupRetransmit(s, RETRANSMIT_1);

    await this.sendRaw(pkt, s.address, s.port);

    // Alice's first data packet number starts at 1 (0 = SessionConfirmed)
    s.sendPktNum = 1;

    // After sending SCF, Alice is effectively established
    // (she'll retransmit SCF until she receives Bob's ACK)
    s.state = 'established';
    this.clearRetransmit(s);
    this.emit('established', { sessionId: sessionKey(s.address, s.port) });

    // Send initial ACK
    this.sendAck(s);
  }

  // ── Process Session Confirmed (Bob side) ──────────────────────────────────

  private processSessionConfirmed(s: SSU2Session, raw: Buffer): void {
    if (raw.length < 80) return; // min: 16 hdr + 48 ctApk + 16 MAC

    const bik = Buffer.from(this.opts.introKey!);
    const kHdr2SCF = s.ns.kHdr2Next ?? bik;

    const pkt = Buffer.from(raw);
    tryUnprotectShortHeader(pkt, bik, kHdr2SCF);

    const pktNum = pkt.readUInt32BE(8);
    const ns = s.ns;

    // The header (before decryption) = original bytes 0-15
    const hdrOrig = Buffer.from(pkt.subarray(0, 16));

    // KDF: MixHash(header)
    ns.h = sha256(Buffer.concat([ns.h, hdrOrig]));

    // Part 1: decrypt Alice's static key
    // k = k from Session Request KDF (es step), saved as kFromSR in handleSessionRequest
    const kPart1 = ns.kFromSR ?? ns.k!;
    const ctApk  = raw.subarray(16, 64); // 48 bytes (32 static + 16 MAC)
    const nonce1 = makeNonce(1);
    let apk: Buffer;
    try {
      apk = Buffer.from(
        Crypto.decryptChaCha20Poly1305(kPart1, nonce1, ctApk, ns.h)
      );
    } catch {
      return;
    }

    // MixHash(ctApk)
    ns.h = sha256(Buffer.concat([ns.h, ctApk]));

    // se message pattern: MixKey(DH(besk, apk))
    // besk = ns.ePriv (Bob's ephemeral private key, saved in sendSessionCreated)
    const dh2 = Buffer.from(Crypto.x25519DiffieHellman(ns.ePriv!, apk));
    const mk2 = mixKey(ns.ck, dh2);
    ns.ck = mk2.ck;
    ns.k  = mk2.k;
    ns.n  = 0;

    // Part 2: decrypt payload (RouterInfo + other blocks)
    const aeadPl = raw.subarray(64);
    const nonce0 = makeNonce(0);
    let plainPayload: Buffer;
    try {
      plainPayload = Buffer.from(
        Crypto.decryptChaCha20Poly1305(ns.k, nonce0, aeadPl, ns.h)
      );
    } catch {
      return;
    }

    // Extract Alice's intro key from her RouterInfo if present
    s.remoteIntroKey = extractIntroKeyFromBlocks(plainPayload);

    // Derive data phase keys via split()
    this.deriveDataPhaseKeys(s);

    this.clearRetransmit(s);

    s.receivedPackets.add(pktNum);
    s.state = 'established';
    this.emit('established', { sessionId: sessionKey(s.address, s.port) });

    // Bob sends ACK of packet 0 (SessionConfirmed)
    s.sendPktNum = 0;
    this.sendAck(s);
  }

  // ── Data Phase Keys (split()) ─────────────────────────────────────────────

  private deriveDataPhaseKeys(s: SSU2Session): void {
    const ns = s.ns;
    // split(): derive k_ab and k_ba
    const keydata64 = hkdf64(ns.ck, Buffer.alloc(0), '');
    const kAB = keydata64.subarray(0, 32);
    const kBA = keydata64.subarray(32, 64);

    // For each direction, derive k_data and k_header_2
    const kdAB = hkdf64(kAB, Buffer.alloc(0), 'HKDFSSU2DataKeys');
    const kABData = kdAB.subarray(0, 32);
    const kABHdr2 = kdAB.subarray(32, 64);

    const kdBA = hkdf64(kBA, Buffer.alloc(0), 'HKDFSSU2DataKeys');
    const kBAData = kdBA.subarray(0, 32);
    const kBAHdr2 = kdBA.subarray(32, 64);

    if (s.isInitiator) {
      // Alice sends AB, receives BA
      s.kSend    = Buffer.from(kABData);
      s.kHdr2Send= Buffer.from(kABHdr2);
      s.kRecv    = Buffer.from(kBAData);
      s.kHdr2Recv= Buffer.from(kBAHdr2);
    } else {
      // Bob sends BA, receives AB
      s.kSend    = Buffer.from(kBAData);
      s.kHdr2Send= Buffer.from(kBAHdr2);
      s.kRecv    = Buffer.from(kABData);
      s.kHdr2Recv= Buffer.from(kABHdr2);
    }
  }

  // ── Data Packet ────────────────────────────────────────────────────────────

  private sendDataPacket(s: SSU2Session, blocks: Buffer[]): void {
    if (!s.kSend || !s.kHdr2Send) return;
    const bik = this.getLocalIntroKey();
    const receiverIntroKey = this.getRemoteIntroKey(s) ?? bik;

    const pktNum = s.sendPktNum++;
    const hdr = buildShortHeader(s.sendConnId, pktNum, MSG_DATA);

    const payload = ensureMinPayload(Buffer.concat(blocks));
    const nonce = makeDataNonce(pktNum);
    const aeadPl = Buffer.from(
      Crypto.encryptChaCha20Poly1305(s.kSend, nonce, payload, hdr)
    );

    const pkt = Buffer.concat([hdr, aeadPl]);
    // k_header_1 = receiver's intro key; k_header_2 = s.kHdr2Send
    protectShortHeader(pkt, receiverIntroKey, s.kHdr2Send);

    this.sendRaw(pkt, s.address, s.port).catch(() => {});
  }

  private sendAck(s: SSU2Session): void {
    if (!s.kSend || !s.kHdr2Send) return;
    const received = Array.from(s.receivedPackets).sort((a, b) => b - a);
    if (received.length === 0) {
      // Send empty ack-like padding packet
      this.sendDataPacket(s, [buildPaddingBlock(8)]);
      return;
    }
    const ackBlk = buildAckBlock(received);
    this.sendDataPacket(s, [ackBlk]);
  }

  private processData(s: SSU2Session, raw: Buffer): void {
    if (!s.kRecv || !s.kHdr2Recv) return;

    const bik = this.getLocalIntroKey();
    const kHdr2 = s.kHdr2Recv;

    const pkt = Buffer.from(raw);
    tryUnprotectShortHeader(pkt, bik, kHdr2);

    const pktNum = pkt.readUInt32BE(8);
    const msgType = pkt.readUInt8(12);
    if (msgType !== MSG_DATA) return;

    // Deduplicate
    if (s.receivedPackets.has(pktNum)) return;

    const hdrOrig = Buffer.from(pkt.subarray(0, 16)); // unencrypted header as AD
    const aeadData = raw.subarray(16);
    const nonce = makeDataNonce(pktNum);

    let plainPayload: Buffer;
    try {
      plainPayload = Buffer.from(
        Crypto.decryptChaCha20Poly1305(s.kRecv, nonce, aeadData, hdrOrig)
      );
    } catch {
      return;
    }

    s.receivedPackets.add(pktNum);

    // Parse blocks
    const blocks = parseBlocks(plainPayload);
    const sessionId = sessionKey(s.address, s.port);

    for (const blk of blocks) {
      if (blk.type === BLK_I2NP) {
        this.emit('message', { sessionId, data: blk.data });
      } else if (blk.type === BLK_ACK) {
        this.processAckBlock(s, blk.data);
      } else if (blk.type === BLK_TERMINATION) {
        const reason = blk.data.length >= 9 ? blk.data.readUInt8(8) : 0;
        this.emit('terminated', { sessionId, reason });
        this.closeSession(s);
        return;
      } else if (blk.type === BLK_NEW_TOKEN && blk.data.length >= 12) {
        const expires = blk.data.readUInt32BE(0) * 1000;
        const token   = blk.data.readBigUInt64BE(4);
        this.tokenCache.set(sessionId, { token, expires });
      }
    }

    // Send ACK periodically (after every received packet for simplicity)
    if (s.receivedPackets.size % 4 === 0) {
      this.sendAck(s);
    }
  }

  // ── ACK Processing ─────────────────────────────────────────────────────────

  private processAckBlock(s: SSU2Session, data: Buffer): void {
    if (data.length < 5) return;
    const ackThrough = data.readUInt32BE(0);
    const acnt       = data.readUInt8(4);
    for (let i = ackThrough; i >= Math.max(0, ackThrough - acnt); i--) {
      s.ackedByPeer.add(i);
    }
  }

  // ── Helpers ────────────────────────────────────────────────────────────────

  private storeSession(s: SSU2Session): void {
    const key = sessionKey(s.address, s.port);
    this.sessions.set(key, s);
    this.byRecvConnId.set(s.recvConnId, key);
  }

  private closeSession(s: SSU2Session): void {
    this.clearRetransmit(s);
    const key = sessionKey(s.address, s.port);
    this.sessions.delete(key);
    this.byRecvConnId.delete(s.recvConnId);
  }

  private setupRetransmit(s: SSU2Session, intervalMs: number): void {
    this.clearRetransmit(s);
    s.retransmitTimer = setInterval(() => {
      if (s.handshakeTimedOut) {
        this.clearRetransmit(s);
        return;
      }
      if (!s.pendingHandshakePkt) return;

      s.retransmitCount++;
      if (s.retransmitCount > 3) {
        // Timeout
        s.handshakeTimedOut = true;
        this.clearRetransmit(s);
        this.emit('handshakeTimeout', { sessionId: sessionKey(s.address, s.port) });
        return;
      }

      const nextInterval =
        s.retransmitCount === 1 ? RETRANSMIT_2 :
        s.retransmitCount === 2 ? RETRANSMIT_3 : HANDSHAKE_TIMEOUT;
      clearInterval(s.retransmitTimer);
      s.retransmitTimer = setInterval(() => {
        if (s.pendingHandshakePkt) {
          this.sendRaw(s.pendingHandshakePkt, s.address, s.port).catch(() => {});
        }
      }, nextInterval);

      this.sendRaw(s.pendingHandshakePkt, s.address, s.port).catch(() => {});
    }, intervalMs);
  }

  private clearRetransmit(s: SSU2Session): void {
    if (s.retransmitTimer) {
      clearInterval(s.retransmitTimer);
      s.retransmitTimer = undefined;
    }
  }

  private getRemoteIntroKey(s: SSU2Session): Buffer {
    if (s.remoteIntroKey) return s.remoteIntroKey;
    if (this.opts.introKey) return Buffer.from(this.opts.introKey);
    return Buffer.alloc(32);
  }

  private getLocalIntroKey(): Buffer {
    if (this.opts.introKey) return Buffer.from(this.opts.introKey);
    return Buffer.alloc(32);
  }

  private async sendRaw(data: Buffer, host: string, port: number): Promise<void> {
    if (!this.socket) return;
    return new Promise((resolve, reject) => {
      this.socket!.send(data, port, host, (err) => (err ? reject(err) : resolve()));
    });
  }
}

export default SSU2Transport;

// ═══════════════════════════════════════════════════════════════════════════════
// Noise KDF helpers
// ═══════════════════════════════════════════════════════════════════════════════

function initNoiseState(remoteStaticPub: Uint8Array): NoiseState {
  // h = SHA256(protocol_name)
  let h = sha256(PROTOCOL_NAME);
  // ck = h
  const ck = Buffer.from(h);
  // h = SHA256(h)  [MixHash(null prologue)]
  h = sha256(h);
  // h = SHA256(h || bpk)  [MixHash(remote static key)]
  h = sha256(Buffer.concat([h, Buffer.from(remoteStaticPub)]));

  return { h: Buffer.from(h), ck: Buffer.from(ck), k: null, n: 0 };
}

function mixKey(ck: Buffer, dh: Buffer): { ck: Buffer; k: Buffer } {
  const keydata = Crypto.hkdf(ck, dh, new Uint8Array(0), 64);
  return {
    ck: Buffer.from(keydata.subarray(0, 32)),
    k:  Buffer.from(keydata.subarray(32, 64)),
  };
}

function hkdf32(salt: Buffer, ikm: Buffer, info: string): Buffer {
  const infoBytes = info.length > 0 ? Buffer.from(info, 'ascii') : Buffer.alloc(0);
  return Buffer.from(Crypto.hkdf(salt, ikm, infoBytes, 32));
}

function hkdf64(salt: Buffer, ikm: Buffer, info: string): Buffer {
  const infoBytes = info.length > 0 ? Buffer.from(info, 'ascii') : Buffer.alloc(0);
  return Buffer.from(Crypto.hkdf(salt, ikm, infoBytes, 64));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Header building
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Build a 32-byte long header (unencrypted).
 * Layout: [destConnId(8)][pktNum(4)][type(1)][ver(1)][netId(1)][flags(1)][srcConnId(8)][token(8)]
 */
function buildLongHeader(destConnId: bigint, srcConnId: bigint,
                          msgType: number, netId: number,
                          token: bigint, pktNum: number): Buffer {
  const hdr = Buffer.alloc(32);
  hdr.writeBigUInt64BE(destConnId, 0);
  hdr.writeUInt32BE(pktNum, 8);
  hdr.writeUInt8(msgType, 12);
  hdr.writeUInt8(PROTOCOL_VERSION, 13);
  hdr.writeUInt8(netId & 0xff, 14);
  hdr.writeUInt8(0, 15); // flags
  hdr.writeBigUInt64BE(srcConnId, 16);
  hdr.writeBigUInt64BE(token, 24);
  return hdr;
}

/**
 * Build a 16-byte short header (unencrypted).
 * Layout: [destConnId(8)][pktNum(4)][type(1)][flags(3)]
 */
function buildShortHeader(destConnId: bigint, pktNum: number, msgType: number): Buffer {
  const hdr = Buffer.alloc(16);
  hdr.writeBigUInt64BE(destConnId, 0);
  hdr.writeUInt32BE(pktNum, 8);
  hdr.writeUInt8(msgType, 12);
  // flags = 0 (bytes 13-15)
  return hdr;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Header protection (ChaCha20-based obfuscation)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * Generate 8 bytes of ChaCha20 keystream from key and 12-byte nonce.
 * Used for header mask computation.
 */
function chacha20Keystream8(key: Uint8Array, nonce12: Uint8Array): Uint8Array {
  const zeros = new Uint8Array(8);
  return chacha20(Uint8Array.from(key), Uint8Array.from(nonce12), zeros);
}

/**
 * Encrypt/decrypt an arbitrary length buffer with ChaCha20, nonce = all zeros.
 */
function chacha20ZeroNonce(key: Uint8Array, data: Uint8Array): Uint8Array {
  const nonce = new Uint8Array(12);
  return chacha20(Uint8Array.from(key), nonce, Uint8Array.from(data));
}

/**
 * Apply header protection (encrypt) to a long-header packet.
 * Mutates pkt in place.
 * withEphemeral: true for SessionRequest and SessionCreated
 *   (encrypt bytes 16-63, covering header[16:32] + ephemeral key).
 *   false for Retry, TokenRequest, PeerTest, HolePunch
 *   (encrypt only bytes 16-31, the second half of the long header).
 */
function protectLongHeader(pkt: Buffer, k1: Uint8Array, k2: Uint8Array,
                             withEphemeral: boolean): void {
  const end = withEphemeral ? 64 : 32;
  if (pkt.length >= end) {
    const plain = Uint8Array.from(pkt.subarray(16, end));
    const enc   = chacha20ZeroNonce(k2, plain);
    pkt.set(enc, 16);
  }
  applyHeaderMasks(pkt, k1, k2);
}

/**
 * Apply header protection to a short-header packet (SessionConfirmed, Data).
 */
function protectShortHeader(pkt: Buffer, k1: Uint8Array, k2: Uint8Array): void {
  applyHeaderMasks(pkt, k1, k2);
}

/**
 * XOR bytes 0-7 and 8-15 with ChaCha20 keystreams derived from packet tail.
 */
function applyHeaderMasks(pkt: Buffer, k1: Uint8Array, k2: Uint8Array): void {
  const len = pkt.length;
  if (len < 24) return;
  const iv1 = Uint8Array.from(pkt.subarray(len - 24, len - 12));
  const iv2 = Uint8Array.from(pkt.subarray(len - 12));

  const mask1 = chacha20Keystream8(k1, iv1);
  const mask2 = chacha20Keystream8(k2, iv2);
  for (let i = 0; i < 8; i++) pkt[i]     ^= mask1[i]!;
  for (let i = 0; i < 8; i++) pkt[8 + i] ^= mask2[i]!;
}

/**
 * Remove header protection from a long header packet.
 * withEphemeral: also decrypt bytes 16-63 (for SR/SC);
 *   false decrypts bytes 16-31 (for Retry/TokenRequest/etc.).
 */
function tryUnprotectHeader(pkt: Buffer, k1: Uint8Array, k2: Uint8Array,
                              withEphemeral: boolean): void {
  // Remove masks from bytes 0-15
  applyHeaderMasks(pkt, k1, k2);
  // Reverse ChaCha20 encryption of bytes 16-63 (SR/SC) or 16-31 (others)
  const end = withEphemeral ? 64 : 32;
  if (pkt.length >= end) {
    const enc = Uint8Array.from(pkt.subarray(16, end));
    const dec = chacha20ZeroNonce(k2, enc);
    pkt.set(dec, 16);
  }
}

/**
 * Remove header protection from a short header packet.
 */
function tryUnprotectShortHeader(pkt: Buffer, k1: Uint8Array, k2: Uint8Array): void {
  applyHeaderMasks(pkt, k1, k2);
}

// ═══════════════════════════════════════════════════════════════════════════════
// AEAD helpers (non-Noise, for TokenRequest/Retry/PeerTest)
// ═══════════════════════════════════════════════════════════════════════════════

/**
 * AEAD encryption using the long header as AD, nonce = pktNum.
 */
function aesEncAD(key: Uint8Array, pktNum: number, plain: Buffer, hdr: Buffer): Buffer {
  const nonce = makeNonce(pktNum);
  return Buffer.from(Crypto.encryptChaCha20Poly1305(key, nonce, plain, hdr));
}

function aesDecAD(key: Uint8Array, pktNum: number, ct: Buffer | Uint8Array, hdr: Buffer): Buffer {
  const nonce = makeNonce(pktNum);
  return Buffer.from(Crypto.decryptChaCha20Poly1305(key, nonce, ct, hdr));
}

// ═══════════════════════════════════════════════════════════════════════════════
// Block builders and parsers
// ═══════════════════════════════════════════════════════════════════════════════

/** DateTime block (type 0, 7 bytes total) */
function buildDateTimeBlock(): Buffer {
  const ts = Math.floor(Date.now() / 1000);
  const blk = Buffer.alloc(7);
  blk.writeUInt8(BLK_DATETIME, 0);
  blk.writeUInt16BE(4, 1);
  blk.writeUInt32BE(ts >>> 0, 3);
  return blk;
}

/** RouterInfo block (type 2) */
function buildRouterInfoBlock(ri: Buffer): Buffer {
  // flag=0 (local store, uncompressed), frag=0x01 (frag 0/1)
  const header = Buffer.alloc(3 + 2); // blk + size + flag + frag
  header.writeUInt8(BLK_ROUTERINFO, 0);
  header.writeUInt16BE(2 + ri.length, 1); // size = 2 (flag+frag) + ri
  header.writeUInt8(0, 3);  // flag
  header.writeUInt8(0x01, 4); // frag = 0x01 (fragment 0, total 1)
  return Buffer.concat([header, ri]);
}

/** I2NP block (type 3) */
function buildI2NPBlock(msg: Buffer): Buffer {
  // msg already includes the 9-byte I2NP short header
  const blk = Buffer.alloc(3);
  blk.writeUInt8(BLK_I2NP, 0);
  blk.writeUInt16BE(msg.length, 1);
  return Buffer.concat([blk, msg]);
}

/** Termination block (type 6, minimum 12 bytes) */
function buildTerminationBlock(reason: number, validPkts: number): Buffer {
  const blk = Buffer.alloc(12);
  blk.writeUInt8(BLK_TERMINATION, 0);
  blk.writeUInt16BE(9, 1);
  blk.writeBigUInt64BE(BigInt(validPkts), 3);
  blk.writeUInt8(reason, 11);
  return blk;
}

/** ACK block (type 12) */
function buildAckBlock(receivedDesc: number[]): Buffer {
  if (receivedDesc.length === 0) return buildPaddingBlock(8);
  const ackThrough = receivedDesc[0]!;
  let acnt = 0;
  for (let i = 1; i < receivedDesc.length; i++) {
    if (receivedDesc[i] === ackThrough - i) acnt++;
    else break;
  }
  acnt = Math.min(acnt, 255);
  const blk = Buffer.alloc(3 + 5);
  blk.writeUInt8(BLK_ACK, 0);
  blk.writeUInt16BE(5, 1);
  blk.writeUInt32BE(ackThrough, 3);
  blk.writeUInt8(acnt, 7);
  return blk;
}

/** Address block (type 13) */
function buildAddressBlock(host: string, port: number): Buffer {
  const ipParts = host.split('.').map(Number);
  const isIPv4 = ipParts.length === 4 && ipParts.every((p) => p >= 0 && p <= 255);
  const size = isIPv4 ? 6 : 18;
  const blk = Buffer.alloc(3 + size);
  blk.writeUInt8(BLK_ADDRESS, 0);
  blk.writeUInt16BE(size, 1);
  blk.writeUInt16BE(port, 3);
  if (isIPv4) {
    for (let i = 0; i < 4; i++) blk.writeUInt8(ipParts[i]!, 5 + i);
  }
  return blk;
}

/** Padding block (type 254) */
function buildPaddingBlock(size: number): Buffer {
  const blk = Buffer.alloc(3 + size);
  blk.writeUInt8(BLK_PADDING, 0);
  blk.writeUInt16BE(size, 1);
  // data = zeros (or random for privacy, but zeros for simplicity)
  return blk;
}

/** Ensure payload is at least 8 bytes (SSU2 minimum) */
function ensureMinPayload(payload: Buffer): Buffer {
  if (payload.length >= 8) return payload;
  return Buffer.concat([payload, buildPaddingBlock(8 - payload.length)]);
}

interface ParsedBlock { type: number; data: Buffer }

function parseBlocks(payload: Buffer): ParsedBlock[] {
  const blocks: ParsedBlock[] = [];
  let offset = 0;
  while (offset + 3 <= payload.length) {
    const type = payload.readUInt8(offset);
    const size = payload.readUInt16BE(offset + 1);
    const data = payload.subarray(offset + 3, offset + 3 + size);
    if (offset + 3 + size > payload.length) break;
    blocks.push({ type, data: Buffer.from(data) });
    offset += 3 + size;
    if (type === BLK_TERMINATION || type === BLK_PADDING) break;
  }
  return blocks;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Misc utilities
// ═══════════════════════════════════════════════════════════════════════════════

function sha256(data: Buffer | Uint8Array): Buffer {
  return Buffer.from(Crypto.sha256(data instanceof Buffer ? data : Buffer.from(data)));
}

function makeNonce(n: number): Uint8Array {
  const nonce = new Uint8Array(12);
  // First 4 bytes = 0, last 8 bytes = n as 64-bit LE
  nonce[4] = n & 0xff;
  nonce[5] = (n >>> 8)  & 0xff;
  nonce[6] = (n >>> 16) & 0xff;
  nonce[7] = (n >>> 24) & 0xff;
  return nonce;
}

function makeDataNonce(pktNum: number): Uint8Array {
  // Same format: packet number in bytes 4-7 (LE)
  return makeNonce(pktNum);
}

function randomConnId(): bigint {
  const buf = Buffer.from(Crypto.randomBytes(8));
  return buf.readBigUInt64BE(0);
}

function randomU32(): number {
  const buf = Buffer.from(Crypto.randomBytes(4));
  return buf.readUInt32BE(0);
}

function sessionKey(address: string, port: number): string {
  return `${address}:${port}`;
}

function extractSsu2Key(ri: RouterInfo, option: 's' | 'i'): Uint8Array {
  const addr = ri.addresses.find(
    (a) => a.transportStyle === 'SSU2' && a.options[option]
  );
  if (!addr) throw new Error(`Remote RouterInfo has no SSU2 address with '${option}'`);
  const key = i2pBase64Decode(addr.options[option]);
  if (key.length !== 32) throw new Error(`SSU2 '${option}' key must be 32 bytes`);
  return new Uint8Array(key);
}

/**
 * Try to extract the intro key from RouterInfo blocks embedded in SessionConfirmed.
 * Returns undefined if not found.
 */
function extractIntroKeyFromBlocks(payload: Buffer): Buffer | undefined {
  const blocks = parseBlocks(payload);
  for (const blk of blocks) {
    if (blk.type === BLK_ROUTERINFO && blk.data.length > 2) {
      // blk.data = flag(1) + frag(1) + routerInfoBytes
      const riBytes = blk.data.subarray(2);
      // Parse SSU2 address 'i' option from raw RI bytes (simplified)
      return extractIntroKeyFromRIBytes(riBytes);
    }
  }
  return undefined;
}

/**
 * Minimal RI parser to extract SSU2 intro key.
 * Returns undefined if not found or on error.
 */
function extractIntroKeyFromRIBytes(ri: Buffer): Buffer | undefined {
  try {
    // Look for the string "i=" in the RI binary - it's followed by the base64 key
    // This is a simplified heuristic; a full RI parser would be more robust.
    const marker = Buffer.from('i=');
    let pos = 0;
    while (pos < ri.length - marker.length - 44) {
      if (ri.subarray(pos, pos + 2).equals(marker)) {
        // Read up to the next ';'
        const end = ri.indexOf(0x3b, pos + 2); // 0x3b = ';'
        if (end > pos + 2) {
          const b64 = ri.subarray(pos + 2, end).toString('ascii');
          const key = i2pBase64Decode(b64);
          if (key.length === 32) return Buffer.from(key);
        }
      }
      pos++;
    }
  } catch {
    // ignore
  }
  return undefined;
}


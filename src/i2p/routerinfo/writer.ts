import { randomBytes as nodeRandomBytes } from 'crypto';
import { ed25519 } from '@noble/curves/ed25519';
import { writeI2PString, writeParams } from './params.js';
import { i2pBase64Encode } from '../base64.js';

export interface RouterInfoAddress {
  transportStyle: string; // "NTCP2" / "SSU2"
  cost?: number; // 0..255
  dateMs?: number; // uint64 ms
  options: Record<string, string>; // includes host/port/v and possibly s/i
}

export interface RouterInfoWriteOptions {
  identityBytes: Buffer;
  publishedMs: number;
  addresses: RouterInfoAddress[];
  peers?: Buffer[]; // router hashes (32 bytes each)
  routerProperties: Record<string, string>;
  signingPrivateKey: Uint8Array; // Ed25519 secret key (32 bytes seed)
}

function u64be(n: number): Buffer {
  const b = Buffer.alloc(8);
  b.writeBigUInt64BE(BigInt(Math.max(0, Math.floor(n))), 0);
  return b;
}

function writeAddress(addr: RouterInfoAddress): Buffer {
  const cost = addr.cost ?? 5;
  const dateMs = addr.dateMs ?? Date.now();
  const style = addr.transportStyle;

  const styleStr = writeI2PString(style);
  // Address options are wrapped with a 2-byte length prefix (not the same as RouterInfo properties block)
  const optBody = Buffer.concat(
    Object.keys(addr.options)
      .sort()
      .map((k) => {
        const v = addr.options[k];
        const kb = writeI2PString(k);
        const vb = writeI2PString(v ?? '');
        return Buffer.concat([kb, Buffer.from([0x3d]), vb, Buffer.from([0x3b])]);
      })
  );
  if (optBody.length > 0xffff) throw new Error(`Address options too long: ${optBody.length}`);
  const optLen = Buffer.alloc(2);
  optLen.writeUInt16BE(optBody.length, 0);

  return Buffer.concat([Buffer.from([cost & 0xff]), u64be(dateMs), styleStr, optLen, optBody]);
}

/**
 * Serialize an i2pd-compatible RouterInfo (wire format).
 *
 * Layout:
 *   identityBytes
 *   published(8)
 *   addrCount(1) + addr...
 *   peerCount(1) + peers (N*32)
 *   properties (2-byte len + params)
 *   signature (Ed25519, 64 bytes) over everything before signature
 */
export function writeRouterInfoEd25519(opts: RouterInfoWriteOptions): Buffer {
  const peers = opts.peers ?? [];
  for (const p of peers) {
    if (p.length !== 32) throw new Error('peer hash must be 32 bytes');
  }

  const published = u64be(opts.publishedMs);
  if (opts.addresses.length > 255) throw new Error('too many addresses');

  const addrParts: Buffer[] = [Buffer.from([opts.addresses.length & 0xff])];
  for (const a of opts.addresses) addrParts.push(writeAddress(a));

  const peerParts: Buffer[] = [Buffer.from([peers.length & 0xff]), ...peers];
  const props = writeParams(opts.routerProperties);

  const unsigned = Buffer.concat([opts.identityBytes, published, ...addrParts, ...peerParts, props]);
  const sig = Buffer.from(ed25519.sign(unsigned, opts.signingPrivateKey));
  return Buffer.concat([unsigned, sig]);
}

/**
 * Helper to make a minimal, "published" NTCP2 address options map.
 * Generates `i` (16 bytes) if not provided.
 */
export function makeNtcp2PublishedOptions(params: {
  host: string;
  port: number;
  staticKey: Uint8Array; // `s` raw bytes (32)
  ivB64?: string; // `i` (I2P base64) 16 bytes
  v?: string;
  caps?: string;
  rnd?: (n: number) => Buffer;
}): Record<string, string> {
  const rnd = params.rnd ?? ((n) => nodeRandomBytes(n));
  const v = params.v ?? '2';
  const ivB64 = params.ivB64 ?? i2pBase64Encode(rnd(16));
  const staticKeyB64 = i2pBase64Encode(params.staticKey);
  const out: Record<string, string> = {
    host: params.host,
    port: String(params.port),
    s: staticKeyB64,
    i: ivB64,
    v
  };
  if (params.caps) out.caps = params.caps;
  return out;
}


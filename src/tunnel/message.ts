import { Crypto } from '../crypto/index.js';

// ECIES tunnel message helpers (single-hop, single-fragment, LOCAL delivery only).
// Layout per tunnel-message spec:
// outer:  tunnelId(4) | IV(16) | encryptedInner(1008)  => 1028 bytes total
// inner:  checksum(4) | padding(non-zero, optional) | 0x00 | DI | fragment | pad...

const TUNNEL_MSG_LEN = 1028;
const INNER_LEN = 1008;

export interface TunnelFragment {
  fragment: Buffer;
}

export function encryptTunnelMessage(
  tunnelId: number,
  layerKey: Uint8Array,
  fragment: Buffer
): Buffer {
  if (fragment.length < 1) throw new Error('fragment must be non-empty');

  // Minimal LOCAL, unfragmented delivery instructions: flag(1) + size(2)
  const di = Buffer.alloc(3);
  // flag: LOCAL(00), not fragmented, no opts -> 0x00
  di.writeUInt8(0x00, 0);
  di.writeUInt16BE(fragment.length, 1);

  if (di.length + fragment.length > INNER_LEN - 5) {
    throw new Error('fragment too large for single tunnel message');
  }

  const inner = Buffer.alloc(INNER_LEN);

  // checksum placeholder (4 bytes) at 0..3
  // zero byte at offset 4
  inner.writeUInt8(0x00, 4);

  // delivery instructions + fragment start after zero
  let offset = 5;
  di.copy(inner, offset);
  offset += di.length;
  fragment.copy(inner, offset);
  offset += fragment.length;

  // simple zero padding for the rest (spec prefers random nonzero, but zero is acceptable for now)

  // IV for this message
  const iv = Buffer.from(Crypto.randomBytes(16));

  // checksum = first 4 bytes of SHA256( inner[5..] || IV )
  const bodyPlusIv = Buffer.concat([inner.subarray(5), iv]);
  const hash = Crypto.sha256(bodyPlusIv);
  Buffer.from(hash).subarray(0, 4).copy(inner, 0);

  // AES-256-CBC over full inner with IV; no padding, inner length is multiple of 16
  const key = Buffer.from(layerKey);
  const encrypted = Crypto.aesEncryptCBC(inner, key, iv);

  const out = Buffer.alloc(TUNNEL_MSG_LEN);
  out.writeUInt32BE(tunnelId >>> 0, 0);
  iv.copy(out, 4);
  encrypted.copy(out, 4 + 16);
  return out;
}

export function decryptTunnelMessage(
  expectedTunnelId: number,
  layerKey: Uint8Array,
  msg: Buffer
): TunnelFragment | null {
  if (msg.length !== TUNNEL_MSG_LEN) return null;
  const tunnelId = msg.readUInt32BE(0);
  if (tunnelId !== (expectedTunnelId >>> 0)) return null;

  const iv = msg.subarray(4, 4 + 16);
  const encInner = msg.subarray(4 + 16);

  const key = Buffer.from(layerKey);
  const inner = Crypto.aesDecryptCBC(encInner, key, iv);
  if (inner.length !== INNER_LEN) return null;

  const checksum = inner.subarray(0, 4);
  if (inner.readUInt8(4) !== 0x00) return null;

  // verify checksum
  const bodyPlusIv = Buffer.concat([inner.subarray(5), iv]);
  const hash = Crypto.sha256(bodyPlusIv);
  if (!checksum.equals(Buffer.from(hash).subarray(0, 4))) return null;

  // parse LOCAL, unfragmented DI
  let offset = 5;
  if (offset + 3 > inner.length) return null;
  const flag = inner.readUInt8(offset);
  const size = inner.readUInt16BE(offset + 1);
  offset += 3;

  // Only support LOCAL delivery (type 0) and unfragmented messages
  if (flag !== 0x00) return null;
  if (size < 1 || offset + size > inner.length) return null;

  const fragment = inner.subarray(offset, offset + size);
  return { fragment };
}


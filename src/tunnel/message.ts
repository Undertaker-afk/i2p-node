import { Crypto } from '../crypto/index.js';

const TUNNEL_MSG_LEN = 1028;
const DATA_LEN = 1024;

export function encryptHop(data: Buffer, layerKey: Uint8Array, ivKey: Uint8Array): Buffer {
  const iv = Crypto.aesEncryptECB(data.subarray(0, 16), ivKey);
  const encryptedData = Crypto.aesEncryptCBC(data.subarray(16), layerKey, iv);
  const result = Buffer.alloc(DATA_LEN);
  iv.copy(result, 0);
  encryptedData.copy(result, 16);
  return result;
}

export function decryptHop(data: Buffer, layerKey: Uint8Array, ivKey: Uint8Array): Buffer {
  const encryptedIV = data.subarray(0, 16);
  const decryptedData = Crypto.aesDecryptCBC(data.subarray(16), layerKey, encryptedIV);
  const iv = Crypto.aesDecryptECB(encryptedIV, ivKey);
  const result = Buffer.alloc(DATA_LEN);
  iv.copy(result, 0);
  decryptedData.copy(result, 16);
  return result;
}

export function encryptTunnelMessage(gatewayTunnelId: number, hops: { layerKey: Uint8Array, ivKey: Uint8Array }[], i2npMsg: Buffer): any {
  const data = Buffer.alloc(DATA_LEN);
  const offset = 4;
  data.writeUInt16BE(offset, 0);
  data.writeUInt8(0x00, offset);
  data.writeUInt16BE(i2npMsg.length, offset + 1);
  i2npMsg.copy(data, offset + 3);

  if (i2npMsg.length + offset + 3 < DATA_LEN) {
    const pad = Crypto.randomBytes(DATA_LEN - (i2npMsg.length + offset + 3));
    pad.copy(data, offset + 3 + i2npMsg.length);
  }

  let encrypted = data;
  for (let i = hops.length - 1; i >= 0; i--) {
    encrypted = encryptHop(encrypted, hops[i].layerKey, hops[i].ivKey) as any;
  }

  const out = Buffer.allocUnsafe(TUNNEL_MSG_LEN);
  out.writeUInt32BE(gatewayTunnelId >>> 0, 0);
  encrypted.copy(out, 4);
  return out;
}

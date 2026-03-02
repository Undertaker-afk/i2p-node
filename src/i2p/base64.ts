/**
 * I2P Base64 uses '-' and '~' instead of '+' and '/'.
 * Padding '=' is generally omitted.
 */
export function i2pBase64ToStd(s: string): string {
  return s.replace(/-/g, '+').replace(/~/g, '/');
}

export function stdBase64ToI2p(s: string): string {
  return s.replace(/\+/g, '-').replace(/\//g, '~').replace(/=+$/g, '');
}

export function i2pBase64Decode(s: string): Buffer {
  const std = i2pBase64ToStd(s);
  const padLen = (4 - (std.length % 4)) % 4;
  const padded = std + '='.repeat(padLen);
  return Buffer.from(padded, 'base64');
}

export function i2pBase64Encode(buf: Uint8Array): string {
  const std = Buffer.from(buf).toString('base64');
  return stdBase64ToI2p(std);
}


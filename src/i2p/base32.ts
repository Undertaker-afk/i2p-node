// RFC 4648 base32 (lowercase, no padding) for .b32.i2p hostnames.

const ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

export function base32DecodeToHash(host: string): Buffer | null {
  // Expect something like xxxx.b32.i2p
  const lower = host.toLowerCase();
  const suffix = '.b32.i2p';
  if (!lower.endsWith(suffix)) return null;
  const label = lower.slice(0, -suffix.length);
  if (!/^[a-z2-7]+$/.test(label)) return null;

  const bits: number[] = [];
  for (const ch of label) {
    const idx = ALPHABET.indexOf(ch);
    if (idx < 0) return null;
    for (let b = 4; b >= 0; b--) {
      bits.push((idx >> b) & 1);
    }
  }

  const out = Buffer.alloc(32);
  let byte = 0;
  let bitCount = 0;
  let outPos = 0;

  for (const bit of bits) {
    byte = (byte << 1) | bit;
    bitCount++;
    if (bitCount === 8) {
      if (outPos < 32) out[outPos++] = byte;
      byte = 0;
      bitCount = 0;
    }
    if (outPos >= 32) break;
  }

  if (outPos !== 32) return null;
  return out;
}


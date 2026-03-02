export function writeI2PString(s: string): Buffer {
  const b = Buffer.from(s, 'utf8');
  if (b.length > 255) throw new Error(`I2P string too long: ${b.length}`);
  return Buffer.concat([Buffer.from([b.length]), b]);
}

export function writeParam(key: string, value: string): Buffer {
  return Buffer.concat([writeI2PString(key), Buffer.from([0x3d]), writeI2PString(value), Buffer.from([0x3b])]);
}

export function writeParams(params: Record<string, string>): Buffer {
  const parts: Buffer[] = [];
  // i2pd writes in map iteration order; we sort for stable output.
  const keys = Object.keys(params).sort();
  for (const k of keys) {
    const v = params[k];
    if (v === undefined) continue;
    parts.push(writeParam(k, v));
  }
  const body = Buffer.concat(parts);
  if (body.length > 0xffff) throw new Error(`Params block too long: ${body.length}`);
  const len = Buffer.alloc(2);
  len.writeUInt16BE(body.length, 0);
  return Buffer.concat([len, body]);
}


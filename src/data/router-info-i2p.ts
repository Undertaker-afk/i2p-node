import { createHash } from 'crypto';
import { RouterIdentity, RouterAddress, RouterInfo } from './router-info.js';
import { logger } from '../utils/logger.js';

/**
 * Parser for I2P-compatible RouterInfo binary format as implemented in i2pd.
 *
 * This reads:
 * - Identity (standard + extended certificate)
 * - RouterInfo payload: timestamp, addresses, peers (ignored), properties
 *
 * Signature verification is NOT performed here; we rely on the presence of a
 * non-empty signature buffer elsewhere if needed.
 */

export function getIdentityLength(buf: Buffer): number {
  // Mirrors GetIdentityBufferLen in Identity.cpp:
  // DEFAULT_IDENTITY_SIZE (387 bytes) + certificate length (last 2 bytes)
  const DEFAULT_IDENTITY_SIZE = 387;
  if (buf.length < DEFAULT_IDENTITY_SIZE) return 0;
  const certLen = buf.readUInt16BE(DEFAULT_IDENTITY_SIZE - 2);
  const total = DEFAULT_IDENTITY_SIZE + certLen;
  if (total > buf.length) return 0;
  return total;
}

function readI2PString(buf: Buffer, offset: number): { value: string; bytes: number } {
  if (offset >= buf.length) return { value: '', bytes: 0 };
  const len = buf.readUInt8(offset);
  const end = offset + 1 + len;
  if (end > buf.length) return { value: '', bytes: buf.length - offset };
  const value = buf.slice(offset + 1, end).toString('utf8');
  return { value, bytes: 1 + len };
}

function readParam(buf: Buffer, offset: number): { key: string; value: string; bytes: number } {
  const { value: key, bytes: keyBytes } = readI2PString(buf, offset);
  if (!key) return { key: '', value: '', bytes: buf.length - offset };
  let pos = offset + keyBytes;
  if (pos >= buf.length || buf[pos] !== 0x3d /* '=' */) {
    return { key: '', value: '', bytes: buf.length - offset };
  }
  pos++;
  const { value, bytes: valBytes } = readI2PString(buf, pos);
  pos += valBytes;
  if (pos >= buf.length || buf[pos] !== 0x3b /* ';' */) {
    return { key: '', value: '', bytes: buf.length - offset };
  }
  pos++;
  return { key, value, bytes: pos - offset };
}

export function parseI2PRouterInfo(buffer: Buffer): RouterInfo | null {
  try {
    if (buffer.length < 40) {
      logger.warn('I2P-RI: buffer too small', undefined, 'I2P-RI');
      return null;
    }

    // 1) Identity (we treat it as opaque, but compute proper ident hash)
    const idLen = getIdentityLength(buffer);
    if (!idLen) {
      logger.warn('I2P-RI: invalid identity length', undefined, 'I2P-RI');
      return null;
    }
    const identityBytes = buffer.subarray(0, idLen);
    const identHash = createHash('sha256').update(identityBytes).digest();

    // 2) Payload starts after identity; includes timestamp, addresses, peers, properties, signature tail
    const payload = buffer.subarray(idLen);
    if (payload.length < 9) {
      logger.warn('I2P-RI: payload too small', undefined, 'I2P-RI');
      return null;
    }

    let offset = 0;

    // Timestamp (8 bytes, big endian)
    const publishedMs = Number(payload.readBigUInt64BE(offset));
    offset += 8;

    // Addresses
    const addresses: RouterAddress[] = [];
    const numAddresses = payload.readUInt8(offset);
    offset += 1;

    for (let i = 0; i < numAddresses; i++) {
      if (offset + 9 > payload.length) {
        logger.warn('I2P-RI: truncated address header', undefined, 'I2P-RI');
        return null;
      }

      // cost (ignored) + date
      offset += 1; // cost
      const date = Number(payload.readBigUInt64BE(offset));
      offset += 8;

      // transport style string
      const { value: style, bytes: styleBytes } = readI2PString(payload, offset);
      offset += styleBytes;

      // size of address options block
      if (offset + 2 > payload.length) return null;
      const size = payload.readUInt16BE(offset);
      offset += 2;
      if (offset + size > payload.length) return null;

      let host = '';
      let port = 0;
      const options: Record<string, string> = {};

      const addrEnd = offset + size;
      while (offset < addrEnd) {
        const { key, value, bytes } = readParam(payload, offset);
        if (!key) {
          // malformed param; bail out of this address
          offset = addrEnd;
          break;
        }
        offset += bytes;
        options[key] = value;
        if (key === 'host') host = value;
        else if (key === 'port') {
          const parsed = Number.parseInt(value, 10);
          if (!Number.isNaN(parsed)) port = parsed;
        }
      }

      // Only keep NTCP2 / SSU2 addresses we understand
      let transport = '';
      if (style.startsWith('NTCP')) transport = 'NTCP2';
      else if (style.startsWith('SSU')) transport = 'SSU2';
      else continue;

      const routerAddr = new RouterAddress(
        transport,
        // Keep ALL parsed options (including `s`, `i`, introducers, mtu, etc.)
        // so transports can use them later.
        {
          ...options,
          ...(host ? { host } : {}),
          ...(port ? { port: String(port) } : {}),
          ...(options.v ? { v: options.v } : { v: '2' })
        },
        5,
        date
      );

      addresses.push(routerAddr);
    }

    // Peers section: 1 byte count + 32 bytes per peer, skip it
    if (offset + 1 > payload.length) return null;
    const numPeers = payload.readUInt8(offset);
    offset += 1 + numPeers * 32;
    if (offset + 2 > payload.length) return null;

    // Properties block
    const propsSize = payload.readUInt16BE(offset);
    offset += 2;
    if (offset + propsSize > payload.length) return null;

    const propsEnd = offset + propsSize;
    const options: Record<string, string> = {};

    while (offset < propsEnd) {
      const { key, value, bytes } = readParam(payload, offset);
      if (!key) break;
      offset += bytes;
      options[key] = value;
    }

    // Map important properties into options keys our code expects
    const caps = options['caps'] || '';
    const netId = options['netId'] || '2';
    const routerVersion = options['router.version'] || '0.0.0';
    const coreVersion = options['core.version'] || routerVersion;

    const riOptions: Record<string, string> = {
      caps,
      netId,
      'router.version': routerVersion,
      'core.version': coreVersion
    };

    // Build RouterIdentity with precomputed hash
    const signingKey = identHash.subarray(0, 32);
    const encKey = identHash.subarray(0, 32);
    const identity = new RouterIdentity(signingKey, encKey, { type: 0, data: Buffer.alloc(0) });
    identity.setHash(identHash);

    // We don't retain the real signature here; use a non-empty placeholder
    const signature = Buffer.alloc(64);

    const routerInfo = new RouterInfo(identity, addresses, riOptions, publishedMs, signature);
    routerInfo.setWireFormatData(buffer);
    return routerInfo;
  } catch (err) {
    logger.error('I2P-RI: parse failed', { error: (err as Error).message }, 'I2P-RI');
    return null;
  }
}


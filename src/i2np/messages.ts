import * as crypto from 'crypto';

export enum I2NPMessageType {
  DATABASE_STORE = 1,
  DATABASE_LOOKUP = 2,
  DATABASE_SEARCH_REPLY = 3,
  DELIVERY_STATUS = 10,
  GARLIC = 11,
  TUNNEL_DATA = 18,
  TUNNEL_GATEWAY = 19,
  TUNNEL_BUILD = 20,
  TUNNEL_BUILD_REPLY = 21,
  VARIABLE_TUNNEL_BUILD = 22,
  VARIABLE_TUNNEL_BUILD_REPLY = 23,
  SHORT_TUNNEL_BUILD = 25,
  SHORT_TUNNEL_BUILD_REPLY = 26
}


export interface DatabaseLookupOptions {
  replyTunnelId?: number;
  eciesSessionKey?: Uint8Array;
  eciesSessionTag?: Uint8Array;
}

export interface ParsedGarlicOuterMessage {
  length: number;
  body: Buffer;
  sessionTag?: Buffer;
  ephemeralPublicKey?: Buffer;
  encryptedPayload: Buffer;
}

export interface GarlicCloveMessage {
  deliveryFlag: number;
  message: I2NPMessage;
}

const GARLIC_CLOVE_TYPE_OFFSET = 1;
const GARLIC_CLOVE_UNIQUE_ID_OFFSET = 2;
const GARLIC_CLOVE_EXPIRATION_OFFSET = 6;
const GARLIC_CLOVE_PAYLOAD_OFFSET = 10;

export interface I2NPMessage {
  type: I2NPMessageType;
  uniqueId: number;
  /**
   * Expiration in milliseconds since epoch (local representation).
   * Serialized on the wire as seconds (short_expiration) for NTCP2/SSU2.
   */
  expiration: number;
  payload: Buffer;
}

export class I2NPMessages {
  private static readonly TUNNEL_BUILD_MSG_EXPIRATION_MS = 60000;
  /**
   * Parse an I2NP message with the NTCP2/SSU2 "short" header:
   * type(1) | msg_id(4) | short_expiration(4, seconds) | payload...
   */
  static parseMessage(data: Buffer): I2NPMessage {
    if (data.length < 9) {
      throw new Error('I2NP packet too short');
    }

    const type = data.readUInt8(0);
    const uniqueId = data.readUInt32BE(1);
    const shortExp = data.readUInt32BE(5); // seconds since epoch
    const expiration = shortExp * 1000;
    const payload = data.subarray(9);

    return { type, uniqueId, expiration, payload };
  }

  /**
   * Serialize an I2NP message using the NTCP2/SSU2 "short" header:
   * type(1) | msg_id(4) | short_expiration(4, seconds) | payload...
   *
   * Size and checksum are provided by the transport (NTCP2/SSU2 frames).
   */
  static serializeMessage(msg: I2NPMessage): Buffer {
    const header = Buffer.alloc(9);
    header.writeUInt8(msg.type, 0);
    header.writeUInt32BE(msg.uniqueId >>> 0, 1);
    const expSec = Math.max(0, Math.floor(msg.expiration / 1000)) >>> 0;
    header.writeUInt32BE(expSec, 5);
    return Buffer.concat([header, msg.payload]);
  }

  static createDatabaseStore(
    key: Uint8Array,
    data: Buffer,
    replyToken: number,
    fromHash: Uint8Array,
    storeType = 0
  ): I2NPMessage {
    // DatabaseStore payload (simplified):
    // key(32) | type(1=RouterInfo) | replyToken(4) |
    // [ reply_tunnelId(4) | reply_gateway(32) if replyToken>0 ] | data...
    const keyBuf = Buffer.from(key);
    const typeBuf = Buffer.alloc(1);
    // 0 => RouterInfo, 1 => LS1, 3 => LS2 (and other DatabaseStore types as needed)
    typeBuf.writeUInt8(storeType & 0xFF);

    const replyTokenBuf = Buffer.alloc(4);
    replyTokenBuf.writeUInt32BE(replyToken);

    const parts: Buffer[] = [keyBuf, typeBuf, replyTokenBuf];
    if (replyToken > 0) {
      const tunnelIdBuf = Buffer.alloc(4); // 0 = direct to router
      const gatewayBuf = Buffer.from(fromHash); // reply gateway hash
      parts.push(tunnelIdBuf, gatewayBuf);
    }
    parts.push(data);

    const payload = Buffer.concat(parts);
    
    return {
      type: I2NPMessageType.DATABASE_STORE,
      uniqueId: crypto.randomBytes(4).readUInt32BE(0),
      expiration: Date.now() + 60000,
      payload
    };
  }

  static createDatabaseLookup(
    key: Uint8Array,
    fromHash: Uint8Array,
    lookupType: 0 | 1 | 2 | 3,
    excludedPeers: Uint8Array[] = [],
    options: DatabaseLookupOptions = {}
  ): I2NPMessage {
    // DatabaseLookup payload:
    // key(32) | from(32) | flags(1) | [reply_tunnelId(4)] | size(2) | excluded[size*32] |
    // [sessionKey(32) | numTags(1) | sessionTag(8)] when ECIES flag set.
    const keyBuf = Buffer.from(key);
    const fromBuf = Buffer.from(fromHash);
    if (keyBuf.length !== 32) {
      throw new Error('DatabaseLookup key must be 32 bytes');
    }
    if (fromBuf.length !== 32) {
      throw new Error('DatabaseLookup fromHash must be 32 bytes');
    }

    const lookupBits = (lookupType & 0x03) << 2;
    const hasDelivery = typeof options.replyTunnelId === 'number';
    const hasEciesKey = options.eciesSessionKey !== undefined;
    const hasEciesTag = options.eciesSessionTag !== undefined;
    if (hasEciesKey !== hasEciesTag) {
      throw new Error('DatabaseLookup ECIES options require both eciesSessionKey and eciesSessionTag');
    }
    if (
      hasDelivery &&
      (!Number.isInteger(options.replyTunnelId) || options.replyTunnelId! <= 0 || options.replyTunnelId! > 0xFFFFFFFF)
    ) {
      throw new Error('DatabaseLookup replyTunnelId must be a non-zero integer');
    }
    const hasEcies = hasEciesKey && hasEciesTag;
    let flags = lookupBits;
    if (hasDelivery) flags |= 0x01;
    if (hasEcies) flags |= 0x10;

    const flagsBuf = Buffer.alloc(1);
    flagsBuf.writeUInt8(flags);

    const parts: Buffer[] = [keyBuf, fromBuf, flagsBuf];

    if (hasDelivery) {
      const replyTunnelIdBuf = Buffer.alloc(4);
      replyTunnelIdBuf.writeUInt32BE(options.replyTunnelId! >>> 0);
      parts.push(replyTunnelIdBuf);
    }

    const count = Math.min(excludedPeers.length, 512);
    const sizeBuf = Buffer.alloc(2);
    sizeBuf.writeUInt16BE(count);
    parts.push(sizeBuf);

    for (const peer of excludedPeers.slice(0, count)) {
      const peerBuf = Buffer.from(peer);
      if (peerBuf.length !== 32) {
        throw new Error('DatabaseLookup excluded peers must be 32 bytes each');
      }
      parts.push(peerBuf);
    }

    if (hasEcies) {
      const sessionKey = Buffer.from(options.eciesSessionKey!);
      const sessionTag = Buffer.from(options.eciesSessionTag!);
      if (sessionKey.length !== 32) {
        throw new Error('DatabaseLookup eciesSessionKey must be 32 bytes');
      }
      if (sessionTag.length !== 8) {
        throw new Error('DatabaseLookup eciesSessionTag must be 8 bytes');
      }
      const numTagsBuf = Buffer.alloc(1);
      numTagsBuf.writeUInt8(1);
      parts.push(sessionKey, numTagsBuf, sessionTag);
    }

    const payload = Buffer.concat(parts);

    return {
      type: I2NPMessageType.DATABASE_LOOKUP,
      uniqueId: crypto.randomBytes(4).readUInt32BE(0),
      expiration: Date.now() + 30000,
      payload
    };
  }

  static createTunnelBuild(
    records: Buffer[]
  ): I2NPMessage {
    const recordCount = Buffer.alloc(1);
    recordCount.writeUInt8(records.length);
    
    const payload = Buffer.concat([
      recordCount,
      ...records
    ]);
    
    return {
      type: I2NPMessageType.TUNNEL_BUILD,
      uniqueId: crypto.randomBytes(4).readUInt32BE(0),
      expiration: Date.now() + I2NPMessages.TUNNEL_BUILD_MSG_EXPIRATION_MS,
      payload
    };
  }

  static createVariableTunnelBuild(records: Buffer[], uniqueId?: number): I2NPMessage {
    const recordCount = Buffer.alloc(1);
    recordCount.writeUInt8(records.length);

    return {
      type: I2NPMessageType.VARIABLE_TUNNEL_BUILD,
      uniqueId: uniqueId ?? crypto.randomBytes(4).readUInt32BE(0),
      expiration: Date.now() + I2NPMessages.TUNNEL_BUILD_MSG_EXPIRATION_MS,
      payload: Buffer.concat([recordCount, ...records])
    };
  }

  static createTunnelData(
    tunnelId: number,
    data: Buffer
  ): I2NPMessage {
    const tunnelIdBuf = Buffer.alloc(4);
    tunnelIdBuf.writeUInt32BE(tunnelId);
    
    const payload = Buffer.concat([
      tunnelIdBuf,
      data
    ]);
    
    return {
      type: I2NPMessageType.TUNNEL_DATA,
      uniqueId: crypto.randomBytes(4).readUInt32BE(0),
      expiration: Date.now() + 30000,
      payload
    };
  }

  /**
   * Create a DatabaseSearchReply message.
   * Wire format: key(32) | num(1) | routers(N*32) | from(32)
   */
  static createDatabaseSearchReply(
    key: Uint8Array,
    routerHashes: Uint8Array[],
    fromHash: Uint8Array
  ): I2NPMessage {
    const count = Math.min(routerHashes.length, 16);
    const keyBuf = Buffer.from(key);
    const numBuf = Buffer.alloc(1);
    numBuf.writeUInt8(count);
    const fromBuf = Buffer.from(fromHash);

    const parts: Buffer[] = [keyBuf, numBuf];
    for (let i = 0; i < count; i++) {
      parts.push(Buffer.from(routerHashes[i]));
    }
    parts.push(fromBuf);

    const payload = Buffer.concat(parts);

    return {
      type: I2NPMessageType.DATABASE_SEARCH_REPLY,
      uniqueId: crypto.randomBytes(4).readUInt32BE(0),
      expiration: Date.now() + 30000,
      payload
    };
  }

  /**
   * Parse a DatabaseSearchReply payload.
   * Wire format: key(32) | num(1) | routers(N*32) | from(32)
   */
  static parseDatabaseSearchReply(payload: Buffer): {
    key: Buffer;
    routerHashes: Buffer[];
    from: Buffer;
  } | null {
    if (payload.length < 32 + 1 + 32) return null;

    const key = payload.subarray(0, 32);
    const num = payload.readUInt8(32);

    const expectedLen = 33 + num * 32 + 32;
    if (payload.length < expectedLen) return null;

    const routerHashes: Buffer[] = [];
    let offset = 33;
    for (let i = 0; i < num; i++) {
      routerHashes.push(payload.subarray(offset, offset + 32));
      offset += 32;
    }

    const from = payload.subarray(offset, offset + 32);
    return { key, routerHashes, from };
  }

  static createDeliveryStatus(
    msgId: number,
    timestamp: number
  ): I2NPMessage {
    const msgIdBuf = Buffer.alloc(4);
    msgIdBuf.writeUInt32BE(msgId);
    
    const timestampBuf = Buffer.alloc(8);
    timestampBuf.writeBigUInt64BE(BigInt(timestamp));
    
    const payload = Buffer.concat([msgIdBuf, timestampBuf]);
    
    return {
      type: I2NPMessageType.DELIVERY_STATUS,
      uniqueId: msgId,
      expiration: Date.now() + 30000,
      payload
    };
  }

  static parseGarlicOuterMessage(payload: Buffer): ParsedGarlicOuterMessage | null {
    if (payload.length < 4 + 8 + 16) return null;

    const length = payload.readUInt32BE(0);
    if (length <= 0 || payload.length < 4 + length) return null;

    const body = payload.subarray(4, 4 + length);
    return {
      length,
      body,
      encryptedPayload: body
    };
  }

  static parseGarlicCloveMessages(payload: Buffer): GarlicCloveMessage[] | null {
    const cloves: GarlicCloveMessage[] = [];
    let offset = 0;

    while (offset < payload.length) {
      if (offset + 3 > payload.length) return null;
      const blockType = payload.readUInt8(offset);
      const blockSize = payload.readUInt16BE(offset + 1);
      offset += 3;
      if (offset + blockSize > payload.length) return null;

      const blockData = payload.subarray(offset, offset + blockSize);
      offset += blockSize;

      if (blockType === 0 || blockType === 254) {
        continue;
      }

      if (blockType !== 3 || blockData.length < 1 + 1 + 4 + 4) {
        continue;
      }

      const deliveryFlag = blockData.readUInt8(0);
      if (deliveryFlag !== 0x00) {
        continue;
      }

      const type = blockData.readUInt8(GARLIC_CLOVE_TYPE_OFFSET);
      const uniqueId = blockData.readUInt32BE(GARLIC_CLOVE_UNIQUE_ID_OFFSET);
      const expiration = blockData.readUInt32BE(GARLIC_CLOVE_EXPIRATION_OFFSET) * 1000;
      const clovePayload = blockData.subarray(GARLIC_CLOVE_PAYLOAD_OFFSET);
      cloves.push({
        deliveryFlag,
        message: {
          type,
          uniqueId,
          expiration,
          payload: Buffer.from(clovePayload)
        }
      });
    }

    return cloves;
  }

  static createGarlicClovePayload(messages: I2NPMessage[]): Buffer {
    const blocks: Buffer[] = [];
    const nowSeconds = Math.floor(Date.now() / 1000);
    const dateBlock = Buffer.alloc(1 + 2 + 4);
    dateBlock.writeUInt8(0, 0);
    dateBlock.writeUInt16BE(4, 1);
    dateBlock.writeUInt32BE(nowSeconds >>> 0, 3);
    blocks.push(dateBlock);

    for (const message of messages) {
      const expirationSeconds = Math.max(0, Math.floor(message.expiration / 1000)) >>> 0;
      const cloveData = Buffer.alloc(1 + 1 + 4 + 4 + message.payload.length);
      cloveData.writeUInt8(0x00, 0);
      cloveData.writeUInt8(message.type, 1);
      cloveData.writeUInt32BE(message.uniqueId >>> 0, 2);
      cloveData.writeUInt32BE(expirationSeconds, 6);
      message.payload.copy(cloveData, 10);

      const header = Buffer.alloc(3);
      header.writeUInt8(3, 0);
      header.writeUInt16BE(cloveData.length, 1);
      blocks.push(Buffer.concat([header, cloveData]));
    }

    return Buffer.concat(blocks);
  }
}

export default I2NPMessages;

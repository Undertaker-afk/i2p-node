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
  VARIABLE_TUNNEL_BUILD_REPLY = 23
}

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
      uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
      expiration: Date.now() + 60000,
      payload
    };
  }

  static createDatabaseLookup(
    key: Uint8Array,
    fromHash: Uint8Array,
    lookupType: 0 | 1 | 2 | 3,
    excludedPeers: Uint8Array[] = []
  ): I2NPMessage {
    // DatabaseLookup payload (subset):
    // key(32) | from(32) | flags(1) | reply_tunnelId?(4) | size(2) | excluded[size*32]
    const keyBuf = Buffer.from(key);
    const fromBuf = Buffer.from(fromHash);

    // flags: bits 3-2 are lookup type; we don't use delivery/encryption/ECIES here.
    const lookupBits = (lookupType & 0x03) << 2;
    const flagsBuf = Buffer.alloc(1);
    flagsBuf.writeUInt8(lookupBits);

    const sizeBuf = Buffer.alloc(2);
    const count = Math.min(excludedPeers.length, 512);
    sizeBuf.writeUInt16BE(count);

    const excluded = excludedPeers.slice(0, count).map((p) => Buffer.from(p));
    const payload = Buffer.concat([keyBuf, fromBuf, flagsBuf, sizeBuf, ...excluded]);

    return {
      type: I2NPMessageType.DATABASE_LOOKUP,
      uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
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
      uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
      expiration: Date.now() + 60000,
      payload
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
      uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
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
      uniqueId: Math.floor(Math.random() * 0xFFFFFFFF),
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
}

export default I2NPMessages;

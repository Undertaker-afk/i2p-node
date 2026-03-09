import { createHash } from 'crypto';

export interface Certificate {
  type: number;
  data: Buffer;
}

export interface DeserializedIdentity {
  identity: RouterIdentity;
  bytesRead: number;
}

export interface DeserializedAddress {
  address: RouterAddress;
  bytesRead: number;
}

export interface DeserializedRouterInfo {
  routerInfo: RouterInfo;
  bytesRead: number;
}

export class RouterIdentity {
  signingPublicKey: Uint8Array;
  encryptionPublicKey: Uint8Array;
  certificate: Certificate;
  private _hash: Buffer | null = null;
  private _precomputedHash: Buffer | null = null;

  constructor(
    signingPublicKey: Uint8Array,
    encryptionPublicKey: Uint8Array,
    certificate: Certificate | null = null
  ) {
    this.signingPublicKey = signingPublicKey;
    this.encryptionPublicKey = encryptionPublicKey;
    this.certificate = certificate || { type: 0, data: Buffer.alloc(0) };
  }

  /**
   * Set a precomputed router hash (for I2P-compatible identities where the
   * hash is defined over the raw identity bytes). When set, this overrides
   * the default hash derived from this class's custom serialization.
   */
  setHash(hash: Buffer): void {
    this._precomputedHash = Buffer.from(hash);
  }

  static async generate(): Promise<{ identity: RouterIdentity; signingPrivateKey: Uint8Array; encryptionPrivateKey: Uint8Array }> {
    const { Crypto } = await import('../crypto/index.js');
    const signingKeys = Crypto.generateKeyPair();
    const encryptionKeys = Crypto.generateKeyPair();
    
    return {
      identity: new RouterIdentity(signingKeys.publicKey, encryptionKeys.publicKey),
      signingPrivateKey: signingKeys.privateKey,
      encryptionPrivateKey: encryptionKeys.privateKey
    };
  }

  getHash(): Buffer {
    if (this._precomputedHash) {
      return this._precomputedHash;
    }
    if (!this._hash) {
      const data = this.serialize();
      this._hash = createHash('sha256').update(data).digest();
    }
    return this._hash;
  }

  serialize(): Buffer {
    const signingKeyLen = Buffer.alloc(2);
    signingKeyLen.writeUInt16BE(this.signingPublicKey.length);
    
    const encKeyLen = Buffer.alloc(2);
    encKeyLen.writeUInt16BE(this.encryptionPublicKey.length);
    
    const certType = Buffer.alloc(1);
    certType.writeUInt8(this.certificate.type);
    
    const certLen = Buffer.alloc(2);
    certLen.writeUInt16BE(this.certificate.data.length);
    
    return Buffer.concat([
      signingKeyLen,
      Buffer.from(this.signingPublicKey),
      encKeyLen,
      Buffer.from(this.encryptionPublicKey),
      certType,
      certLen,
      this.certificate.data
    ]);
  }

  static deserialize(data: Buffer, offset = 0): DeserializedIdentity {
    let pos = offset;
    
    const signingKeyLen = data.readUInt16BE(pos);
    pos += 2;
    
    const signingPublicKey = data.slice(pos, pos + signingKeyLen);
    pos += signingKeyLen;
    
    const encKeyLen = data.readUInt16BE(pos);
    pos += 2;
    
    const encryptionPublicKey = data.slice(pos, pos + encKeyLen);
    pos += encKeyLen;
    
    const certType = data.readUInt8(pos);
    pos += 1;
    
    const certLen = data.readUInt16BE(pos);
    pos += 2;
    
    const certData = data.slice(pos, pos + certLen);
    pos += certLen;
    
    const identity = new RouterIdentity(signingPublicKey, encryptionPublicKey, {
      type: certType,
      data: certData
    });
    
    return { identity, bytesRead: pos - offset };
  }
}

export class RouterAddress {
  cost: number;
  expiration: number;
  transportStyle: string;
  options: Record<string, string>;

  constructor(
    transportStyle: string,
    options: Record<string, string> = {},
    cost = 5,
    expiration: number | null = null
  ) {
    this.cost = cost;
    this.expiration = expiration || 0;
    this.transportStyle = transportStyle;
    this.options = options;
  }

  serialize(): Buffer {
    const cost = Buffer.alloc(1);
    cost.writeUInt8(this.cost);
    
    const expiration = Buffer.alloc(8);
    expiration.writeBigUInt64BE(BigInt(this.expiration));
    
    const styleLen = Buffer.alloc(1);
    const styleBuf = Buffer.from(this.transportStyle, 'utf8');
    styleLen.writeUInt8(styleBuf.length);
    
    const optionsData = this.serializeOptions();
    
    return Buffer.concat([cost, expiration, styleLen, styleBuf, optionsData]);
  }

  serializeOptions(): Buffer {
    const entries = Object.entries(this.options);
    const count = Buffer.alloc(1);
    count.writeUInt8(entries.length);
    
    const parts: Buffer[] = [count];
    
    for (const [key, value] of entries) {
      const keyBuf = Buffer.from(key, 'utf8');
      const valBuf = Buffer.from(value, 'utf8');
      
      const keyLen = Buffer.alloc(1);
      keyLen.writeUInt8(keyBuf.length);
      
      const valLen = Buffer.alloc(2);
      valLen.writeUInt16BE(valBuf.length);
      
      parts.push(keyLen, keyBuf, valLen, valBuf);
    }
    
    return Buffer.concat(parts);
  }

  static deserialize(data: Buffer, offset = 0): DeserializedAddress {
    let pos = offset;
    
    const cost = data.readUInt8(pos);
    pos += 1;
    
    const expiration = Number(data.readBigUInt64BE(pos));
    pos += 8;
    
    const styleLen = data.readUInt8(pos);
    pos += 1;
    
    const transportStyle = data.slice(pos, pos + styleLen).toString('utf8');
    pos += styleLen;
    
    const { options, bytesRead } = RouterAddress.deserializeOptions(data, pos);
    pos += bytesRead;
    
    return {
      address: new RouterAddress(transportStyle, options, cost, expiration),
      bytesRead: pos - offset
    };
  }

  static deserializeOptions(data: Buffer, offset: number): { options: Record<string, string>; bytesRead: number } {
    let pos = offset;
    const count = data.readUInt8(pos);
    pos += 1;
    
    const options: Record<string, string> = {};
    
    for (let i = 0; i < count; i++) {
      const keyLen = data.readUInt8(pos);
      pos += 1;
      
      const key = data.slice(pos, pos + keyLen).toString('utf8');
      pos += keyLen;
      
      const valLen = data.readUInt16BE(pos);
      pos += 2;
      
      const value = data.slice(pos, pos + valLen).toString('utf8');
      pos += valLen;
      
      options[key] = value;
    }
    
    return { options, bytesRead: pos - offset };
  }
}

export class RouterInfo {
  identity: RouterIdentity;
  addresses: RouterAddress[];
  options: Record<string, string>;
  published: number;
  signature: Buffer | null;
  private wireFormatData: Buffer | null;

  constructor(
    identity: RouterIdentity,
    addresses: RouterAddress[] = [],
    options: Record<string, string> = {},
    published: number | null = null,
    signature: Buffer | null = null
  ) {
    this.identity = identity;
    this.addresses = addresses;
    this.options = options;
    this.published = published || Date.now();
    this.signature = signature;
    this.wireFormatData = null;
  }

  setWireFormatData(data: Buffer): void {
    this.wireFormatData = Buffer.from(data);
  }

  getWireFormatData(): Buffer | null {
    return this.wireFormatData ? Buffer.from(this.wireFormatData) : null;
  }

  getRouterHash(): Buffer {
    return this.identity.getHash();
  }

  serialize(forSigning = false): Buffer {
    const identityData = this.identity.serialize();
    
    const published = Buffer.alloc(8);
    published.writeBigUInt64BE(BigInt(this.published));
    
    const addrCount = Buffer.alloc(1);
    addrCount.writeUInt8(this.addresses.length);
    
    const addrData = Buffer.concat(this.addresses.map(a => a.serialize()));
    
    const optionsData = this.serializeOptions();
    
    const data = Buffer.concat([identityData, published, addrCount, addrData, optionsData]);
    
    if (!forSigning && this.signature) {
      const sigLen = Buffer.alloc(2);
      sigLen.writeUInt16BE(this.signature.length);
      return Buffer.concat([data, sigLen, this.signature]);
    }
    
    return data;
  }

  serializeOptions(): Buffer {
    const entries = Object.entries(this.options);
    const count = Buffer.alloc(2);
    count.writeUInt16BE(entries.length);
    
    const parts: Buffer[] = [count];
    
    for (const [key, value] of entries) {
      const keyBuf = Buffer.from(key, 'utf8');
      const valBuf = Buffer.from(value, 'utf8');
      
      const keyLen = Buffer.alloc(1);
      keyLen.writeUInt8(keyBuf.length);
      
      const valLen = Buffer.alloc(2);
      valLen.writeUInt16BE(valBuf.length);
      
      parts.push(keyLen, keyBuf, valLen, valBuf);
    }
    
    return Buffer.concat(parts);
  }

  static deserialize(data: Buffer): RouterInfo {
    let pos = 0;
    
    const { identity, bytesRead: idBytes } = RouterIdentity.deserialize(data, pos);
    pos += idBytes;
    
    const published = Number(data.readBigUInt64BE(pos));
    pos += 8;
    
    const addrCount = data.readUInt8(pos);
    pos += 1;
    
    const addresses: RouterAddress[] = [];
    for (let i = 0; i < addrCount; i++) {
      const { address, bytesRead } = RouterAddress.deserialize(data, pos);
      addresses.push(address);
      pos += bytesRead;
    }
    
    const { options, bytesRead: optBytes } = RouterInfo.deserializeOptions(data, pos);
    pos += optBytes;
    
    let signature: Buffer | null = null;
    if (pos + 2 <= data.length) {
      const sigLen = data.readUInt16BE(pos);
      pos += 2;
      if (pos + sigLen <= data.length) {
        signature = data.slice(pos, pos + sigLen);
      }
    }
    
    return new RouterInfo(identity, addresses, options, published, signature);
  }

  static deserializeOptions(data: Buffer, offset: number): { options: Record<string, string>; bytesRead: number } {
    let pos = offset;
    const count = data.readUInt16BE(pos);
    pos += 2;
    
    const options: Record<string, string> = {};
    
    for (let i = 0; i < count; i++) {
      const keyLen = data.readUInt8(pos);
      pos += 1;
      
      const key = data.slice(pos, pos + keyLen).toString('utf8');
      pos += keyLen;
      
      const valLen = data.readUInt16BE(pos);
      pos += 2;
      
      const value = data.slice(pos, pos + valLen).toString('utf8');
      pos += valLen;
      
      options[key] = value;
    }
    
    return { options, bytesRead: pos - offset };
  }
}

export default { RouterIdentity, RouterAddress, RouterInfo };

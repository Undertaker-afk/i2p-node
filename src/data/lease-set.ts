import { RouterIdentity } from './router-info.js';

export interface DeserializedLease {
  lease: Lease;
  bytesRead: number;
}

export class Lease {
  tunnelGateway: Uint8Array;
  tunnelId: number;
  expiration: number;

  constructor(tunnelGateway: Uint8Array, tunnelId: number, expiration: number) {
    this.tunnelGateway = tunnelGateway;
    this.tunnelId = tunnelId;
    this.expiration = expiration;
  }

  serialize(): Buffer {
    const tunnelId = Buffer.alloc(4);
    tunnelId.writeUInt32BE(this.tunnelId);
    
    const expiration = Buffer.alloc(8);
    expiration.writeBigUInt64BE(BigInt(this.expiration));
    
    return Buffer.concat([
      Buffer.from(this.tunnelGateway),
      tunnelId,
      expiration
    ]);
  }

  static deserialize(data: Buffer, offset = 0): DeserializedLease {
    let pos = offset;
    
    const tunnelGateway = data.slice(pos, pos + 32);
    pos += 32;
    
    const tunnelId = data.readUInt32BE(pos);
    pos += 4;
    
    const expiration = Number(data.readBigUInt64BE(pos));
    pos += 8;
    
    return {
      lease: new Lease(tunnelGateway, tunnelId, expiration),
      bytesRead: pos - offset
    };
  }
}

export class LeaseSet {
  destination: RouterIdentity;
  encryptionKey: Uint8Array;
  signingKey: Uint8Array;
  leases: Lease[];
  signature: Uint8Array | null;
  private wireFormatData: Buffer | null;

  constructor(
    destination: RouterIdentity,
    encryptionKey: Uint8Array,
    signingKey: Uint8Array,
    leases: Lease[] = [],
    signature: Uint8Array | null = null
  ) {
    this.destination = destination;
    this.encryptionKey = encryptionKey;
    this.signingKey = signingKey;
    this.leases = leases;
    this.signature = signature;
    this.wireFormatData = null;
  }

  setWireFormatData(data: Buffer): void {
    this.wireFormatData = Buffer.from(data);
  }

  getWireFormatData(): Buffer | null {
    return this.wireFormatData ? Buffer.from(this.wireFormatData) : null;
  }

  getHash(): Buffer {
    // The LeaseSet hash is the ident hash = SHA256(identity bytes).
    // When the destination has a precomputed hash (set from I2P wire data)
    // this returns the correct I2P-compatible ident hash.
    return this.destination.getHash();
  }

  getExpiration(): number {
    if (this.leases.length === 0) return 0;
    return Math.max(...this.leases.map(l => l.expiration));
  }

  serialize(forSigning = false): Buffer {
    const destData = this.destination.serialize();
    
    const encKeyLen = Buffer.alloc(2);
    encKeyLen.writeUInt16BE(this.encryptionKey.length);
    
    const sigKeyLen = Buffer.alloc(2);
    sigKeyLen.writeUInt16BE(this.signingKey.length);
    
    const leaseCount = Buffer.alloc(1);
    leaseCount.writeUInt8(this.leases.length);
    
    const leaseData = Buffer.concat(this.leases.map(l => l.serialize()));
    
    const data = Buffer.concat([
      destData,
      encKeyLen,
      Buffer.from(this.encryptionKey),
      sigKeyLen,
      Buffer.from(this.signingKey),
      leaseCount,
      leaseData
    ]);
    
    if (!forSigning && this.signature) {
      return Buffer.concat([data, Buffer.from(this.signature)]);
    }
    
    return data;
  }

  static deserialize(data: Buffer): LeaseSet {
    let pos = 0;
    
    const { identity: destination, bytesRead: destBytes } = RouterIdentity.deserialize(data, pos);
    pos += destBytes;
    
    const encKeyLen = data.readUInt16BE(pos);
    pos += 2;
    
    const encryptionKey = data.slice(pos, pos + encKeyLen);
    pos += encKeyLen;
    
    const sigKeyLen = data.readUInt16BE(pos);
    pos += 2;
    
    const signingKey = data.slice(pos, pos + sigKeyLen);
    pos += sigKeyLen;
    
    const leaseCount = data.readUInt8(pos);
    pos += 1;
    
    const leases: Lease[] = [];
    for (let i = 0; i < leaseCount; i++) {
      const { lease, bytesRead } = Lease.deserialize(data, pos);
      leases.push(lease);
      pos += bytesRead;
    }
    
    const signature = data.slice(pos);
    
    return new LeaseSet(destination, encryptionKey, signingKey, leases, signature);
  }
}

export default { Lease, LeaseSet };

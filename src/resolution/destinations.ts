import { NetworkDatabase } from '../netdb/index.js';
import { LeaseSet } from '../data/lease-set.js';
import { base32DecodeToHash } from '../i2p/base32.js';

/**
 * Resolve a .b32.i2p hostname to a LeaseSet in the local NetDb, if present.
 * Returns null if the host is not a valid base32 name or the LeaseSet is unknown.
 */
export function resolveBase32LeaseSet(host: string, netDb: NetworkDatabase): LeaseSet | null {
  const hash = base32DecodeToHash(host);
  if (!hash) return null;
  return netDb.lookupLeaseSet(hash);
}


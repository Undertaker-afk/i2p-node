import test from 'node:test';
import assert from 'node:assert/strict';
import { TunnelManager, TunnelType } from './manager.js';
import { NetworkDatabase } from '../netdb/index.js';
import { RouterIdentity, RouterInfo } from '../data/router-info.js';
import { Crypto } from '../crypto/index.js';

function buildLocalRouterInfo(): RouterInfo {
  const identity = new RouterIdentity(Crypto.randomBytes(32), Crypto.randomBytes(32));
  identity.setHash(Buffer.alloc(32, 0xaa));
  return new RouterInfo(identity, [], { caps: 'LR' }, Date.now(), Buffer.alloc(64, 0xbb));
}

test('TunnelManager builds zero-hop inbound tunnels for local replies', async () => {
  const localRouterInfo = buildLocalRouterInfo();
  const tunnelManager = new TunnelManager(new NetworkDatabase({ enableReseed: false }), localRouterInfo);

  const tunnel = await tunnelManager.buildTunnel(TunnelType.INBOUND, 0);
  assert.ok(tunnel);
  assert.equal(tunnel.hops.length, 0);
  assert.deepEqual(tunnel.gateway.getRouterHash(), localRouterInfo.getRouterHash());
  assert.deepEqual(tunnel.endpoint.getRouterHash(), localRouterInfo.getRouterHash());

  const leaseSet = tunnelManager.createLeaseSet([tunnel.id]);
  assert.equal(leaseSet.leases.length, 1);
  assert.deepEqual(leaseSet.leases[0].tunnelGateway, localRouterInfo.getRouterHash());
  assert.equal(leaseSet.leases[0].tunnelId, tunnel.id);

  const raw = Buffer.from('inner-i2np');
  const wrapped = tunnelManager.encryptForTunnel(tunnel.id, raw);
  assert.deepEqual(wrapped, [raw]);
});

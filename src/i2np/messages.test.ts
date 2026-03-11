import test from 'node:test';
import assert from 'node:assert/strict';
import { I2NPMessages, I2NPMessageType } from './messages.js';

test('createDatabaseLookup validates delivery and ECIES inputs', () => {
  const key = Buffer.alloc(32, 1);
  const fromHash = Buffer.alloc(32, 2);

  assert.throws(
    () => I2NPMessages.createDatabaseLookup(key, fromHash, 1, [], { replyTunnelId: 0 }),
    /replyTunnelId must be a non-zero integer/
  );

  assert.throws(
    () => I2NPMessages.createDatabaseLookup(key, fromHash, 1, [], { eciesSessionKey: Buffer.alloc(32, 3) }),
    /require both eciesSessionKey and eciesSessionTag/
  );

  assert.throws(
    () => I2NPMessages.createDatabaseLookup(key, fromHash, 1, [Buffer.alloc(31)], {}),
    /excluded peers must be 32 bytes/
  );
});

test('createDatabaseLookup serializes valid ECIES reply material', () => {
  const key = Buffer.alloc(32, 1);
  const fromHash = Buffer.alloc(32, 2);
  const sessionKey = Buffer.alloc(32, 3);
  const sessionTag = Buffer.alloc(8, 4);
  const excluded = [Buffer.alloc(32, 5)];

  const msg = I2NPMessages.createDatabaseLookup(key, fromHash, 1, excluded, {
    replyTunnelId: 7,
    eciesSessionKey: sessionKey,
    eciesSessionTag: sessionTag
  });

  assert.equal(msg.type, I2NPMessageType.DATABASE_LOOKUP);
  assert.equal(msg.payload.readUInt8(64), 0x15);
  assert.equal(msg.payload.readUInt32BE(65), 7);
  assert.equal(msg.payload.readUInt16BE(69), 1);
  assert.deepEqual(msg.payload.subarray(71, 103), excluded[0]);
  assert.deepEqual(msg.payload.subarray(103, 135), sessionKey);
  assert.equal(msg.payload.readUInt8(135), 1);
  assert.deepEqual(msg.payload.subarray(136, 144), sessionTag);
});

test('garlic clove payload round-trips local I2NP messages', () => {
  const inner = I2NPMessages.createDatabaseSearchReply(
    Buffer.alloc(32, 1),
    [Buffer.alloc(32, 2), Buffer.alloc(32, 3)],
    Buffer.alloc(32, 4)
  );

  const payload = I2NPMessages.createGarlicClovePayload([inner]);
  const parsed = I2NPMessages.parseGarlicCloveMessages(payload);

  assert.ok(parsed);
  assert.equal(parsed.length, 1);
  assert.equal(parsed[0].deliveryFlag, 0);
  assert.equal(parsed[0].message.type, inner.type);
  assert.equal(parsed[0].message.uniqueId, inner.uniqueId);
  assert.equal(parsed[0].message.expiration, Math.floor(inner.expiration / 1000) * 1000);
  assert.deepEqual(parsed[0].message.payload, inner.payload);
});

test('parseGarlicOuterMessage reads the length-delimited body', () => {
  const body = Buffer.concat([Buffer.alloc(8, 9), Buffer.alloc(24, 7)]);
  const payload = Buffer.alloc(4 + body.length);
  payload.writeUInt32BE(body.length, 0);
  body.copy(payload, 4);

  const parsed = I2NPMessages.parseGarlicOuterMessage(payload);
  assert.ok(parsed);
  assert.equal(parsed.length, body.length);
  assert.deepEqual(parsed.body, body);
});

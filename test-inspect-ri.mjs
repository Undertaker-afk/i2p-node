import { readFileSync } from 'fs';

const file = 'c:/Users/floga/Desktop/coding/fun/i2p-node/i2p-test-data/netDb/routerInfo-0012fc6e56612b14f6235c3717ba2b04cab5e2e7c114fc47cf9073b65e194270.dat';
const data = readFileSync(file);
console.log('file size:', data.length);
console.log('first 32 bytes:', data.slice(0, 32).toString('hex'));
console.log('bytes 383-391:', data.slice(383, 392).toString('hex'));

// Check cert type at offset 384 (standard layout: 256+128 = 384)
const certType = data[384];
const certLen = data.readUInt16BE(385);
console.log('cert type at 384:', certType);
console.log('cert len at 385-386:', certLen);
console.log('expected total:', 387 + certLen);

// Try reading first 2 bytes as length prefix (custom format)
const sigKeyLen = data.readUInt16BE(0);
const encKeyLen = data.readUInt16BE(2 + sigKeyLen);
console.log('if custom format: sigKeyLen=', sigKeyLen, 'encKeyLen=', encKeyLen);

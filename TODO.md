## I2P-Node Router TODO

### Legend
- [x] Done
- [~] Partially done
- [ ] Not done

---

## MVP Goal

Start router → establish sessions → build tunnels → resolve LeaseSet via base32 hash → stream connect → HTTP GET succeeds for a b32 eepsite.

---

### Checkpoint A — Identities + RouterInfo Publish (~90%)

- [x] IdentityEx layout (387 standard + 4 extended bytes, CERTIFICATE_TYPE_KEY=5)
- [x] Ed25519 signing/verification via `@noble/curves/ed25519`
- [x] RouterInfo writer — i2pd-compatible wire format (`src/i2p/routerinfo/writer.ts`)
- [x] NTCP2 published/unpublished address options (s, i, host, port, v, caps)
- [x] Retain all address options (s, i, introducers, mtu) from parsed RouterInfos
- [x] I2P base64 with correct padding (required by i2pd's `Base64ToByteStream`)
- [~] NetDb publish — `publishRouterInfo()` finds closest floodfills but does NOT send DatabaseStore over the wire yet

### Checkpoint B — NTCP2 Handshake + Data Phase (~85%)

- [x] Full Noise XK handshake: SessionRequest / SessionCreated / SessionConfirmed
- [x] AES-CBC obfuscation of ephemeral X (and Y with IV chaining)
- [x] SipHash-2-4 length obfuscation in data phase
- [x] ChaCha20-Poly1305 AEAD for all handshake messages and data frames
- [x] Data-phase key derivation (k_ab, k_ba, SipHash keys)
- [x] Data-phase block framing (type + length + data)
- [x] Termination block decoding with human-readable reason names
- [x] Integration test against real i2pd peers (~60% success rate, no more reason-15 rejections)
- [~] Some peers still close with `socket closed before handshake established` (normal for NAT/offline peers)
- [ ] Inbound session handling (Bob side) — implemented but untested against real peers

### Checkpoint C — SSU2 Session Establishment (~70%)

- [x] SessionRequest/SessionCreated with encrypted handshake payloads
- [x] Minimal data packet encrypt/decrypt (ChaCha20-Poly1305, packet number nonce)
- [x] Token exchange (`NewToken` + request retry with token)
- [x] SessionConfirmed message
- [x] Ack/nack protocol (lightweight packet-number based)
- [x] Retry and timeout handling (handshake + data retransmit)
- [x] Key rotation (periodic HMAC-based rekey)
- [ ] NAT traversal, introducers, peer testing

### Checkpoint D — I2NP + NetDb Messaging (~75%)

- [x] I2NP short header format (type/1 + msgId/4 + shortExpiration/4 + payload)
- [x] DatabaseStore — create and handle (with gzip decompression for incoming RI)
- [x] DatabaseLookup — create and handle (respond with DatabaseStore)
- [x] DeliveryStatus — create and handle
- [x] Wire I2NP into NTCP2 transport (block type 3)
- [x] Parse incoming DatabaseStore for RI (type 0), LS1 (type 1), LS2 (type 3)
- [~] DatabaseSearchReply — type enumerated but no parser/builder
- [ ] Full I2NP header variant (16-byte) for tunnel messages
- [ ] Garlic message (type 11) — enumerated but not processed

### Checkpoint E — Tunnels (ECIES) + Tunnel Messages (~30%)

- [x] Tunnel message format — 1028-byte AES-CBC with IV and checksum
- [x] TunnelManager scaffolding — hop selection, layer/IV key generation
- [~] TunnelBuild/TunnelBuildReply handlers — receive but don't process real build records
- [ ] ECIES-X25519 tunnel build records — construct and send over the network
- [ ] Delivery instructions — only LOCAL unfragmented; need TUNNEL/ROUTER types
- [ ] Fragment reassembly for multi-fragment tunnel messages
- [ ] Actually build tunnels over the network (currently local-only)
- [ ] Tunnel renewal and tear-down

### Checkpoint F — Garlic + LeaseSet2 + Base32 Resolution (~60%)

- [x] LeaseSet1 parsing (`parseLeaseSetLS1`)
- [x] LeaseSet2 parsing with ECIES-X25519 encryption key preference (`parseLeaseSetLS2`)
- [x] LeaseSet storage/lookup in NetDb
- [x] Base32 decoding (`xxxx.b32.i2p` → 32-byte hash)
- [x] `resolveBase32LeaseSet()` — NetDb lookup for destination hash
- [x] `fetchLeaseSet()` — query floodfills for missing LeaseSets
- [ ] Garlic message parsing/building (entirely missing)
- [ ] Encrypted LeaseSet2 (ELS2) — blinded keys, HKDF layers, client auth
- [ ] Local LeaseSet creation and publish

### Checkpoint G — Streaming + HTTP Fetch (~15%)

- [~] Custom streaming scaffold — Stream class with seq/ack and naive retransmit
- [ ] I2P streaming protocol spec compliance (SYN/CLOSE/RESET, window sizing, sequence space)
- [ ] HTTP client over streaming to b32 eepsites
- [ ] Local HTTP proxy

### Checkpoint H — Toward Complete (~20%)

- [x] Peer profiling — connection scoring, peer selection by capacity/floodfill/failure rate
- [~] SAM protocol — TCP server with HELLO, SESSION, STREAM, NAMING, DEST commands (not wired to real tunnels)
- [~] WebUI — basic status server
- [~] Crypto suite — X25519, Ed25519, ChaCha20-Poly1305, AES-256-CBC, SHA-256, HMAC, HKDF, SipHash
- [ ] Missing crypto: ElGamal, DSA-SHA1, ECDSA variants, RedDSA, Blinding
- [ ] SU3 signature verification (parsed but not verified against reseed certs)
- [ ] Addressbook hostnames + subscriptions
- [ ] Router participation — relaying, introducers, peer testing, congestion, bans
- [ ] Config file / CLI flags
- [ ] Metrics and health endpoints

---

## Critical Path to MVP

```
E (real tunnel builds) → F (garlic) → G (spec streaming + HTTP) → MVP done
```

Tunnels are the biggest blocker. Once ECIES build records are sent over real NTCP2 sessions, garlic wrapping and streaming can follow.

---

## Reseed & Bootstrap (done)

- [x] HTTPS reseed client (`src/netdb/reseed.ts`)
- [x] Download `i2pseeds.su3` from real reseed servers
- [x] Parse SU3 header and extract embedded ZIP
- [x] Extract routerInfo `.dat` entries from ZIP
- [x] Integrate reseed with `NetworkDatabase.start()` and thresholds

## I2P RouterInfo Parsing (done)

- [x] I2P-compatible RouterInfo parser (`src/data/router-info-i2p.ts`)
- [x] Parse timestamp, addresses, peers (ignored), properties
- [x] Map `caps`, `netId`, `router.version`, `core.version` into options
- [x] Compute correct ident hash from raw identity bytes
- [x] Feed parsed `RouterInfo` objects into `NetworkDatabase.storeRouterInfo`

## NetDb Core (done)

- [x] In-memory router/leaseset storage (`src/netdb/index.ts`)
- [x] Floodfill tracking based on caps containing `f`
- [x] Disk persistence of router infos (`netDb/routerInfo-*.dat`)
- [x] Periodic maintenance + expiration

## Online / Status Heuristics (done)

- [x] `isOnline()` — router count ≥ 90, floodfills ≥ 5, addressed routers ≥ 10
- [x] Web UI status endpoint and basic console

## Repository Maintenance

- [x] Consolidate example test/smoke **source** files into top-level `examples/`.
- [x] Update moved test imports to use `../dist/...` runtime paths so they continue to run via `ts-node --esm` after build.
- [x] Keep compiled outputs out of source test moves (`dist/**` untouched).


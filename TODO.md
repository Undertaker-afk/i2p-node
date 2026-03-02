## I2P-Node Router TODO

### Legend
- [x] Done
- [ ] Not done / partial

---

### 1. Minimal Usable Router (MVP)

Goal: Router can bootstrap, stay peered with the real I2P network, and support basic NetDb operations and simple tunnels (enough for experimental use, not production-hard).

- [x] **Reseed & Bootstrap**
  - [x] Implement HTTPS reseed client (`src/netdb/reseed.ts`)
  - [x] Download `i2pseeds.su3` from real reseed servers
  - [x] Parse SU3 header and extract embedded ZIP
  - [x] Extract routerInfo `.dat` entries from ZIP
  - [x] Integrate reseed with `NetworkDatabase.start()` and thresholds

- [x] **I2P RouterInfo Parsing**
  - [x] Implement I2P-compatible RouterInfo parser (`src/data/router-info-i2p.ts`)
  - [x] Parse timestamp, addresses, peers (ignored), properties
  - [x] Map `caps`, `netId`, `router.version`, `core.version` into options
  - [x] Compute correct ident hash from raw identity bytes
  - [x] Feed parsed `RouterInfo` objects into `NetworkDatabase.storeRouterInfo`

- [x] **NetDb Core**
  - [x] In-memory router/leaseset storage (`src/netdb/index.ts`)
  - [x] Floodfill tracking based on caps containing `f`
  - [x] Disk persistence of router infos (`netDb/routerInfo-*.dat`)
  - [x] Periodic maintenance + expiration
  - [x] Exploratory lookup event emission (no wire protocol yet)

- [x] **Online / Status Heuristics**
  - [x] `isOnline()` based on:
    - [x] Router count ≥ 90
    - [x] Floodfills ≥ 5
    - [x] Routers with at least one address ≥ 10
  - [x] Web UI status endpoint and basic console (`src/webui/simple-server.ts`)

- [ ] **NTCP2 / SSU2 Session Bring-Up (MVP level)**
  - [x] Open listening sockets for NTCP2 and SSU2
  - [ ] Complete Noise-based NTCP2 handshake for outbound sessions
  - [ ] Complete NTCP2 handshake for inbound sessions
  - [ ] Define framing for I2NP messages over NTCP2
  - [ ] Basic SSU2 handshake (can be deferred until after NTCP2 works)

- [ ] **I2NP Core (MVP subset)**
  - [ ] Implement I2NP message header + generic serializer/deserializer
  - [ ] Implement these minimal message types:
    - [ ] `DatabaseLookup`
    - [ ] `DatabaseStore`
    - [ ] `DatabaseSearchReply`
    - [ ] `DeliveryStatus`
  - [ ] Wire `I2NPMessages` to/from transports (NTCP2/SSU2) so `handleTransportMessage` sees real I2NP frames

- [ ] **NetDb over the Wire (MVP subset)**
  - [ ] On exploratory events, send `DatabaseLookup` to known floodfills
  - [ ] On incoming `DatabaseStore` / `DatabaseSearchReply`, update `NetworkDatabase`:
    - [ ] Parse and store `RouterInfo` entries (I2P format)
    - [ ] Parse and store `LeaseSet` entries (at least minimal)

- [ ] **Tunnels (MVP subset)**
  - [ ] Implement minimal `TunnelBuild` / `TunnelBuildReply` handling
  - [ ] Build a single outbound and inbound tunnel for a local client
  - [ ] Route basic payloads through tunnels to known test destinations

---

### 2. Towards a More Complete Router

Goal: Feature set closer to `i2pd` / Java I2P, capable of general-purpose use (still experimental, but not just a toy).

- [ ] **Full RouterInfo / Identity Compatibility**
  - [x] Accept real I2P RouterInfos from reseed and NetDb
  - [ ] Implement full I2P identity representation (encryption/signing key types, certificates)
  - [ ] Honor/verify RouterInfo signatures using signing key
  - [ ] Validate `netId`, versions, and caps more strictly (mark unreachable if invalid)

- [ ] **Transports**
  - [ ] Production-grade NTCP2 implementation (timeouts, reconnection, session limits)
  - [ ] Production-grade SSU2 (NAT traversal, introducers, MTU handling)
  - [ ] IPv4/IPv6/Yggdrasil support flags consistent with caps and address caps

- [ ] **Complete I2NP Coverage**
  - [ ] Implement the full set of core I2NP message types used by tunnels and NetDb
  - [ ] Robust message fragmentation/reassembly if needed
  - [ ] Priority and congestion handling

- [ ] **Tunnels**
  - [ ] Full tunnel build/renew/tear-down logic
  - [ ] Participation as intermediate hop (relay)
  - [ ] Garlic message routing and reply blocks

- [ ] **LeaseSets & Destinations**
  - [x] Basic LeaseSet (LS1) parsing/serialization
  - [x] Standard, public LeaseSet2 (LS2) parsing into internal `LeaseSet` (no encrypted LS2, no offline keys yet)
  - [ ] Encrypted LeaseSet2 (ELS2) support (blinded keys, HKDF layers, client auth)
  - [ ] Full LeaseSet publish path (LocalLeaseSet/LS2 creation and signing)
  - [ ] Local destination management for services (HTTP proxies, IRC, etc.)
  - [ ] Garlic signing/encryption with correct crypto suites

- [ ] **SAM / Application API**
  - [ ] Implement full SAM v3 protocol surface
  - [ ] Map SAM sessions/streams to real tunnels and destinations
  - [ ] Basic stream-level flow control & error handling

- [ ] **Advanced NetDb**
  - [ ] Kademlia-style bucket management / router selection policies
  - [ ] Blacklisting / banning misbehaving routers
  - [ ] Smarter peer selection for tunnels and lookups

- [ ] **Reseed Hardening**
  - [ ] SU3 signature verification against trusted reseed certificates
  - [ ] Configurable reseed servers and thresholds
  - [ ] Yggdrasil reseed URLs (optional)

- [ ] **Operational Features**
  - [ ] Metrics and health endpoints
  - [ ] Config file / CLI flags for all major options
  - [ ] Logging & rotation suitable for long-running nodes

- [ ] **Interop & Testing**
  - [ ] Interoperate with stock `i2pd` and Java I2P in a mixed network
  - [ ] Integration tests for reseed, NetDb sync, tunnel build, and simple SAM streams
  - [ ] Fuzz/basic robustness tests for all on-wire parsers (RouterInfo, I2NP, LeaseSet)


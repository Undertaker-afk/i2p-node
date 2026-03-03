# I2P-Node Expanded Roadmap & Technical TODO

This document provides a detailed technical breakdown of the remaining tasks required to reach a fully functional I2P router/daemon in TypeScript. It expands upon the high-level goals in `TODO.md` with specific protocol requirements and implementation details.

---

## 🏁 MVP Goal
**Start router → establish sessions → build tunnels → resolve LeaseSet via base32 hash → stream connect → HTTP GET succeeds for a b32 eepsite.**

---

## 🏗 Checkpoint A: Identities & RouterInfo (95%)
*Focus: Identity generation and RouterInfo interoperability.*

- [x] **IdentityEx Support**: Implement the 387+4 byte layout with `CERTIFICATE_TYPE_KEY=5`.
- [x] **Ed25519 Signing**: Integration with `@noble/curves`.
- [x] **RouterInfo Writer**: Serialization compatible with i2pd/Java-I2P.
- [x] **I2P Base64**: Custom padding requirements for network interop.
- [ ] **Published RouterInfo Maintenance**:
    - [ ] Implement `isPublished` heuristic based on reachable IP/Port.
    - [ ] Auto-update `stat_uptime` and `published` timestamp.
    - [ ] Sign and re-serialize when addresses or properties change.
- [ ] **NetDb Publication**:
    - [ ] Wrap `DatabaseStore` in `GarlicMessage` for secure publication.
    - [ ] Implement floodfill selection based on XOR distance to router hash.

---

## 📡 Checkpoint B: NTCP2 Transport (90%)
*Focus: High-performance, Noise-based TCP transport.*

- [x] **Noise XK Handshake**: SessionRequest, SessionCreated, SessionConfirmed.
- [x] **AEAD & Obfuscation**: ChaCha20-Poly1305 and SipHash length masking.
- [ ] **Inbound Session Hardening**:
    - [ ] Implement session limits per IP.
    - [ ] Handle simultaneous open (rare but possible).
- [ ] **Performance & Buffering**:
    - [ ] Optimize `recvBuffer` management to avoid excessive `Buffer.concat`.
    - [ ] Implement backpressure for high-bandwidth streams.
- [ ] **Termination Codes**:
    - [ ] Gracefully handle all 18+ termination reason codes.
    - [ ] Implement local termination on timeout or protocol error.

---

## 📶 Checkpoint C: SSU2 Transport (30%)
*Focus: UDP-based transport with NAT traversal.*

- [x] **Basic Handshake**: Token exchange and encrypted handshake payloads.
- [ ] **Packet Management**:
    - [ ] **Retransmission Queue**: Reliable delivery for handshake and signaling packets.
    - [ ] **Ack/Nack**: Precise bitmask-based acknowledgments.
- [ ] **NAT Traversal & Introducers**:
    - [ ] **Peer Testing**: Determine NAT type (Open, Restricted, Symmetric).
    - [ ] **Introducer Role**: Handle `RelayRequest` and `RelayResponse`.
    - [ ] **Hole Punching**: Coordinate with introducers to open UDP ports.
- [ ] **Path MTU Discovery**: Adaptive packet sizing.
- [ ] **IP/Port Change Detection**: Handling roaming or dynamic IP updates.

---

## ✉️ Checkpoint D: I2NP & Messaging (75%)
*Focus: The "Internal Protocol" for network messages.*

- [x] **Short Header**: Implementation for direct transport delivery.
- [ ] **Full 16-byte Header**: Required for tunnel-wrapped messages.
    - [ ] `Type` (1), `Flags` (1), `Expiration` (4), `Size` (2), `Checksum` (1), `MsgID` (4).
- [ ] **Garlic Messages (Type 11)**:
    - [ ] **Clove Parsing**: Handle multiple I2NP messages inside one Garlic message.
    - [ ] **Encryption**: Implement ECIES-X25519 (Ratchet-based) for Garlic.
- [ ] **Message Fragmentation**:
    - [ ] Split large I2NP messages across multiple 1024-byte tunnel messages.
    - [ ] Reassembly logic with timeout and fragment tracking.

---

## 🚇 Checkpoint E: Tunnels (30%)
*Focus: The core of I2P's anonymity layer.*

- [ ] **ECIES-X25519 Tunnel Builds**:
    - [ ] **Build Record Encryption**: Implement the layered ECIES encryption for hop records.
    - [ ] **Reply Path**: Encrypt build replies so only the creator can read them.
- [ ] **Tunnel Operations**:
    - [ ] **Gateway Logic**: Encapsulate I2NP into Tunnel messages.
    - [ ] **Participant Logic**: Layer-decrypt and forward to next hop.
    - [ ] **Endpoint Logic**: Decapsulate and inject back into I2NP handler.
- [ ] **Tunnel Strategy**:
    - [ ] **Hop Selection**: Avoid selecting multiple hops from the same IP prefix or family.
    - [ ] **Tunnel Pool**: Maintain a pool of pre-built tunnels (Inbound/Outbound).
    - [ ] **Exploratory Tunnels**: Low-bandwidth tunnels for NetDb lookups.
- [ ] **Tunnel Renewal**: Build "next" tunnels before current ones expire (10m lifespan).

---

## 🔒 Checkpoint F: Garlic & LeaseSet2 (60%)
*Focus: End-to-end encryption and destination resolution.*

- [x] **LeaseSet1 & LeaseSet2 Parsing**: Support for legacy and modern formats.
- [ ] **Garlic Layer**:
    - [ ] **Encryption Keys**: Track session tags and ratchets for each destination.
    - [ ] **Clove Handling**: Implement `DeliveryInstructions` (Local, Router, Tunnel, Destination).
- [ ] **Base32 Resolution**:
    - [ ] Targeted NetDb lookups for `.b32.i2p`.
    - [ ] Verification of LeaseSet signatures.
- [ ] **Blinded Keys (Encrypted LeaseSet2)**:
    - [ ] Implement Ed25519 blinding for private LeaseSets.
    - [ ] Credential-based access control.

---

## 🌊 Checkpoint G: Streaming Protocol (15%)
*Focus: Reliable, TCP-like streams over I2P.*

- [ ] **Spec Compliance**:
    - [ ] **SYN/ACK/FIN**: Proper 3-way handshake for streams.
    - [ ] **Windowing**: Sliding window flow control to handle high latency.
    - [ ] **Congestion Control**: Slow start and fast retransmit.
- [ ] **Streaming API**:
    - [ ] `Socket`-like interface for developers.
    - [ ] `Server`-like interface to accept incoming streams.
- [ ] **Optimization**:
    - [ ] Packet bundling (Nagle-like).
    - [ ] Keep-alive packets to maintain tunnel activity.

---

## 🛠 Checkpoint H: Management & Integration (20%)
*Focus: Making the router usable.*

- [ ] **SAM v3.3 Protocol**:
    - [ ] Complete `STREAM` support (connecting to and accepting).
    - [ ] `DATAGRAM` and `RAW` message support.
    - [ ] Proper error reporting for naming/connection failures.
- [ ] **Reseed Hardening**:
    - [ ] **SU3 Verification**: Verify reseed signatures against built-in certificates.
    - [ ] Multiple reseed sources and randomized selection.
- [ ] **Peer Profiling**:
    - [ ] Track RTT and success rates for every peer.
    - [ ] "Banning" of unreliable or malicious peers.
    - [ ] Floodfill ranking.
- [ ] **Web UI & Config**:
    - [ ] Real-time tunnel visualization.
    - [ ] NetDb explorer.
    - [ ] Bandwidth usage graphs.
    - [ ] Persisted configuration (`i2p-node.config`).

---

## 🧪 Testing & Verification
- [ ] **Interoperability Tests**: Connect to i2pd/Java nodes and exchange traffic.
- [ ] **Unit Tests**: Coverage for all crypto primitives and I2NP parsers.
- [ ] **Fuzzing**: I2NP and Tunnel message parsers should be fuzzed against malformed data.
- [ ] **Network Simulation**: Test router behavior under high packet loss/latency.

---

## 📚 Reference Specifications
- [NTCP2](https://geti2p.net/spec/ntcp2)
- [SSU2](https://geti2p.net/spec/ssu2)
- [Tunnel Build (ECIES)](https://geti2p.net/spec/proposals/152-ecies-tunnel-build)
- [I2NP](https://geti2p.net/spec/i2np)
- [Streaming](https://geti2p.net/spec/streaming)
- [SAM v3](https://geti2p.net/en/docs/api/samv3)

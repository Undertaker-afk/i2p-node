# I2P Router — TypeScript Implementation

A work-in-progress I2P router written in TypeScript/Node.js, designed to interoperate with the production I2P network (i2pd, Java I2P). The project is structured around a checkpoint-based development plan progressing toward an MVP: start router → build tunnels → resolve a .b32.i2p destination → stream-connect → HTTP GET an eepsite.

## Current Status

| Checkpoint | Area | Progress |
|:----------:|------|:--------:|
| **A** | Identities + RouterInfo publish | ~90% |
| **B** | NTCP2 handshake + data phase | ~85% |
| **C** | SSU2 session establishment | ~20% |
| **D** | I2NP + NetDb messaging | ~75% |
| **E** | Tunnels (ECIES) + tunnel messages | ~30% |
| **F** | Garlic + LeaseSet2 + base32 resolution | ~60% |
| **G** | Streaming + HTTP fetch | ~15% |
| **H** | Toward complete (SAM, WebUI, etc.) | ~20% |

**Critical path to MVP:** `E (real tunnel builds) → F (garlic) → G (streaming + HTTP)`

See [TODO.md](TODO.md) for detailed per-checkpoint task breakdown.

### What Works Today

- **NTCP2 outbound sessions** — Full Noise XK handshake with AES-CBC obfuscation, ChaCha20-Poly1305 AEAD, SipHash length obfuscation. Tested against real i2pd peers with ~60% connection success rate (remaining failures are NAT/offline peers, not protocol bugs).
- **Reseed** — HTTPS reseed from real reseed servers, SU3 parsing, ZIP extraction, RouterInfo import.
- **RouterInfo** — i2pd-compatible wire format writer, Ed25519 signing, correct I2P base64 (with padding), unpublished NTCP2 address.
- **I2NP over NTCP2** — DatabaseStore (with gzip decompression for incoming RI), DatabaseLookup, DeliveryStatus sent and received over established sessions.
- **NetDb** — In-memory + disk-persisted router/leaseset storage, floodfill tracking, maintenance/expiration.
- **LeaseSet parsing** — LS1 and LS2 with ECIES-X25519 encryption key preference.
- **Base32 resolution** — `.b32.i2p` → 32-byte hash → floodfill lookup.
- **Peer profiling** — Connection scoring and peer selection by capacity/floodfill/failure rate.

### What's Missing

- **Tunnel builds over the network** — TunnelManager scaffolds tunnels locally but does not send ECIES-X25519 build records.
- **Garlic messaging** — Entirely unimplemented. Required to wrap messages through tunnels.
- **Spec-compliant streaming** — Only a naive custom scaffold exists. I2P streaming protocol (SYN/CLOSE/RESET, window sizing) is not implemented.
- **SSU2** — Skeleton only; no token exchange, SessionConfirmed, or ack/nack.
- **Router participation** — No relay, introducer, or peer testing support.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         I2P Router                          │
├─────────────────────────────────────────────────────────────┤
│  SAM Protocol  │  Tunnel Manager  │  Network Database       │
│  (scaffold)    │  (local only)    │  (RouterInfo/LeaseSet)  │
├────────────────┴──────────────────┴─────────────────────────┤
│                      I2NP Messages                          │
├─────────────────────────────────────────────────────────────┤
│  NTCP2 Transport        │        SSU2 Transport             │
│  (working)              │        (skeleton)                 │
├─────────────────────────────────────────────────────────────┤
│                 Cryptographic Layer                         │
│  X25519 │ Ed25519 │ ChaCha20-Poly1305 │ AES-CBC │ SipHash   │
│  SHA-256 │ HKDF │ HMAC                                      │
└─────────────────────────────────────────────────────────────┘
```

## Getting Started

### Prerequisites

- Node.js 18+
- npm

### Installation

```bash
npm install
```

### Building

```bash
npx tsc
```

### Running

```bash
# Start the router
node dist/index.js

# Run the NTCP2 connection test (connects to 30 random peers)
node test-ntcp2-connect.mjs
```

## Project Structure

```
i2p-node/
├── src/
│   ├── crypto/             # X25519, Ed25519, ChaCha20, AES, SipHash, HKDF
│   ├── data/               # RouterInfo, RouterIdentity, LeaseSet parsers/writers
│   ├── i2np/               # I2NP message types and serialization
│   ├── i2p/                # Base64, RouterInfo writer, identity utilities
│   ├── netdb/              # Network database, reseed, disk persistence
│   ├── peer/               # Peer profiling and selection
│   ├── resolution/         # Base32 resolution, LeaseSet fetching
│   ├── sam/                # SAM v3. protocol scaffold
│   ├── streaming/          # Streaming protocol scaffold
│   ├── transport/          # NTCP2 (working), SSU2 (skeleton)
│   ├── tunnel/             # Tunnel manager (local-only scaffold)
│   ├── webui/              # Basic status web server
│   ├── utils/              # Logging, helpers
│   ├── router.ts           # Main router orchestration
│   └── index.ts            # Entry point
├── docs/                   # Peer discovery fix notes, test summaries
├── examples/               # Test scripts
├── TODO.md                 # Checkpoint-organized progress tracker
├── package.json
└── tsconfig.json
```

## Protocols

### NTCP2 (Noise XK) — Working
- Full 3-message Noise XK handshake (SessionRequest → SessionCreated → SessionConfirmed)
- AES-256-CBC obfuscation of ephemeral keys for DPI resistance
- ChaCha20-Poly1305 AEAD for all handshake and data-phase frames
- SipHash-2-4 length obfuscation in data phase
- Data-phase key derivation (k_ab, k_ba, SipHash keys)
- Termination block decoding with human-readable reason codes
- Interop-tested against real i2pd peers on the production network

### SSU2 — Skeleton
- Basic SessionRequest/SessionCreated frame structure
- Minimal ChaCha20-Poly1305 encrypt/decrypt
- Missing: token exchange, SessionConfirmed, ack/nack, retry, key rotation, NAT traversal

### I2NP Messages — Partial
- DatabaseStore (type 1) — create, parse, handle (with gzip decompression)
- DatabaseLookup (type 2) — create, parse, handle
- DeliveryStatus (type 10) — create, parse, handle
- DatabaseSearchReply (type 3) — enumerated, no parser
- Garlic (type 11) — enumerated, not processed
- TunnelBuild/TunnelBuildReply (types 20/21) — receive but don't process build records

### SAM v3 — Scaffold
- TCP server with HELLO, SESSION, STREAM, NAMING, DEST command parsing
- Not wired to real tunnel infrastructure

## Cryptographic Primitives

| Primitive | Library | Status |
|-----------|---------|--------|
| X25519 | `@noble/curves` | Working |
| Ed25519 | `@noble/curves/ed25519` | Working |
| ChaCha20-Poly1305 | Node.js `crypto` | Working |
| AES-256-CBC | Node.js `crypto` | Working |
| SHA-256 | Node.js `crypto` | Working |
| HMAC-SHA256 | Node.js `crypto` | Working |
| HKDF-SHA256 | Node.js `crypto` | Working |
| SipHash-2-4 | Custom implementation | Working |
| ElGamal | — | Not implemented |
| DSA-SHA1 | — | Not implemented |
| RedDSA / Blinding | — | Not implemented |

## Bandwidth Classes

| Class | Bandwidth | Description |
|-------|-----------|-------------|
| K | < 12 KB/s | Very low |
| L | 12–48 KB/s | Low |
| M | 48–64 KB/s | Medium |
| N | 64–128 KB/s | High |
| O | 128–256 KB/s | Very high |
| P | 256–2000 KB/s | Extreme |
| X | > 2000 KB/s | Unlimited |

## License

MIT

## References

- [I2P Technical Specification](https://geti2p.net/spec/)
- [NTCP2 Specification](https://geti2p.net/spec/ntcp2)
- [SSU2 Specification](https://geti2p.net/spec/ssu2)
- [I2NP Specification](https://geti2p.net/spec/i2np)
- [SAM v3 Specification](https://geti2p.net/en/docs/api/samv3)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [i2pd C++ Implementation](https://github.com/PurpleI2P/i2pd) (reference implementation used for interop testing)

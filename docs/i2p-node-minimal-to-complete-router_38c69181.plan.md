---
name: i2p-node-minimal-to-complete-router
overview: Implement a real interoperable I2P router in i2p-node (NTCP2 + SSU2 + I2NP + NetDb + tunnels), reaching an MVP that can fetch eepsites by base32 (*.b32.i2p) first, then expand toward a more complete implementation.
todos:
  - id: identity-routerinfo-writer
    content: Implement I2P IdentityEx + RouterInfo writer (signed) and retain transport keys/options from parsed RouterInfos.
    status: completed
  - id: ntcp2-spec
    content: Implement NTCP2 spec-correct handshake and data-phase framing; add handshake smoke test.
    status: completed
  - id: ssu2-spec
    content: Implement SSU2 spec-correct session establishment and data packets; add smoke test.
    status: completed
  - id: i2np-spec
    content: Replace simplified I2NP format with spec-correct header and NetDb message types.
    status: pending
  - id: netdb-over-wire
    content: Send/receive real DatabaseLookup/Store/SearchReply with floodfills using correct I2NP encoding.
    status: pending
  - id: tunnels-ecies
    content: Implement ECIES tunnel creation and tunnel message encryption/decryption + delivery instructions.
    status: pending
  - id: garlic-leaseset2-b32
    content: Implement minimal garlic + LeaseSet2 parsing/storage + base32 destination resolution.
    status: pending
  - id: streaming-http
    content: Implement streaming connect and HTTP fetch/proxy for b32 eepsites.
    status: pending
isProject: false
---

## Context / current state

- Reseed works and we can parse SU3/ZIP and extract routerInfo blobs.
- We have an I2P-style RouterInfo *parser* (`src/data/router-info-i2p.ts`) that reads timestamp/addresses/properties, but we do **not** yet have:
  - A valid I2P router identity representation (IdentityEx/cert/key types)
  - A valid signed RouterInfo *writer* that other routers will accept
  - NTCP2/SSU2 spec-correct handshakes and framed data-phase
  - Spec-correct I2NP, tunnels, garlic, LeaseSets, streaming

## MVP definition (per your selections)

- **Interop target**: Real I2P network
- **Transport scope**: NTCP2 + SSU2
- **Naming in MVP**: `*.b32.i2p` only (addressbook hostnames later)
- **User-visible MVP success**: Start router → establish sessions → build tunnels → resolve LeaseSet via base32 hash → stream connect → HTTP GET succeeds for a b32 eepsite.

## Approach (incremental checkpoints)

### Checkpoint A: Correct identities + RouterInfo publish

- Add I2P identity data structures and signing:
  - New module(s) e.g. `src/i2p/identity/`* implementing IdentityEx layout (standard 387 bytes + CERTIFICATE_TYPE_KEY extended bytes) and key-type handling.
  - Add EdDSA verification/signing (at minimum Ed25519) in `src/crypto/`* (likely via `@noble/curves/ed25519`).
- Add I2P RouterInfo writer:
  - New module e.g. `src/i2p/routerinfo/`* that serializes RouterInfo exactly like i2pd (timestamp, addresses, peers, properties) and appends the correct signature length/type.
  - Include NTCP2 and SSU2 published addresses with required options (`s`, `i`, `host`, `port`, `v`, `caps`, introducers for SSU2 later).
- Update `src/data/router-info-i2p.ts` to **retain all address options** from the RI (not just host/port/v/caps) so we keep `s` (static key) and `i` (iv/intro key) for transport handshakes.
- Implement NetDb publish path:
  - In `src/router.ts`, periodically send DatabaseStore (spec-correct I2NP) to closest floodfills (initially directly; later via tunnels/garlic).

### Checkpoint B: NTCP2 spec-correct handshake + data phase

- Replace the current “plain TCP + length prefix” shortcut in `src/transport/ntcp2.ts` with a spec-correct implementation (from `https://i2p.net/en/docs/specs/ntcp2/`):
  - SessionRequest / SessionCreated / SessionConfirmed
  - AES obfuscation of X and SipHash-obfuscated length fields
  - ChaCha20/Poly1305 for AEAD payloads with correct nonce construction
  - Derive send/recv keys and implement data-phase framing
- Add a small integration harness:
  - Example script that picks a reseeded peer with NTCP2 published address and attempts handshake, logging success/failure.

### Checkpoint C: SSU2 spec-correct session establishment

- Implement SSU2 per `https://beta.i2p.net/en/docs/specs/ssu2/`:
  - Session establishment (token/request/created/confirmed flow)
  - Data packet protection, ack/nack
  - Key rotation (can be deferred until after basic session works)
- Add an SSU2 smoke test example using a reseeded SSU2 peer.

### Checkpoint D: Spec-correct I2NP and NetDb messaging

- Replace the simplified I2NP format in `src/i2np/messages.ts` with the spec-correct header + payloads from `https://beta.i2p.net/en/docs/specs/i2np/`.
- Implement at minimum:
  - DatabaseLookup / DatabaseStore / DatabaseSearchReply
  - DeliveryStatus
- Wire these into the transports so incoming transport frames decode to I2NP messages, and outgoing messages encode correctly.

### Checkpoint E: Tunnels (ECIES) + tunnel message processing

- Implement ECIES tunnel creation per `https://beta.i2p.net/en/docs/specs/tunnel-creation-ecies`.
- Implement tunnel messages per `https://beta.i2p.net/en/docs/specs/tunnel-message/`:
  - Fixed-size 1028-byte tunnel message encryption/decryption
  - Delivery instructions parsing and fragment reassembly
- Build minimal tunnels:
  - 1 outbound + 1 inbound tunnel with small hop count
  - Maintain/renew periodically

### Checkpoint F: Garlic + LeaseSet2 + base32 destination connect

- Implement Garlic messages (subset sufficient for NetDb queries and streaming connect).
- Implement LeaseSet2 parsing/storage and NetDb lookup for leasesets.
- Implement base32 host resolution:
  - Parse `xxxx.b32.i2p` → 32-byte destination hash
  - NetDb lookup for LeaseSet

### Checkpoint G: Streaming + HTTP fetch/proxy

- Implement enough of Streaming protocol (or reuse SAM internally) to open a reliable stream to a destination.
- Add an HTTP client (and optionally a local HTTP proxy) that:
  - Resolves b32
  - Connects via streaming
  - Sends HTTP GET and returns response.

### Checkpoint H: Toward “complete”

- Add addressbook hostnames + subscriptions (random.i2p, etc.)
- Add router participation features: relaying, introducers, peer testing, congestion handling, profiling, bans
- Full signature/crypto suite coverage, SU3 verification, hardened NetDb policies

## Testing strategy (per checkpoint)

- Unit tests for binary parsers/serializers (Identity, RouterInfo, I2NP header)
- Integration smoke tests:
  - NTCP2 handshake to a reseeded peer
  - SSU2 handshake to a reseeded peer
  - NetDb query round-trip (lookup/store/searchreply)
  - Tunnel build success and message forwarding
  - HTTP GET over streaming to a known b32 eepsite


# I2P Router - TypeScript Implementation

A complete I2P (Invisible Internet Project) router implementation in TypeScript/Node.js.

## Overview

This project implements a full-featured I2P router with support for:
- **NTCP2 Transport**: Noise-based TCP transport for router-to-router communication
- **SSU2 Transport**: Modern UDP transport with ChaCha20/Poly1305 encryption
- **I2NP Protocol**: I2P Network Protocol for routing messages
- **Network Database (netDb)**: Distributed storage for RouterInfo and LeaseSet
- **Tunnel Management**: Inbound and outbound tunnel building
- **Peer Profiling**: Quality-based peer selection
- **SAM Protocol**: Simple Anonymous Messaging for client applications

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         I2P Router                          │
├─────────────────────────────────────────────────────────────┤
│  SAM Protocol  │  Tunnel Manager  │  Network Database       │
│  (Port 7656)   │                  │  (RouterInfo/LeaseSet)  │
├────────────────┴──────────────────┴─────────────────────────┤
│                      I2NP Messages                          │
├─────────────────────────────────────────────────────────────┤
│  NTCP2 Transport        │        SSU2 Transport             │
│  (TCP Port 12345)       │        (UDP Port 12346)           │
├─────────────────────────────────────────────────────────────┤
│                 Cryptographic Layer                         │
│     X25519  │  ChaCha20/Poly1305  │  SHA256  │  HKDF        │
└─────────────────────────────────────────────────────────────┘
```

## Installation

```bash
npm install
```

## Building

```bash
npm run build
```

## Running

### Development
```bash
npm run dev
```

### Production
```bash
npm run build
npm start
```

## Configuration

Configure the router using environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `I2P_HOST` | `0.0.0.0` | Bind address |
| `I2P_NTCP2_PORT` | `12345` | NTCP2 transport port |
| `I2P_SSU2_PORT` | `12346` | SSU2 transport port |
| `I2P_SAM_PORT` | `7656` | SAM protocol port |
| `I2P_FLOODFILL` | `false` | Enable floodfill mode |
| `I2P_BANDWIDTH` | `L` | Bandwidth class (K, L, M, N, O, P, X) |
| `I2P_SHARE_PERCENTAGE` | `80` | Bandwidth share percentage |
| `I2P_NET_ID` | `2` | Network ID |
| `I2P_DATA_DIR` | `./i2p-data` | Data directory |

## Usage

### As a CLI Application

```bash
# Start with default settings
node dist/index.js

# Start as floodfill with higher bandwidth
I2P_FLOODFILL=true I2P_BANDWIDTH=X node dist/index.js
```

### As a Library

```typescript
import { I2PRouter } from 'i2p-node';

const router = new I2PRouter({
  host: '0.0.0.0',
  ntcp2Port: 12345,
  ssu2Port: 12346,
  samPort: 7656,
  isFloodfill: false,
  bandwidthClass: 'L'
});

router.on('started', () => {
  console.log('Router started');
});

router.on('tunnelBuilt', ({ tunnelId, type }) => {
  console.log(`Tunnel ${tunnelId} built (${type})`);
});

await router.start();
```

### Building Tunnels

```typescript
// Build an inbound tunnel (for receiving)
const inboundTunnel = await router.buildInboundTunnel(3);

// Build an outbound tunnel (for sending)
const outboundTunnel = await router.buildOutboundTunnel(3);

// Create a LeaseSet for a destination
const leaseSet = router.getTunnelManager()?.createLeaseSet([inboundTunnel!.id]);
```

### Using SAM Protocol

Connect to the SAM bridge at `127.0.0.1:7656`:

```
HELLO VERSION MIN=3.0 MAX=3.1\n
SESSION CREATE STYLE=STREAM ID=mySession DESTINATION=TRANSIENT\n
STREAM CONNECT ID=mySession DESTINATION=target.b32.i2p\n```

## Project Structure

```
i2p-node/
├── src/
│   ├── crypto/
│   │   └── index.ts          # Cryptographic primitives
│   ├── data/
│   │   ├── router-info.ts    # RouterIdentity, RouterAddress, RouterInfo
│   │   └── lease-set.ts      # Lease, LeaseSet
│   ├── transport/
│   │   ├── ntcp2.ts          # NTCP2 transport implementation
│   │   └── ssu2.ts           # SSU2 transport implementation
│   ├── i2np/
│   │   └── messages.ts       # I2NP message types and parsing
│   ├── netdb/
│   │   └── index.ts          # Network database
│   ├── tunnel/
│   │   └── manager.ts        # Tunnel management
│   ├── peer/
│   │   └── profiles.ts       # Peer profiling and selection
│   ├── sam/
│   │   └── protocol.ts       # SAM protocol implementation
│   ├── router.ts             # Main router orchestration
│   └── index.ts              # Entry point
├── dist/                     # Compiled JavaScript
├── package.json
└── tsconfig.json
```

## Protocols Implemented

### NTCP2 (Noise XK)
- X25519 ephemeral keys
- ChaCha20/Poly1305 AEAD encryption
- 3-message handshake
- AES-256-CBC obfuscation for DPI resistance

### SSU2
- X25519 key exchange
- ChaCha20/Poly1305 authenticated encryption
- UDP-based with connection migration
- Relay support for NAT traversal

### I2NP Messages
- DatabaseStore (1)
- DatabaseLookup (2)
- DatabaseSearchReply (3)
- DeliveryStatus (10)
- Garlic (11)
- TunnelData (18)
- TunnelGateway (19)
- TunnelBuild (20)
- TunnelBuildReply (21)

### SAM v3.1
- Session management
- Stream connections
- Forwarding
- Destination generation
- Naming lookups

## Security

- **Encryption**: X25519 ECDH, ChaCha20/Poly1305 AEAD
- **Hashing**: SHA-256 for all hash operations
- **Key Derivation**: HKDF-SHA256
- **Forward Secrecy**: Ephemeral keys for every session
- **DPI Resistance**: Protocol obfuscation in NTCP2

## Bandwidth Classes

| Class | Bandwidth | Description |
|-------|-----------|-------------|
| K | < 12 KB/s | Very low bandwidth |
| L | 12-48 KB/s | Low bandwidth |
| M | 48-64 KB/s | Medium bandwidth |
| N | 64-128 KB/s | High bandwidth |
| O | 128-256 KB/s | Very high bandwidth |
| P | 256-2000 KB/s | Extreme bandwidth |
| X | > 2000 KB/s | Unlimited bandwidth |

## License

MIT

## References

- [I2P Specification](https://geti2p.net/spec/)
- [NTCP2 Specification](https://geti2p.net/spec/ntcp2)
- [SSU2 Specification](https://geti2p.net/spec/ssu2)
- [I2NP Specification](https://geti2p.net/spec/i2np)
- [SAM v3 Specification](https://geti2p.net/en/docs/api/samv3)
- [Noise Protocol Framework](https://noiseprotocol.org/)

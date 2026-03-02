# I2P Node - Logging & Web UI Features

This document describes the logging and web UI features added to the i2p-node library.

## Logging System

The library includes a comprehensive 5-level logging system:

| Level | Value | Description |
|-------|-------|-------------|
| DEBUG | 0 | Detailed diagnostics for developers |
| INFO | 1 | Normal operational milestones |
| WARN | 2 | Potential issues; not breaking |
| ERROR | 3 | Functionality broken, user impact |
| FATAL | 4 | System crash or unrecoverable error |

### Setting Log Level

```javascript
import { I2PRouter, logger, LogLevel } from 'i2p-node';

// Method 1: Set globally before creating router
logger.setLevel(LogLevel.DEBUG);

// Method 2: Pass in router options
const router = new I2PRouter({
  logLevel: LogLevel.DEBUG  // Only logs INFO and above
});

// Method 3: Change at runtime
logger.setLevel(LogLevel.WARN);  // Only warnings and errors
```

### Using the Logger

```javascript
import { logger, debug, info, warn, error, fatal } from 'i2p-node';

// Using the singleton
logger.debug('Detailed debug info', { someData: 123 }, 'MyModule');
logger.info('Operation completed', undefined, 'MyModule');
logger.warn('Connection timeout', { timeout: 5000 }, 'Network');
logger.error('Failed to connect', { error: err.message }, 'Network');
logger.fatal('Unrecoverable error', { stack: err.stack }, 'System');

// Convenience exports
debug('Debug message');
info('Info message');
warn('Warning message');
error('Error message');
fatal('Fatal message');
```

### Log History

```javascript
import { logger } from 'i2p-node';

// Get all logs
const allLogs = logger.getHistory();

// Get only ERROR and FATAL logs
const errors = logger.getHistory({ level: LogLevel.ERROR });

// Get last 100 logs
const recent = logger.getHistory({ limit: 100 });

// Get logs from specific source
const networkLogs = logger.getHistory({ source: 'NTCP2' });

// Get stats
const stats = logger.getStats();
console.log(stats);
// { total: 1500, byLevel: { INFO: 1200, WARN: 200, ERROR: 100 } }

// Clear history
logger.clearHistory();
```

### Custom Log Handlers

```javascript
import { logger } from 'i2p-node';

// Add custom handler
logger.addHandler((entry) => {
  // Send to external service
  sendToLogAggregator({
    time: entry.timestamp,
    level: entry.levelName,
    message: entry.message,
    source: entry.source,
    data: entry.data
  });
});

// Remove handler
logger.removeHandler(myHandler);
```

## Simple Web UI

The library includes a minimal, no-frills web UI for monitoring.

### Starting with Web UI

```javascript
import { I2PRouter } from 'i2p-node';

const router = new I2PRouter({
  enableWebUI: true,
  webUIPort: 7070,  // Default: 7070
  host: '127.0.0.1'
});

await router.start();
// Web UI available at http://127.0.0.1:7070
```

### Web UI Pages

1. **Status Page** (`/`)
   - Router status (online/offline)
   - Uptime
   - Router hash
   - Network stats (peers, floodfills, tunnels)
   - Traffic statistics
   - Recent peers table

2. **Logs Page** (`/logs`)
   - Real-time log viewer
   - Filter by level (DEBUG, INFO, WARN, ERROR, FATAL)
   - Limit number of entries (100, 500, 1000, 5000)
   - Auto-scroll option
   - Source tracking

3. **API Endpoints**
   - `GET /api/status` - Router statistics JSON
   - `GET /api/logs?level=0&limit=500` - Log entries JSON
   - `GET /api/peers` - Connected peers JSON

### Using Web UI Independently

```javascript
import { SimpleWebUI, I2PRouter } from 'i2p-node';

const router = new I2PRouter({...});
await router.start();

// Create and start web UI separately
const webUI = new SimpleWebUI({
  port: 7070,
  host: '127.0.0.1',
  router: router
});

await webUI.start();

// Stop later
webUI.stop();
```

## Example: Complete Setup

```javascript
import { I2PRouter, logger, LogLevel } from 'i2p-node';

// Enable debug logging
logger.setLevel(LogLevel.DEBUG);

// Create router with all features
const router = new I2PRouter({
  // Transport ports
  ntcp2Port: 12345,
  ssu2Port: 12346,
  
  // Router settings
  bandwidthClass: 'L',
  isFloodfill: false,
  
  // Logging
  logLevel: LogLevel.DEBUG,
  
  // Web UI
  enableWebUI: true,
  webUIPort: 7070
});

// Listen to events
router.on('started', () => {
  console.log('Router started!');
  console.log('Web UI: http://127.0.0.1:7070');
});

router.on('tunnelBuilt', ({ tunnelId, type }) => {
  console.log(`Tunnel ${tunnelId} built (${type})`);
});

// Start
await router.start();
```

## Log Output Format

```
[2025-03-02T11:45:32.123Z] [INFO] Router started successfully
[2025-03-02T11:45:32.234Z] [DEBUG] Identity generated (Router)
[2025-03-02T11:45:32.345Z] [INFO] NTCP2 transport listening on 0.0.0.0:12345 (NTCP2)
[2025-03-02T11:45:32.456Z] [WARN] Connection timeout (Network) { timeout: 5000 }
[2025-03-02T11:45:32.567Z] [ERROR] Failed to build tunnel (Tunnel) { tunnelId: 5 }
```

## What's Logged

The library logs:

- **Router lifecycle**: start, stop, identity generation
- **Transport**: connections, disconnections, handshakes, errors
- **Tunnels**: build attempts, successes, failures, expirations
- **Peers**: connections, disconnections, profile updates
- **Network**: packet handling, timeouts, routing decisions
- **Web UI**: server start/stop, API requests

## Browser View

The web UI is intentionally simple with minimal styling:

```
┌─────────────────────────────────────────────┐
│ I2P Router Console                          │
├─────────────────────────────────────────────┤
│ [Status] [Logs]                             │
├─────────────────────────────────────────────┤
│ Router Status                               │
│   Status: ONLINE                            │
│   Uptime: 1h 23m                            │
│   Router Hash: abc123def...                 │
│   Version: 0.9.66                           │
├─────────────────────────────────────────────┤
│ Network                                     │
│   Known Peers: 150                          │
│   Active Peers: 25                          │
│   Floodfills: 10                            │
│   Active Tunnels: 8                         │
├─────────────────────────────────────────────┤
│ Recent Peers                                │
│ ┌──────────────┬──────────┬──────┬────────┐ │
│ │ Hash         │ Type     │ BW   │ Seen   │ │
│ ├──────────────┼──────────┼──────┼────────┤ │
│ │ abc123...    │ Floodfill│ 256  │ 10:23  │ │
│ └──────────────┴──────────┴──────┴────────┘ │
└─────────────────────────────────────────────┘
```

Log page shows:
```
[11:45:32.123] [INFO] Router started
[11:45:32.234] [DEBUG] NTCP2 listening
[11:45:33.456] [WARN] Connection timeout
[11:45:35.678] [INFO] Tunnel 1 built
```

## Testing

Run the test script:

```bash
cd examples
node test-with-logs.mjs
```

Then open http://127.0.0.1:7070 in your browser.

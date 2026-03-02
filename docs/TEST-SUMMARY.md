# I2P Node Library - Test Summary

This document summarizes all the features added to the i2p-node library and how to test them.

## Features Added

### 1. 5-Level Logging System

**Log Levels:**
- `DEBUG` (0) - Detailed diagnostics for developers
- `INFO` (1) - Normal operational milestones  
- `WARN` (2) - Potential issues; not breaking
- `ERROR` (3) - Functionality broken, user impact
- `FATAL` (4) - System crash or unrecoverable error

**Files:**
- `src/utils/logger.ts` - Logging system implementation

**Usage:**
```javascript
import { logger, LogLevel } from 'i2p-node';

// Set log level
logger.setLevel(LogLevel.DEBUG);

// Log messages
logger.debug('Debug info', data, 'Source');
logger.info('Operation completed');
logger.warn('Connection timeout');
logger.error('Failed to connect', { error });
logger.fatal('Unrecoverable error');
```

**Features:**
- Log history (keeps last 10,000 entries by default)
- Filter by level, source, limit
- Custom log handlers
- Stats tracking

---

### 2. Simple Web UI

**Description:** Minimal, no-frills web UI inspired by i2pd console.

**Files:**
- `src/webui/simple-server.ts` - Web UI server

**Features:**
- Plain HTML with minimal styling
- Router status page
- Real-time log viewer with filtering
- API endpoints (JSON)

**Pages:**
- `/` - Status dashboard
- `/logs` - Log viewer with filters
- `/api/status` - Router stats JSON
- `/api/logs` - Logs JSON
- `/api/peers` - Peers JSON

**Usage:**
```javascript
import { I2PRouter } from 'i2p-node';

const router = new I2PRouter({
  enableWebUI: true,
  webUIPort: 7070
});

await router.start();
// Access http://127.0.0.1:7070
```

---

### 3. Enhanced Router with Logging

**Files:**
- `src/router.ts` - Updated with logging

**Logged Events:**
- Router start/stop
- Identity generation
- Transport start/stop
- Tunnel build success/failure
- Peer connections
- Errors and warnings

---

## Testing

### Test 1: Library with Logging Only

```bash
cd i2p-node/examples
node test-with-logs.mjs
```

**What to expect:**
1. Console shows debug logs from router starting
2. Router hash displayed
3. Web UI URL printed
4. Open http://127.0.0.1:7070 to view:
   - Router status
   - Logs in real-time
   - Peer list

### Test 2: Library with TUI Dashboard

```bash
cd i2p-tui/scripts
node test-lib-with-logs.cjs
```

Or directly:
```bash
cd i2p-tui
npm start
```

**What to expect:**
1. New CMD window opens
2. TUI dashboard appears with:
   - Router stats (real data)
   - Service status
   - Event log (with library logs)
3. Web UI available at http://127.0.0.1:9811
4. HTTP Proxy on port 4444
5. SOCKS5 Proxy on port 4445

**Controls:**
- `F1` - Toggle HTTP Proxy
- `F2` - Toggle SOCKS5 Proxy
- `F3` - Toggle Web UI
- `F5` - Refresh display
- `F10` or `Q` - Quit

### Test 3: Direct Library Usage

```javascript
import { I2PRouter, logger, LogLevel } from 'i2p-node';

// Enable all logging
logger.setLevel(LogLevel.DEBUG);

// Create router with web UI
const router = new I2PRouter({
  ntcp2Port: 12345,
  ssu2Port: 12346,
  bandwidthClass: 'L',
  logLevel: LogLevel.DEBUG,
  enableWebUI: true,
  webUIPort: 7070
});

// Listen to events
router.on('started', () => {
  console.log('Router started!');
});

router.on('tunnelBuilt', ({ tunnelId, type }) => {
  console.log(`Tunnel ${tunnelId} built (${type})`);
});

// Start
await router.start();
```

---

## API Reference

### Logger API

```typescript
// Set level
logger.setLevel(LogLevel.DEBUG);  // 0
logger.setLevel(LogLevel.INFO);   // 1
logger.setLevel(LogLevel.WARN);   // 2
logger.setLevel(LogLevel.ERROR);  // 3
logger.setLevel(LogLevel.FATAL);  // 4

// Log methods
logger.debug(message, data?, source?);
logger.info(message, data?, source?);
logger.warn(message, data?, source?);
logger.error(message, data?, source?);
logger.fatal(message, data?, source?);

// History
const logs = logger.getHistory({
  level: LogLevel.WARN,  // Only WARN and above
  source: 'NTCP2',       // Only from NTCP2
  limit: 100             // Last 100 entries
});

// Stats
const stats = logger.getStats();
// { total: 1500, byLevel: { INFO: 1200, WARN: 200, ERROR: 100 } }

// Clear
logger.clearHistory();

// Custom handler
logger.addHandler((entry) => {
  // entry: { timestamp, level, levelName, message, source, data }
  sendToExternal(entry);
});
```

### Router Options

```typescript
interface I2PRouterOptions {
  // Network
  host?: string;              // Default: '0.0.0.0'
  ntcp2Port?: number;         // Default: 12345
  ssu2Port?: number;          // Default: 12346
  samPort?: number;           // Default: 7656
  
  // Router
  bandwidthClass?: string;    // 'K' | 'L' | 'M' | 'N' | 'O' | 'P' | 'X'
  isFloodfill?: boolean;      // Default: false
  sharePercentage?: number;   // Default: 80
  netId?: number;             // Default: 2
  dataDir?: string;           // Default: './i2p-data'
  
  // Logging
  logLevel?: LogLevel;        // Default: LogLevel.INFO
  
  // Web UI
  enableWebUI?: boolean;      // Default: false
  webUIPort?: number;         // Default: 7070
}
```

---

## Log Output Examples

### Console Output
```
[2025-03-02T11:45:32.123Z] [INFO] Router started successfully
[2025-03-02T11:45:32.234Z] [DEBUG] Identity generated (Router)
[2025-03-02T11:45:32.345Z] [INFO] NTCP2 transport listening on 0.0.0.0:12345 (NTCP2)
[2025-03-02T11:45:32.456Z] [WARN] Connection timeout (Network) { timeout: 5000 }
[2025-03-02T11:45:32.567Z] [ERROR] Failed to build tunnel (Tunnel) { tunnelId: 5 }
[2025-03-02T11:45:33.678Z] [INFO] Tunnel 1 built (outbound) (Tunnel)
```

### Web UI Log View
```
[11:45:32.123] [INFO] Router started
[11:45:32.234] [DEBUG] Identity generated (Router)
[11:45:32.345] [INFO] NTCP2 listening (NTCP2)
[11:45:33.456] [WARN] Connection timeout (Network)
[11:45:35.678] [INFO] Tunnel 1 built (outbound) (Tunnel)
```

---

## File Structure

```
i2p-node/
├── src/
│   ├── utils/
│   │   └── logger.ts          # Logging system
│   ├── webui/
│   │   └── simple-server.ts   # Simple web UI
│   ├── transport/
│   │   └── ntcp2.ts           # With logging
│   └── router.ts              # With logging + web UI
├── examples/
│   └── test-with-logs.mjs     # Test script
├── docs/
│   └── LOGGING.md             # Documentation
└── index.ts                   # Exports logger + web UI

i2p-tui/
├── src/
│   └── dashboard.ts           # Uses library logger
└── scripts/
    ├── spawn-test.cjs         # Launch TUI
    └── test-lib-with-logs.cjs # Launch library test
```

---

## What's Logged

**Router:**
- Start/stop
- Identity generation
- Configuration

**Transports (NTCP2/SSU2):**
- Server start/stop
- New connections
- Session close
- Errors

**Tunnels:**
- Build attempts
- Build success/failure
- Expiration

**Peers:**
- Connections
- Disconnections
- Profile updates

**Web UI:**
- Server start/stop
- API requests

---

## Quick Commands

```bash
# Test library with logs
node i2p-node/examples/test-with-logs.mjs

# Test library with TUI
cd i2p-tui/scripts && node test-lib-with-logs.cjs

# Or
npm start

# Build library
cd i2p-node && npm run build

# Build TUI
cd i2p-tui && npm run build
```

---

## Browser Access

When using `enableWebUI: true`:

- **Main Status:** http://127.0.0.1:7070/
- **Logs:** http://127.0.0.1:7070/logs
- **Status API:** http://127.0.0.1:7070/api/status
- **Logs API:** http://127.0.0.1:7070/api/logs?level=0&limit=500
- **Peers API:** http://127.0.0.1:7070/api/peers

When using TUI dashboard:

- **TUI Web UI:** http://127.0.0.1:9811
- **HTTP Proxy:** 127.0.0.1:4444
- **SOCKS5 Proxy:** 127.0.0.1:4445

---

## Summary

✅ **5-Level Logging**: DEBUG, INFO, WARN, ERROR, FATAL
✅ **Configurable**: Set level globally, per-router, or at runtime
✅ **History**: 10,000 entry buffer with filtering
✅ **Web UI**: Simple, minimal, no-frills interface
✅ **Real-time Logs**: Auto-refreshing log viewer
✅ **API**: JSON endpoints for integration
✅ **Library Integration**: Logs from all components
✅ **TUI Integration**: Displays library logs in terminal

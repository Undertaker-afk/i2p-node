import { createServer, Server, IncomingMessage, ServerResponse } from 'http';
import { EventEmitter } from 'events';
import { logger, LogLevel, LogEntry } from '../utils/logger.js';
import { I2PRouter } from '../router.js';

export interface SimpleWebUIOptions {
  port?: number;
  host?: string;
  router?: I2PRouter;
}

export class SimpleWebUI extends EventEmitter {
  private server: Server | null = null;
  private port: number;
  private host: string;
  private router?: I2PRouter;

  constructor(options: SimpleWebUIOptions = {}) {
    super();
    this.port = options.port || 7070;
    this.host = options.host || '127.0.0.1';
    this.router = options.router;
  }

  async start(): Promise<void> {
    if (this.server) return;

    this.server = createServer(this.handleRequest.bind(this));
    
    this.server.on('error', (err) => {
      logger.error('Web UI server error', err, 'WebUI');
      this.emit('error', err);
    });

    return new Promise((resolve, reject) => {
      this.server!.listen(this.port, this.host, () => {
        logger.info(`Simple Web UI started on http://${this.host}:${this.port}`, undefined, 'WebUI');
        this.emit('started', { host: this.host, port: this.port });
        resolve();
      });

      this.server!.on('error', reject);
    });
  }

  stop(): void {
    if (!this.server) return;
    
    this.server.close(() => {
      logger.info('Simple Web UI stopped', undefined, 'WebUI');
      this.emit('stopped');
    });
    this.server = null;
  }

  isRunning(): boolean {
    return this.server !== null;
  }

  private handleRequest(req: IncomingMessage, res: ServerResponse): void {
    const url = req.url || '/';
    
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(200);
      res.end();
      return;
    }

    if (url === '/' || url === '/index.html') {
      this.serveMainPage(res);
    } else if (url === '/logs') {
      this.serveLogsPage(res);
    } else if (url === '/api/logs') {
      this.serveLogsAPI(req, res);
    } else if (url === '/api/status') {
      this.serveStatusAPI(res);
    } else if (url === '/api/peers') {
      this.servePeersAPI(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain' });
      res.end('Not Found');
    }
  }

  private serveMainPage(res: ServerResponse): void {
    const html = `<!DOCTYPE html>
<html>
<head>
    <title>I2P Router - Simple Console</title>
    <meta charset="utf-8">
    <style>
        body { font-family: monospace; margin: 20px; background: #fff; color: #000; }
        h1 { border-bottom: 2px solid #000; padding-bottom: 10px; }
        h2 { margin-top: 30px; border-bottom: 1px solid #ccc; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 20px; color: #00f; }
        .section { margin: 20px 0; }
        .stat { margin: 10px 0; }
        .stat-label { display: inline-block; width: 150px; font-weight: bold; }
        table { border-collapse: collapse; width: 100%; margin-top: 10px; }
        th, td { border: 1px solid #ccc; padding: 8px; text-align: left; }
        th { background: #f0f0f0; }
        .refresh { margin: 20px 0; }
        .refresh button { padding: 10px 20px; cursor: pointer; }
        pre { background: #f5f5f5; padding: 10px; overflow-x: auto; }
        .online { color: green; }
        .offline { color: red; }
    </style>
</head>
<body>
    <h1>I2P Router Console</h1>
    
    <div class="nav">
        <a href="/">Status</a>
        <a href="/logs">Logs</a>
    </div>
    
    <div class="refresh">
        <button onclick="location.reload()">Refresh Page</button>
        <span id="lastUpdate"></span>
    </div>
    
    <div class="section">
        <h2>Router Status</h2>
        <div class="stat"><span class="stat-label">Status:</span> <span id="status">Loading...</span></div>
        <div class="stat"><span class="stat-label">Uptime:</span> <span id="uptime">-</span></div>
        <div class="stat"><span class="stat-label">Router Hash:</span> <span id="routerHash">-</span></div>
        <div class="stat"><span class="stat-label">Version:</span> 0.9.66</div>
    </div>
    
    <div class="section">
        <h2>Network</h2>
        <div class="stat"><span class="stat-label">Known Peers:</span> <span id="knownPeers">-</span></div>
        <div class="stat"><span class="stat-label">Active Peers:</span> <span id="activePeers">-</span></div>
        <div class="stat"><span class="stat-label">Floodfills:</span> <span id="floodfills">-</span></div>
        <div class="stat"><span class="stat-label">Active Tunnels:</span> <span id="tunnels">-</span></div>
    </div>
    
    <div class="section">
        <h2>Traffic</h2>
        <div class="stat"><span class="stat-label">Data Received:</span> <span id="received">-</span></div>
        <div class="stat"><span class="stat-label">Data Sent:</span> <span id="sent">-</span></div>
        <div class="stat"><span class="stat-label">Messages In:</span> <span id="msgIn">-</span></div>
        <div class="stat"><span class="stat-label">Messages Out:</span> <span id="msgOut">-</span></div>
    </div>
    
    <div class="section">
        <h2>Recent Peers</h2>
        <table id="peersTable">
            <tr><th>Hash</th><th>Type</th><th>Bandwidth</th><th>Last Seen</th></tr>
        </table>
    </div>
    
    <script>
        function formatBytes(bytes) {
            if (bytes < 1024) return bytes + ' B';
            if (bytes < 1024*1024) return (bytes/1024).toFixed(1) + ' KB';
            return (bytes/(1024*1024)).toFixed(1) + ' MB';
        }
        
        function formatTime(seconds) {
            const h = Math.floor(seconds / 3600);
            const m = Math.floor((seconds % 3600) / 60);
            return h + 'h ' + m + 'm';
        }
        
        async function loadData() {
            try {
                const res = await fetch('/api/status');
                const data = await res.json();
                
                document.getElementById('status').innerHTML = data.running ? 
                    '<span class="online">ONLINE</span>' : '<span class="offline">OFFLINE</span>';
                document.getElementById('uptime').textContent = formatTime(data.uptime);
                document.getElementById('routerHash').textContent = data.routerHash.substring(0, 16) + '...';
                document.getElementById('knownPeers').textContent = data.knownPeers;
                document.getElementById('activePeers').textContent = data.activePeers;
                document.getElementById('floodfills').textContent = data.floodfillPeers;
                document.getElementById('tunnels').textContent = data.activeTunnels;
                document.getElementById('received').textContent = formatBytes(data.bytesReceived);
                document.getElementById('sent').textContent = formatBytes(data.bytesSent);
                document.getElementById('msgIn').textContent = data.messagesReceived;
                document.getElementById('msgOut').textContent = data.messagesSent;
            } catch(e) {
                console.error('Failed to load status:', e);
            }
            
            try {
                const res = await fetch('/api/peers');
                const data = await res.json();
                const table = document.getElementById('peersTable');
                table.innerHTML = '<tr><th>Hash</th><th>Type</th><th>Bandwidth</th><th>Last Seen</th></tr>';
                
                data.peers.slice(0, 10).forEach(p => {
                    const row = table.insertRow();
                    row.insertCell().textContent = p.hash.substring(0, 20) + '...';
                    row.insertCell().textContent = p.isFloodfill ? 'Floodfill' : 'Peer';
                    row.insertCell().textContent = p.capacity + ' KB/s';
                    row.insertCell().textContent = new Date(p.lastSeen).toLocaleTimeString();
                });
            } catch(e) {
                console.error('Failed to load peers:', e);
            }
            
            document.getElementById('lastUpdate').textContent = 'Last updated: ' + new Date().toLocaleTimeString();
        }
        
        loadData();
        setInterval(loadData, 5000);
    </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  }

  private serveLogsPage(res: ServerResponse): void {
    const html = `<!DOCTYPE html>
<html>
<head>
    <title>I2P Router - Logs</title>
    <meta charset="utf-8">
    <style>
        body { font-family: monospace; margin: 20px; background: #fff; color: #000; }
        h1 { border-bottom: 2px solid #000; padding-bottom: 10px; }
        .nav { margin: 20px 0; }
        .nav a { margin-right: 20px; color: #00f; }
        .controls { margin: 20px 0; padding: 10px; background: #f5f5f5; }
        .controls label { margin-right: 10px; }
        .controls select, .controls button { padding: 5px 10px; margin-right: 10px; }
        #logs { margin-top: 20px; }
        .log-entry { padding: 5px; border-bottom: 1px solid #eee; }
        .log-entry.DEBUG { color: #666; }
        .log-entry.INFO { color: #000; }
        .log-entry.WARN { color: #f90; }
        .log-entry.ERROR { color: #f00; font-weight: bold; }
        .log-entry.FATAL { color: #f00; background: #fee; font-weight: bold; }
        .timestamp { color: #666; margin-right: 10px; }
        .level { display: inline-block; width: 60px; font-weight: bold; }
        .source { color: #666; margin-left: 10px; }
        .auto-scroll { margin-left: 20px; }
    </style>
</head>
<body>
    <h1>I2P Router Logs</h1>
    
    <div class="nav">
        <a href="/">Status</a>
        <a href="/logs">Logs</a>
    </div>
    
    <div class="controls">
        <label>Level:</label>
        <select id="levelFilter">
            <option value="0">DEBUG</option>
            <option value="1" selected>INFO</option>
            <option value="2">WARN</option>
            <option value="3">ERROR</option>
            <option value="4">FATAL</option>
        </select>
        
        <label>Limit:</label>
        <select id="limitFilter">
            <option value="100">100</option>
            <option value="500" selected>500</option>
            <option value="1000">1000</option>
            <option value="5000">5000</option>
        </select>
        
        <button onclick="loadLogs()">Refresh</button>
        <button onclick="clearLogs()">Clear</button>
        
        <label class="auto-scroll">
            <input type="checkbox" id="autoScroll" checked> Auto-scroll
        </label>
    </div>
    
    <div id="logs">Loading...</div>
    
    <script>
        let scrollInterval;
        
        function formatTime(ts) {
            const d = new Date(ts);
            return d.toLocaleTimeString() + '.' + String(d.getMilliseconds()).padStart(3, '0');
        }
        
        async function loadLogs() {
            const level = document.getElementById('levelFilter').value;
            const limit = document.getElementById('limitFilter').value;
            
            try {
                const res = await fetch('/api/logs?level=' + level + '&limit=' + limit);
                const data = await res.json();
                
                const logsDiv = document.getElementById('logs');
                logsDiv.innerHTML = '';
                
                data.logs.forEach(log => {
                    const div = document.createElement('div');
                    div.className = 'log-entry ' + log.levelName;
                    div.innerHTML = '<span class="timestamp">' + formatTime(log.timestamp) + 
                                   '</span><span class="level">[' + log.levelName + 
                                   ']</span>' + log.message +
                                   (log.source ? '<span class="source">(' + log.source + ')</span>' : '');
                    logsDiv.appendChild(div);
                });
                
                if (document.getElementById('autoScroll').checked) {
                    window.scrollTo(0, document.body.scrollHeight);
                }
            } catch(e) {
                console.error('Failed to load logs:', e);
            }
        }
        
        function clearLogs() {
            document.getElementById('logs').innerHTML = '';
        }
        
        // Load initially and every 2 seconds
        loadLogs();
        scrollInterval = setInterval(loadLogs, 2000);
    </script>
</body>
</html>`;

    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(html);
  }

  private serveLogsAPI(req: IncomingMessage, res: ServerResponse): void {
    const url = new URL(req.url!, `http://${req.headers.host}`);
    const level = parseInt(url.searchParams.get('level') || '0');
    const limit = parseInt(url.searchParams.get('limit') || '500');
    
    const logs = logger.getHistory({ level, limit });
    
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ logs }));
  }

  private serveStatusAPI(res: ServerResponse): void {
    const stats = this.router?.getStats();
    const routerHash = this.router?.getRouterInfo()?.getRouterHash().toString('hex') || 'unknown';
    
    const status = {
      running: this.router?.isRunning() || false,
      uptime: stats ? Math.floor((Date.now() - stats.startTime) / 1000) : 0,
      routerHash,
      knownPeers: stats?.knownPeers || 0,
      activePeers: stats?.activePeers || 0,
      floodfillPeers: stats?.floodfillPeers || 0,
      activeTunnels: stats?.activeTunnels || 0,
      bytesReceived: stats?.bytesReceived || 0,
      bytesSent: stats?.bytesSent || 0,
      messagesReceived: stats?.messagesReceived || 0,
      messagesSent: stats?.messagesSent || 0
    };

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(status));
  }

  private servePeersAPI(res: ServerResponse): void {
    const profiles = this.router?.getPeerProfiles().getAllProfiles() || [];
    
    const peers = profiles.map(p => ({
      hash: p.routerHash,
      capacity: p.capacity,
      isFloodfill: p.isFloodfill,
      lastSeen: p.stats.lastSeen
    }));

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ peers }));
  }
}

export default SimpleWebUI;

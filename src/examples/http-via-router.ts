import http from 'http';
import { I2PRouter } from '../router.js';

async function main(): Promise<void> {
  const b32 = process.argv[2] || 'nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p';
  const port = parseInt(process.argv[3] || '8080', 10);

  console.log(`Starting router + HTTP proxy for ${b32} on http://127.0.0.1:${port}`);

  const router = new I2PRouter({
    enableWebUI: false,
    dataDir: './i2p-test-data',
    logLevel: 0
  });

  await router.start();
  const server = http.createServer(async (req, res) => {
    if (!req.url) {
      res.writeHead(400);
      res.end('Missing URL');
      return;
    }

    console.log(`HTTP proxy request: ${req.method} ${req.url}`);

    // For now, always target the configured b32 destination.
    const stream = await router.openStreamToBase32(b32);
    if (!stream) {
      res.writeHead(503);
      res.end('Failed to open stream to destination');
      return;
    }

    const chunks: Buffer[] = [];
    stream.on('data', (buf: Buffer) => {
      chunks.push(buf);
    });

    stream.once('close', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end(body);
    });

    const path = req.url || '/';
    const httpReq =
      `GET ${path} HTTP/1.1\r\n` +
      `Host: ${b32}\r\n` +
      `User-Agent: i2p-node-router-http/0.1\r\n` +
      `Connection: close\r\n` +
      `Accept: */*\r\n` +
      `\r\n`;
    stream.send(Buffer.from(httpReq, 'utf8'));
  });

  server.listen(port, '127.0.0.1', () => {
    console.log(`Local HTTP proxy listening on http://127.0.0.1:${port}`);
  });
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


import net from 'net';

interface SamConnectOptions {
  host: string;
  port: number;
  destination: string; // e.g. notbob.i2p or xxxx.b32.i2p
  httpHostHeader?: string;
  path?: string;
}

function sendLine(socket: net.Socket, line: string): void {
  socket.write(line + '\n');
}

function readLine(socket: net.Socket): Promise<string> {
  return new Promise((resolve, reject) => {
    let buffer = '';
    const onData = (data: Buffer) => {
      buffer += data.toString('utf8');
      const idx = buffer.indexOf('\n');
      if (idx !== -1) {
        const line = buffer.slice(0, idx).trim();
        socket.off('data', onData);
        socket.off('error', onError);
        resolve(line);
      }
    };
    const onError = (err: Error) => {
      socket.off('data', onData);
      socket.off('error', onError);
      reject(err);
    };
    socket.on('data', onData);
    socket.on('error', onError);
  });
}

async function samHttpRequest(opts: SamConnectOptions): Promise<void> {
  const { host, port, destination } = opts;
  const httpHost = opts.httpHostHeader ?? destination;
  const path = opts.path ?? '/';

  const socket = net.createConnection({ host, port });

  await new Promise<void>((resolve, reject) => {
    socket.once('connect', () => resolve());
    socket.once('error', (err) => reject(err));
  });

  // HELLO
  sendLine(socket, 'HELLO VERSION MIN=3.0 MAX=3.1');
  let line = await readLine(socket);
  if (!line.includes('RESULT=OK')) {
    throw new Error(`SAM HELLO failed: ${line}`);
  }

  // For a simple client, we can use a transient session and connect a stream on this same socket.
  // STREAM CONNECT (no prior SESSION CREATE; i2pd accepts this pattern for transient streams).
  sendLine(socket, `STREAM CONNECT ID=transient DESTINATION=${destination}`);
  line = await readLine(socket);
  if (!line.includes('RESULT=OK')) {
    throw new Error(`SAM STREAM CONNECT failed: ${line}`);
  }

  // Now the same socket is the data stream. Send an HTTP GET.
  const httpReq =
    `GET ${path} HTTP/1.1\r\n` +
    `Host: ${httpHost}\r\n` +
    `User-Agent: i2p-node-http-test/0.1\r\n` +
    `Connection: close\r\n` +
    `Accept: */*\r\n` +
    `\r\n`;
  socket.write(httpReq);

  // Read and dump the response (up to some limit)
  let total = 0;
  const maxBytes = 16384;
  await new Promise<void>((resolve) => {
    socket.on('data', (chunk) => {
      total += chunk.length;
      process.stdout.write(chunk.toString('utf8'));
      if (total >= maxBytes) {
        socket.end();
      }
    });
    socket.on('end', () => resolve());
    socket.on('close', () => resolve());
  });
}

async function main(): Promise<void> {
  const dest = process.argv[2] || 'notbob.i2p';
  const path = process.argv[3] || '/';

  console.log(`SAM HTTP test: destination=${dest} path=${path}`);
  console.log('Make sure your i2pd/Java I2P router is running with SAM enabled on 127.0.0.1:7656.');

  try {
    await samHttpRequest({
      host: '127.0.0.1',
      port: 7656,
      destination: dest,
      httpHostHeader: dest,
      path
    });
  } catch (e) {
    console.error('SAM HTTP request failed:', (e as Error).message);
    process.exitCode = 1;
  }
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


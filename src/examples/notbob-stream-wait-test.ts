import { execSync } from 'child_process';
import { I2PRouter } from '../router.js';
import { logger, LogLevel } from '../utils/logger.js';

const NOTBOB_B32 = 'nytzrhrjjfsutowojvxi7hphesskpqqr65wpistz6wa7cpajhp7a.b32.i2p';
const NTCP2_PORT = 12345; // must match router options

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function killProcessesOnPort(port: number): void {
  if (process.platform !== 'win32') return;
  try {
    // Find all lines with :<port> in netstat output and extract the PID (last column)
    const output = execSync(`netstat -ano | findstr :${port}`, { encoding: 'utf8' });
    const pids = new Set<number>();
    for (const line of output.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const parts = trimmed.split(/\s+/);
      const pidStr = parts[parts.length - 1];
      const pid = Number(pidStr);
      if (!Number.isNaN(pid) && pid !== process.pid) {
        pids.add(pid);
      }
    }
    for (const pid of pids) {
      try {
        execSync(`taskkill /PID ${pid} /F`);
      } catch {
        // ignore failures for individual PIDs
      }
    }
  } catch {
    // If netstat/findstr fails, just ignore and continue
  }
}

async function main(): Promise<void> {
  logger.setLevel(LogLevel.DEBUG);

  console.log(`Notbob stream test via router`);
  console.log(`Destination: ${NOTBOB_B32}`);

  console.log(`Ensuring port ${NTCP2_PORT} is free (killing any existing listeners)...`);
  killProcessesOnPort(NTCP2_PORT);

  const router = new I2PRouter({
    enableWebUI: true,
    webUIPort: 7070,
    dataDir: './i2p-test-data',
    logLevel: LogLevel.DEBUG,
    ntcp2Port: NTCP2_PORT
  });

  let stopping = false;
  const stopRouter = () => {
    if (stopping) return;
    stopping = true;
    try {
      router.stop();
    } catch {
      // ignore
    }
  };

  process.on('SIGINT', () => {
    console.log('\nSIGINT received, stopping router...');
    stopRouter();
  });

  console.log('Starting router...');
  await router.start();

  console.log('Router started. Waiting 40 seconds before first notbob attempt...');
  await sleep(40000);

  const tryConnect = async (label: string): Promise<boolean> => {
    console.log(`[${label}] Trying router.openStreamToBase32(${NOTBOB_B32})...`);
    const stream = await router.openStreamToBase32(NOTBOB_B32, 20000);
    if (!stream) {
      console.log(`[${label}] openStreamToBase32 returned null (no LeaseSet/stream).`);
      return false;
    }
    console.log(`[${label}] Stream opened successfully (id=${stream.id}).`);
    // We don't send data here; just treat successful open as success.
    stream.close();
    return true;
  };

  const firstOk = await tryConnect('first');
  if (firstOk) {
    console.log('Notbob connection succeeded on first attempt.');
    stopRouter();
    return;
  }

  console.log('First attempt failed. Waiting additional 30 seconds before retry...');
  await sleep(30000);

  const secondOk = await tryConnect('second');
  if (secondOk) {
    console.log('Notbob connection succeeded on second attempt.');
  } else {
    console.log('Second attempt also failed. Giving up.');
  }

  stopRouter();
}

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});


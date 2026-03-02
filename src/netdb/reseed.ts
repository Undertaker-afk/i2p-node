import { createHash } from 'crypto';
import { EventEmitter } from 'events';
import { logger } from '../utils/logger.js';
import https from 'https';
import http from 'http';
import { URL } from 'url';
import AdmZip from 'adm-zip';

export interface ReseedServer {
  url: string;
  enabled: boolean;
}

export interface RouterInfoData {
  hash: string;
  data: Buffer;
}

/**
 * SU3 File Format Parser
 * SU3 files contain signed router information in ZIP format
 */
class SU3Parser {
  /**
   * Parse SU3 file and extract router infos.
   *
   * In i2pd the SU3 structure is:
   *  - 7 bytes magic ("I2Psu3" + 0)
   *  - 1 byte version
   *  - 2 bytes signature type (BE)
   *  - 2 bytes signature length (BE)
   *  - 1 byte unused
   *  - 1 byte version string length
   *  - 1 byte unused
   *  - 1 byte signer ID length
   *  - 8 bytes content length (BE)   <-- ZIP size
   *  - 1 byte unused
   *  - 1 byte file type (0x00 == ZIP)
   *  - 1 byte unused
   *  - 1 byte content type (0x03 == reseed data)
   *  - 12 bytes unused
   *  - version string (versionLength bytes)
   *  - signer ID (signerIdLength bytes)
   *  - ZIP content (contentLength bytes)
   *  - signature (signatureLength bytes)
   */
  static parse(data: Buffer): RouterInfoData[] {
    const routers: RouterInfoData[] = [];

    let zipData: Buffer = data;

    try {
      logger.debug(`Parsing SU3/ZIP file (${data.length} bytes)`, undefined, 'Reseed');

      // Detect SU3 magic ("I2Psu3" + zero byte)
      const hasSu3Magic =
        data.length >= 7 &&
        data.subarray(0, 6).toString('ascii') === 'I2Psu3';

      if (hasSu3Magic) {
        let offset = 0;

        // Skip magic (6 chars + terminating zero)
        offset += 7;

        if (data.length < offset + 1 + 2 + 2 + 1 + 1 + 1 + 8 + 1 + 1 + 1 + 12) {
          logger.error('SU3 header too short', undefined, 'Reseed');
          return [];
        }

        // su3 file format version
        offset += 1;

        // signature type (unused here)
        const signatureType = data.readUInt16BE(offset);
        offset += 2;

        // signature length
        const signatureLength = data.readUInt16BE(offset);
        offset += 2;

        // unused
        offset += 1;

        const versionLength = data.readUInt8(offset);
        offset += 1;

        // unused
        offset += 1;

        const signerIdLength = data.readUInt8(offset);
        offset += 1;

        const contentLengthBig = data.readBigUInt64BE(offset);
        const contentLength = Number(contentLengthBig);
        offset += 8;

        // unused
        offset += 1;

        const fileType = data.readUInt8(offset);
        offset += 1;

        if (fileType !== 0x00) {
          logger.error(`Unsupported SU3 fileType ${fileType} (expected 0x00 ZIP)`, undefined, 'Reseed');
          return [];
        }

        // unused
        offset += 1;

        const contentType = data.readUInt8(offset);
        offset += 1;

        // 12 bytes unused
        offset += 12;

        // Skip version string and signer ID
        offset += versionLength;
        offset += signerIdLength;

        const zipStart = offset;
        const zipEnd = zipStart + contentLength;

        if (zipEnd > data.length) {
          logger.error('SU3 content length exceeds file size', undefined, 'Reseed');
          return [];
        }

        zipData = data.subarray(zipStart, zipEnd);

        logger.debug(
          `Detected SU3 container: sigType=${signatureType}, sigLen=${signatureLength}, contentType=${contentType}, zipSize=${contentLength}`,
          undefined,
          'Reseed'
        );
      } else {
        logger.debug('No SU3 magic found, treating data as plain ZIP', undefined, 'Reseed');
      }

      const zip = new AdmZip(zipData);
      const entries = zip.getEntries();

      logger.debug(`ZIP contains ${entries.length} entries`, undefined, 'Reseed');

      for (const entry of entries) {
        if (entry.isDirectory) continue;
        if (!entry.entryName.endsWith('.dat') && !entry.entryName.includes('routerInfo')) {
          continue;
        }

        try {
          const routerData = entry.getData();

          if (routerData.length < 100) {
            logger.debug(
              `Skipping small file: ${entry.entryName} (${routerData.length} bytes)`,
              undefined,
              'Reseed'
            );
            continue;
          }

          const hash = createHash('sha256').update(routerData).digest('hex');

          routers.push({
            hash,
            data: routerData
          });

          logger.debug(
            `Extracted router info: ${entry.entryName} (${routerData.length} bytes)`,
            undefined,
            'Reseed'
          );
        } catch (err) {
          logger.warn(
            `Failed to extract ${entry.entryName}`,
            { error: (err as Error).message },
            'Reseed'
          );
        }
      }
    } catch (err) {
      logger.error('Failed to parse reseed data', { error: (err as Error).message }, 'Reseed');
    }

    return routers;
  }
}

/**
 * Reseeder - Bootstraps peer discovery by downloading router infos from reseed servers
 * 
 * In I2P, reseed servers are HTTPS servers that provide signed router information
 * files (SU3 format) containing initial peers to connect to.
 */
export class Reseeder extends EventEmitter {
  private servers: ReseedServer[] = [
    { url: 'https://reseed.sahil.world/', enabled: true },
    { url: 'https://i2p.diyarciftci.xyz/', enabled: true },
    { url: 'https://reseed2.i2p.net/', enabled: true },
    { url: 'https://reseed.diva.exchange/', enabled: true },
    { url: 'https://reseed-fr.i2pd.xyz/', enabled: true },
    { url: 'https://reseed.onion.im/', enabled: true },
    { url: 'https://i2pseed.creativecowpat.net:8443/', enabled: true },
    { url: 'https://reseed.i2pgit.org/', enabled: true },
    { url: 'https://coconut.incognet.io/', enabled: true },
    { url: 'https://reseed-pl.i2pd.xyz/', enabled: true },
    { url: 'https://www2.mk16.de/', enabled: true },
    { url: 'https://i2p.novg.net/', enabled: true },
    { url: 'https://reseed.stormycloud.org/', enabled: true }
  ];

  private minRouters: number;
  private minFloodfills: number;
  private isRunning = false;
  private reseedInProgress = false;
  private requestTimeout = 30000; // 30 seconds

  constructor(options: { minRouters?: number; minFloodfills?: number; requestTimeout?: number } = {}) {
    super();
    this.minRouters = options.minRouters || 90;
    this.minFloodfills = options.minFloodfills || 5;
    this.requestTimeout = options.requestTimeout || 30000;
  }

  /**
   * Check if reseeding is needed based on current peer count
   */
  isReseedNeeded(routerCount: number, floodfillCount: number): boolean {
    return routerCount < this.minRouters || floodfillCount < this.minFloodfills;
  }

  /**
   * Bootstrap by downloading router infos from reseed servers
   */
  async bootstrap(): Promise<RouterInfoData[]> {
    if (this.reseedInProgress) {
      logger.warn('Reseed already in progress', undefined, 'Reseed');
      return [];
    }

    this.reseedInProgress = true;
    logger.info('Starting reseed process...', undefined, 'Reseed');

    try {
      let routers: RouterInfoData[] = [];
      try {
        routers = await this.reseedFromServers();
      } catch (err) {
        logger.error('Reseed from servers failed, trying local file fallback', { error: (err as Error).message }, 'Reseed');
      }

      if (routers.length === 0) {
        // Fallback: try local i2pseeds.su3 in project root if present
        routers = await this.reseedFromFile('./i2pseeds.su3');
      }

      logger.info(`Reseed completed: ${routers.length} routers downloaded`, undefined, 'Reseed');
      return routers;
    } catch (err) {
      logger.error('Reseed failed', { error: (err as Error).message }, 'Reseed');
      return [];
    } finally {
      this.reseedInProgress = false;
    }
  }

  /**
   * Try reseeding from multiple servers until one succeeds
   */
  private async reseedFromServers(): Promise<RouterInfoData[]> {
    const enabledServers = this.servers.filter(s => s.enabled);
    
    // Shuffle servers for load balancing
    const shuffled = [...enabledServers].sort(() => Math.random() - 0.5);
    
    for (const server of shuffled) {
      try {
        logger.info(`Trying reseed server: ${server.url}`, undefined, 'Reseed');
        const routers = await this.reseedFromServer(server.url);
        
        if (routers.length > 0) {
          logger.info(`Successfully reseeded ${routers.length} routers from ${server.url}`, undefined, 'Reseed');
          return routers;
        }
      } catch (err) {
        logger.warn(`Reseed from ${server.url} failed`, { error: (err as Error).message }, 'Reseed');
      }
    }

    throw new Error('All reseed servers failed');
  }

  /**
   * Download router infos from a single reseed server
   */
  private async reseedFromServer(baseUrl: string): Promise<RouterInfoData[]> {
    const su3Url = `${baseUrl}i2pseeds.su3`;
    logger.debug(`Downloading from ${su3Url}`, undefined, 'Reseed');
    
    try {
      // Download the SU3 file
      const data = await this.downloadFile(su3Url);
      
      if (data.length === 0) {
        throw new Error('Downloaded file is empty');
      }
      
      logger.debug(`Downloaded ${data.length} bytes`, undefined, 'Reseed');
      
      // Parse the SU3 file
      const routers = SU3Parser.parse(data);
      
      if (routers.length === 0) {
        logger.warn('No router infos found in SU3 file', undefined, 'Reseed');
      }
      
      return routers;
    } catch (err) {
      throw new Error(`Download failed: ${(err as Error).message}`);
    }
  }

  /**
   * Download a file from URL using HTTPS
   */
  private downloadFile(url: string): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      const parsedUrl = new URL(url);
      const client = parsedUrl.protocol === 'https:' ? https : http;
      
      const options = {
        hostname: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        path: parsedUrl.pathname + parsedUrl.search,
        method: 'GET',
        headers: {
          'User-Agent': 'i2p-node/0.9.66',
          'Accept': 'application/octet-stream, */*'
        },
        timeout: this.requestTimeout,
        // Accept self-signed certificates (reseed servers may use them)
        rejectUnauthorized: false
      };
      
      const chunks: Buffer[] = [];
      
      const req = client.request(options, (res) => {
        if (res.statusCode !== 200) {
          reject(new Error(`HTTP ${res.statusCode}`));
          return;
        }
        
        res.on('data', (chunk) => {
          chunks.push(Buffer.from(chunk));
        });
        
        res.on('end', () => {
          resolve(Buffer.concat(chunks));
        });
      });
      
      req.on('error', (err) => {
        reject(err);
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      
      req.end();
    });
  }

  /**
   * Load router infos from a local file (for offline reseeding)
   */
  async reseedFromFile(filepath: string): Promise<RouterInfoData[]> {
    logger.info(`Loading reseed from file: ${filepath}`, undefined, 'Reseed');
    
    try {
      const fs = await import('fs');
      const data = await fs.promises.readFile(filepath);
      
      logger.debug(`Loaded ${data.length} bytes from file`, undefined, 'Reseed');
      
      // Parse SU3 or ZIP file
      return SU3Parser.parse(data);
    } catch (err) {
      logger.error(`Failed to load reseed file`, { error: (err as Error).message }, 'Reseed');
      return [];
    }
  }

  /**
   * Generate mock router infos for testing
   * Used when real reseed servers are unavailable
   */
  generateMockRouters(count: number): RouterInfoData[] {
    logger.warn(`Generating ${count} mock routers for testing`, undefined, 'Reseed');
    
    const routers: RouterInfoData[] = [];
    
    for (let i = 0; i < count; i++) {
      try {
        // Generate a mock router info using the RouterInfo class
        const routerInfo = this.createMockRouterInfo(i);
        const routerData = routerInfo.serialize();
        const hash = createHash('sha256').update(routerData).digest('hex');
        
        routers.push({ hash, data: routerData });
      } catch (err) {
        logger.warn(`Failed to generate mock router ${i}`, { error: (err as Error).message }, 'Reseed');
      }
    }
    
    logger.info(`Generated ${routers.length} mock routers`, undefined, 'Reseed');
    return routers;
  }
  
  /**
   * Create a mock RouterInfo using the actual class
   */
  private createMockRouterInfo(index: number): any {
    // Import here to avoid circular dependency issues
    const { RouterIdentity, RouterAddress, RouterInfo } = require('../data/router-info.js');
    const { Crypto } = require('../crypto/index.js');
    
    // Generate keys
    const signingKeys = Crypto.generateKeyPair();
    const encryptionKeys = Crypto.generateKeyPair();
    
    // Create identity
    const identity = new RouterIdentity(signingKeys.publicKey, encryptionKeys.publicKey);
    
    // Create address (mock NTCP2)
    const address = new RouterAddress('NTCP2', {
      host: `192.168.${Math.floor(index / 256) % 256}.${index % 256}`,
      port: (12345 + (index % 1000)).toString(),
      v: '2'
    });
    
    // Some routers are floodfills (every 10th router)
    const isFloodfill = index % 10 === 0;
    const caps = isFloodfill ? 'fLR' : 'LR';
    
    // Create router info
    const routerInfo = new RouterInfo(
      identity,
      [address],
      {
        caps,
        netId: '2',
        'router.version': '0.9.66',
        'core.version': '0.9.66'
      },
      Date.now() - (index * 1000), // Staggered publish times
      Buffer.alloc(64) // Mock signature
    );
    
    return routerInfo;
  }

  /**
   * Add a custom reseed server
   */
  addServer(url: string): void {
    this.servers.push({ url, enabled: true });
    logger.debug(`Added reseed server: ${url}`, undefined, 'Reseed');
  }

  /**
   * Get list of configured reseed servers
   */
  getServers(): ReseedServer[] {
    return [...this.servers];
  }

  /**
   * Enable/disable a reseed server
   */
  setServerEnabled(url: string, enabled: boolean): void {
    const server = this.servers.find(s => s.url === url);
    if (server) {
      server.enabled = enabled;
    }
  }
}

export default Reseeder;

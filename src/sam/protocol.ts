import { createServer, Server, Socket } from 'net';
import { EventEmitter } from 'events';

export enum SAMCommand {
  HELLO = 'HELLO',
  SESSION_CREATE = 'SESSION CREATE',
  STREAM_CONNECT = 'STREAM CONNECT',
  STREAM_ACCEPT = 'STREAM ACCEPT',
  STREAM_FORWARD = 'STREAM FORWARD',
  NAMING_LOOKUP = 'NAMING LOOKUP',
  DEST_GENERATE = 'DEST GENERATE'
}

export enum SAMReply {
  HELLO_REPLY = 'HELLO REPLY',
  SESSION_STATUS = 'SESSION STATUS',
  STREAM_STATUS = 'STREAM STATUS',
  NAMING_REPLY = 'NAMING REPLY',
  DEST_REPLY = 'DEST REPLY'
}

export interface SAMSession {
  id: string;
  socket: Socket;
  destination: string;
  style: 'STREAM' | 'DATAGRAM' | 'RAW';
  isReady: boolean;
}

export interface SAMOptions {
  host?: string;
  port?: number;
}

export class SAMProtocol extends EventEmitter {
  private server: Server | null = null;
  private sessions: Map<string, SAMSession> = new Map();
  private options: SAMOptions;

  constructor(options: SAMOptions = {}) {
    super();
    this.options = {
      host: '127.0.0.1',
      port: 7656,
      ...options
    };
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer(this.handleConnection.bind(this));
      
      this.server.on('error', (err) => {
        this.emit('error', err);
        reject(err);
      });
      
      this.server.listen(this.options.port, this.options.host, () => {
        this.emit('listening', { host: this.options.host, port: this.options.port });
        resolve();
      });
    });
  }

  stop(): void {
    if (this.server) {
      this.server.close();
      this.server = null;
    }
    
    for (const session of this.sessions.values()) {
      session.socket.destroy();
    }
    this.sessions.clear();
  }

  private handleConnection(socket: Socket): void {
    let buffer = '';
    let currentSession: SAMSession | null = null;

    socket.on('data', (data) => {
      buffer += data.toString('utf8');
      
      let lines = buffer.split('\n');
      buffer = lines.pop() || '';
      
      for (const line of lines) {
        this.handleCommand(socket, line.trim(), currentSession);
      }
    });

    socket.on('close', () => {
      if (currentSession !== null) {
        this.sessions.delete((currentSession as SAMSession).id);
        this.emit('sessionClosed', { sessionId: (currentSession as SAMSession).id });
      }
    });

    socket.on('error', (err) => {
      this.emit('error', { error: err, socket });
    });
  }

  private handleCommand(socket: Socket, line: string, session: SAMSession | null): void {
    if (!line) return;

    const parts = line.split(' ');
    const command = parts[0].toUpperCase();

    switch (command) {
      case 'HELLO':
        this.handleHello(socket, parts);
        break;
      case 'SESSION':
        this.handleSession(socket, parts);
        break;
      case 'STREAM':
        this.handleStream(socket, parts, session);
        break;
      case 'NAMING':
        this.handleNaming(socket, parts);
        break;
      case 'DEST':
        this.handleDest(socket, parts);
        break;
      default:
        this.sendReply(socket, `${SAMReply.HELLO_REPLY} RESULT=NOVERSION`);
    }
  }

  private handleHello(socket: Socket, parts: string[]): void {
    const version = this.parseValue(parts.join(' '), 'VERSION');
    
    if (version === '3.0' || version === '3.1') {
      this.sendReply(socket, `${SAMReply.HELLO_REPLY} RESULT=OK VERSION=3.1`);
    } else {
      this.sendReply(socket, `${SAMReply.HELLO_REPLY} RESULT=NOVERSION`);
    }
  }

  private handleSession(socket: Socket, parts: string[]): void {
    const subCommand = parts[1]?.toUpperCase();
    
    if (subCommand !== 'CREATE') {
      this.sendReply(socket, `${SAMReply.SESSION_STATUS} RESULT=I2P_ERROR MESSAGE="Unknown subcommand"`);
      return;
    }

    const style = this.parseValue(parts.join(' '), 'STYLE') as 'STREAM' | 'DATAGRAM' | 'RAW';
    const sessionId = this.parseValue(parts.join(' '), 'ID');
    const destination = this.parseValue(parts.join(' '), 'DESTINATION') || 'TRANSIENT';

    if (!sessionId) {
      this.sendReply(socket, `${SAMReply.SESSION_STATUS} RESULT=I2P_ERROR MESSAGE="Missing ID"`);
      return;
    }

    if (this.sessions.has(sessionId)) {
      this.sendReply(socket, `${SAMReply.SESSION_STATUS} RESULT=DUPLICATED_ID`);
      return;
    }

    const newSession: SAMSession = {
      id: sessionId,
      socket,
      destination,
      style: style || 'STREAM',
      isReady: true
    };

    this.sessions.set(sessionId, newSession);
    
    this.emit('sessionCreate', {
      sessionId,
      style: newSession.style,
      destination
    });

    this.sendReply(socket, `${SAMReply.SESSION_STATUS} RESULT=OK DESTINATION=${destination}`);
  }

  private handleStream(socket: Socket, parts: string[], session: SAMSession | null): void {
    const subCommand = parts[1]?.toUpperCase();
    
    switch (subCommand) {
      case 'CONNECT':
        this.handleStreamConnect(socket, parts, session);
        break;
      case 'ACCEPT':
        this.handleStreamAccept(socket, parts, session);
        break;
      case 'FORWARD':
        this.handleStreamForward(socket, parts, session);
        break;
      default:
        this.sendReply(socket, `${SAMReply.STREAM_STATUS} RESULT=I2P_ERROR MESSAGE="Unknown subcommand"`);
    }
  }

  private handleStreamConnect(socket: Socket, parts: string[], session: SAMSession | null): void {
    const destination = this.parseValue(parts.join(' '), 'DESTINATION');
    
    if (!destination) {
      this.sendReply(socket, `${SAMReply.STREAM_STATUS} RESULT=I2P_ERROR MESSAGE="Missing DESTINATION"`);
      return;
    }

    this.emit('streamConnect', { socket, destination, session });
    this.sendReply(socket, `${SAMReply.STREAM_STATUS} RESULT=OK`);
  }

  private handleStreamAccept(socket: Socket, parts: string[], session: SAMSession | null): void {
    this.emit('streamAccept', { socket, session });
    this.sendReply(socket, `${SAMReply.STREAM_STATUS} RESULT=OK`);
  }

  private handleStreamForward(socket: Socket, parts: string[], session: SAMSession | null): void {
    const port = parseInt(this.parseValue(parts.join(' '), 'PORT') || '0');
    
    this.emit('streamForward', { socket, port, session });
    this.sendReply(socket, `${SAMReply.STREAM_STATUS} RESULT=OK`);
  }

  private handleNaming(socket: Socket, parts: string[]): void {
    const name = this.parseValue(parts.join(' '), 'NAME');
    
    if (!name) {
      this.sendReply(socket, `${SAMReply.NAMING_REPLY} RESULT=KEY_NOT_FOUND`);
      return;
    }

    this.emit('namingLookup', { socket, name });
  }

  private handleDest(socket: Socket, parts: string[]): void {
    const subCommand = parts[1]?.toUpperCase();
    
    if (subCommand === 'GENERATE') {
      this.emit('destGenerate', { socket });
      this.sendReply(socket, `${SAMReply.DEST_REPLY} RESULT=OK PUB=${Buffer.alloc(32).toString('base64')} PRIV=${Buffer.alloc(32).toString('base64')}`);
    } else {
      this.sendReply(socket, `${SAMReply.DEST_REPLY} RESULT=I2P_ERROR`);
    }
  }

  private parseValue(line: string, key: string): string | null {
    const regex = new RegExp(`${key}=([^\\s]+)`);
    const match = line.match(regex);
    return match ? match[1] : null;
  }

  private sendReply(socket: Socket, reply: string): void {
    socket.write(reply + '\n');
  }

  getSession(sessionId: string): SAMSession | undefined {
    return this.sessions.get(sessionId);
  }

  getAllSessions(): SAMSession[] {
    return Array.from(this.sessions.values());
  }
}

export default SAMProtocol;

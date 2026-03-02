export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  FATAL = 4
}

export interface LogEntry {
  timestamp: number;
  level: LogLevel;
  levelName: string;
  message: string;
  source?: string;
  data?: any;
}

export type LogHandler = (entry: LogEntry) => void;

export class Logger {
  private static instance: Logger;
  private level: LogLevel = LogLevel.INFO;
  private handlers: LogHandler[] = [];
  private history: LogEntry[] = [];
  private maxHistorySize: number = 10000;
  private source: string = 'I2P';

  static getInstance(): Logger {
    if (!Logger.instance) {
      Logger.instance = new Logger();
    }
    return Logger.instance;
  }

  configure(options: { level?: LogLevel; maxHistorySize?: number; source?: string }): void {
    if (options.level !== undefined) this.level = options.level;
    if (options.maxHistorySize !== undefined) this.maxHistorySize = options.maxHistorySize;
    if (options.source !== undefined) this.source = options.source;
  }

  setLevel(level: LogLevel): void {
    this.level = level;
    this.info(`Log level set to ${LogLevel[level]}`);
  }

  getLevel(): LogLevel {
    return this.level;
  }

  addHandler(handler: LogHandler): void {
    this.handlers.push(handler);
  }

  removeHandler(handler: LogHandler): void {
    const index = this.handlers.indexOf(handler);
    if (index > -1) {
      this.handlers.splice(index, 1);
    }
  }

  private log(level: LogLevel, message: string, data?: any, source?: string): void {
    if (level < this.level) return;

    const entry: LogEntry = {
      timestamp: Date.now(),
      level,
      levelName: LogLevel[level],
      message,
      source: source || this.source,
      data
    };

    // Add to history
    this.history.push(entry);
    if (this.history.length > this.maxHistorySize) {
      this.history.shift();
    }

    // Call handlers
    for (const handler of this.handlers) {
      try {
        handler(entry);
      } catch (err) {
        console.error('Log handler error:', err);
      }
    }

    // Default console output
    const timestamp = new Date(entry.timestamp).toISOString();
    const prefix = `[${timestamp}] [${entry.levelName}]${source ? ` [${source}]` : ''}`;
    
    switch (level) {
      case LogLevel.DEBUG:
        console.debug(prefix, message, data || '');
        break;
      case LogLevel.INFO:
        console.info(prefix, message, data || '');
        break;
      case LogLevel.WARN:
        console.warn(prefix, message, data || '');
        break;
      case LogLevel.ERROR:
      case LogLevel.FATAL:
        console.error(prefix, message, data || '');
        break;
    }
  }

  debug(message: string, data?: any, source?: string): void {
    this.log(LogLevel.DEBUG, message, data, source);
  }

  info(message: string, data?: any, source?: string): void {
    this.log(LogLevel.INFO, message, data, source);
  }

  warn(message: string, data?: any, source?: string): void {
    this.log(LogLevel.WARN, message, data, source);
  }

  error(message: string, data?: any, source?: string): void {
    this.log(LogLevel.ERROR, message, data, source);
  }

  fatal(message: string, data?: any, source?: string): void {
    this.log(LogLevel.FATAL, message, data, source);
  }

  getHistory(filter?: { level?: LogLevel; source?: string; limit?: number }): LogEntry[] {
    let result = [...this.history];

    if (filter?.level !== undefined) {
      result = result.filter(e => e.level >= filter.level!);
    }

    if (filter?.source) {
      result = result.filter(e => e.source === filter.source);
    }

    if (filter?.limit) {
      result = result.slice(-filter.limit);
    }

    return result;
  }

  clearHistory(): void {
    this.history = [];
  }

  getStats(): { total: number; byLevel: Record<string, number> } {
    const byLevel: Record<string, number> = {};
    
    for (const entry of this.history) {
      byLevel[entry.levelName] = (byLevel[entry.levelName] || 0) + 1;
    }

    return {
      total: this.history.length,
      byLevel
    };
  }
}

// Export singleton instance
export const logger = Logger.getInstance();

// Convenience exports
export const debug = (msg: string, data?: any, src?: string) => logger.debug(msg, data, src);
export const info = (msg: string, data?: any, src?: string) => logger.info(msg, data, src);
export const warn = (msg: string, data?: any, src?: string) => logger.warn(msg, data, src);
export const error = (msg: string, data?: any, src?: string) => logger.error(msg, data, src);
export const fatal = (msg: string, data?: any, src?: string) => logger.fatal(msg, data, src);

export default logger;

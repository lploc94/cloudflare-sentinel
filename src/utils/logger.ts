/**
 * Structured logger for Sentinel
 * Provides consistent logging with context and levels
 */

export enum LogLevel {
  DEBUG = 0,
  INFO = 1,
  WARN = 2,
  ERROR = 3,
  NONE = 4,
}

export interface LogContext {
  component?: string;
  requestId?: string;
  ip?: string;
  endpoint?: string;
  attackType?: string;
  error?: Error;
  [key: string]: any;
}

export class SentinelLogger {
  private level: LogLevel;
  private prefix: string;

  constructor(level: LogLevel = LogLevel.INFO, prefix: string = '[Sentinel]') {
    this.level = level;
    this.prefix = prefix;
  }

  debug(message: string, context?: LogContext): void {
    if (this.level <= LogLevel.DEBUG) {
      this.log('DEBUG', message, context);
    }
  }

  info(message: string, context?: LogContext): void {
    if (this.level <= LogLevel.INFO) {
      this.log('INFO', message, context);
    }
  }

  warn(message: string, context?: LogContext): void {
    if (this.level <= LogLevel.WARN) {
      this.log('WARN', message, context);
    }
  }

  error(message: string, context?: LogContext): void {
    if (this.level <= LogLevel.ERROR) {
      this.log('ERROR', message, context);
    }
  }

  private log(level: string, message: string, context?: LogContext): void {
    const timestamp = new Date().toISOString();
    const component = context?.component ? `[${context.component}]` : '';
    const logMessage = `${this.prefix} ${component} ${level}: ${message}`;

    // Extract error for separate logging
    const { error, ...cleanContext } = context || {};

    // Format context for logging
    const contextStr = Object.keys(cleanContext).length > 0 
      ? `\n  Context: ${JSON.stringify(cleanContext, null, 2)}`
      : '';

    const errorStr = error
      ? `\n  Error: ${error.message}\n  Stack: ${error.stack}`
      : '';

    const fullMessage = `${logMessage}${contextStr}${errorStr}`;

    // Use appropriate console method
    switch (level) {
      case 'DEBUG':
      case 'INFO':
        console.log(fullMessage);
        break;
      case 'WARN':
        console.warn(fullMessage);
        break;
      case 'ERROR':
        console.error(fullMessage);
        break;
    }
  }

  /**
   * Create a child logger with additional context
   */
  child(context: LogContext): SentinelLogger {
    const childLogger = new SentinelLogger(this.level, this.prefix);
    // Wrap logging methods to include child context
    const originalDebug = childLogger.debug.bind(childLogger);
    const originalInfo = childLogger.info.bind(childLogger);
    const originalWarn = childLogger.warn.bind(childLogger);
    const originalError = childLogger.error.bind(childLogger);

    childLogger.debug = (message: string, additionalContext?: LogContext) => {
      originalDebug(message, { ...context, ...additionalContext });
    };

    childLogger.info = (message: string, additionalContext?: LogContext) => {
      originalInfo(message, { ...context, ...additionalContext });
    };

    childLogger.warn = (message: string, additionalContext?: LogContext) => {
      originalWarn(message, { ...context, ...additionalContext });
    };

    childLogger.error = (message: string, additionalContext?: LogContext) => {
      originalError(message, { ...context, ...additionalContext });
    };

    return childLogger;
  }

  /**
   * Set log level
   */
  setLevel(level: LogLevel): void {
    this.level = level;
  }

  /**
   * Get current log level
   */
  getLevel(): LogLevel {
    return this.level;
  }
}

/**
 * Create logger from environment/config
 */
export function createLogger(debug?: boolean): SentinelLogger {
  const level = debug ? LogLevel.DEBUG : LogLevel.INFO;
  return new SentinelLogger(level);
}

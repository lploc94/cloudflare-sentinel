/**
 * Log Handler - Write logs to console
 * 
 * For Analytics Engine logging, use `AnalyticsHandler` instead.
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';

export interface LogHandlerOptions {
  /** Enable console logging (default: true) */
  console?: boolean;
  /** Log prefix (default: '[Sentinel]') */
  prefix?: string;
}

/**
 * LogHandler - Writes detection logs to console
 * 
 * For Analytics Engine, use `AnalyticsHandler` instead.
 * 
 * @example
 * ```typescript
 * import { ActionType, LogHandler } from 'cloudflare-sentinel';
 * 
 * pipeline.on(ActionType.LOG, new LogHandler({ console: true }));
 * 
 * // Custom prefix
 * pipeline.on(ActionType.LOG, new LogHandler({ prefix: '[WAF]' }));
 * ```
 */
export class LogHandler implements IActionHandler {
  constructor(private options: LogHandlerOptions = {}) {
    this.options.console = options.console ?? true;
  }

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    const { level, ...data } = action.data || {};
    
    const logEntry = {
      timestamp: Date.now(),
      level,
      score: ctx.score.score,
      threatLevel: ctx.score.level,
      detections: ctx.results.length,
      ...data,
    };

    // Console logging
    if (this.options.console) {
      const prefix = this.options.prefix || '[Sentinel]';
      const method = level === 'error' ? 'error' : level === 'warn' ? 'warn' : 'log';
      console[method](`${prefix}`, logEntry);
    }
  }
}

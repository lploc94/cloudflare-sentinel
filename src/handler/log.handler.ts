/**
 * Log Handler - Write logs to console or analytics
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';

export interface LogHandlerOptions {
  /** Analytics Engine binding */
  analytics?: AnalyticsEngineDataset;
  /** Enable console logging */
  console?: boolean;
  /** Log prefix */
  prefix?: string;
}

/**
 * LogHandler - Writes detection logs
 * 
 * @example
 * ```typescript
 * pipeline.on(ActionType.LOG, new LogHandler({ console: true }));
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

    // Analytics Engine
    if (this.options.analytics) {
      this.options.analytics.writeDataPoint({
        blobs: [
          JSON.stringify(logEntry),
        ],
        doubles: [ctx.score.score],
        indexes: [ctx.score.level],
      });
    }
  }
}

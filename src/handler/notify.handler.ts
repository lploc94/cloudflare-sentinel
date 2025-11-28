/**
 * Notify Handler - Send notifications via webhook
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';

export interface NotifyHandlerOptions {
  /** Webhook URL */
  webhookUrl?: string;
  /** Webhook URL from environment variable name */
  webhookEnvKey?: string;
  /** Headers to include */
  headers?: Record<string, string>;
  /** Timeout in milliseconds (default: 5000) */
  timeout?: number;
  /** Retry count on failure (default: 0) */
  retries?: number;
}

/**
 * NotifyHandler - Sends webhook notifications
 * 
 * @example
 * ```typescript
 * // Basic
 * pipeline.on('notify', new NotifyHandler({ webhookUrl: 'https://...' }));
 * 
 * // With timeout and retries
 * pipeline.on('notify', new NotifyHandler({
 *   webhookUrl: 'https://...',
 *   timeout: 3000,
 *   retries: 2,
 * }));
 * ```
 */
export class NotifyHandler implements IActionHandler {
  constructor(private options: NotifyHandlerOptions = {}) {}

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    const { channel, message, ...data } = action.data || {};
    
    const webhookUrl = this.options.webhookUrl 
      || (this.options.webhookEnvKey && ctx.env ? ctx.env[this.options.webhookEnvKey] as string : null);
    
    if (!webhookUrl) {
      console.warn('[Sentinel] NotifyHandler: No webhook URL configured');
      return;
    }

    const payload = {
      channel,
      message,
      timestamp: new Date().toISOString(),
      score: ctx.score?.score,
      threatLevel: ctx.score?.level,
      detections: ctx.results?.map(r => ({
        type: r.attackType,
        severity: r.severity,
        confidence: r.confidence,
      })) || [],
      request: {
        url: ctx.request?.url,
        method: ctx.request?.method,
        ip: ctx.request?.headers.get('cf-connecting-ip'),
      },
      ...data,
    };

    const timeout = this.options.timeout ?? 5000;
    const retries = this.options.retries ?? 0;

    await this.sendWithRetry(webhookUrl, payload, timeout, retries);
  }

  private async sendWithRetry(
    url: string, 
    payload: object, 
    timeout: number, 
    retriesLeft: number
  ): Promise<void> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), timeout);

      try {
        const response = await fetch(url, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            ...this.options.headers,
          },
          body: JSON.stringify(payload),
          signal: controller.signal,
        });

        if (!response.ok && retriesLeft > 0) {
          console.warn(`[Sentinel] NotifyHandler: HTTP ${response.status}, retrying...`);
          return this.sendWithRetry(url, payload, timeout, retriesLeft - 1);
        }
      } finally {
        clearTimeout(timeoutId);
      }
    } catch (error) {
      if (retriesLeft > 0) {
        console.warn(`[Sentinel] NotifyHandler error, retrying... (${retriesLeft} left)`);
        return this.sendWithRetry(url, payload, timeout, retriesLeft - 1);
      }
      console.error('[Sentinel] NotifyHandler error:', error);
    }
  }
}

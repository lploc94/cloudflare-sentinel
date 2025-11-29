/**
 * Analytics Engine Handler
 * 
 * Writes security events to Cloudflare Analytics Engine.
 * Standard format compatible with other CF Workers patterns.
 * 
 * **Data Format:**
 * - blobs: [source, category, action, level, ip, evidence]
 * - doubles: [score, detectionCount, eventCount]
 * - indexes: [identifier]
 */

import type { IActionHandler } from './types';
import type { Action, HandlerContext } from '../pipeline/types';
import { extractIPFromContext } from '../utils/extract';

export interface AnalyticsHandlerOptions {
  /** Analytics Engine dataset binding */
  analytics: AnalyticsEngineDataset;
  /** Source identifier (default: 'sentinel') */
  source?: string;
  /** Category for events (default: 'security') */
  category?: string;
  /** Custom index extractor (default: IP) */
  indexExtractor?: (ctx: HandlerContext) => string;
}

/**
 * AnalyticsHandler - Write security events to Cloudflare Analytics Engine
 * 
 * @example
 * ```typescript
 * // Basic usage
 * pipeline.on(ActionType.LOG, new AnalyticsHandler({
 *   analytics: env.ANALYTICS,
 * }));
 * 
 * // Custom source/category
 * pipeline.on(ActionType.LOG, new AnalyticsHandler({
 *   analytics: env.ANALYTICS,
 *   source: 'api-gateway',
 *   category: 'waf',
 * }));
 * 
 * // Custom index (e.g., by user ID from your app)
 * pipeline.on(ActionType.LOG, new AnalyticsHandler({
 *   analytics: env.ANALYTICS,
 *   indexExtractor: (ctx) => ctx.request?.headers.get('x-user-id') || 'anonymous',
 * }));
 * ```
 * 
 * @remarks
 * **Data written to Analytics Engine:**
 * 
 * | Field | Value |
 * |-------|-------|
 * | blobs[0] | source (default: 'sentinel') |
 * | blobs[1] | category (default: 'security') |
 * | blobs[2] | action type (log, block, etc.) |
 * | blobs[3] | threat level |
 * | blobs[4] | client IP |
 * | blobs[5] | evidence JSON |
 * | doubles[0] | threat score |
 * | doubles[1] | detection count |
 * | doubles[2] | event count (always 1) |
 * | indexes[0] | identifier (default: IP) |
 * 
 * Query example:
 * ```sql
 * SELECT blob1 as category, blob3 as level, double1 as score, count() as events
 * FROM sentinel_analytics
 * WHERE blob1 = 'security'
 * GROUP BY category, level
 * ```
 */
export class AnalyticsHandler implements IActionHandler {
  private source: string;
  private category: string;
  private indexExtractor?: (ctx: HandlerContext) => string;

  constructor(private options: AnalyticsHandlerOptions) {
    this.source = options.source ?? 'sentinel';
    this.category = options.category ?? 'security';
    this.indexExtractor = options.indexExtractor;
  }

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    if (!this.options.analytics) {
      return;
    }

    try {
      const ip = extractIPFromContext(ctx) || 'unknown';
      const evidence = this.buildEvidence(ctx);
      const index = this.indexExtractor ? this.indexExtractor(ctx) : ip;

      this.options.analytics.writeDataPoint({
        blobs: [
          this.source,
          this.category,
          action.type,
          ctx.score.level,
          ip,
          evidence,
        ].slice(0, 20), // Analytics Engine limit
        doubles: [
          ctx.score.score,
          ctx.results.length,
          1, // event count
        ],
        indexes: [index],
      });
    } catch (error) {
      // Analytics should never break main flow - silent fail
      console.error('[Sentinel] AnalyticsHandler error:', error);
    }
  }

  private buildEvidence(ctx: HandlerContext): string {
    const evidence = ctx.results.map(r => ({
      type: String(r.attackType),
      severity: r.severity,
      confidence: r.confidence,
      field: r.evidence?.field,
    }));

    return JSON.stringify(evidence);
  }
}

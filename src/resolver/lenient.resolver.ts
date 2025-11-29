/**
 * Lenient Action Resolver
 * 
 * Usability-first resolver that only blocks severe/critical threats.
 * Use for public endpoints where false positives are costly.
 * 
 * @module resolver
 */

import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

/**
 * Options for LenientResolver
 */
export interface LenientResolverOptions {
  /** 
   * Score threshold to block (default: 90)
   * Much higher than DefaultResolver (70) for minimal blocking
   */
  blockThreshold?: number;
}

/**
 * LenientResolver - Usability-first, only blocks critical threats
 * 
 * **Key difference from DefaultResolver:**
 * - Much higher threshold (90 vs 70)
 * - Only logs when there are actual detections
 * - Designed to minimize false positives
 * 
 * **Behavior:**
 * - Score >= blockThreshold (90): BLOCK + NOTIFY (critical only)
 * - Any detection: LOG info
 * - No detection: PROCEED silently
 * 
 * **When to use:**
 * - Public search endpoints
 * - High-traffic APIs where blocking = lost revenue
 * - Content that may trigger false positives (user-generated)
 * - Endpoints where UX > security
 * 
 * **When NOT to use:**
 * - Authentication endpoints
 * - Admin panels
 * - Payment/financial endpoints
 * - Any endpoint handling sensitive data
 * 
 * @example
 * ```typescript
 * import { SentinelPipeline, LenientResolver } from 'cloudflare-sentinel';
 * 
 * // For /search endpoint (user input may look suspicious)
 * const searchPipeline = SentinelPipeline.sync([
 *   new BlocklistDetector({ kv }),
 *   new SQLInjectionRequestDetector(),
 *   new XSSRequestDetector(),
 * ])
 *   .score(new MaxScoreAggregator())
 *   .resolve(new LenientResolver());
 * 
 * // Even more lenient - only block score 95+
 * const ultraLenient = SentinelPipeline.sync([...])
 *   .resolve(new LenientResolver({ blockThreshold: 95 }));
 * ```
 * 
 * @see DefaultResolver for balanced security
 * @see StrictResolver for sensitive endpoints
 */
export class LenientResolver extends BaseActionResolver {
  name = 'lenient';
  
  private blockThreshold: number;

  constructor(options: LenientResolverOptions = {}) {
    super();
    this.blockThreshold = options.blockThreshold ?? 90;
  }

  async resolve(ctx: ResolverContext): Promise<Action[]> {
    const actions: Action[] = [];
    const { score, results } = ctx;

    // Log only if detections
    if (results.length > 0) {
      actions.push(this.log('info', {
        score: score.score,
        level: score.level,
        detections: results.length,
      }));
    }

    // Only block critical threats
    if (score.score >= this.blockThreshold) {
      actions.push(this.block(`Critical threat: score ${score.score}`));
      actions.push(this.notify('security', `Critical block: score ${score.score}`));
      return actions;
    }

    actions.push(this.proceed());
    return actions;
  }
}

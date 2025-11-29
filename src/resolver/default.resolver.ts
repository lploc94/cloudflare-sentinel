/**
 * Default Action Resolver
 * 
 * Standard score-to-action mapping with configurable thresholds.
 * Good for most use cases with balanced security/usability.
 * 
 * @module resolver
 */

import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

/**
 * Options for DefaultResolver
 */
export interface DefaultResolverOptions {
  /** 
   * Score threshold to block request (default: 70)
   * Requests with score >= this value will be blocked
   */
  blockThreshold?: number;
  
  /** 
   * Score threshold to log warning (default: 40)
   * Requests with score >= this value will log a warning
   */
  warnThreshold?: number;
  
  /** 
   * Always log all requests, even score 0 (default: false)
   * Useful for debugging or full audit trails
   */
  alwaysLog?: boolean;
}

/**
 * DefaultResolver - Standard score-to-action mapping
 * 
 * **Behavior:**
 * - Score >= blockThreshold (70): BLOCK + NOTIFY
 * - Score >= warnThreshold (40): LOG warning
 * - Score > 0: LOG info
 * - Always: PROCEED (unless blocked)
 * 
 * **When to use:**
 * - General-purpose APIs
 * - Balanced security/usability requirements
 * - When you want simple threshold-based blocking
 * 
 * @example
 * ```typescript
 * import { SentinelPipeline, DefaultResolver } from 'cloudflare-sentinel';
 * 
 * // Default thresholds
 * const pipeline = SentinelPipeline.sync([...detectors])
 *   .score(...)
 *   .resolve(new DefaultResolver());
 * 
 * // Custom thresholds
 * const strictPipeline = SentinelPipeline.sync([...detectors])
 *   .score(...)
 *   .resolve(new DefaultResolver({
 *     blockThreshold: 50,   // Block at lower score
 *     warnThreshold: 20,    // Warn earlier
 *     alwaysLog: true,      // Log everything
 *   }));
 * ```
 * 
 * @see StrictResolver for stricter blocking
 * @see LenientResolver for more permissive blocking
 * @see MultiLevelResolver for configurable multi-level actions
 */
export class DefaultResolver extends BaseActionResolver {
  name = 'default';
  
  private blockThreshold: number;
  private warnThreshold: number;
  private alwaysLog: boolean;

  constructor(options: DefaultResolverOptions = {}) {
    super();
    this.blockThreshold = options.blockThreshold ?? 70;
    this.warnThreshold = options.warnThreshold ?? 40;
    this.alwaysLog = options.alwaysLog ?? false;
  }

  async resolve(ctx: ResolverContext): Promise<Action[]> {
    const actions: Action[] = [];
    const { score, results } = ctx;

    // Always log if enabled or score > 0
    if (this.alwaysLog || score.score > 0) {
      actions.push(this.log('info', {
        score: score.score,
        level: score.level,
        detections: results.length,
      }));
    }

    // Block if score exceeds threshold
    if (score.score >= this.blockThreshold) {
      actions.push(this.block(`Threat score ${score.score} exceeded threshold`));
      actions.push(this.notify('default', `Blocked request with score ${score.score}`));
      return actions;
    }

    // Warn if score exceeds warning threshold
    if (score.score >= this.warnThreshold) {
      actions.push(this.log('warn', {
        message: 'Elevated threat score',
        score: score.score,
      }));
    }

    // Proceed
    actions.push(this.proceed());
    return actions;
  }
}

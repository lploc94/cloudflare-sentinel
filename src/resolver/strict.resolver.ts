/**
 * Strict Action Resolver
 * 
 * Security-first resolver that blocks on ANY detection or low scores.
 * Use for sensitive endpoints where security is paramount.
 * 
 * @module resolver
 */

import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

/**
 * Options for StrictResolver
 */
export interface StrictResolverOptions {
  /** 
   * Score threshold to block (default: 50)
   * Lower than DefaultResolver for stricter security
   */
  blockThreshold?: number;
}

/**
 * StrictResolver - Security-first, blocks on ANY detection
 * 
 * **Key difference from DefaultResolver:**
 * - Blocks if ANY detection exists (regardless of score)
 * - Lower default threshold (50 vs 70)
 * - Always logs all requests
 * 
 * **Behavior:**
 * - Score >= blockThreshold (50): BLOCK + NOTIFY
 * - Any detection (even score 0): BLOCK + NOTIFY
 * - No detection & score < threshold: LOG + PROCEED
 * 
 * **When to use:**
 * - Authentication endpoints (/login, /auth/*)
 * - Admin panels (/admin/*)
 * - Payment/financial endpoints
 * - Any endpoint where security > usability
 * 
 * **When NOT to use:**
 * - Public search/browse endpoints (high false positive risk)
 * - Static content serving
 * - High-traffic public APIs
 * 
 * @example
 * ```typescript
 * import { SentinelPipeline, StrictResolver } from 'cloudflare-sentinel';
 * 
 * // For /login endpoint
 * const authPipeline = SentinelPipeline.sync([
 *   new BlocklistDetector({ kv }),
 *   new BruteForceDetector({ kv }),
 *   new SQLInjectionRequestDetector(),
 * ])
 *   .score(new MaxScoreAggregator())
 *   .resolve(new StrictResolver());
 * 
 * // Even stricter - block at score 30
 * const ultraStrictPipeline = SentinelPipeline.sync([...])
 *   .resolve(new StrictResolver({ blockThreshold: 30 }));
 * ```
 * 
 * @see DefaultResolver for balanced security
 * @see LenientResolver for public endpoints
 */
export class StrictResolver extends BaseActionResolver {
  name = 'strict';
  
  private blockThreshold: number;

  constructor(options: StrictResolverOptions = {}) {
    super();
    this.blockThreshold = options.blockThreshold ?? 50;
  }

  async resolve(ctx: ResolverContext): Promise<Action[]> {
    const actions: Action[] = [];
    const { score, results } = ctx;

    // Always log
    actions.push(this.log('info', {
      score: score.score,
      level: score.level,
      detections: results.length,
    }));

    // Block if any detection or score exceeds threshold
    if (score.score >= this.blockThreshold || results.length > 0) {
      const reason = results.length > 0
        ? `Detected: ${results.map(r => r.attackType).join(', ')}`
        : `Threat score ${score.score}`;
      
      actions.push(this.block(reason));
      actions.push(this.notify('security', `Strict block: ${reason}`));
      return actions;
    }

    actions.push(this.proceed());
    return actions;
  }
}

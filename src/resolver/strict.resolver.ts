/**
 * Strict Action Resolver
 */

import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

export interface StrictResolverOptions {
  /** Score threshold to block (default: 50) */
  blockThreshold?: number;
}

/**
 * StrictResolver - Lower threshold, stricter blocking
 * 
 * Use for sensitive endpoints like auth, admin
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

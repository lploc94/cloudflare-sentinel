/**
 * Lenient Action Resolver
 */

import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

export interface LenientResolverOptions {
  /** Score threshold to block (default: 90) */
  blockThreshold?: number;
}

/**
 * LenientResolver - Higher threshold, only blocks severe threats
 * 
 * Use for public endpoints with lower security requirements
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

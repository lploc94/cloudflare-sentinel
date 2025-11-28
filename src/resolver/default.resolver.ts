/**
 * Default Action Resolver
 */

import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

export interface DefaultResolverOptions {
  /** Score threshold to block (default: 70) */
  blockThreshold?: number;
  /** Score threshold to log warning (default: 40) */
  warnThreshold?: number;
  /** Always log all requests */
  alwaysLog?: boolean;
}

/**
 * DefaultResolver - Standard score-to-action mapping
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

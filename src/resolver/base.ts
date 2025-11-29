/**
 * Base Action Resolver
 * 
 * Abstract base class for action resolution strategies.
 * Provides helper methods for creating standard actions.
 * 
 * @module resolver
 */

import { ActionType, type Action, type ResolverContext } from '../pipeline/types';
import type { IActionResolver } from './types';

/**
 * Base class for action resolvers
 * 
 * Resolvers determine what actions to take based on the threat score.
 * Subclasses implement the `resolve` method to define the resolution logic.
 * 
 * **Available Actions:**
 * | Action | Method | Description |
 * |--------|--------|-------------|
 * | BLOCK | `block()` | Block the request |
 * | PROCEED | `proceed()` | Allow the request |
 * | LOG | `log()` | Log the detection |
 * | NOTIFY | `notify()` | Send notification |
 * | UPDATE_REPUTATION | `updateReputation()` | Update IP reputation |
 * 
 * @example
 * ```typescript
 * class CustomResolver extends BaseActionResolver {
 *   name = 'custom';
 *   
 *   async resolve(ctx: ResolverContext): Promise<Action[]> {
 *     const actions: Action[] = [];
 *     
 *     if (ctx.score.score >= 80) {
 *       actions.push(this.block('High threat score'));
 *       actions.push(this.notify('security', 'Request blocked'));
 *     } else {
 *       actions.push(this.log('info', { score: ctx.score.score }));
 *       actions.push(this.proceed());
 *     }
 *     
 *     return actions;
 *   }
 * }
 * ```
 */
export abstract class BaseActionResolver implements IActionResolver {
  /** Resolver name for identification */
  abstract name: string;
  
  /** Resolve threat score into list of actions */
  abstract resolve(ctx: ResolverContext): Promise<Action[]>;

  /**
   * Create block action
   * 
   * @param reason - Human-readable block reason
   * @param statusCode - HTTP status code (default: 403)
   * @returns Block action
   */
  protected block(reason: string, statusCode: number = 403): Action {
    return {
      type: ActionType.BLOCK,
      data: { reason, statusCode },
    };
  }

  /**
   * Create proceed action
   */
  protected proceed(): Action {
    return { type: ActionType.PROCEED };
  }

  /**
   * Create log action
   */
  protected log(level: 'debug' | 'info' | 'warn' | 'error', data: any): Action {
    return {
      type: ActionType.LOG,
      data: { level, ...data },
    };
  }

  /**
   * Create notify action
   */
  protected notify(channel: string, message: string, data?: any): Action {
    return {
      type: ActionType.NOTIFY,
      data: { channel, message, ...data },
    };
  }

  /**
   * Create update reputation action
   */
  protected updateReputation(delta: number, data?: any): Action {
    return {
      type: ActionType.UPDATE_REPUTATION,
      data: { delta, ...data },
    };
  }
}

/**
 * Base action resolver classes
 */

import { ActionType, type Action, type ResolverContext } from '../pipeline/types';
import type { IActionResolver } from './types';

/**
 * Base class for action resolvers
 */
export abstract class BaseActionResolver implements IActionResolver {
  abstract name: string;
  abstract resolve(ctx: ResolverContext): Promise<Action[]>;

  /**
   * Create block action
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
}

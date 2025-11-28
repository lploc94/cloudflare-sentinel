/**
 * Handler types for Cloudflare Sentinel
 */

import type { Action, HandlerContext } from '../pipeline/types';

/**
 * Action handler interface
 * 
 * Handlers are registered with `pipeline.on(actionType, handler)`,
 * so no `type` property is needed on the handler itself.
 */
export interface IActionHandler {
  /**
   * Execute the action
   */
  execute(action: Action, ctx: HandlerContext): Promise<void>;
}

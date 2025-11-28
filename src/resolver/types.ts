/**
 * Resolver types for Cloudflare Sentinel
 */

import type { Action, ResolverContext } from '../pipeline/types';

/**
 * Action resolver interface
 * Converts threat score into a list of actions
 */
export interface IActionResolver {
  /** Resolver name */
  name: string;
  
  /**
   * Resolve threat score into actions
   */
  resolve(ctx: ResolverContext): Promise<Action[]>;
}

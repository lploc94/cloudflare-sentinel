/**
 * Decision - Pipeline Result
 * 
 * Returned by sync pipelines to allow checking what actions were resolved.
 * Primary use is checking `decision.has('block')` to determine if request should be blocked.
 * 
 * @module pipeline
 */

import type { Action, ThreatScore } from './types';

/**
 * Decision - Result from sync pipeline processing
 * 
 * Contains all resolved actions and the aggregated threat score.
 * Provides helper methods for checking and retrieving action data.
 * 
 * **Common Usage Pattern:**
 * ```typescript
 * const decision = await pipeline.process(request, { env, ctx });
 * 
 * if (decision.has('block')) {
 *   const reason = decision.get('block')?.reason;
 *   return new Response(`Blocked: ${reason}`, { status: 403 });
 * }
 * 
 * // Continue processing
 * return fetch(request);
 * ```
 * 
 * @example
 * ```typescript
 * // Check for specific actions
 * if (decision.has(ActionType.BLOCK)) {
 *   // Request should be blocked
 * }
 * 
 * if (decision.has(ActionType.NOTIFY)) {
 *   // Notification was triggered
 * }
 * 
 * // Get action data
 * const blockData = decision.get(ActionType.BLOCK);
 * console.log(blockData?.reason); // 'SQL Injection detected'
 * 
 * // Access threat score
 * console.log(decision.score.score);  // 85
 * console.log(decision.score.level);  // 'critical'
 * 
 * // Get all actions for logging
 * console.log(decision.getActionTypes()); // ['log', 'block', 'notify']
 * ```
 */
export class Decision {
  /**
   * Create a new Decision
   * 
   * @param actions - Resolved actions from the pipeline
   * @param score - Aggregated threat score
   */
  constructor(
    private readonly actions: Action[],
    public readonly score: ThreatScore
  ) {}

  /**
   * Check if an action type was resolved
   * 
   * @param type - Action type to check (e.g., 'block', ActionType.BLOCK)
   * @returns true if action exists
   * 
   * @example
   * ```typescript
   * if (decision.has('block')) {
   *   return new Response('Blocked', { status: 403 });
   * }
   * ```
   */
  has(type: string): boolean {
    return this.actions.some(a => a.type === type);
  }

  /**
   * Get data for a specific action type
   * 
   * @param type - Action type to get data for
   * @returns Action data object or undefined
   * 
   * @example
   * ```typescript
   * const blockData = decision.get('block');
   * if (blockData) {
   *   console.log(blockData.reason);     // 'SQL Injection'
   *   console.log(blockData.statusCode); // 403
   * }
   * ```
   */
  get(type: string): Record<string, any> | undefined {
    return this.actions.find(a => a.type === type)?.data;
  }

  /**
   * Get all resolved actions
   * 
   * Returns a copy to prevent mutation.
   * 
   * @returns Copy of all actions
   * 
   * @example
   * ```typescript
   * const actions = decision.getActions();
   * actions.forEach(action => {
   *   console.log(`${action.type}: ${JSON.stringify(action.data)}`);
   * });
   * ```
   */
  getActions(): Action[] {
    return [...this.actions];
  }

  /**
   * Get all action types as strings
   * 
   * Useful for logging or debugging.
   * 
   * @returns Array of action type strings
   * 
   * @example
   * ```typescript
   * console.log(decision.getActionTypes());
   * // ['log', 'update_reputation', 'block', 'notify']
   * ```
   */
  getActionTypes(): string[] {
    return this.actions.map(a => a.type);
  }
}

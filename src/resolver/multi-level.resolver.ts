/**
 * Multi-Level Action Resolver
 * 
 * Fully configurable threshold levels with custom actions per level.
 * Actions cascade from lower levels to higher levels.
 * 
 * @module resolver
 */

import { ActionType, type Action, type ActionTypeValue, type ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

/**
 * Threshold level configuration
 * 
 * Defines the maximum score for this level and which actions to trigger.
 * Actions from all levels up to and including the matched level are executed.
 */
export interface ThresholdLevel {
  /** 
   * Maximum score for this level (inclusive)
   * Score <= maxScore will match this level
   */
  maxScore: number;
  
  /** 
   * Actions to trigger at this level
   * Can use ActionType enum or custom string actions
   */
  actions: (ActionTypeValue | string)[];
}

/**
 * Options for MultiLevelResolver
 */
export interface MultiLevelResolverOptions {
  /** 
   * Threshold levels with actions
   * Will be sorted by maxScore automatically
   */
  levels: ThresholdLevel[];
}

/**
 * MultiLevelResolver - Configurable multi-threshold resolver
 * 
 * **Key Features:**
 * - Define multiple threshold levels
 * - Each level has its own set of actions
 * - Actions cascade from lower to higher levels
 * - Supports custom action types
 * 
 * **Cascading Example:**
 * ```
 * Level 1 (0-30):  [LOG]
 * Level 2 (31-60): [LOG, UPDATE_REPUTATION]
 * Level 3 (61+):   [LOG, UPDATE_REPUTATION, BLOCK, NOTIFY]
 * 
 * Score 70 → matches Level 3 → executes ALL actions from levels 1-3
 * ```
 * 
 * **When to use:**
 * - Complex security policies with multiple response levels
 * - Different actions for different threat severities
 * - Custom action types beyond built-in ones
 * 
 * @example
 * ```typescript
 * import { SentinelPipeline, MultiLevelResolver, ActionType } from 'cloudflare-sentinel';
 * 
 * const pipeline = SentinelPipeline.sync([...detectors])
 *   .score(new MaxScoreAggregator())
 *   .resolve(new MultiLevelResolver({
 *     levels: [
 *       { maxScore: 30, actions: [ActionType.LOG] },
 *       { maxScore: 60, actions: [ActionType.LOG, ActionType.UPDATE_REPUTATION] },
 *       { maxScore: 100, actions: [ActionType.BLOCK, ActionType.NOTIFY] },
 *     ],
 *   }));
 * 
 * // Custom actions
 * const advancedPipeline = SentinelPipeline.sync([...detectors])
 *   .score(...)
 *   .resolve(new MultiLevelResolver({
 *     levels: [
 *       { maxScore: 50, actions: [ActionType.LOG] },
 *       { maxScore: 80, actions: ['escalate'] },  // Custom action
 *       { maxScore: 100, actions: [ActionType.BLOCK, 'ai_analyze'] },
 *     ],
 *   }))
 *   .on('escalate', new EscalateHandler())
 *   .on('ai_analyze', new AIHandler());
 * ```
 * 
 * @see DefaultResolver for simpler threshold-based resolution
 */
export class MultiLevelResolver extends BaseActionResolver {
  name = 'multi-level';
  
  private levels: ThresholdLevel[];

  constructor(options: MultiLevelResolverOptions) {
    super();
    // Sort levels by maxScore ascending
    this.levels = [...options.levels].sort((a, b) => a.maxScore - b.maxScore);
  }

  async resolve(ctx: ResolverContext): Promise<Action[]> {
    const actions: Action[] = [];
    const { score, results } = ctx;
    
    // Find which level this score falls into
    let matchedLevelIndex = 0;
    for (let i = 0; i < this.levels.length; i++) {
      if (score.score <= this.levels[i].maxScore) {
        matchedLevelIndex = i;
        break;
      }
      matchedLevelIndex = i;
    }
    
    // Collect all actions from level 0 to matched level (cascading)
    const allActions = new Set<string>();
    for (let i = 0; i <= matchedLevelIndex; i++) {
      this.levels[i].actions.forEach(a => allActions.add(a));
    }
    
    // Convert action names to Action objects
    for (const actionName of allActions) {
      switch (actionName) {
        case ActionType.LOG:
          actions.push(this.log('info', {
            score: score.score,
            level: score.level,
            matchedLevel: matchedLevelIndex,
            detections: results.length,
          }));
          break;
          
        case ActionType.NOTIFY:
          actions.push(this.notify('multi-level', `Score ${score.score} at level ${matchedLevelIndex + 1}`));
          break;
          
        case ActionType.BLOCK:
          actions.push(this.block(`Blocked at level ${matchedLevelIndex + 1} (score: ${score.score})`));
          break;
          
        case ActionType.UPDATE_REPUTATION:
          actions.push(this.updateReputation(-10 * (matchedLevelIndex + 1), {
            reason: `Multi-level detection at level ${matchedLevelIndex + 1}`,
            score: score.score,
          }));
          break;
          
        case ActionType.PROCEED:
          actions.push(this.proceed());
          break;
      }
    }
    
    // If no block action, add proceed
    if (!allActions.has(ActionType.BLOCK)) {
      actions.push(this.proceed());
    }
    
    return actions;
  }
}

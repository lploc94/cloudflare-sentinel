/**
 * Multi-Level Action Resolver
 * 
 * Allows configurable threshold levels with custom actions per level.
 * Each level inherits actions from previous levels (cascading).
 */

import { ActionType, type Action, type ActionTypeValue, type ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

export interface ThresholdLevel {
  /** Maximum score for this level (exclusive for next level) */
  maxScore: number;
  /** Actions to trigger at this level */
  actions: (ActionTypeValue | string)[];
}

export interface MultiLevelResolverOptions {
  /** Threshold levels with actions */
  levels: ThresholdLevel[];
}

/**
 * MultiLevelResolver - Configurable multi-threshold resolver
 * 
 * Example:
 * ```typescript
 * import { ActionType } from '../pipeline/types';
 * 
 * new MultiLevelResolver({
 *   levels: [
 *     { maxScore: 30, actions: [ActionType.LOG] },
 *     { maxScore: 60, actions: [ActionType.LOG, ActionType.NOTIFY] },
 *     { maxScore: 100, actions: [ActionType.BLOCK, ActionType.NOTIFY] },
 *   ]
 * })
 * ```
 * 
 * With score 70:
 * - Level 3 is matched (maxScore: 100)
 * - Actions executed: log + notify + block
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

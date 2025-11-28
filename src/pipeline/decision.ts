/**
 * Decision - Result from sync pipeline
 */

import type { Action, ThreatScore } from './types';

/**
 * Decision returned by sync pipeline
 * User checks decision.has('block') to determine response
 */
export class Decision {
  constructor(
    private readonly actions: Action[],
    public readonly score: ThreatScore
  ) {}

  /**
   * Check if action type exists
   */
  has(type: string): boolean {
    return this.actions.some(a => a.type === type);
  }

  /**
   * Get data for specific action type
   */
  get(type: string): Record<string, any> | undefined {
    return this.actions.find(a => a.type === type)?.data;
  }

  /**
   * Get all actions
   */
  getActions(): Action[] {
    return [...this.actions];
  }

  /**
   * Get all action types
   */
  getActionTypes(): string[] {
    return this.actions.map(a => a.type);
  }
}

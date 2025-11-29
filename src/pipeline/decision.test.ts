/**
 * Decision tests
 */

import { describe, it, expect } from 'vitest';
import { Decision } from './decision';
import { ActionType } from './types';
import type { ThreatScore, Action } from './types';

function createScore(score: number = 50): ThreatScore {
  return {
    score,
    level: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low',
    results: [],
  };
}

describe('Decision', () => {
  describe('has()', () => {
    it('should return true if action type exists', () => {
      const actions: Action[] = [
        { type: ActionType.LOG },
        { type: ActionType.BLOCK },
      ];
      const decision = new Decision(actions, createScore());

      expect(decision.has(ActionType.LOG)).toBe(true);
      expect(decision.has(ActionType.BLOCK)).toBe(true);
    });

    it('should return false if action type does not exist', () => {
      const actions: Action[] = [
        { type: ActionType.LOG },
      ];
      const decision = new Decision(actions, createScore());

      expect(decision.has(ActionType.BLOCK)).toBe(false);
      expect(decision.has(ActionType.NOTIFY)).toBe(false);
    });

    it('should work with custom action types', () => {
      const actions: Action[] = [
        { type: 'custom_action' },
      ];
      const decision = new Decision(actions, createScore());

      expect(decision.has('custom_action')).toBe(true);
      expect(decision.has('other_action')).toBe(false);
    });
  });

  describe('get()', () => {
    it('should return action data if exists', () => {
      const actions: Action[] = [
        { type: ActionType.BLOCK, data: { reason: 'Test block', statusCode: 403 } },
      ];
      const decision = new Decision(actions, createScore());

      const data = decision.get(ActionType.BLOCK);
      expect(data).toEqual({ reason: 'Test block', statusCode: 403 });
    });

    it('should return undefined if action does not exist', () => {
      const actions: Action[] = [
        { type: ActionType.LOG },
      ];
      const decision = new Decision(actions, createScore());

      expect(decision.get(ActionType.BLOCK)).toBeUndefined();
    });

    it('should return undefined if action has no data', () => {
      const actions: Action[] = [
        { type: ActionType.PROCEED },
      ];
      const decision = new Decision(actions, createScore());

      expect(decision.get(ActionType.PROCEED)).toBeUndefined();
    });

    it('should return first matching action data', () => {
      const actions: Action[] = [
        { type: ActionType.LOG, data: { message: 'first' } },
        { type: ActionType.LOG, data: { message: 'second' } },
      ];
      const decision = new Decision(actions, createScore());

      expect(decision.get(ActionType.LOG)).toEqual({ message: 'first' });
    });
  });

  describe('getActions()', () => {
    it('should return copy of all actions', () => {
      const actions: Action[] = [
        { type: ActionType.LOG },
        { type: ActionType.BLOCK },
        { type: ActionType.NOTIFY },
      ];
      const decision = new Decision(actions, createScore());

      const result = decision.getActions();
      expect(result).toHaveLength(3);
      expect(result).toEqual(actions);
    });

    it('should return copy, not reference', () => {
      const actions: Action[] = [
        { type: ActionType.LOG },
      ];
      const decision = new Decision(actions, createScore());

      const result = decision.getActions();
      result.push({ type: ActionType.BLOCK });

      // Original should not be modified
      expect(decision.getActions()).toHaveLength(1);
    });

    it('should return empty array if no actions', () => {
      const decision = new Decision([], createScore());
      expect(decision.getActions()).toEqual([]);
    });
  });

  describe('getActionTypes()', () => {
    it('should return all action types', () => {
      const actions: Action[] = [
        { type: ActionType.LOG },
        { type: ActionType.BLOCK },
        { type: 'custom' },
      ];
      const decision = new Decision(actions, createScore());

      const types = decision.getActionTypes();
      expect(types).toEqual([ActionType.LOG, ActionType.BLOCK, 'custom']);
    });

    it('should return empty array if no actions', () => {
      const decision = new Decision([], createScore());
      expect(decision.getActionTypes()).toEqual([]);
    });
  });

  describe('score', () => {
    it('should expose score as public property', () => {
      const score = createScore(85);
      const decision = new Decision([], score);

      expect(decision.score).toBe(score);
      expect(decision.score.score).toBe(85);
      expect(decision.score.level).toBe('critical');
    });
  });

  describe('Common patterns', () => {
    it('should support if (decision.has("block")) pattern', () => {
      const blockedDecision = new Decision(
        [{ type: ActionType.BLOCK, data: { reason: 'Attack' } }],
        createScore(90)
      );

      if (blockedDecision.has('block')) {
        const reason = blockedDecision.get('block')?.reason;
        expect(reason).toBe('Attack');
      } else {
        expect.fail('Should have block action');
      }
    });

    it('should support checking multiple actions', () => {
      const decision = new Decision(
        [
          { type: ActionType.LOG },
          { type: ActionType.UPDATE_REPUTATION },
        ],
        createScore(50)
      );

      expect(decision.has(ActionType.LOG)).toBe(true);
      expect(decision.has(ActionType.UPDATE_REPUTATION)).toBe(true);
      expect(decision.has(ActionType.BLOCK)).toBe(false);
    });
  });
});

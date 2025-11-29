/**
 * Multi-Level Resolver tests
 */

import { describe, it, expect } from 'vitest';
import { MultiLevelResolver } from './multi-level.resolver';
import { ActionType } from '../pipeline/types';
import { AttackType, SecuritySeverity } from '../types';
import type { ResolverContext } from '../pipeline/types';

function createContext(score: number, detections: number = 1): ResolverContext {
  const level = score > 80 ? 'critical' : score > 60 ? 'high' : score > 30 ? 'medium' : score > 0 ? 'low' : 'none';
  return {
    score: { score, level, results: [] },
    results: Array(detections).fill({
      detected: true,
      attackType: AttackType.SQL_INJECTION,
      severity: SecuritySeverity.HIGH,
      confidence: 1.0,
      detectorName: 'test',
    }),
    request: new Request('https://example.com'),
  };
}

describe('MultiLevelResolver', () => {
  const standardLevels = [
    { maxScore: 30, actions: [ActionType.LOG] },
    { maxScore: 60, actions: [ActionType.LOG, ActionType.UPDATE_REPUTATION] },
    { maxScore: 100, actions: [ActionType.BLOCK, ActionType.UPDATE_REPUTATION, ActionType.NOTIFY] },
  ];

  describe('Level matching', () => {
    it('should match level 1 for score <= 30', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(20));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.LOG);
      expect(types).not.toContain(ActionType.UPDATE_REPUTATION);
      expect(types).not.toContain(ActionType.BLOCK);
    });

    it('should match level 2 for score 31-60', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(50));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.LOG);
      expect(types).toContain(ActionType.UPDATE_REPUTATION);
      expect(types).not.toContain(ActionType.BLOCK);
    });

    it('should match level 3 for score 61-100', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(80));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.BLOCK);
      expect(types).toContain(ActionType.UPDATE_REPUTATION);
      expect(types).toContain(ActionType.NOTIFY);
    });
  });

  describe('Cascading actions', () => {
    it('should cascade actions from lower levels', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(70));

      // Level 3 should include all actions from levels 1-3
      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.LOG);           // from level 1
      expect(types).toContain(ActionType.UPDATE_REPUTATION); // from level 2
      expect(types).toContain(ActionType.BLOCK);         // from level 3
      expect(types).toContain(ActionType.NOTIFY);        // from level 3
    });
  });

  describe('Proceed action', () => {
    it('should add proceed when no block action', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(20));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.PROCEED);
    });

    it('should not add proceed when block action exists', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(80));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.BLOCK);
      expect(types).not.toContain(ActionType.PROCEED);
    });
  });

  describe('Level sorting', () => {
    it('should sort levels by maxScore', async () => {
      // Levels in wrong order
      const resolver = new MultiLevelResolver({
        levels: [
          { maxScore: 100, actions: [ActionType.BLOCK] },
          { maxScore: 30, actions: [ActionType.LOG] },
          { maxScore: 60, actions: [ActionType.NOTIFY] },
        ],
      });

      const actions = await resolver.resolve(createContext(25));
      const types = actions.map(a => a.type);
      
      expect(types).toContain(ActionType.LOG);
      expect(types).not.toContain(ActionType.BLOCK);
    });
  });

  describe('Action data', () => {
    it('should include score and level info in log', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(50, 2));

      const logAction = actions.find(a => a.type === ActionType.LOG);
      expect(logAction?.data?.score).toBe(50);
      expect(logAction?.data?.detections).toBe(2);
      expect(logAction?.data?.matchedLevel).toBeDefined();
    });

    it('should include level in block reason', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(80));

      const blockAction = actions.find(a => a.type === ActionType.BLOCK);
      expect(blockAction?.data?.reason).toContain('level');
    });
  });

  describe('Custom action types', () => {
    it('should support custom action types', async () => {
      const resolver = new MultiLevelResolver({
        levels: [
          { maxScore: 50, actions: [ActionType.LOG] },
          { maxScore: 100, actions: ['escalate', ActionType.BLOCK] },
        ],
      });

      const actions = await resolver.resolve(createContext(70));
      const types = actions.map(a => a.type);
      
      // Custom 'escalate' won't be converted to Action, but BLOCK will
      expect(types).toContain(ActionType.BLOCK);
    });
  });

  describe('Edge cases', () => {
    it('should handle score exactly at threshold', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      
      // Score 30 should be level 1 (maxScore 30)
      const actions30 = await resolver.resolve(createContext(30));
      expect(actions30.map(a => a.type)).not.toContain(ActionType.UPDATE_REPUTATION);

      // Score 31 should be level 2
      const actions31 = await resolver.resolve(createContext(31));
      expect(actions31.map(a => a.type)).toContain(ActionType.UPDATE_REPUTATION);
    });

    it('should handle score 0', async () => {
      const resolver = new MultiLevelResolver({ levels: standardLevels });
      const actions = await resolver.resolve(createContext(0));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.LOG);
      expect(types).toContain(ActionType.PROCEED);
    });
  });
});

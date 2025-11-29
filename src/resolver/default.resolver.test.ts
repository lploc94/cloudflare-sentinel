/**
 * Default Resolver tests
 */

import { describe, it, expect } from 'vitest';
import { DefaultResolver } from './default.resolver';
import { ActionType } from '../pipeline/types';
import { AttackType, SecuritySeverity } from '../types';
import type { ResolverContext } from '../pipeline/types';

function createContext(score: number, detections: number = 0): ResolverContext {
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

describe('DefaultResolver', () => {
  describe('Default thresholds', () => {
    it('should block when score >= 70', async () => {
      const resolver = new DefaultResolver();
      const actions = await resolver.resolve(createContext(70));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.BLOCK);
      expect(types).toContain(ActionType.NOTIFY);
    });

    it('should not block when score < 70', async () => {
      const resolver = new DefaultResolver();
      const actions = await resolver.resolve(createContext(69));

      const types = actions.map(a => a.type);
      expect(types).not.toContain(ActionType.BLOCK);
      expect(types).toContain(ActionType.PROCEED);
    });

    it('should log warning when score >= 40', async () => {
      const resolver = new DefaultResolver();
      const actions = await resolver.resolve(createContext(50));

      const logActions = actions.filter(a => a.type === ActionType.LOG);
      expect(logActions.length).toBeGreaterThanOrEqual(1);
      
      const warnLog = logActions.find(a => a.data?.level === 'warn');
      expect(warnLog).toBeDefined();
    });
  });

  describe('Custom thresholds', () => {
    it('should respect custom blockThreshold', async () => {
      const resolver = new DefaultResolver({ blockThreshold: 50 });
      
      const actions50 = await resolver.resolve(createContext(50));
      expect(actions50.map(a => a.type)).toContain(ActionType.BLOCK);

      const actions49 = await resolver.resolve(createContext(49));
      expect(actions49.map(a => a.type)).not.toContain(ActionType.BLOCK);
    });

    it('should respect custom warnThreshold', async () => {
      const resolver = new DefaultResolver({ warnThreshold: 20 });
      const actions = await resolver.resolve(createContext(25));

      const warnLog = actions.find(a => a.type === ActionType.LOG && a.data?.level === 'warn');
      expect(warnLog).toBeDefined();
    });
  });

  describe('Always log option', () => {
    it('should log when alwaysLog is true even with score 0', async () => {
      const resolver = new DefaultResolver({ alwaysLog: true });
      const actions = await resolver.resolve(createContext(0));

      const logAction = actions.find(a => a.type === ActionType.LOG);
      expect(logAction).toBeDefined();
    });

    it('should not log score 0 when alwaysLog is false', async () => {
      const resolver = new DefaultResolver({ alwaysLog: false });
      const actions = await resolver.resolve(createContext(0));

      const logAction = actions.find(a => a.type === ActionType.LOG);
      expect(logAction).toBeUndefined();
    });
  });

  describe('Action data', () => {
    it('should include score in log data', async () => {
      const resolver = new DefaultResolver();
      const actions = await resolver.resolve(createContext(50, 2));

      // First log action contains score info
      const logActions = actions.filter(a => a.type === ActionType.LOG);
      const scoreLog = logActions.find(a => a.data?.score !== undefined);
      expect(scoreLog?.data?.score).toBe(50);
      expect(scoreLog?.data?.detections).toBe(2);
    });

    it('should include reason in block action', async () => {
      const resolver = new DefaultResolver();
      const actions = await resolver.resolve(createContext(80));

      const blockAction = actions.find(a => a.type === ActionType.BLOCK);
      expect(blockAction?.data?.reason).toContain('80');
    });
  });
});

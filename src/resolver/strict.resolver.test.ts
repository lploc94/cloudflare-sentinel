/**
 * Strict Resolver tests
 */

import { describe, it, expect } from 'vitest';
import { StrictResolver } from './strict.resolver';
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

describe('StrictResolver', () => {
  describe('Default behavior', () => {
    it('should block when score >= 50', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(50));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.BLOCK);
      expect(types).toContain(ActionType.NOTIFY);
    });

    it('should not block when score < 50 and no detections', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(40, 0));

      const types = actions.map(a => a.type);
      expect(types).not.toContain(ActionType.BLOCK);
      expect(types).toContain(ActionType.PROCEED);
    });
  });

  describe('Strict detection blocking', () => {
    it('should block when any detection exists (regardless of score)', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(10, 1));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.BLOCK);
    });

    it('should include attack types in block reason', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(10, 1));

      const blockAction = actions.find(a => a.type === ActionType.BLOCK);
      expect(blockAction?.data?.reason).toContain(AttackType.SQL_INJECTION);
    });
  });

  describe('Custom threshold', () => {
    it('should respect custom blockThreshold', async () => {
      const resolver = new StrictResolver({ blockThreshold: 30 });
      
      const actions30 = await resolver.resolve(createContext(30, 0));
      expect(actions30.map(a => a.type)).toContain(ActionType.BLOCK);

      const actions29 = await resolver.resolve(createContext(29, 0));
      expect(actions29.map(a => a.type)).not.toContain(ActionType.BLOCK);
    });
  });

  describe('Always logs', () => {
    it('should always log regardless of score', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(0, 0));

      const logAction = actions.find(a => a.type === ActionType.LOG);
      expect(logAction).toBeDefined();
    });
  });

  describe('Notification', () => {
    it('should notify on block', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(60));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.NOTIFY);
    });

    it('should include security channel in notify', async () => {
      const resolver = new StrictResolver();
      const actions = await resolver.resolve(createContext(60));

      const notifyAction = actions.find(a => a.type === ActionType.NOTIFY);
      expect(notifyAction?.data?.channel).toBe('security');
    });
  });
});

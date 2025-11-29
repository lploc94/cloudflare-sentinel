/**
 * Lenient Resolver tests
 */

import { describe, it, expect } from 'vitest';
import { LenientResolver } from './lenient.resolver';
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

describe('LenientResolver', () => {
  describe('Default behavior', () => {
    it('should only block when score >= 90', async () => {
      const resolver = new LenientResolver();
      
      const actions89 = await resolver.resolve(createContext(89));
      expect(actions89.map(a => a.type)).not.toContain(ActionType.BLOCK);

      const actions90 = await resolver.resolve(createContext(90));
      expect(actions90.map(a => a.type)).toContain(ActionType.BLOCK);
    });

    it('should proceed for most scores', async () => {
      const resolver = new LenientResolver();
      const actions = await resolver.resolve(createContext(70));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.PROCEED);
      expect(types).not.toContain(ActionType.BLOCK);
    });
  });

  describe('Custom threshold', () => {
    it('should respect custom blockThreshold', async () => {
      const resolver = new LenientResolver({ blockThreshold: 80 });
      
      const actions80 = await resolver.resolve(createContext(80));
      expect(actions80.map(a => a.type)).toContain(ActionType.BLOCK);

      const actions79 = await resolver.resolve(createContext(79));
      expect(actions79.map(a => a.type)).not.toContain(ActionType.BLOCK);
    });
  });

  describe('Logging behavior', () => {
    it('should only log when there are detections', async () => {
      const resolver = new LenientResolver();
      
      // No detections = no log
      const actionsNoDetect = await resolver.resolve(createContext(50, 0));
      const logNoDetect = actionsNoDetect.find(a => a.type === ActionType.LOG);
      expect(logNoDetect).toBeUndefined();

      // With detections = log
      const actionsWithDetect = await resolver.resolve(createContext(50, 1));
      const logWithDetect = actionsWithDetect.find(a => a.type === ActionType.LOG);
      expect(logWithDetect).toBeDefined();
    });
  });

  describe('Critical block', () => {
    it('should notify on critical block', async () => {
      const resolver = new LenientResolver();
      const actions = await resolver.resolve(createContext(95));

      const types = actions.map(a => a.type);
      expect(types).toContain(ActionType.BLOCK);
      expect(types).toContain(ActionType.NOTIFY);
    });

    it('should include critical in block reason', async () => {
      const resolver = new LenientResolver();
      const actions = await resolver.resolve(createContext(95));

      const blockAction = actions.find(a => a.type === ActionType.BLOCK);
      expect(blockAction?.data?.reason).toContain('Critical');
    });
  });
});

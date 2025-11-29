/**
 * Reputation Handler tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReputationHandler } from './reputation.handler';
import { AttackType, SecuritySeverity } from '../types';
import type { HandlerContext, Action } from '../pipeline/types';

function createMockKV(data: Record<string, any> = {}) {
  return {
    get: vi.fn(async (key: string, type?: string) => {
      const value = data[key];
      if (type === 'json' && value) {
        return typeof value === 'string' ? JSON.parse(value) : value;
      }
      return value ?? null;
    }),
    put: vi.fn(),
  } as unknown as KVNamespace;
}

function createMockContext(overrides: Partial<HandlerContext> = {}): HandlerContext {
  return {
    env: {},
    ctx: { waitUntil: vi.fn() } as unknown as ExecutionContext,
    score: {
      score: 80,
      level: 'high',
      results: [],
    },
    results: [
      {
        detected: true,
        attackType: AttackType.SQL_INJECTION,
        severity: SecuritySeverity.HIGH,
        confidence: 0.9,
        detectorName: 'sql-injection',
      },
    ],
    request: new Request('https://example.com/api/test', {
      headers: { 'cf-connecting-ip': '192.168.1.100' },
    }),
    ...overrides,
  };
}

describe('ReputationHandler', () => {
  let mockKV: KVNamespace;

  beforeEach(() => {
    vi.clearAllMocks();
    mockKV = createMockKV();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('Basic functionality', () => {
    it('should update reputation for IP', async () => {
      const handler = new ReputationHandler({ kv: mockKV });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        'reputation:192.168.1.100',
        expect.any(String),
        expect.objectContaining({ expirationTtl: 86400 })
      );
    });

    it('should use custom key prefix', async () => {
      const handler = new ReputationHandler({ kv: mockKV, keyPrefix: 'rep:' });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        'rep:192.168.1.100',
        expect.any(String),
        expect.any(Object)
      );
    });

    it('should use custom TTL', async () => {
      const handler = new ReputationHandler({ kv: mockKV, ttl: 3600 });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({ expirationTtl: 3600 })
      );
    });
  });

  describe('Delta calculation', () => {
    it('should calculate delta based on severity', async () => {
      const handler = new ReputationHandler({ kv: mockKV, useConfidence: false });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        results: [
          { detected: true, attackType: AttackType.SQL_INJECTION, severity: SecuritySeverity.HIGH, confidence: 1.0, detectorName: 'test' },
        ],
      });

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.score).toBe(-10); // HIGH = -10
    });

    it('should factor in confidence', async () => {
      const handler = new ReputationHandler({ kv: mockKV, useConfidence: true });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        results: [
          { detected: true, attackType: AttackType.SQL_INJECTION, severity: SecuritySeverity.HIGH, confidence: 0.5, detectorName: 'test' },
        ],
      });

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.score).toBe(-5); // HIGH(-10) * 0.5 = -5
    });

    it('should cap delta at minDelta', async () => {
      const handler = new ReputationHandler({ kv: mockKV, minDelta: -50 });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        results: Array(10).fill({
          detected: true,
          attackType: AttackType.SQL_INJECTION,
          severity: SecuritySeverity.CRITICAL,
          confidence: 1.0,
          detectorName: 'test',
        }),
      });

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.score).toBe(-50); // 10 * -20 = -200, capped at -50
    });
  });

  describe('Skip reputation update', () => {
    it('should skip detections with skipReputationUpdate flag', async () => {
      const handler = new ReputationHandler({ kv: mockKV });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        results: [
          {
            detected: true,
            attackType: AttackType.SUSPICIOUS_PATTERN,
            severity: SecuritySeverity.CRITICAL,
            confidence: 1.0,
            detectorName: 'reputation',
            metadata: { skipReputationUpdate: true },
          },
        ],
      });

      await handler.execute(action, ctx);

      expect(mockKV.put).not.toHaveBeenCalled();
    });

    it('should only count real detections', async () => {
      const handler = new ReputationHandler({ kv: mockKV, useConfidence: false });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        results: [
          {
            detected: true,
            attackType: AttackType.SUSPICIOUS_PATTERN,
            severity: SecuritySeverity.CRITICAL,
            confidence: 1.0,
            detectorName: 'reputation',
            metadata: { skipReputationUpdate: true },
          },
          {
            detected: true,
            attackType: AttackType.SQL_INJECTION,
            severity: SecuritySeverity.HIGH,
            confidence: 1.0,
            detectorName: 'sql-injection',
          },
        ],
      });

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.score).toBe(-10); // Only HIGH detection counted
    });
  });

  describe('History tracking', () => {
    it('should keep last 10 history entries', async () => {
      const existingData = {
        score: -20,
        history: Array(9).fill({ delta: -2, reason: 'test', timestamp: Date.now() }),
        lastUpdated: Date.now(),
      };
      mockKV = createMockKV({ 'reputation:192.168.1.100': existingData });

      const handler = new ReputationHandler({ kv: mockKV });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.history).toHaveLength(10);
    });

    it('should accumulate score from existing', async () => {
      const existingData = {
        score: -20,
        history: [],
        lastUpdated: Date.now(),
      };
      mockKV = createMockKV({ 'reputation:192.168.1.100': existingData });

      const handler = new ReputationHandler({ kv: mockKV, useConfidence: false });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        results: [
          { detected: true, attackType: AttackType.SQL_INJECTION, severity: SecuritySeverity.HIGH, confidence: 1.0, detectorName: 'test' },
        ],
      });

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.score).toBe(-30); // -20 + (-10)
    });
  });

  describe('Edge cases', () => {
    it('should not update when no IP', async () => {
      const handler = new ReputationHandler({ kv: mockKV });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext({
        request: new Request('https://example.com'),
      });

      await handler.execute(action, ctx);

      expect(mockKV.put).not.toHaveBeenCalled();
    });

    it('should handle KV errors gracefully', async () => {
      (mockKV.put as any).mockRejectedValue(new Error('KV error'));
      
      const handler = new ReputationHandler({ kv: mockKV });
      const action: Action = { type: 'update_reputation' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('ReputationHandler error'),
        expect.any(Error)
      );
    });
  });
});

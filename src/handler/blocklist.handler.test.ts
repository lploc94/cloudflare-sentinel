/**
 * Blocklist Handler tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BlocklistHandler } from './blocklist.handler';
import { AttackType, SecuritySeverity } from '../types';
import type { HandlerContext, Action } from '../pipeline/types';

function createMockKV() {
  return {
    get: vi.fn(),
    put: vi.fn(),
    delete: vi.fn(),
  } as unknown as KVNamespace;
}

function createMockContext(overrides: Partial<HandlerContext> = {}): HandlerContext {
  return {
    env: {},
    ctx: { waitUntil: vi.fn() } as unknown as ExecutionContext,
    score: {
      score: 90,
      level: 'critical',
      results: [],
    },
    results: [
      {
        detected: true,
        attackType: AttackType.SQL_INJECTION,
        severity: SecuritySeverity.CRITICAL,
        confidence: 0.99,
        detectorName: 'sql-injection',
      },
    ],
    request: new Request('https://example.com/api/test', {
      headers: { 'cf-connecting-ip': '192.168.1.100' },
    }),
    ...overrides,
  };
}

describe('BlocklistHandler', () => {
  let mockKV: KVNamespace;

  beforeEach(() => {
    vi.clearAllMocks();
    mockKV = createMockKV();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('Basic blocking', () => {
    it('should block IP from request', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        'blocked:192.168.1.100',
        expect.any(String),
        expect.objectContaining({ expirationTtl: 3600 })
      );
    });

    it('should use custom key from action data', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block', data: { key: 'user:123' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        'blocked:user:123',
        expect.any(String),
        expect.any(Object)
      );
    });

    it('should use custom duration from action data', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block', data: { duration: 7200 } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({ expirationTtl: 7200 })
      );
    });

    it('should use custom reason from action data', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block', data: { reason: 'Brute force attack' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      expect(record.reason).toBe('Brute force attack');
    });
  });

  describe('Options', () => {
    it('should use custom key prefix', async () => {
      const handler = new BlocklistHandler({ kv: mockKV, keyPrefix: 'ban:' });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        'ban:192.168.1.100',
        expect.any(String),
        expect.any(Object)
      );
    });

    it('should use custom default duration', async () => {
      const handler = new BlocklistHandler({ kv: mockKV, defaultDuration: 86400 });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalledWith(
        expect.any(String),
        expect.any(String),
        expect.objectContaining({ expirationTtl: 86400 })
      );
    });
  });

  describe('Block record', () => {
    it('should include score and attack types', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const putCall = (mockKV.put as any).mock.calls[0];
      const record = JSON.parse(putCall[1]);
      
      expect(record.blocked).toBe(true);
      expect(record.score).toBe(90);
      expect(record.attackTypes).toContain(AttackType.SQL_INJECTION);
      expect(record.blockedAt).toBeDefined();
      expect(record.expiresAt).toBeDefined();
    });
  });

  describe('Skip blocklist update', () => {
    it('should skip when all detections have skipBlocklistUpdate', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        results: [
          {
            detected: true,
            attackType: AttackType.BLOCKLIST,
            severity: SecuritySeverity.CRITICAL,
            confidence: 1.0,
            detectorName: 'blocklist',
            metadata: { skipBlocklistUpdate: true },
          },
        ],
      });

      await handler.execute(action, ctx);

      expect(mockKV.put).not.toHaveBeenCalled();
    });

    it('should not skip when some detections are real attacks', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        results: [
          {
            detected: true,
            attackType: AttackType.BLOCKLIST,
            severity: SecuritySeverity.CRITICAL,
            confidence: 1.0,
            detectorName: 'blocklist',
            metadata: { skipBlocklistUpdate: true },
          },
          {
            detected: true,
            attackType: AttackType.SQL_INJECTION,
            severity: SecuritySeverity.CRITICAL,
            confidence: 0.99,
            detectorName: 'sql-injection',
          },
        ],
      });

      await handler.execute(action, ctx);

      expect(mockKV.put).toHaveBeenCalled();
    });
  });

  describe('Error handling', () => {
    it('should warn when no key to block', async () => {
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        request: new Request('https://example.com'),
      });

      await handler.execute(action, ctx);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('No key to block')
      );
      expect(mockKV.put).not.toHaveBeenCalled();
    });

    it('should handle KV errors gracefully', async () => {
      (mockKV.put as any).mockRejectedValue(new Error('KV error'));
      
      const handler = new BlocklistHandler({ kv: mockKV });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('BlocklistHandler error'),
        expect.any(Error)
      );
    });
  });
});

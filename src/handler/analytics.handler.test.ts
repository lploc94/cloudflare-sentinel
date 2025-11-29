/**
 * Analytics Handler tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { AnalyticsHandler } from './analytics.handler';
import { AttackType, SecuritySeverity } from '../types';
import type { HandlerContext, Action } from '../pipeline/types';

function createMockAnalytics() {
  return {
    writeDataPoint: vi.fn(),
  } as unknown as AnalyticsEngineDataset;
}

function createMockContext(overrides: Partial<HandlerContext> = {}): HandlerContext {
  return {
    env: {},
    ctx: { waitUntil: vi.fn() } as unknown as ExecutionContext,
    score: {
      score: 75,
      level: 'high',
      results: [],
    },
    results: [
      {
        detected: true,
        attackType: AttackType.SQL_INJECTION,
        severity: SecuritySeverity.HIGH,
        confidence: 0.95,
        detectorName: 'sql-injection',
        evidence: {
          field: 'ip',
          value: '192.168.1.100',
        },
      },
    ],
    request: new Request('https://example.com/api/test'),
    ...overrides,
  };
}

describe('AnalyticsHandler', () => {
  let mockAnalytics: AnalyticsEngineDataset;

  beforeEach(() => {
    vi.clearAllMocks();
    mockAnalytics = createMockAnalytics();
  });

  describe('Basic functionality', () => {
    it('should write datapoint to analytics', async () => {
      const handler = new AnalyticsHandler({ analytics: mockAnalytics });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockAnalytics.writeDataPoint).toHaveBeenCalledTimes(1);
    });

    it('should include correct blobs', async () => {
      const handler = new AnalyticsHandler({ analytics: mockAnalytics });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.blobs[0]).toBe('sentinel'); // source
      expect(call.blobs[1]).toBe('security'); // category
      expect(call.blobs[2]).toBe('block'); // action type
      expect(call.blobs[3]).toBe('high'); // level
      expect(call.blobs[4]).toBe('192.168.1.100'); // IP
    });

    it('should include correct doubles', async () => {
      const handler = new AnalyticsHandler({ analytics: mockAnalytics });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.doubles[0]).toBe(75); // score
      expect(call.doubles[1]).toBe(1); // detection count
      expect(call.doubles[2]).toBe(1); // event count
    });

    it('should use IP as default index', async () => {
      const handler = new AnalyticsHandler({ analytics: mockAnalytics });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.indexes[0]).toBe('192.168.1.100');
    });
  });

  describe('Custom options', () => {
    it('should use custom source', async () => {
      const handler = new AnalyticsHandler({
        analytics: mockAnalytics,
        source: 'api-gateway',
      });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.blobs[0]).toBe('api-gateway');
    });

    it('should use custom category', async () => {
      const handler = new AnalyticsHandler({
        analytics: mockAnalytics,
        category: 'waf',
      });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.blobs[1]).toBe('waf');
    });

    it('should use custom index extractor', async () => {
      const handler = new AnalyticsHandler({
        analytics: mockAnalytics,
        indexExtractor: () => 'custom-index-123',
      });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.indexes[0]).toBe('custom-index-123');
    });
  });

  describe('Evidence serialization', () => {
    it('should serialize evidence as JSON in blobs', async () => {
      const handler = new AnalyticsHandler({ analytics: mockAnalytics });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      const evidence = JSON.parse(call.blobs[5]);
      
      expect(evidence).toHaveLength(1);
      expect(evidence[0].type).toBe('sql_injection');
      expect(evidence[0].severity).toBe('high');
      expect(evidence[0].confidence).toBe(0.95);
    });
  });

  describe('Error handling', () => {
    it('should not throw on analytics error', async () => {
      const errorAnalytics = {
        writeDataPoint: vi.fn().mockImplementation(() => {
          throw new Error('Analytics error');
        }),
      } as unknown as AnalyticsEngineDataset;

      const handler = new AnalyticsHandler({ analytics: errorAnalytics });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      // Should not throw
      await expect(handler.execute(action, ctx)).resolves.toBeUndefined();
    });

    it('should handle missing analytics binding', async () => {
      const handler = new AnalyticsHandler({ analytics: null as any });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      // Should not throw
      await expect(handler.execute(action, ctx)).resolves.toBeUndefined();
    });
  });

  describe('IP extraction', () => {
    it('should use unknown if no IP found', async () => {
      const handler = new AnalyticsHandler({ analytics: mockAnalytics });
      const action: Action = { type: 'log' };
      const ctx = createMockContext({
        results: [],
        request: new Request('https://example.com'),
      });

      await handler.execute(action, ctx);

      const call = (mockAnalytics.writeDataPoint as any).mock.calls[0][0];
      expect(call.blobs[4]).toBe('unknown');
    });
  });
});

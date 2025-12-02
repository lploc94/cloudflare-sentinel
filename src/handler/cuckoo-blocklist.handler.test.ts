/**
 * Cuckoo Blocklist Handler tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  CuckooBlocklistHandler,
  sendBlockToQueue,
  sendUnblockToQueue,
  processBlocklistQueue,
  rebuildBlocklistFilter,
  getBlocklistStats,
  type BlockQueueMessage,
} from './cuckoo-blocklist.handler';
import { CuckooBlocklistDetector } from '../detector/cuckoo-blocklist.detector';
import { CuckooFilter } from '../utils/cuckoo';
import { AttackType, SecuritySeverity } from '../types';
import type { HandlerContext, Action } from '../pipeline/types';

// Mock KV Namespace
function createMockKV(data: Record<string, ArrayBuffer | string | null> = {}) {
  return {
    get: vi.fn(async (key: string, options?: any) => {
      const value = data[key];
      if (options === 'arrayBuffer' && value instanceof ArrayBuffer) {
        return value;
      }
      return value ?? null;
    }),
    put: vi.fn(),
    delete: vi.fn(),
    list: vi.fn(async () => ({ keys: [], list_complete: true })),
    getWithMetadata: vi.fn(),
  } as unknown as KVNamespace;
}

// Mock Queue
function createMockQueue() {
  return {
    send: vi.fn(),
    sendBatch: vi.fn(),
  } as unknown as Queue;
}

// Mock Cache API
function createMockCache() {
  const store = new Map<string, Response>();
  return {
    match: vi.fn(async (url: string) => store.get(url) ?? null),
    put: vi.fn(async (url: string, response: Response) => {
      store.set(url, response);
    }),
    delete: vi.fn(async (url: string) => store.delete(url)),
    _store: store,
  };
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

describe('CuckooBlocklistHandler', () => {
  let mockCache: ReturnType<typeof createMockCache>;
  let originalCaches: any;

  beforeEach(() => {
    vi.clearAllMocks();
    mockCache = createMockCache();
    
    // Mock global caches (Cloudflare Workers runtime)
    originalCaches = (globalThis as any).caches;
    (globalThis as any).caches = {
      default: mockCache,
    };

    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    (globalThis as any).caches = originalCaches;
  });

  describe('Basic blocking', () => {
    it('should add IP to pending cache', async () => {
      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockCache.put).toHaveBeenCalledWith(
        expect.stringContaining('pending/192.168.1.100'),
        expect.any(Response)
      );
    });

    it('should use custom key from action data', async () => {
      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block', data: { key: 'user:123' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockCache.put).toHaveBeenCalledWith(
        expect.stringContaining('pending/user%3A123'),
        expect.any(Response)
      );
    });

    it('should use custom duration from action data', async () => {
      const handler = new CuckooBlocklistHandler({ pendingTtl: 600 });
      const action: Action = { type: 'block', data: { duration: 3600 } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      // Check that put was called (TTL is in Cache-Control header)
      expect(mockCache.put).toHaveBeenCalled();
    });
  });

  describe('Queue integration', () => {
    it('should send message to queue when provided', async () => {
      const mockQueue = createMockQueue();
      const handler = new CuckooBlocklistHandler({ queue: mockQueue });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockQueue.send).toHaveBeenCalledWith(
        expect.objectContaining({
          key: '192.168.1.100',
          action: 'add',
          reason: expect.any(String),
          timestamp: expect.any(Number),
        })
      );
    });

    it('should not send to queue when not provided', async () => {
      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      // No queue means no send call
      expect(mockCache.put).toHaveBeenCalled();
    });

    it('should include score and attack types in queue message', async () => {
      const mockQueue = createMockQueue();
      const handler = new CuckooBlocklistHandler({ queue: mockQueue });
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(mockQueue.send).toHaveBeenCalledWith(
        expect.objectContaining({
          score: 90,
          attackTypes: [AttackType.SQL_INJECTION],
        })
      );
    });
  });

  describe('Skip blocklist update', () => {
    it('should skip when all detections have skipBlocklistUpdate', async () => {
      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        results: [
          {
            detected: true,
            attackType: AttackType.BLOCKLIST,
            severity: SecuritySeverity.CRITICAL,
            confidence: 1.0,
            detectorName: 'cuckoo-blocklist',
            metadata: { skipBlocklistUpdate: true },
          },
        ],
      });

      await handler.execute(action, ctx);

      expect(mockCache.put).not.toHaveBeenCalled();
    });

    it('should not skip when some detections are real attacks', async () => {
      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        results: [
          {
            detected: true,
            attackType: AttackType.BLOCKLIST,
            severity: SecuritySeverity.CRITICAL,
            confidence: 1.0,
            detectorName: 'cuckoo-blocklist',
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

      expect(mockCache.put).toHaveBeenCalled();
    });
  });

  describe('Error handling', () => {
    it('should warn when no key to block', async () => {
      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        request: new Request('https://example.com'),
      });

      await handler.execute(action, ctx);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('No key to block')
      );
    });

    it('should handle cache errors gracefully', async () => {
      mockCache.put = vi.fn().mockRejectedValue(new Error('Cache error'));

      const handler = new CuckooBlocklistHandler();
      const action: Action = { type: 'block' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.error).toHaveBeenCalledWith(
        expect.stringContaining('CuckooBlocklistHandler error'),
        expect.any(Error)
      );
    });
  });

  describe('Custom key extractor', () => {
    it('should use custom key extractor', async () => {
      const handler = new CuckooBlocklistHandler({
        keyExtractor: (action, ctx) => ctx.request?.headers.get('x-user-id') ?? null,
      });
      const action: Action = { type: 'block' };
      const ctx = createMockContext({
        request: new Request('https://example.com', {
          headers: { 'x-user-id': 'user-456' },
        }),
      });

      await handler.execute(action, ctx);

      expect(mockCache.put).toHaveBeenCalledWith(
        expect.stringContaining('pending/user-456'),
        expect.any(Response)
      );
    });
  });
});

describe('Queue Producer Helpers', () => {
  describe('sendBlockToQueue', () => {
    it('should send block message to queue', async () => {
      const mockQueue = createMockQueue();

      await sendBlockToQueue(mockQueue, '1.2.3.4', 'Spam detected');

      expect(mockQueue.send).toHaveBeenCalledWith(
        expect.objectContaining({
          key: '1.2.3.4',
          action: 'add',
          reason: 'Spam detected',
          timestamp: expect.any(Number),
        })
      );
    });

    it('should include optional fields', async () => {
      const mockQueue = createMockQueue();

      await sendBlockToQueue(mockQueue, '1.2.3.4', 'Attack', {
        score: 95,
        attackTypes: ['sql_injection'],
        expiresAt: 1700000000,
      });

      expect(mockQueue.send).toHaveBeenCalledWith(
        expect.objectContaining({
          score: 95,
          attackTypes: ['sql_injection'],
          expiresAt: 1700000000,
        })
      );
    });
  });

  describe('sendUnblockToQueue', () => {
    it('should send unblock message to queue', async () => {
      const mockQueue = createMockQueue();

      await sendUnblockToQueue(mockQueue, '1.2.3.4');

      expect(mockQueue.send).toHaveBeenCalledWith(
        expect.objectContaining({
          key: '1.2.3.4',
          action: 'remove',
          timestamp: expect.any(Number),
        })
      );
    });
  });
});

describe('Queue Consumer Helper', () => {
  describe('processBlocklistQueue', () => {
    it('should add keys to filter and KV', async () => {
      const mockKV = createMockKV();
      const mockBatch = {
        messages: [
          { body: { key: '1.2.3.4', action: 'add', reason: 'Spam' }, ack: vi.fn(), retry: vi.fn() },
          { body: { key: '5.6.7.8', action: 'add' }, ack: vi.fn(), retry: vi.fn() },
        ],
      } as unknown as MessageBatch<BlockQueueMessage>;

      const result = await processBlocklistQueue(mockBatch, mockKV);

      expect(result.processed).toBe(2);
      expect(result.errors).toBe(0);
      // Filter should be saved
      expect(mockKV.put).toHaveBeenCalledWith('filter_snapshot', expect.any(Uint8Array));
      // KV entries should be created (source of truth)
      expect(mockKV.put).toHaveBeenCalledWith(
        'blocked:1.2.3.4',
        expect.stringContaining('Spam'),
        expect.objectContaining({ expirationTtl: expect.any(Number) })
      );
      expect(mockKV.put).toHaveBeenCalledWith(
        'blocked:5.6.7.8',
        expect.any(String),
        expect.any(Object)
      );
    });

    it('should remove keys from filter and KV', async () => {
      // Create filter with existing key
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const mockKV = createMockKV({
        'filter_snapshot': filterBuffer.buffer as ArrayBuffer,
      });

      const mockBatch = {
        messages: [
          { body: { key: '1.2.3.4', action: 'remove' }, ack: vi.fn(), retry: vi.fn() },
        ],
      } as unknown as MessageBatch<BlockQueueMessage>;

      const result = await processBlocklistQueue(mockBatch, mockKV);

      expect(result.processed).toBe(1);
      // Filter should be updated
      expect(mockKV.put).toHaveBeenCalledWith('filter_snapshot', expect.any(Uint8Array));
      // KV entry should be deleted
      expect(mockKV.delete).toHaveBeenCalledWith('blocked:1.2.3.4');
    });

    it('should use expiresAt for TTL calculation', async () => {
      const mockKV = createMockKV();
      const futureTime = Date.now() + 7200000; // 2 hours from now
      const mockBatch = {
        messages: [
          { body: { key: '1.2.3.4', action: 'add', expiresAt: futureTime }, ack: vi.fn(), retry: vi.fn() },
        ],
      } as unknown as MessageBatch<BlockQueueMessage>;

      await processBlocklistQueue(mockBatch, mockKV);

      expect(mockKV.put).toHaveBeenCalledWith(
        'blocked:1.2.3.4',
        expect.any(String),
        expect.objectContaining({ expirationTtl: expect.any(Number) })
      );
      // TTL should be approximately 7200 seconds
      const putCall = (mockKV.put as any).mock.calls.find((c: any[]) => c[0] === 'blocked:1.2.3.4');
      expect(putCall[2].expirationTtl).toBeGreaterThan(7100);
      expect(putCall[2].expirationTtl).toBeLessThanOrEqual(7200);
    });

    it('should ack processed messages', async () => {
      const mockKV = createMockKV();
      const ackFn = vi.fn();
      const mockBatch = {
        messages: [
          { body: { key: '1.2.3.4', action: 'add' }, ack: ackFn, retry: vi.fn() },
        ],
      } as unknown as MessageBatch<BlockQueueMessage>;

      await processBlocklistQueue(mockBatch, mockKV);

      expect(ackFn).toHaveBeenCalled();
    });

    it('should retry failed messages', async () => {
      const mockKV = createMockKV();
      const retryFn = vi.fn();
      const mockBatch = {
        messages: [
          {
            body: null, // Invalid message
            ack: vi.fn(),
            retry: retryFn,
          },
        ],
      } as unknown as MessageBatch<BlockQueueMessage>;

      const result = await processBlocklistQueue(mockBatch, mockKV);

      expect(result.errors).toBe(1);
      expect(retryFn).toHaveBeenCalled();
    });

    it('should use custom blocklist prefix', async () => {
      const mockKV = createMockKV();
      const mockBatch = {
        messages: [
          { body: { key: '1.2.3.4', action: 'add' }, ack: vi.fn(), retry: vi.fn() },
        ],
      } as unknown as MessageBatch<BlockQueueMessage>;

      await processBlocklistQueue(mockBatch, mockKV, { blocklistKeyPrefix: 'ban:' });

      expect(mockKV.put).toHaveBeenCalledWith(
        'ban:1.2.3.4',
        expect.any(String),
        expect.any(Object)
      );
    });
  });
});

describe('Cron Rebuild Helper', () => {
  describe('rebuildBlocklistFilter', () => {
    beforeEach(() => {
      vi.spyOn(console, 'log').mockImplementation(() => {});
      vi.spyOn(console, 'warn').mockImplementation(() => {});
      vi.spyOn(console, 'error').mockImplementation(() => {});
    });

    it('should rebuild filter from KV blocklist', async () => {
      const mockKV = {
        get: vi.fn(async () => null),
        put: vi.fn(),
        list: vi.fn(async () => ({
          keys: [
            { name: 'blocked:1.2.3.4' },
            { name: 'blocked:5.6.7.8' },
          ],
          list_complete: true,
        })),
      } as unknown as KVNamespace;

      const result = await rebuildBlocklistFilter(mockKV);

      expect(result.success).toBe(true);
      expect(result.itemCount).toBe(2);
      expect(result.filterSize).toBeGreaterThan(0);
      expect(mockKV.put).toHaveBeenCalledWith('filter_snapshot', expect.any(Uint8Array));
      expect(mockKV.put).toHaveBeenCalledWith('filter_version', expect.stringContaining('rebuild-'));
    });

    it('should skip expired entries', async () => {
      const mockKV = {
        get: vi.fn(async () => null),
        put: vi.fn(),
        list: vi.fn(async () => ({
          keys: [
            { name: 'blocked:1.2.3.4' },
            { name: 'blocked:5.6.7.8', expiration: 1 }, // Expired (timestamp in past)
          ],
          list_complete: true,
        })),
      } as unknown as KVNamespace;

      const result = await rebuildBlocklistFilter(mockKV);

      expect(result.itemCount).toBe(1); // Only non-expired
    });

    it('should use custom prefix', async () => {
      const mockKV = {
        get: vi.fn(async () => null),
        put: vi.fn(),
        list: vi.fn(async () => ({
          keys: [{ name: 'ban:1.2.3.4' }],
          list_complete: true,
        })),
      } as unknown as KVNamespace;

      const result = await rebuildBlocklistFilter(mockKV, {
        blocklistPrefix: 'ban:',
      });

      expect(result.success).toBe(true);
      expect(result.itemCount).toBe(1);
    });

    it('should handle errors gracefully', async () => {
      const mockKV = {
        list: vi.fn().mockRejectedValue(new Error('KV error')),
      } as unknown as KVNamespace;

      const result = await rebuildBlocklistFilter(mockKV);

      expect(result.success).toBe(false);
      expect(result.error).toBe('KV error');
    });
  });
});

describe('Stats Helper', () => {
  describe('getBlocklistStats', () => {
    it('should return blocklist statistics', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const mockKV = {
        get: vi.fn(async (key: string, options?: any) => {
          if (key === 'filter_snapshot' && options === 'arrayBuffer') {
            return filterBuffer.buffer;
          }
          if (key === 'filter_version') {
            return 'v1.0';
          }
          return null;
        }),
        list: vi.fn(async () => ({
          keys: [
            { name: 'blocked:1.2.3.4' },
            { name: 'blocked:5.6.7.8' },
          ],
          list_complete: true,
        })),
      } as unknown as KVNamespace;

      const stats = await getBlocklistStats(mockKV);

      expect(stats.totalBlocked).toBe(2);
      expect(stats.filterVersion).toBe('v1.0');
      expect(stats.filterSize).toBeGreaterThan(0);
      expect(stats.filterCapacity).toBe(1000);
      expect(stats.filterUtilization).toBeGreaterThan(0);
    });

    it('should handle missing filter', async () => {
      const mockKV = {
        get: vi.fn(async () => null),
        list: vi.fn(async () => ({
          keys: [],
          list_complete: true,
        })),
      } as unknown as KVNamespace;

      const stats = await getBlocklistStats(mockKV);

      expect(stats.totalBlocked).toBe(0);
      expect(stats.filterSize).toBe(0);
      expect(stats.filterVersion).toBeNull();
    });
  });
});

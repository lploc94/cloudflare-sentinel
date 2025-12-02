/**
 * Cuckoo Blocklist Detector Tests
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { CuckooBlocklistDetector } from './cuckoo-blocklist.detector';
import { CuckooFilter } from '../utils/cuckoo';
import { AttackType, SecuritySeverity } from '../types';

// Mock KV Namespace
const createMockKV = (data: Record<string, ArrayBuffer | string | null> = {}): KVNamespace => ({
  get: vi.fn(async (key: string, options?: any) => {
    const value = data[key];
    if (options === 'arrayBuffer' && value instanceof ArrayBuffer) {
      return value;
    }
    return value ?? null;
  }),
  put: vi.fn(),
  delete: vi.fn(),
  list: vi.fn(),
  getWithMetadata: vi.fn(),
} as unknown as KVNamespace);

// Mock Cache API
const createMockCache = () => {
  const store = new Map<string, Response>();
  return {
    match: vi.fn(async (url: string) => store.get(url) ?? null),
    put: vi.fn(async (url: string, response: Response) => {
      store.set(url, response);
    }),
    delete: vi.fn(async (url: string) => store.delete(url)),
    _store: store,
  };
};

describe('CuckooBlocklistDetector', () => {
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

  describe('Pending cache blocking', () => {
    it('should detect IP in pending cache with KV verification', async () => {
      const kv = createMockKV({
        'blocked:1.2.3.4': 'blocked', // KV confirms block
      });
      const detector = new CuckooBlocklistDetector({ kv, verifyWithKV: true });

      // Add to pending cache
      await CuckooBlocklistDetector.addToPending('1.2.3.4', 300);

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.BLOCKLIST);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('Pending block (verified)');
    });

    it('should allow IP when pending exists but KV says unblocked', async () => {
      const kv = createMockKV(); // No KV entry = unblocked
      const detector = new CuckooBlocklistDetector({ kv, verifyWithKV: true });

      // Add to pending cache (stale)
      await CuckooBlocklistDetector.addToPending('1.2.3.4', 300);

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      // Should be allowed because KV says not blocked
      expect(result).toBeNull();
      // Stale pending cache should be deleted
      expect(mockCache.delete).toHaveBeenCalledWith(
        expect.stringContaining('pending/1.2.3.4')
      );
    });

    it('should block immediately without KV check when verifyWithKV is false', async () => {
      const kv = createMockKV(); // No KV entry
      const detector = new CuckooBlocklistDetector({ kv, verifyWithKV: false });

      await CuckooBlocklistDetector.addToPending('1.2.3.4', 300);

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('Pending block (immediate)');
    });

    it('should allow IP not in pending cache', async () => {
      const kv = createMockKV();
      const detector = new CuckooBlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '5.6.7.8' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Filter-based blocking', () => {
    it('should detect IP in filter with KV verification', async () => {
      // Create filter with blocked IP
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const kv = createMockKV({
        'filter_snapshot': filterBuffer.buffer as ArrayBuffer,
        'blocked:1.2.3.4': 'blocked',
      });

      const detector = new CuckooBlocklistDetector({ kv, verifyWithKV: true });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('Blocklisted (verified)');
    });

    it('should allow IP when filter says blocked but KV says no (false positive)', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const kv = createMockKV({
        'filter_snapshot': filterBuffer.buffer as ArrayBuffer,
        // No 'blocked:1.2.3.4' key - simulating false positive
      });

      const detector = new CuckooBlocklistDetector({ kv, verifyWithKV: true });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull(); // False positive filtered out
    });

    it('should block without KV verification when verifyWithKV is false', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const kv = createMockKV({
        'filter_snapshot': filterBuffer.buffer as ArrayBuffer,
      });

      const detector = new CuckooBlocklistDetector({ kv, verifyWithKV: false });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('Blocklisted');
    });

    it('should allow IP not in filter', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const kv = createMockKV({
        'filter_snapshot': filterBuffer.buffer as ArrayBuffer,
      });

      const detector = new CuckooBlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '5.6.7.8' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Custom key extractor', () => {
    it('should use custom key extractor', async () => {
      const kv = createMockKV({
        'blocked:user-123': 'blocked', // KV confirms block
      });
      const detector = new CuckooBlocklistDetector({
        kv,
        keyExtractor: (req) => req.headers.get('x-user-id'),
      });

      // Add user to pending cache
      await CuckooBlocklistDetector.addToPending('user-123');

      const request = new Request('https://example.com', {
        headers: { 'x-user-id': 'user-123' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.value).toBe('user-123');
    });

    it('should return null if key extractor returns null', async () => {
      const kv = createMockKV();
      const detector = new CuckooBlocklistDetector({
        kv,
        keyExtractor: (req) => req.headers.get('x-user-id'),
      });

      const request = new Request('https://example.com');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      const kv = createMockKV();
      const detector = new CuckooBlocklistDetector({ kv });

      expect(detector.name).toBe('cuckoo-blocklist');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(100);
    });

    it('should use custom filter snapshot key', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      filter.add('1.2.3.4');
      const filterBuffer = filter.toBuffer();

      const kv = createMockKV({
        'custom_filter': filterBuffer.buffer as ArrayBuffer,
        'custom:1.2.3.4': 'blocked',
      });

      const detector = new CuckooBlocklistDetector({
        kv,
        filterSnapshotKey: 'custom_filter',
        blocklistKeyPrefix: 'custom:',
      });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Static helper methods', () => {
    it('should add to pending cache', async () => {
      await CuckooBlocklistDetector.addToPending('test-key', 600);

      expect(mockCache.put).toHaveBeenCalledWith(
        expect.stringContaining('pending/test-key'),
        expect.any(Response)
      );
    });

    it('should remove from pending cache', async () => {
      await CuckooBlocklistDetector.addToPending('test-key');
      const removed = await CuckooBlocklistDetector.removeFromPending('test-key');

      expect(mockCache.delete).toHaveBeenCalledWith(
        expect.stringContaining('pending/test-key')
      );
    });

    it('should check if in pending cache', async () => {
      await CuckooBlocklistDetector.addToPending('test-key');
      
      const inPending = await CuckooBlocklistDetector.isInPending('test-key');

      expect(inPending).toBe(true);
    });

    it('should invalidate filter cache', async () => {
      await CuckooBlocklistDetector.invalidateFilterCache();

      expect(mockCache.delete).toHaveBeenCalledWith(
        expect.stringContaining('filter/v1')
      );
    });

    it('should expose cache keys', () => {
      const keys = CuckooBlocklistDetector.cacheKeys;

      expect(keys.FILTER_KEY).toContain('filter');
      expect(keys.VERSION_KEY).toContain('version');
      expect(keys.PENDING_PREFIX).toContain('pending');
    });
  });

  describe('Cache behavior', () => {
    it('should cache filter from KV', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      const filterBuffer = filter.toBuffer();

      const kv = createMockKV({
        'filter_snapshot': filterBuffer.buffer as ArrayBuffer,
      });

      const detector = new CuckooBlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '5.6.7.8' },
      });

      // First request - load from KV
      await detector.detectRequest(request, {});
      
      expect(kv.get).toHaveBeenCalledWith('filter_snapshot', 'arrayBuffer');
      expect(mockCache.put).toHaveBeenCalled();
    });

    it('should use cached filter on subsequent requests', async () => {
      const filter = new CuckooFilter({ capacity: 1000 });
      const filterBuffer = filter.toBuffer();

      // Pre-cache the filter
      const cacheKey = 'https://sentinel.internal/blocklist/filter/v1';
      mockCache._store.set(cacheKey, new Response(filterBuffer));

      const kv = createMockKV();
      const detector = new CuckooBlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '5.6.7.8' },
      });

      await detector.detectRequest(request, {});

      // Should not call KV since filter is cached
      expect(kv.get).not.toHaveBeenCalledWith('filter_snapshot', 'arrayBuffer');
    });
  });

  describe('Error handling', () => {
    it('should fail-open when no filter exists', async () => {
      const kv = createMockKV();
      const detector = new CuckooBlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should fail-open on cache errors', async () => {
      mockCache.match = vi.fn().mockRejectedValue(new Error('Cache error'));

      const kv = createMockKV();
      const detector = new CuckooBlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
      expect(console.error).toHaveBeenCalled();
    });
  });

  describe('Skip blocklist update metadata', () => {
    it('should include skipBlocklistUpdate in result metadata', async () => {
      const kv = createMockKV({
        'blocked:1.2.3.4': 'blocked', // KV confirms block
      });
      const detector = new CuckooBlocklistDetector({ kv });

      await CuckooBlocklistDetector.addToPending('1.2.3.4');

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result?.metadata?.skipBlocklistUpdate).toBe(true);
    });
  });
});

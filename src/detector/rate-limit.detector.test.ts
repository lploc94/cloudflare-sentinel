/**
 * Rate Limit Detector Tests
 * 
 * Tests both modes:
 * - Cloudflare Rate Limiting API
 * - KV-based rate limiting
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { RateLimitDetector, type RateLimiter } from './rate-limit.detector';
import { AttackType, SecuritySeverity } from '../types';

/**
 * Smart RateLimiter Mock
 * Simulates Cloudflare Rate Limiting API behavior
 */
const createMockRateLimiter = (config: { limit: number; windowMs?: number } = { limit: 5 }): RateLimiter & { _reset: () => void; _getCount: (key: string) => number } => {
  const counters = new Map<string, { count: number; resetAt: number }>();
  const windowMs = config.windowMs ?? 60000;

  return {
    limit: vi.fn(async ({ key }: { key: string }) => {
      const now = Date.now();
      const entry = counters.get(key);

      // Check if window expired
      if (entry && entry.resetAt <= now) {
        counters.delete(key);
      }

      const current = counters.get(key);
      if (!current) {
        counters.set(key, { count: 1, resetAt: now + windowMs });
        return { success: true };
      }

      current.count++;
      if (current.count > config.limit) {
        return { success: false };
      }

      return { success: true };
    }),
    // Test helpers
    _reset: () => counters.clear(),
    _getCount: (key: string) => counters.get(key)?.count ?? 0,
  };
};

/**
 * Smart KV Mock with counter simulation
 */
const createSmartKV = (initialData: Record<string, string> = {}) => {
  const store = new Map<string, string>(Object.entries(initialData));

  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string) => store.set(key, value)),
    delete: vi.fn(async (key: string) => store.delete(key)),
    list: vi.fn(),
    getWithMetadata: vi.fn(),
    // Test helpers
    _store: store,
    _clear: () => store.clear(),
    _set: (key: string, value: string) => store.set(key, value),
  } as unknown as KVNamespace & { 
    _store: Map<string, string>; 
    _clear: () => void;
    _set: (key: string, value: string) => void;
  };
};

// Helper to create request with IP
const createRequest = (ip: string, url = 'https://example.com/api') =>
  new Request(url, { headers: { 'cf-connecting-ip': ip } });

describe('RateLimitDetector', () => {
  describe('Cloudflare Mode', () => {
    let rateLimiter: ReturnType<typeof createMockRateLimiter>;

    beforeEach(() => {
      rateLimiter = createMockRateLimiter({ limit: 3 });
    });

    it('should allow requests within limit', async () => {
      const detector = new RateLimitDetector({ rateLimiter });
      const request = createRequest('1.2.3.4');

      // First 3 requests should be allowed (limit=3)
      for (let i = 0; i < 3; i++) {
        const result = await detector.detectRequest(request, {});
        expect(result).toBeNull();
      }
    });

    it('should detect rate limit violation', async () => {
      const detector = new RateLimitDetector({ rateLimiter });
      const request = createRequest('1.2.3.4');

      // Exhaust limit
      for (let i = 0; i < 3; i++) {
        await detector.detectRequest(request, {});
      }

      // 4th request should be blocked
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.RATE_LIMIT_VIOLATION);
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
      expect(result?.confidence).toBe(1.0);
      expect(result?.metadata?.mode).toBe('cloudflare');
    });

    it('should track IPs separately', async () => {
      const detector = new RateLimitDetector({ rateLimiter });

      // IP1 exhausts limit
      for (let i = 0; i < 4; i++) {
        await detector.detectRequest(createRequest('1.1.1.1'), {});
      }

      // IP2 should still be allowed
      const result = await detector.detectRequest(createRequest('2.2.2.2'), {});
      expect(result).toBeNull();
    });

    it('should use custom key extractor', async () => {
      const detector = new RateLimitDetector({
        rateLimiter,
        keyExtractor: (req) => req.headers.get('x-user-id'),
      });

      const request = new Request('https://example.com', {
        headers: { 'x-user-id': 'user-123' },
      });

      await detector.detectRequest(request, {});

      expect(rateLimiter.limit).toHaveBeenCalledWith({ key: 'rl:user-123' });
    });

    it('should use custom key prefix', async () => {
      const detector = new RateLimitDetector({
        rateLimiter,
        keyPrefix: 'api-limit',
      });

      await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(rateLimiter.limit).toHaveBeenCalledWith({ key: 'api-limit:1.2.3.4' });
    });

    it('should return null if no key available', async () => {
      const detector = new RateLimitDetector({
        rateLimiter,
        keyExtractor: (req) => req.headers.get('x-missing'),
      });

      const request = new Request('https://example.com');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
      expect(rateLimiter.limit).not.toHaveBeenCalled();
    });
  });

  describe('KV Mode', () => {
    let kv: ReturnType<typeof createSmartKV>;

    beforeEach(() => {
      kv = createSmartKV();
    });

    it('should allow requests within limit', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 5,
        windowSeconds: 60,
      });

      const request = createRequest('1.2.3.4');

      // First 5 requests should be allowed
      for (let i = 0; i < 5; i++) {
        const result = await detector.detectRequest(request, {});
        expect(result).toBeNull();
      }
    });

    it('should detect rate limit violation', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 3,
        windowSeconds: 60,
      });

      const request = createRequest('1.2.3.4');

      // Exhaust limit
      for (let i = 0; i < 3; i++) {
        await detector.detectRequest(request, {});
      }

      // 4th request should be blocked
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.RATE_LIMIT_VIOLATION);
      expect(result?.metadata?.mode).toBe('kv');
      expect(result?.metadata?.count).toBe(3);
      expect(result?.metadata?.limit).toBe(3);
    });

    it('should include count in evidence', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 2,
        windowSeconds: 60,
      });

      const request = createRequest('1.2.3.4');

      // Exhaust limit
      await detector.detectRequest(request, {});
      await detector.detectRequest(request, {});

      const result = await detector.detectRequest(request, {});

      expect(result?.evidence?.value).toBe('2/2');
      expect(result?.evidence?.rawContent).toContain('2/2');
    });

    it('should track IPs separately', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 2,
        windowSeconds: 60,
      });

      // IP1 exhausts limit
      await detector.detectRequest(createRequest('1.1.1.1'), {});
      await detector.detectRequest(createRequest('1.1.1.1'), {});
      const blocked = await detector.detectRequest(createRequest('1.1.1.1'), {});

      // IP2 should still be allowed
      const allowed = await detector.detectRequest(createRequest('2.2.2.2'), {});

      expect(blocked).not.toBeNull();
      expect(allowed).toBeNull();
    });

    it('should use custom key extractor', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 10,
        windowSeconds: 60,
        keyExtractor: (req) => req.headers.get('x-api-key'),
      });

      const request = new Request('https://example.com', {
        headers: { 'x-api-key': 'key-abc' },
      });

      await detector.detectRequest(request, {});

      expect(kv.get).toHaveBeenCalledWith('rl:key-abc');
    });

    it('should use custom key prefix', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 10,
        windowSeconds: 60,
        keyPrefix: 'hourly',
      });

      await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(kv.get).toHaveBeenCalledWith('hourly:1.2.3.4');
    });

    it('should set expiration TTL on put', async () => {
      const detector = new RateLimitDetector({
        kv,
        limit: 100,
        windowSeconds: 3600, // 1 hour
      });

      await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(kv.put).toHaveBeenCalledWith(
        'rl:1.2.3.4',
        '1',
        { expirationTtl: 3600 }
      );
    });

    it('should handle pre-existing counter', async () => {
      // Pre-set counter to 4
      kv._set('rl:1.2.3.4', '4');

      const detector = new RateLimitDetector({
        kv,
        limit: 5,
        windowSeconds: 60,
      });

      const request = createRequest('1.2.3.4');

      // Should allow one more (count becomes 5)
      const result1 = await detector.detectRequest(request, {});
      expect(result1).toBeNull();

      // Should block (count is 5, >= limit)
      const result2 = await detector.detectRequest(request, {});
      expect(result2).not.toBeNull();
    });
  });

  describe('Mode detection', () => {
    it('should detect cloudflare mode when rateLimiter provided', async () => {
      const rateLimiter = createMockRateLimiter({ limit: 10 });
      const detector = new RateLimitDetector({ rateLimiter });

      // Exhaust and trigger to check mode in result
      for (let i = 0; i < 11; i++) {
        await detector.detectRequest(createRequest('1.2.3.4'), {});
      }
      const result = await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(result?.metadata?.mode).toBe('cloudflare');
    });

    it('should detect kv mode when kv provided', async () => {
      const kv = createSmartKV();
      kv._set('rl:1.2.3.4', '10'); // Pre-set at limit

      const detector = new RateLimitDetector({
        kv,
        limit: 10,
        windowSeconds: 60,
      });

      const result = await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(result?.metadata?.mode).toBe('kv');
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      const rateLimiter = createMockRateLimiter();
      const detector = new RateLimitDetector({ rateLimiter });

      expect(detector.name).toBe('rate-limit');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(95);
    });
  });

  describe('Error handling', () => {
    it('should handle cloudflare API errors gracefully', async () => {
      const rateLimiter = {
        limit: vi.fn().mockRejectedValue(new Error('API error')),
      } as unknown as RateLimiter;

      const detector = new RateLimitDetector({ rateLimiter });
      const result = await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(result).toBeNull();
    });

    it('should handle KV errors gracefully', async () => {
      const kv = {
        get: vi.fn().mockRejectedValue(new Error('KV error')),
        put: vi.fn(),
      } as unknown as KVNamespace;

      const detector = new RateLimitDetector({
        kv,
        limit: 10,
        windowSeconds: 60,
      });

      const result = await detector.detectRequest(createRequest('1.2.3.4'), {});

      expect(result).toBeNull();
    });
  });

  describe('Real-world scenarios', () => {
    it('should handle burst traffic', async () => {
      const rateLimiter = createMockRateLimiter({ limit: 10 });
      const detector = new RateLimitDetector({ rateLimiter });

      const results: (typeof detector extends { detectRequest: (...args: any[]) => Promise<infer R> } ? R : never)[] = [];

      // Simulate burst: 15 requests
      for (let i = 0; i < 15; i++) {
        const result = await detector.detectRequest(createRequest('attacker-ip'), {});
        results.push(result);
      }

      // First 10 should pass, rest should be blocked
      const passed = results.filter(r => r === null).length;
      const blocked = results.filter(r => r !== null).length;

      expect(passed).toBe(10);
      expect(blocked).toBe(5);
    });

    it('should work with multiple endpoints (different prefixes)', async () => {
      const rateLimiter = createMockRateLimiter({ limit: 2 });
      
      const apiLimiter = new RateLimitDetector({ rateLimiter, keyPrefix: 'api' });
      const authLimiter = new RateLimitDetector({ rateLimiter, keyPrefix: 'auth' });

      const request = createRequest('1.2.3.4');

      // Exhaust API limit
      await apiLimiter.detectRequest(request, {});
      await apiLimiter.detectRequest(request, {});
      const apiBlocked = await apiLimiter.detectRequest(request, {});

      // Auth should still work (different prefix)
      const authAllowed = await authLimiter.detectRequest(request, {});

      expect(apiBlocked).not.toBeNull();
      expect(authAllowed).toBeNull();
    });
  });
});

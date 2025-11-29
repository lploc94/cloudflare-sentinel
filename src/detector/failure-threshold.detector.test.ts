/**
 * Failure Threshold & Brute Force Detector Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { FailureThresholdDetector, FailureStatusPresets } from './failure-threshold.detector';
import { BruteForceDetector } from './brute-force.detector';
import { AttackType, SecuritySeverity } from '../types';

/**
 * Smart KV Mock that simulates actual KV behavior
 * - Tracks put/get calls
 * - Stores data in memory
 * - Supports expiration simulation
 */
const createSmartKV = (initialData: Record<string, string> = {}) => {
  const store = new Map<string, string>(Object.entries(initialData));

  return {
    get: vi.fn(async (key: string) => store.get(key) ?? null),
    put: vi.fn(async (key: string, value: string) => {
      store.set(key, value);
    }),
    delete: vi.fn(async (key: string) => store.delete(key)),
    list: vi.fn(),
    getWithMetadata: vi.fn(),
    // Test helpers
    _store: store,
    _clear: () => store.clear(),
  } as unknown as KVNamespace & { _store: Map<string, string>; _clear: () => void };
};

// Helper to create request with IP
const createRequest = (ip: string, url = 'https://example.com/api') =>
  new Request(url, { headers: { 'cf-connecting-ip': ip } });

// Helper to create response with status
const createResponse = (status: number) => new Response(null, { status });

describe('FailureThresholdDetector', () => {
  let kv: ReturnType<typeof createSmartKV>;

  beforeEach(() => {
    kv = createSmartKV();
  });

  describe('Basic detection', () => {
    it('should not trigger below threshold', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 5,
        failureStatuses: [401],
      });

      const request = createRequest('1.2.3.4');
      const response = createResponse(401);

      // 4 failures - below threshold
      for (let i = 0; i < 4; i++) {
        const result = await detector.detectResponse(request, response, {});
        expect(result).toBeNull();
      }
    });

    it('should trigger at threshold', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 5,
        failureStatuses: [401],
      });

      const request = createRequest('1.2.3.4');
      const response = createResponse(401);

      // 5 failures - exactly threshold
      let result;
      for (let i = 0; i < 5; i++) {
        result = await detector.detectResponse(request, response, {});
      }

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SUSPICIOUS_PATTERN);
      expect(result?.metadata?.failedAttempts).toBe(5);
    });

    it('should increment count correctly', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 3,
        failureStatuses: [401],
      });

      const request = createRequest('10.0.0.1');
      const response = createResponse(401);

      await detector.detectResponse(request, response, {});
      await detector.detectResponse(request, response, {});
      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.failedAttempts).toBe(3);
    });
  });

  describe('Status filtering', () => {
    it('should ignore non-configured statuses', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 1,
        failureStatuses: [401],
      });

      const request = createRequest('1.2.3.4');

      // 200 OK - should not count
      await detector.detectResponse(request, createResponse(200), {});
      // 404 - not in list, should not count
      await detector.detectResponse(request, createResponse(404), {});
      // 500 - not in list, should not count
      await detector.detectResponse(request, createResponse(500), {});

      expect(kv.put).not.toHaveBeenCalled();
    });

    it('should count multiple failure statuses', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 3,
        failureStatuses: [401, 403, 429],
      });

      const request = createRequest('1.2.3.4');

      await detector.detectResponse(request, createResponse(401), {});
      await detector.detectResponse(request, createResponse(403), {});
      const result = await detector.detectResponse(request, createResponse(429), {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.failedAttempts).toBe(3);
    });
  });

  describe('IP isolation', () => {
    it('should track IPs separately', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 2,
        failureStatuses: [401],
      });

      const response = createResponse(401);

      // IP1 - 2 failures (triggers)
      await detector.detectResponse(createRequest('1.1.1.1'), response, {});
      const result1 = await detector.detectResponse(createRequest('1.1.1.1'), response, {});

      // IP2 - 1 failure (no trigger)
      const result2 = await detector.detectResponse(createRequest('2.2.2.2'), response, {});

      expect(result1).not.toBeNull();
      expect(result2).toBeNull();
    });

    it('should return null if no IP header', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 1,
        failureStatuses: [401],
      });

      const request = new Request('https://example.com'); // No IP header
      const result = await detector.detectResponse(request, createResponse(401), {});

      expect(result).toBeNull();
    });
  });

  describe('Severity escalation', () => {
    it('should increase severity with count', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 2,
        failureStatuses: [401],
      });

      const request = createRequest('1.2.3.4');
      const response = createResponse(401);

      // threshold = 2
      await detector.detectResponse(request, response, {});
      let result = await detector.detectResponse(request, response, {}); // count=2, 1x threshold
      expect(result?.severity).toBe(SecuritySeverity.MEDIUM);

      // count=4, 2x threshold
      await detector.detectResponse(request, response, {});
      result = await detector.detectResponse(request, response, {});
      expect(result?.severity).toBe(SecuritySeverity.HIGH);

      // count=6, 3x threshold
      await detector.detectResponse(request, response, {});
      result = await detector.detectResponse(request, response, {});
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('Confidence calculation', () => {
    it('should use baseConfidence (default 1.0) - failure count is exact', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 2,
        failureStatuses: [401],
      });

      const request = createRequest('1.2.3.4');
      const response = createResponse(401);

      await detector.detectResponse(request, response, {});
      let result = await detector.detectResponse(request, response, {}); // count=2
      expect(result?.confidence).toBe(1.0); // default baseConfidence

      result = await detector.detectResponse(request, response, {}); // count=3
      expect(result?.confidence).toBe(1.0); // stays at baseConfidence

      result = await detector.detectResponse(request, response, {}); // count=4
      expect(result?.confidence).toBe(1.0); // stays at baseConfidence
    });

    it('should use custom baseConfidence if provided', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 2,
        baseConfidence: 0.8,
        failureStatuses: [401],
      });

      const request = createRequest('1.2.3.4');
      const response = createResponse(401);

      await detector.detectResponse(request, response, {});
      const result = await detector.detectResponse(request, response, {});

      expect(result?.confidence).toBe(0.8);
    });
  });

  describe('FailureStatusPresets', () => {
    it('should have correct AUTH preset', () => {
      expect(FailureStatusPresets.AUTH).toEqual([401, 403]);
    });

    it('should have correct RATE_LIMIT preset', () => {
      expect(FailureStatusPresets.RATE_LIMIT).toEqual([429]);
    });

    it('should work with presets', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        threshold: 1,
        failureStatuses: [...FailureStatusPresets.SERVER_ERRORS],
      });

      const request = createRequest('1.2.3.4');
      const result = await detector.detectResponse(request, createResponse(500), {});

      expect(result).not.toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      const detector = new FailureThresholdDetector({ kv });
      expect(detector.name).toBe('failure-threshold');
      expect(detector.phase).toBe('response');
    });

    it('should use custom key prefix', async () => {
      const detector = new FailureThresholdDetector({
        kv,
        keyPrefix: 'custom-prefix',
        threshold: 1,
        failureStatuses: [401],
      });

      await detector.detectResponse(createRequest('1.2.3.4'), createResponse(401), {});

      expect(kv.put).toHaveBeenCalledWith(
        'custom-prefix:1.2.3.4',
        '1',
        expect.any(Object)
      );
    });
  });
});

describe('BruteForceDetector', () => {
  let kv: ReturnType<typeof createSmartKV>;

  beforeEach(() => {
    kv = createSmartKV();
  });

  it('should detect brute force on 401', async () => {
    const detector = new BruteForceDetector({ kv, threshold: 3 });
    const request = createRequest('1.2.3.4');

    await detector.detectResponse(request, createResponse(401), {});
    await detector.detectResponse(request, createResponse(401), {});
    const result = await detector.detectResponse(request, createResponse(401), {});

    expect(result).not.toBeNull();
    expect(result?.attackType).toBe(AttackType.BRUTE_FORCE);
  });

  it('should detect brute force on 403', async () => {
    const detector = new BruteForceDetector({ kv, threshold: 2 });
    const request = createRequest('5.6.7.8');

    await detector.detectResponse(request, createResponse(403), {});
    const result = await detector.detectResponse(request, createResponse(403), {});

    expect(result).not.toBeNull();
    expect(result?.attackType).toBe(AttackType.BRUTE_FORCE);
  });

  it('should ignore non-auth statuses', async () => {
    const detector = new BruteForceDetector({ kv, threshold: 1 });
    const request = createRequest('1.2.3.4');

    // These should not trigger
    await detector.detectResponse(request, createResponse(200), {});
    await detector.detectResponse(request, createResponse(404), {});
    await detector.detectResponse(request, createResponse(500), {});

    expect(kv.put).not.toHaveBeenCalled();
  });

  it('should use brute key prefix', async () => {
    const detector = new BruteForceDetector({ kv, threshold: 1 });

    await detector.detectResponse(createRequest('1.2.3.4'), createResponse(401), {});

    expect(kv.put).toHaveBeenCalledWith(
      'brute:1.2.3.4',
      '1',
      expect.any(Object)
    );
  });

  it('should have correct name', () => {
    const detector = new BruteForceDetector({ kv });
    expect(detector.name).toBe('brute-force');
  });
});

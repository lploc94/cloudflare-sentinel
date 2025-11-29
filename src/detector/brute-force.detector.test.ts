/**
 * Brute Force Detector Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { BruteForceDetector } from './brute-force.detector';
import { AttackType } from '../types';

// Mock KV namespace
function createMockKV(data: Record<string, any> = {}) {
  return {
    get: vi.fn(async (key: string) => data[key] ?? null),
    put: vi.fn(async () => {}),
    delete: vi.fn(async () => {}),
    list: vi.fn(async () => ({ keys: [] })),
    getWithMetadata: vi.fn(async (key: string) => ({
      value: data[key] ?? null,
      metadata: null,
    })),
  } as unknown as KVNamespace;
}

function createMockRequest(
  method: string,
  url: string,
  ip: string = '192.168.1.100'
): Request {
  return new Request(url, {
    method,
    headers: new Headers({
      'cf-connecting-ip': ip,
    }),
  });
}

function createMockResponse(status: number): Response {
  return new Response(null, { status });
}

describe('BruteForceDetector', () => {
  let mockKV: KVNamespace;

  beforeEach(() => {
    vi.clearAllMocks();
    mockKV = createMockKV();
  });

  describe('Constructor', () => {
    it('should create detector with default options', () => {
      const detector = new BruteForceDetector({ kv: mockKV });
      
      expect(detector.name).toBe('brute-force');
      expect(detector.priority).toBe(85);
    });

    it('should use auth-specific failure statuses (401, 403)', async () => {
      const detector = new BruteForceDetector({ kv: mockKV });
      const request = createMockRequest('POST', 'https://api.example.com/login');
      
      // 401 should count as failure
      const response401 = createMockResponse(401);
      await detector.detectResponse(request, response401, {});
      
      // 403 should count as failure
      const response403 = createMockResponse(403);
      await detector.detectResponse(request, response403, {});
      
      // 400 should NOT count as failure (not in auth failure list)
      const response400 = createMockResponse(400);
      await detector.detectResponse(request, response400, {});
      
      // Should have called KV put for 401 and 403 only
      const putCalls = (mockKV.put as any).mock.calls;
      expect(putCalls.length).toBe(2);
    });

    it('should use custom threshold', async () => {
      const detector = new BruteForceDetector({
        kv: mockKV,
        threshold: 3,
      });
      
      const request = createMockRequest('POST', 'https://api.example.com/login');
      const response = createMockResponse(401);
      
      // First failure - no detection (count will be 1 after increment)
      (mockKV.get as any).mockResolvedValueOnce(null);
      let result = await detector.detectResponse(request, response, {});
      expect(result).toBeNull();
      
      // 2nd failure - no detection (count will be 2)
      (mockKV.get as any).mockResolvedValueOnce(1);
      result = await detector.detectResponse(request, response, {});
      expect(result).toBeNull();
      
      // 3rd failure - should detect (count reaches threshold)
      (mockKV.get as any).mockResolvedValueOnce(2);
      result = await detector.detectResponse(request, response, {});
      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.BRUTE_FORCE);
    });

    it('should use custom window seconds', () => {
      const detector = new BruteForceDetector({
        kv: mockKV,
        windowSeconds: 300, // 5 minutes
      });
      
      expect(detector).toBeDefined();
    });
  });

  describe('Detection', () => {
    it('should detect brute force after threshold failures', async () => {
      const detector = new BruteForceDetector({
        kv: mockKV,
        threshold: 5,
      });
      
      const request = createMockRequest('POST', 'https://api.example.com/login');
      const response = createMockResponse(401);
      
      // Mock KV to return 5 (threshold reached)
      (mockKV.get as any).mockResolvedValue(5);
      
      const result = await detector.detectResponse(request, response, {});
      
      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.BRUTE_FORCE);
      expect(result?.confidence).toBeGreaterThan(0);
    });

    it('should not detect on successful response', async () => {
      const detector = new BruteForceDetector({ kv: mockKV });
      const request = createMockRequest('POST', 'https://api.example.com/login');
      const response = createMockResponse(200);
      
      const result = await detector.detectResponse(request, response, {});
      
      expect(result).toBeNull();
    });

    it('should use "brute" key prefix', async () => {
      const detector = new BruteForceDetector({ kv: mockKV });
      const request = createMockRequest('POST', 'https://api.example.com/login', '10.0.0.1');
      const response = createMockResponse(401);
      
      await detector.detectResponse(request, response, {});
      
      const getCalls = (mockKV.get as any).mock.calls;
      expect(getCalls.length).toBeGreaterThan(0);
      expect(getCalls[0][0]).toContain('brute');
    });
  });

  describe('Response phase', () => {
    it('should only run on response phase', () => {
      const detector = new BruteForceDetector({ kv: mockKV });
      expect(detector.phase).toBe('response');
    });
  });
});

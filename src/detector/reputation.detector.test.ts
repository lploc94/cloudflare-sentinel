/**
 * Reputation Detector Tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { ReputationDetector } from './reputation.detector';
import { AttackType, SecuritySeverity } from '../types';

// Mock KV namespace
function createMockKV(data: Record<string, any> = {}) {
  return {
    get: vi.fn(async (key: string, type?: string) => {
      const value = data[key];
      if (type === 'json' && value) {
        return typeof value === 'string' ? JSON.parse(value) : value;
      }
      return value ?? null;
    }),
    put: vi.fn(async () => {}),
    delete: vi.fn(async () => {}),
    list: vi.fn(async () => ({ keys: [] })),
  } as unknown as KVNamespace;
}

function createMockRequest(ip: string = '192.168.1.100'): Request {
  return new Request('https://api.example.com/test', {
    method: 'GET',
    headers: new Headers({
      'cf-connecting-ip': ip,
    }),
  });
}

function createReputationData(score: number, lastUpdated?: number) {
  return {
    score,
    history: [
      { delta: -10, reason: 'Suspicious activity', timestamp: Date.now() - 3600000 },
    ],
    lastUpdated: lastUpdated ?? Date.now(),
  };
}

describe('ReputationDetector', () => {
  let mockKV: KVNamespace;

  beforeEach(() => {
    vi.clearAllMocks();
    mockKV = createMockKV();
  });

  describe('Constructor', () => {
    it('should create detector with default options', () => {
      const detector = new ReputationDetector({ kv: mockKV });
      
      expect(detector.name).toBe('reputation');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(100);
      expect(detector.enabled).toBe(true);
    });

    it('should accept custom thresholds', () => {
      const detector = new ReputationDetector({
        kv: mockKV,
        blockThreshold: -100,
        warnThreshold: -30,
      });
      
      expect(detector).toBeDefined();
    });

    it('should accept custom key prefix', () => {
      const detector = new ReputationDetector({
        kv: mockKV,
        keyPrefix: 'custom:rep:',
      });
      
      expect(detector).toBeDefined();
    });
  });

  describe('Clean IP handling', () => {
    it('should return null for IP with no reputation data', async () => {
      const detector = new ReputationDetector({ kv: mockKV });
      const request = createMockRequest('10.0.0.1');
      
      const result = await detector.detectRequest(request);
      
      expect(result).toBeNull();
    });

    it('should return null if no IP header', async () => {
      const detector = new ReputationDetector({ kv: mockKV });
      const request = new Request('https://api.example.com/test');
      
      const result = await detector.detectRequest(request);
      
      expect(result).toBeNull();
    });

    it('should return null if score decayed to 0', async () => {
      const oldTimestamp = Date.now() - (24 * 60 * 60 * 1000); // 24 hours ago
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-20, oldTimestamp),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        decayPerHour: 5, // 5 points per hour = 120 points in 24h
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result).toBeNull(); // -20 + 120 = 100, capped at 0
    });
  });

  describe('Block threshold', () => {
    it('should return CRITICAL result when score below block threshold', async () => {
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-60),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        blockThreshold: -50,
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.confidence).toBe(1.0);
      expect(result?.attackType).toBe(AttackType.SUSPICIOUS_PATTERN);
      expect(result?.metadata?.action).toBe('block');
    });

    it('should return CRITICAL result when score equals block threshold', async () => {
      mockKV = createMockKV({
        'reputation:10.0.0.1': createReputationData(-50),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        blockThreshold: -50,
      });
      const request = createMockRequest('10.0.0.1');
      
      const result = await detector.detectRequest(request);
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.action).toBe('block');
    });
  });

  describe('Warn threshold', () => {
    it('should return MEDIUM result when score below warn threshold', async () => {
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-30),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        blockThreshold: -50,
        warnThreshold: -20,
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.MEDIUM);
      expect(result?.metadata?.action).toBe('warn');
    });

    it('should return null when score above warn threshold', async () => {
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-10),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        warnThreshold: -20,
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result).toBeNull();
    });
  });

  describe('Score decay', () => {
    it('should apply decay based on time elapsed', async () => {
      const twoHoursAgo = Date.now() - (2 * 60 * 60 * 1000);
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-30, twoHoursAgo),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        warnThreshold: -20,
        decayPerHour: 5, // 5 points per hour = 10 points in 2 hours
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      // -30 + 10 = -20, which equals warn threshold
      expect(result).not.toBeNull();
      expect(result?.metadata?.effectiveScore).toBe(-20);
      expect(result?.metadata?.decayApplied).toBe(10);
    });

    it('should cap effective score at 0', async () => {
      const twentyHoursAgo = Date.now() - (20 * 60 * 60 * 1000);
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-30, twentyHoursAgo),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        decayPerHour: 5, // 5 * 20 = 100, so -30 + 100 = 70, capped at 0
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result).toBeNull(); // Score decayed above 0
    });
  });

  describe('Metadata', () => {
    it('should include all metadata fields in result', async () => {
      mockKV = createMockKV({
        'reputation:192.168.1.100': createReputationData(-60),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        blockThreshold: -50,
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result?.metadata).toHaveProperty('detector', 'reputation');
      expect(result?.metadata).toHaveProperty('storedScore', -60);
      expect(result?.metadata).toHaveProperty('effectiveScore');
      expect(result?.metadata).toHaveProperty('decayApplied');
      expect(result?.metadata).toHaveProperty('hoursElapsed');
      expect(result?.metadata).toHaveProperty('threshold');
      expect(result?.metadata).toHaveProperty('recentHistory');
      expect(result?.metadata).toHaveProperty('action');
      expect(result?.metadata).toHaveProperty('skipReputationUpdate', true);
    });

    it('should include recent history (last 3 entries)', async () => {
      const dataWithHistory = {
        score: -60,
        history: [
          { delta: -10, reason: 'Attack 1', timestamp: Date.now() - 5000 },
          { delta: -20, reason: 'Attack 2', timestamp: Date.now() - 4000 },
          { delta: -15, reason: 'Attack 3', timestamp: Date.now() - 3000 },
          { delta: -15, reason: 'Attack 4', timestamp: Date.now() - 2000 },
        ],
        lastUpdated: Date.now(),
      };
      
      mockKV = createMockKV({
        'reputation:192.168.1.100': dataWithHistory,
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        blockThreshold: -50,
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result?.metadata?.recentHistory).toHaveLength(3);
    });
  });

  describe('Error handling', () => {
    it('should return null on KV error', async () => {
      const errorKV = {
        get: vi.fn().mockRejectedValue(new Error('KV error')),
      } as unknown as KVNamespace;
      
      const detector = new ReputationDetector({ kv: errorKV });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(result).toBeNull();
    });
  });

  describe('Key prefix', () => {
    it('should use custom key prefix', async () => {
      mockKV = createMockKV({
        'custom:192.168.1.100': createReputationData(-60),
      });
      
      const detector = new ReputationDetector({
        kv: mockKV,
        keyPrefix: 'custom:',
        blockThreshold: -50,
      });
      const request = createMockRequest('192.168.1.100');
      
      const result = await detector.detectRequest(request);
      
      expect(mockKV.get).toHaveBeenCalledWith('custom:192.168.1.100', 'json');
      expect(result).not.toBeNull();
    });
  });
});

/**
 * Unit tests for BehaviorTracker
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { BehaviorTracker } from './behavior-tracker';
import { AttackType, SecuritySeverity } from '../types';

// Mock KV namespace
class MockKVNamespace {
  private store = new Map<string, string>();

  async get(key: string, type?: string): Promise<any> {
    const value = this.store.get(key);
    if (!value) return null;
    return type === 'json' ? JSON.parse(value) : value;
  }

  async put(key: string, value: string, options?: any): Promise<void> {
    this.store.set(key, value);
  }

  async delete(key: string): Promise<void> {
    this.store.delete(key);
  }

  async list(options?: any): Promise<any> {
    const prefix = options?.prefix || '';
    const keys = Array.from(this.store.keys())
      .filter(k => k.startsWith(prefix))
      .map(name => ({ name }));
    return { keys };
  }

  clear() {
    this.store.clear();
  }
}

describe('BehaviorTracker', () => {
  let kv: MockKVNamespace;
  let tracker: BehaviorTracker;

  beforeEach(() => {
    kv = new MockKVNamespace();
    tracker = new BehaviorTracker(kv as any, {
      failureThreshold: 5,
      timeWindowSeconds: 60,
      maxTrackedPaths: 20,
    });
  });

  describe('trackAndDetect', () => {
    it('should not detect with few failures', async () => {
      const result = await tracker.trackAndDetect('1.2.3.4', '/api/users/1', 404, {});

      expect(result.detected).toBe(false);
      expect(result.sequentialFailures).toBe(1);
    });

    it('should ignore success responses', async () => {
      const result = await tracker.trackAndDetect('1.2.3.4', '/api/users/1', 200, {});

      expect(result.detected).toBe(false);
      expect(result.sequentialFailures).toBe(0);
    });

    it('should detect resource enumeration with many 404s', async () => {
      const ip = '1.2.3.4';

      // Simulate sequential 404s
      for (let i = 1; i <= 6; i++) {
        await tracker.trackAndDetect(ip, `/api/users/${i}`, 404, {});
      }

      const result = await tracker.trackAndDetect(ip, '/api/users/7', 404, {});

      expect(result.detected).toBe(true);
      expect(result.attackType).toBe(AttackType.RESOURCE_ENUMERATION);
      expect(result.severity).toBe(SecuritySeverity.MEDIUM);
      expect(result.confidence).toBeGreaterThan(0.6);
    });

    it('should detect unauthorized access attempts with many 403s', async () => {
      const ip = '1.2.3.4';

      // Simulate many 403s
      for (let i = 0; i < 6; i++) {
        await tracker.trackAndDetect(ip, '/api/admin/users', 403, {});
      }

      const result = await tracker.trackAndDetect(ip, '/api/admin/settings', 403, {});

      expect(result.detected).toBe(true);
      expect(result.attackType).toBe(AttackType.UNAUTHORIZED_ACCESS_ATTEMPT);
      expect(result.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect endpoint probing on sensitive paths', async () => {
      const ip = '1.2.3.4';

      // Try various admin paths
      await tracker.trackAndDetect(ip, '/api/admin/users', 403, {});
      await tracker.trackAndDetect(ip, '/api/admin/settings', 404, {});
      await tracker.trackAndDetect(ip, '/api/private/data', 403, {});
      await tracker.trackAndDetect(ip, '/backup/files', 404, {});
      await tracker.trackAndDetect(ip, '/config/app', 404, {});
      await tracker.trackAndDetect(ip, '/api/internal/stats', 403, {});

      const result = await tracker.trackAndDetect(ip, '/admin/dashboard', 403, {});

      expect(result.detected).toBe(true);
      expect(result.attackType).toBe(AttackType.ENDPOINT_PROBING);
      expect(result.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect generic sequential failures', async () => {
      const ip = '1.2.3.4';

      // Many random errors
      for (let i = 0; i < 11; i++) {
        await tracker.trackAndDetect(ip, `/api/random/${i}`, 500, {});
      }

      const result = await tracker.trackAndDetect(ip, '/api/random/12', 500, {});

      expect(result.detected).toBe(true);
      expect(result.attackType).toBe(AttackType.SEQUENTIAL_FAILURE);
      expect(result.severity).toBe(SecuritySeverity.LOW);
    });

    it('should clean old timestamps outside window', async () => {
      const ip = '1.2.3.4';

      // Add some failures
      for (let i = 0; i < 3; i++) {
        await tracker.trackAndDetect(ip, `/api/users/${i}`, 404, {});
      }

      // Mock old timestamp by manipulating state
      const key = `behavior:${ip}:/api/users/{id}`;
      const state = await kv.get(key, 'json');
      state.timestamps = [Date.now() - 120000]; // 2 minutes ago
      await kv.put(key, JSON.stringify(state));

      // New request should reset count
      const result = await tracker.trackAndDetect(ip, '/api/users/999', 404, {});

      expect(result.sequentialFailures).toBe(1);
    });
  });

  describe('getIpStatistics', () => {
    it('should return statistics for an IP', async () => {
      const ip = '1.2.3.4';

      await tracker.trackAndDetect(ip, '/api/users/1', 404, {});
      await tracker.trackAndDetect(ip, '/api/users/2', 404, {});
      await tracker.trackAndDetect(ip, '/api/posts/1', 403, {});

      const stats = await tracker.getIpStatistics(ip);

      expect(stats.totalFailures).toBeGreaterThan(0);
      expect(Object.keys(stats.endpoints).length).toBeGreaterThan(0);
    });

    it('should return empty stats for IP with no failures', async () => {
      const stats = await tracker.getIpStatistics('5.6.7.8');

      expect(stats.totalFailures).toBe(0);
      expect(Object.keys(stats.endpoints).length).toBe(0);
    });
  });

  describe('clearIp', () => {
    it('should clear all tracking data for an IP', async () => {
      const ip = '1.2.3.4';

      await tracker.trackAndDetect(ip, '/api/users/1', 404, {});
      await tracker.trackAndDetect(ip, '/api/users/2', 404, {});

      await tracker.clearIp(ip);

      const stats = await tracker.getIpStatistics(ip);
      expect(stats.totalFailures).toBe(0);
    });
  });

  describe('endpoint normalization', () => {
    it('should normalize numeric IDs', async () => {
      const ip = '1.2.3.4';

      await tracker.trackAndDetect(ip, '/api/users/123', 404, {});
      await tracker.trackAndDetect(ip, '/api/users/456', 404, {});

      // Both should be tracked under same normalized key
      const stats = await tracker.getIpStatistics(ip);
      expect(Object.keys(stats.endpoints)).toContain('/api/users/{id}');
    });

    it('should normalize UUIDs', async () => {
      const ip = '1.2.3.4';

      await tracker.trackAndDetect(ip, '/api/items/550e8400-e29b-41d4-a716-446655440000', 404, {});
      await tracker.trackAndDetect(ip, '/api/items/6ba7b810-9dad-11d1-80b4-00c04fd430c8', 404, {});

      const stats = await tracker.getIpStatistics(ip);
      expect(Object.keys(stats.endpoints)).toContain('/api/items/{uuid}');
    });
  });

  describe('sequential ID detection', () => {
    it('should detect sequential IDs', async () => {
      const ip = '1.2.3.4';

      // Sequential IDs: 1, 2, 3, 4, 5, 6
      for (let i = 1; i <= 6; i++) {
        await tracker.trackAndDetect(ip, `/api/users/${i}`, 404, {});
      }

      const result = await tracker.trackAndDetect(ip, '/api/users/7', 404, {});

      expect(result.detected).toBe(true);
      expect(result.metadata?.pattern).toBe('sequential_ids');
    });

    it('should not detect non-sequential IDs as sequential', async () => {
      const ip = '1.2.3.4';

      // Random IDs
      const ids = [100, 999, 42, 777, 12, 555];
      for (const id of ids) {
        await tracker.trackAndDetect(ip, `/api/users/${id}`, 404, {});
      }

      const result = await tracker.trackAndDetect(ip, '/api/users/888', 404, {});

      if (result.detected && result.attackType === AttackType.RESOURCE_ENUMERATION) {
        expect(result.metadata?.pattern).toBe('random_probing');
      }
    });
  });
});

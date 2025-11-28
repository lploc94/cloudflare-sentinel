/**
 * Blocklist Detector Tests
 */

import { describe, it, expect, vi } from 'vitest';
import { BlocklistDetector } from './blocklist.detector';
import { AttackType, SecuritySeverity } from '../types';

// Mock KV Namespace
const createMockKV = (data: Record<string, string | null> = {}): KVNamespace => ({
  get: vi.fn(async (key: string) => data[key] ?? null),
  put: vi.fn(),
  delete: vi.fn(),
  list: vi.fn(),
  getWithMetadata: vi.fn(),
} as unknown as KVNamespace);

describe('BlocklistDetector', () => {
  // Default key prefix used by BlocklistDetector and BlocklistHandler
  const PREFIX = 'blocked:';

  describe('IP blocking', () => {
    it('should detect blocklisted IP', async () => {
      const kv = createMockKV({ [`${PREFIX}1.2.3.4`]: 'true' });
      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.BLOCKLIST);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.confidence).toBe(1.0);
    });

    it('should allow non-blocklisted IP', async () => {
      const kv = createMockKV({ [`${PREFIX}1.2.3.4`]: 'true' });
      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '5.6.7.8' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should include IP in evidence', async () => {
      const kv = createMockKV({ [`${PREFIX}10.0.0.1`]: 'true' });
      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '10.0.0.1' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result?.evidence?.field).toBe('ip');
      expect(result?.evidence?.value).toBe('10.0.0.1');
    });
  });

  describe('Reason parsing', () => {
    it('should parse JSON reason', async () => {
      const kv = createMockKV({
        [`${PREFIX}1.2.3.4`]: JSON.stringify({ reason: 'Spam detected', blockedAt: 1700000000 }),
      });
      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result?.metadata?.reason).toBe('Spam detected');
      expect(result?.metadata?.blockedAt).toBe(1700000000);
    });

    it('should use string value as reason', async () => {
      const kv = createMockKV({ [`${PREFIX}1.2.3.4`]: 'Abusive behavior' });
      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result?.metadata?.reason).toBe('Abusive behavior');
    });

    it('should use default reason for "true" value', async () => {
      const kv = createMockKV({ [`${PREFIX}1.2.3.4`]: 'true' });
      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result?.metadata?.reason).toBe('IP is blocklisted');
    });
  });

  describe('Custom key extractor', () => {
    it('should use custom key extractor', async () => {
      const kv = createMockKV({ [`${PREFIX}user-123`]: 'Banned user' });
      const detector = new BlocklistDetector({
        kv,
        keyExtractor: (req) => req.headers.get('x-user-id'),
      });

      const request = new Request('https://example.com', {
        headers: { 'x-user-id': 'user-123' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.value).toBe('user-123');
    });

    it('should return null if key extractor returns null', async () => {
      const kv = createMockKV({ [`${PREFIX}user-123`]: 'true' });
      const detector = new BlocklistDetector({
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
      const detector = new BlocklistDetector({ kv });

      expect(detector.name).toBe('blocklist');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(100);
    });

    it('should use cacheTtl for KV reads', async () => {
      const kv = createMockKV({ [`${PREFIX}1.2.3.4`]: 'true' });
      const detector = new BlocklistDetector({ kv, cacheTtl: 1800 });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      await detector.detectRequest(request, {});

      expect(kv.get).toHaveBeenCalledWith(`${PREFIX}1.2.3.4`, { cacheTtl: 1800 });
    });
  });

  describe('Error handling', () => {
    it('should handle KV errors gracefully', async () => {
      const kv = {
        get: vi.fn().mockRejectedValue(new Error('KV error')),
      } as unknown as KVNamespace;

      const detector = new BlocklistDetector({ kv });

      const request = new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '1.2.3.4' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });
});

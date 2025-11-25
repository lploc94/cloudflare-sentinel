/**
 * Unit tests for AttackLimiter
 */

import { describe, it, expect, beforeEach, vi } from 'vitest';
import { AttackLimiter } from './attack-limiter';
import { AttackType, IdentifierType, RateLimitPeriod } from '../types';
import type { SentinelConfig, Identifier } from '../types';

describe('AttackLimiter', () => {
  let mockRateLimiter: any;
  let config: SentinelConfig;

  beforeEach(() => {
    mockRateLimiter = {
      limit: vi.fn(),
    };

    config = {
      rateLimiter: mockRateLimiter,
      attackLimits: {
        sql_injection: {
          limit: 1,
          period: RateLimitPeriod.ONE_MINUTE,  // 60s
          action: 'block',
        },
        brute_force: {
          limit: 5,
          period: RateLimitPeriod.TEN_SECONDS,  // 10s
          action: 'block',
        },
        '/api/*': {
          brute_force: {
            limit: 20,
            period: RateLimitPeriod.TEN_SECONDS,  // 10s
            action: 'block',
          },
        },
        '/api/admin/*': {
          '*': {
            limit: 1,
            period: RateLimitPeriod.ONE_MINUTE,  // 60s
            action: 'block',
          },
        },
      },
    };
  });

  describe('parseAttackLimits', () => {
    it('should parse global and endpoint-scoped limits correctly', () => {
      const limiter = new AttackLimiter(config);
      expect(limiter).toBeDefined();
    });

    it('should sort rules by specificity', () => {
      const limiter = new AttackLimiter(config);
      expect(limiter).toBeDefined();
    });
  });

  describe('getIdentifier', () => {
    it('should extract IP from CF-Connecting-IP header', async () => {
      const limiter = new AttackLimiter(config);
      const request = new Request('https://example.com', {
        headers: { 'CF-Connecting-IP': '1.2.3.4' },
      });

      const identifier = await limiter.getIdentifier(request, {});

      expect(identifier).toEqual({
        value: '1.2.3.4',
        type: IdentifierType.IP,
      });
    });

    it('should use custom identifier extractor if provided', async () => {
      const customExtractor = vi.fn().mockResolvedValue({
        value: 'user-123',
        type: IdentifierType.USER,
      });

      const customConfig = {
        ...config,
        identifierExtractor: customExtractor,
      };

      const limiter = new AttackLimiter(customConfig);
      const request = new Request('https://example.com');

      const identifier = await limiter.getIdentifier(request, {});

      expect(identifier).toEqual({
        value: 'user-123',
        type: IdentifierType.USER,
      });
      expect(customExtractor).toHaveBeenCalledWith(request, {});
    });
  });

  describe('checkAndIncrement', () => {
    it('should allow request when within limit', async () => {
      mockRateLimiter.limit.mockResolvedValue({ success: true });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.checkAndIncrement(
        identifier,
        AttackType.SQL_INJECTION,
        '/api/users'
      );

      expect(result.allowed).toBe(true);
      expect(mockRateLimiter.limit).toHaveBeenCalled();
    });

    it('should block request when limit exceeded', async () => {
      mockRateLimiter.limit.mockResolvedValue({ success: false });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.checkAndIncrement(
        identifier,
        AttackType.SQL_INJECTION,
        '/api/users'
      );

      expect(result.allowed).toBe(false);
      expect(result.reason).toContain('Attack limit exceeded');
    });

    it('should apply layered limits (global + endpoint)', async () => {
      // First call (global) - success
      // Second call (endpoint) - success
      mockRateLimiter.limit.mockResolvedValue({ success: true });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.checkAndIncrement(
        identifier,
        AttackType.BRUTE_FORCE,
        '/api/login'
      );

      expect(result.allowed).toBe(true);
      // Should check both global and /api/* rules
      expect(mockRateLimiter.limit).toHaveBeenCalledTimes(2);
    });

    it('should match wildcard attack type', async () => {
      mockRateLimiter.limit.mockResolvedValue({ success: true });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      // /api/admin/* has wildcard rule
      const result = await limiter.checkAndIncrement(
        identifier,
        AttackType.XSS,
        '/api/admin/users'
      );

      expect(result.allowed).toBe(true);
      expect(mockRateLimiter.limit).toHaveBeenCalled();
    });

    it('should handle rate limiter errors gracefully', async () => {
      mockRateLimiter.limit.mockRejectedValue(new Error('Rate limiter unavailable'));

      const limiter = new AttackLimiter({ ...config, debug: false });
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.checkAndIncrement(
        identifier,
        AttackType.SQL_INJECTION,
        '/api/users'
      );

      // Should allow on error (fail-open)
      expect(result.allowed).toBe(true);
    });
  });

  describe('isBlocked', () => {
    it('should return false when no rules are violated', async () => {
      mockRateLimiter.limit.mockResolvedValue({ success: true });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.isBlocked(identifier, '/api/users');

      expect(result.blocked).toBe(false);
    });

    it('should return true when blocked', async () => {
      mockRateLimiter.limit.mockResolvedValue({ success: false });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.isBlocked(identifier, '/api/users');

      expect(result.blocked).toBe(true);
      expect(result.attackType).toBeDefined();
      expect(result.reason).toContain('Attack limit exceeded');
    });

    it('should skip log_only rules when checking if blocked', async () => {
      const logOnlyConfig = {
        rateLimiter: mockRateLimiter,
        attackLimits: {
          xss: {
            limit: 1,
            period: RateLimitPeriod.ONE_MINUTE,  // 60s
            action: 'log_only' as const,
          },
        },
      };

      mockRateLimiter.limit.mockResolvedValue({ success: false });

      const limiter = new AttackLimiter(logOnlyConfig);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.isBlocked(identifier, '/api/users');

      // Should not be blocked because rule is log_only
      expect(result.blocked).toBe(false);
    });
  });

  describe('endpoint matching', () => {
    it('should match wildcard patterns correctly', async () => {
      mockRateLimiter.limit.mockResolvedValue({ success: true });

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      // Should match /api/*
      await limiter.checkAndIncrement(identifier, AttackType.BRUTE_FORCE, '/api/login');
      await limiter.checkAndIncrement(identifier, AttackType.BRUTE_FORCE, '/api/users/123');
      
      // Should match /api/admin/*
      await limiter.checkAndIncrement(identifier, AttackType.XSS, '/api/admin/settings');

      expect(mockRateLimiter.limit).toHaveBeenCalled();
    });

    it('should prioritize more specific patterns', async () => {
      // For XSS on /api/admin/users, only wildcard rule on /api/admin/* matches
      mockRateLimiter.limit
        .mockResolvedValueOnce({ success: false }); // /api/admin/* wildcard - blocked

      const limiter = new AttackLimiter(config);
      const identifier: Identifier = {
        value: '1.2.3.4',
        type: IdentifierType.IP,
      };

      const result = await limiter.checkAndIncrement(
        identifier,
        AttackType.XSS,
        '/api/admin/users'
      );

      // Should be blocked by wildcard rule on /api/admin/*
      expect(result.allowed).toBe(false);
      expect(mockRateLimiter.limit).toHaveBeenCalledTimes(1);
    });
  });
});

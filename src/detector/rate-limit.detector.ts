/**
 * Rate Limit Detector - Check and track request rates
 * 
 * Supports 2 modes:
 * 1. Cloudflare Rate Limiting API (free, fixed 10s/60s windows)
 * 2. KV-based (flexible windows, KV cost ~$0.50/M reads)
 */

import { BaseDetector, type BaseDetectorOptions, type DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/**
 * Cloudflare Rate Limiter binding type
 * Add to wrangler.toml: [[unsafe.bindings]] name = "RATE_LIMITER" type = "ratelimit"
 */
export interface RateLimiter {
  limit(options: { key: string }): Promise<{ success: boolean }>;
}

/** Cloudflare Rate Limiting mode config */
export interface CloudflareRateLimitConfig extends BaseDetectorOptions {
  /** Cloudflare Rate Limiter binding */
  rateLimiter: RateLimiter;
  /** Key extractor (default: IP address) */
  keyExtractor?: (request: Request) => string | null;
  /** Key prefix for namespacing */
  keyPrefix?: string;
}

/** KV-based rate limiting config */
export interface KVRateLimitConfig extends BaseDetectorOptions {
  /** KV namespace for counters */
  kv: KVNamespace;
  /** Max requests allowed in window */
  limit: number;
  /** Time window in seconds (flexible, any value) */
  windowSeconds: number;
  /** Key extractor (default: IP address) */
  keyExtractor?: (request: Request) => string | null;
  /** Key prefix for namespacing */
  keyPrefix?: string;
}

/** Combined config - provide either rateLimiter OR kv */
export type RateLimitDetectorConfig = CloudflareRateLimitConfig | KVRateLimitConfig;

/**
 * RateLimitDetector - Detect rate limit violations
 * 
 * Two modes available:
 * - **Cloudflare**: Uses CF Rate Limiting API (free, 10s/60s windows)
 * - **KV**: Uses KV storage (flexible windows, has cost)
 * 
 * @example
 * ```typescript
 * // === CLOUDFLARE MODE (recommended - free, fast) ===
 * // 
 * // Step 1: Configure in wrangler.toml
 * // [[unsafe.bindings]]
 * // name = "RATE_LIMITER"
 * // type = "ratelimit"
 * // namespace_id = "1001"  # unique ID
 * // simple = { limit = 100, period = 60 }  # 100 req/60s
 * //
 * // Step 2: Use in code
 * new RateLimitDetector({
 *   rateLimiter: env.RATE_LIMITER,
 * })
 * 
 * // Different limits per endpoint (multiple bindings)
 * // wrangler.toml:
 * // [[unsafe.bindings]]
 * // name = "API_RATE_LIMITER"
 * // type = "ratelimit"
 * // namespace_id = "1002"
 * // simple = { limit = 1000, period = 60 }  # 1000 req/min for API
 * //
 * // [[unsafe.bindings]]
 * // name = "AUTH_RATE_LIMITER"
 * // type = "ratelimit"
 * // namespace_id = "1003"
 * // simple = { limit = 5, period = 60 }  # 5 req/min for auth
 * 
 * // With custom key (e.g., by user ID instead of IP)
 * new RateLimitDetector({
 *   rateLimiter: env.RATE_LIMITER,
 *   keyExtractor: (req) => req.headers.get('x-user-id'),
 * })
 * 
 * // === KV MODE (flexible windows, has cost) ===
 * // Use when you need custom windows (not 10s or 60s)
 * new RateLimitDetector({
 *   kv: env.RATE_LIMIT_KV,
 *   limit: 100,
 *   windowSeconds: 60,
 * })
 * 
 * // Custom window (e.g., 1000 req/hour - not possible with CF API)
 * new RateLimitDetector({
 *   kv: env.RATE_LIMIT_KV,
 *   limit: 1000,
 *   windowSeconds: 3600,  // 1 hour
 * })
 * ```
 * 
 * @remarks
 * **Cloudflare Mode:**
 * - Free (included in Workers)
 * - Fixed windows: 10s or 60s (configure in dashboard)
 * - No KV cost
 * - Recommended for most use cases
 * 
 * **KV Mode:**
 * - Flexible: any window size
 * - Cost: ~$0.50 per million reads
 * - Use when you need custom windows (e.g., 5 min, 1 hour)
 */
export class RateLimitDetector extends BaseDetector {
  name = 'rate-limit';
  phase = 'request' as const;
  priority = 95; // Check early

  private mode: 'cloudflare' | 'kv';
  private config: RateLimitDetectorConfig;

  constructor(config: RateLimitDetectorConfig) {
    super();
    this.config = config;
    this.mode = 'rateLimiter' in config ? 'cloudflare' : 'kv';
  }

  async detectRequest(
    request: Request,
    context: any
  ): Promise<DetectorResult | null> {
    const key = this.buildKey(request);
    if (!key) return null;

    try {
      if (this.mode === 'cloudflare') {
        return await this.checkCloudflare(key);
      } else {
        return await this.checkKV(key);
      }
    } catch (error) {
      console.error('[Sentinel] RateLimitDetector error:', error);
      return null;
    }
  }

  private buildKey(request: Request): string | null {
    const extractor = this.config.keyExtractor;
    const baseKey = extractor 
      ? extractor(request) 
      : request.headers.get('cf-connecting-ip');
    
    if (!baseKey) return null;
    
    const prefix = this.config.keyPrefix || 'rl';
    return `${prefix}:${baseKey}`;
  }

  /** Cloudflare Rate Limiting API mode */
  private async checkCloudflare(key: string): Promise<DetectorResult | null> {
    const config = this.config as CloudflareRateLimitConfig;
    const { success } = await config.rateLimiter.limit({ key });

    if (!success) {
      return this.createResult(
        AttackType.RATE_LIMIT_VIOLATION,
        SecuritySeverity.HIGH,
        1.0,
        { 
          field: 'rate', 
          value: key,
          rawContent: 'Rate limit exceeded (Cloudflare)',
        },
        { mode: 'cloudflare', key }
      );
    }

    return null; // Within limit
  }

  /** 
   * KV-based rate limiting mode
   * 
   * **Design Note:** This detector both checks AND increments the counter.
   * This is intentional because:
   * 1. Counter must increment for EVERY request (not just when exceeded)
   * 2. Check and increment must happen together to avoid race conditions
   * 
   * For Cloudflare API mode, the API handles this automatically.
   * For KV mode, this detector handles the full lifecycle.
   * 
   * IncrementHandler is for OTHER use cases (custom counters, not rate limiting).
   */
  private async checkKV(key: string): Promise<DetectorResult | null> {
    const config = this.config as KVRateLimitConfig;
    const { kv, limit, windowSeconds } = config;

    // Read current count
    const countStr = await kv.get(key);
    const count = countStr ? parseInt(countStr, 10) : 0;

    // Check if exceeded BEFORE incrementing
    if (count >= limit) {
      return this.createResult(
        AttackType.RATE_LIMIT_VIOLATION,
        SecuritySeverity.HIGH,
        1.0,
        { 
          field: 'rate', 
          value: `${count}/${limit}`,
          rawContent: `Rate limit exceeded: ${count}/${limit} in ${windowSeconds}s`,
        },
        { 
          mode: 'kv', 
          count, 
          limit, 
          windowSeconds,
          key,
        }
      );
    }

    // Increment counter for this request (must happen for every request)
    await kv.put(key, (count + 1).toString(), {
      expirationTtl: windowSeconds,
    });

    return null; // Within limit
  }
}

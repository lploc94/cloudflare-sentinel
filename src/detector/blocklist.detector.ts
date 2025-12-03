/**
 * Blocklist Detector - Check if IP/user is blocked
 * 
 * Supports two modes:
 * - 'direct': Direct KV read per request (simple)
 * - 'cuckoo': Pending Cache → Cuckoo Filter → KV verify (fast, cost-efficient)
 */

import { BaseDetector, type DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';
import { CuckooFilter } from '../utils/cuckoo';

// Cloudflare Workers Cache API
declare const caches: { default: Cache };

// Cache key constants
const CACHE_PREFIX = 'https://sentinel.internal';
const FILTER_KEY = `${CACHE_PREFIX}/blocklist/filter/v1`;
const PENDING_PREFIX = `${CACHE_PREFIX}/blocklist/pending/`;

// Default TTLs
const DEFAULT_FILTER_TTL = 300;   // 5 minutes
const DEFAULT_PENDING_TTL = 300;  // 5 minutes

export interface BlocklistDetectorOptions {
  /** KV namespace containing blocklist */
  kv: KVNamespace;
  
  /**
   * Mode:
   * - 'direct': Direct KV read per request (simple, ~$0.50/1M reads)
   * - 'cuckoo': Pending Cache → Cuckoo Filter → KV verify (fast, ~$0.001/1M reads)
   * 
   * Default: 'direct'
   */
  mode?: 'direct' | 'cuckoo';
  
  /** Key prefix (default: 'blocked:') - must match BlocklistHandler */
  keyPrefix?: string;
  
  /** Key extractor (default: IP address) */
  keyExtractor?: (request: Request) => string | null;
  
  /** Cache TTL in seconds for KV reads (default: 3600) */
  cacheTtl?: number;
  
  // ─── Cuckoo mode options ───────────────────────────────────────────────
  
  /** Filter snapshot key in KV (default: 'filter_snapshot') */
  filterSnapshotKey?: string;
  
  /** Filter cache TTL in seconds (default: 300) */
  filterCacheTtl?: number;
  
  /** Pending cache TTL in seconds (default: 300) */
  pendingCacheTtl?: number;
  
  /** 
   * Verify with KV when filter reports blocked (default: true)
   * - true: Check KV to eliminate false positives (~1% filter FP rate)
   * - false: Trust filter result (zero KV reads, but ~1% false positive blocks)
   */
  verifyWithKV?: boolean;
}

/**
 * BlocklistDetector - Blocks requests from blocklisted IPs/users
 * 
 * @example
 * ```typescript
 * // Simple mode - direct KV read
 * new BlocklistDetector({
 *   kv: env.BLOCKLIST_KV,
 *   mode: 'direct',
 * })
 * 
 * // Cuckoo mode - fast + cost-efficient
 * new BlocklistDetector({
 *   kv: env.BLOCKLIST_KV,
 *   mode: 'cuckoo',
 *   verifyWithKV: true,
 * })
 * 
 * // Custom key extractor (e.g., by user ID)
 * new BlocklistDetector({
 *   kv: env.BLOCKLIST_KV,
 *   keyExtractor: (req) => req.headers.get('x-user-id'),
 * })
 * ```
 */
export class BlocklistDetector extends BaseDetector {
  name = 'blocklist';
  phase = 'request' as const;
  priority = 100; // High priority - check first

  private mode: 'direct' | 'cuckoo';
  private keyPrefix: string;
  private filterSnapshotKey: string;
  private filterCacheTtl: number;
  private pendingCacheTtl: number;
  private verifyWithKV: boolean;

  constructor(private options: BlocklistDetectorOptions) {
    super();
    this.mode = options.mode ?? 'direct';
    this.keyPrefix = options.keyPrefix ?? 'blocked:';
    this.filterSnapshotKey = options.filterSnapshotKey ?? 'filter_snapshot';
    this.filterCacheTtl = options.filterCacheTtl ?? DEFAULT_FILTER_TTL;
    this.pendingCacheTtl = options.pendingCacheTtl ?? DEFAULT_PENDING_TTL;
    this.verifyWithKV = options.verifyWithKV ?? true;
  }

  async detectRequest(
    request: Request,
    context: any
  ): Promise<DetectorResult | null> {
    const rawKey = this.options.keyExtractor
      ? this.options.keyExtractor(request)
      : request.headers.get('cf-connecting-ip');

    if (!rawKey) {
      return null;
    }

    try {
      if (this.mode === 'cuckoo') {
        return await this.detectCuckooMode(rawKey);
      } else {
        return await this.detectDirectMode(rawKey);
      }
    } catch (error) {
      console.error('[Sentinel] BlocklistDetector error:', error);
      return null; // Fail-open
    }
  }

  /**
   * Direct mode: Read KV per request
   */
  private async detectDirectMode(rawKey: string): Promise<DetectorResult | null> {
    const key = `${this.keyPrefix}${rawKey}`;
    
    const blocked = await this.options.kv.get(key, {
      cacheTtl: this.options.cacheTtl ?? 3600,
    });

    if (blocked) {
      const { reason, blockedAt } = this.parseBlockRecord(blocked);
      return this.createBlockResult(rawKey, reason, blockedAt);
    }

    return null;
  }

  /**
   * Cuckoo mode: Pending Cache → Filter → KV verify
   */
  private async detectCuckooMode(rawKey: string): Promise<DetectorResult | null> {
    const cache = caches.default;

    // 1. Check Pending Cache (immediate blocks - highest priority)
    const pendingUrl = `${PENDING_PREFIX}${encodeURIComponent(rawKey)}`;
    const pendingResponse = await cache.match(pendingUrl);
    
    if (pendingResponse) {
      // Verify with KV if enabled (handles unblock case)
      if (this.verifyWithKV) {
        const kvKey = `${this.keyPrefix}${rawKey}`;
        const kvValue = await this.options.kv.get(kvKey, { cacheTtl: 3600 });
        
        if (!kvValue) {
          // Unblocked in KV - remove stale pending cache
          await cache.delete(pendingUrl);
          // Continue to filter check
        } else {
          return this.createBlockResult(rawKey, 'Pending block (verified)');
        }
      } else {
        return this.createBlockResult(rawKey, 'Pending block (immediate)');
      }
    }

    // 2. Get Cuckoo Filter from Cache or KV
    const filter = await this.getFilter(cache);
    
    if (!filter) {
      // No filter available - fall back to direct KV check
      return this.detectDirectMode(rawKey);
    }

    // 3. Check Filter
    if (filter.contains(rawKey)) {
      // Filter says blocked - may be false positive (~1%)
      
      if (this.verifyWithKV) {
        const kvKey = `${this.keyPrefix}${rawKey}`;
        const kvValue = await this.options.kv.get(kvKey, { cacheTtl: 3600 });
        
        if (kvValue) {
          const { reason, blockedAt } = this.parseBlockRecord(kvValue);
          return this.createBlockResult(rawKey, reason, blockedAt);
        }
        // Not in KV - false positive, allow
        return null;
      }
      
      // No verification - trust filter
      return this.createBlockResult(rawKey, 'Blocklisted');
    }

    return null;
  }

  /**
   * Get Cuckoo Filter from Cache API, fallback to KV
   */
  private async getFilter(cache: Cache): Promise<CuckooFilter | null> {
    // Try cache first
    const cachedResponse = await cache.match(FILTER_KEY);
    
    if (cachedResponse) {
      try {
        const buffer = await cachedResponse.arrayBuffer();
        return CuckooFilter.fromBuffer(new Uint8Array(buffer));
      } catch {
        // Cache corrupted - reload from KV
      }
    }

    // Load from KV
    const snapshot = await this.options.kv.get(this.filterSnapshotKey, 'arrayBuffer');
    
    if (!snapshot) {
      return null;
    }

    try {
      const filter = CuckooFilter.fromBuffer(new Uint8Array(snapshot));

      // Cache at edge
      await cache.put(FILTER_KEY, new Response(snapshot, {
        headers: {
          'Cache-Control': `max-age=${this.filterCacheTtl}`,
          'Content-Type': 'application/octet-stream',
        },
      }));

      return filter;
    } catch {
      return null;
    }
  }

  /**
   * Parse block record from KV value
   */
  private parseBlockRecord(value: string): { reason: string; blockedAt?: number } {
    let reason = 'IP is blocklisted';
    let blockedAt: number | undefined;

    try {
      const data = JSON.parse(value);
      reason = data.reason || reason;
      blockedAt = data.blockedAt || data.timestamp;
    } catch {
      if (value !== 'true' && value !== '1') {
        reason = value;
      }
    }

    return { reason, blockedAt };
  }

  /**
   * Create block detection result
   */
  private createBlockResult(
    rawKey: string,
    reason: string,
    blockedAt?: number
  ): DetectorResult {
    return this.createResult(
      AttackType.BLOCKLIST,
      SecuritySeverity.CRITICAL,
      1.0,
      { field: 'ip', value: rawKey },
      { 
        reason, 
        blockedAt,
        key: `${this.keyPrefix}${rawKey}`,
        skipBlocklistUpdate: true,
      }
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STATIC HELPERS (for mode='cuckoo')
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Add item to pending cache (immediate block)
   */
  static async addToPending(
    key: string,
    ttl: number = DEFAULT_PENDING_TTL
  ): Promise<void> {
    const cache = caches.default;
    const pendingUrl = `${PENDING_PREFIX}${encodeURIComponent(key)}`;
    
    await cache.put(pendingUrl, new Response('1', {
      headers: {
        'Cache-Control': `max-age=${ttl}`,
        'Content-Type': 'text/plain',
      },
    }));
  }

  /**
   * Remove item from pending cache (LOCAL ONLY)
   * 
   * ⚠️ WARNING: This only removes from the CURRENT edge cluster's cache.
   * For global unblock, use sendUnblockToQueue() from blocklist.handler.
   */
  static async removeFromPending(key: string): Promise<boolean> {
    const cache = caches.default;
    const pendingUrl = `${PENDING_PREFIX}${encodeURIComponent(key)}`;
    return cache.delete(pendingUrl);
  }

  /**
   * Check if item is in pending cache
   */
  static async isInPending(key: string): Promise<boolean> {
    const cache = caches.default;
    const pendingUrl = `${PENDING_PREFIX}${encodeURIComponent(key)}`;
    const response = await cache.match(pendingUrl);
    return !!response;
  }

  /**
   * Invalidate cached filter (force reload from KV)
   */
  static async invalidateFilterCache(): Promise<boolean> {
    const cache = caches.default;
    return cache.delete(FILTER_KEY);
  }

  /**
   * Get cache key constants
   */
  static get cacheKeys() {
    return { FILTER_KEY, PENDING_PREFIX };
  }
}

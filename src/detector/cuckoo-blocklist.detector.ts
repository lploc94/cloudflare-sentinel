/**
 * Cuckoo Blocklist Detector - Cache-based blocklist with Cuckoo Filter
 * 
 * Cost-efficient blocklist detection using:
 * - Cache API for edge-local storage (FREE, no KV reads per request)
 * - Cuckoo Filter for O(1) probabilistic lookup
 * - Pending cache for immediate blocking (before global sync)
 * 
 * Architecture:
 * 1. Check pending cache (immediate blocks) - 0ms latency
 * 2. Check Cuckoo Filter from cache - ~1ms latency
 * 3. On cache miss: load filter from KV and cache it
 * 
 * @example
 * ```typescript
 * const detector = new CuckooBlocklistDetector({
 *   kv: env.BLOCKLIST_KV,
 *   // Optional: custom key extractor
 *   keyExtractor: (req) => req.headers.get('x-user-id'),
 * });
 * 
 * pipeline.addDetector(detector);
 * ```
 */

import { BaseDetector, type DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';
import { CuckooFilter } from '../utils/cuckoo';

// Cache key constants - use internal domain to avoid collisions
const CACHE_PREFIX = 'https://sentinel.internal';
const FILTER_KEY = `${CACHE_PREFIX}/blocklist/filter/v1`;
const VERSION_KEY = `${CACHE_PREFIX}/blocklist/version`;
const PENDING_PREFIX = `${CACHE_PREFIX}/blocklist/pending/`;

// Default TTLs
const DEFAULT_FILTER_TTL = 300;   // 5 minutes
const DEFAULT_PENDING_TTL = 300;  // 5 minutes

export interface CuckooBlocklistDetectorOptions {
  /** KV namespace containing filter snapshot */
  kv: KVNamespace;
  
  /** Key extractor - extracts identifier from request (default: IP address) */
  keyExtractor?: (request: Request) => string | null;
  
  /** Filter snapshot key in KV (default: 'filter_snapshot') */
  filterSnapshotKey?: string;
  
  /** Filter version key in KV (default: 'filter_version') */
  filterVersionKey?: string;
  
  /** Filter cache TTL in seconds (default: 300) */
  filterCacheTtl?: number;
  
  /** Pending cache TTL in seconds (default: 300) */
  pendingCacheTtl?: number;
  
  /** Filter capacity - used when creating new filter (default: 100000) */
  filterCapacity?: number;
  
  /** 
   * Verify with KV when filter reports blocked (default: true)
   * - true: Check KV to eliminate false positives (~1% filter FP rate)
   * - false: Trust filter result (zero KV reads, but ~1% false positive blocks)
   */
  verifyWithKV?: boolean;
  
  /** Key prefix for blocklist entries in KV (default: 'blocked:') */
  blocklistKeyPrefix?: string;
}

/**
 * CuckooBlocklistDetector - High-performance blocklist using Cache API + Cuckoo Filter
 * 
 * Cost comparison (1M requests/month):
 * - KV-based BlocklistDetector: ~$0.50 (1M reads)
 * - CuckooBlocklistDetector: ~$0.001 (only cold start reads)
 */
export class CuckooBlocklistDetector extends BaseDetector {
  name = 'cuckoo-blocklist';
  phase = 'request' as const;
  priority = 100; // High priority - check first

  private filterSnapshotKey: string;
  private filterVersionKey: string;
  private filterCacheTtl: number;
  private pendingCacheTtl: number;
  private filterCapacity: number;
  private verifyWithKV: boolean;
  private blocklistKeyPrefix: string;

  constructor(private options: CuckooBlocklistDetectorOptions) {
    super();
    this.filterSnapshotKey = options.filterSnapshotKey ?? 'filter_snapshot';
    this.filterVersionKey = options.filterVersionKey ?? 'filter_version';
    this.filterCacheTtl = options.filterCacheTtl ?? DEFAULT_FILTER_TTL;
    this.pendingCacheTtl = options.pendingCacheTtl ?? DEFAULT_PENDING_TTL;
    this.filterCapacity = options.filterCapacity ?? 100000;
    this.verifyWithKV = options.verifyWithKV ?? true; // Default: verify to avoid false positives
    this.blocklistKeyPrefix = options.blocklistKeyPrefix ?? 'blocked:';
  }

  async detectRequest(
    request: Request,
    context: any
  ): Promise<DetectorResult | null> {
    // Extract key (IP or custom)
    const key = this.options.keyExtractor
      ? this.options.keyExtractor(request)
      : request.headers.get('cf-connecting-ip');

    if (!key) {
      return null;
    }

    try {
      const cache = caches.default;

      // 1. Check Pending Cache (immediate blocks - highest priority)
      const pendingUrl = `${PENDING_PREFIX}${encodeURIComponent(key)}`;
      const pendingResponse = await cache.match(pendingUrl);
      
      if (pendingResponse) {
        // Pending found - but verify with KV if enabled (handles unblock case)
        if (this.verifyWithKV) {
          const kvKey = `${this.blocklistKeyPrefix}${key}`;
          const kvValue = await this.options.kv.get(kvKey, {
            cacheTtl: 3600,
          });
          
          if (!kvValue) {
            // Unblocked in KV but pending cache still exists
            // Remove stale pending cache and allow
            await cache.delete(pendingUrl);
            // Continue to filter check (don't return blocked)
          } else {
            return this.createBlockResult(key, 'Pending block (verified)');
          }
        } else {
          return this.createBlockResult(key, 'Pending block (immediate)');
        }
      }

      // 2. Get Cuckoo Filter from Cache or KV
      const filter = await this.getFilter(cache);
      
      if (!filter) {
        // No filter available - allow request (fail-open)
        return null;
      }

      // 3. Check Filter
      if (filter.contains(key)) {
        // Filter says blocked - but may be false positive (~1%)
        
        if (this.verifyWithKV) {
          // Verify with KV to eliminate false positives
          const kvKey = `${this.blocklistKeyPrefix}${key}`;
          const kvValue = await this.options.kv.get(kvKey, {
            cacheTtl: 3600, // Cache KV result at edge for 1 hour
          });
          
          if (kvValue) {
            // Confirmed blocked in KV - true positive
            return this.createBlockResult(key, 'Blocklisted (verified)');
          }
          
          // Not in KV - false positive, allow request
          // Note: This could happen if:
          // 1. Filter false positive
          // 2. Block expired in KV but filter not yet rebuilt
          return null;
        }
        
        // No verification - trust filter (may have ~1% false positives)
        return this.createBlockResult(key, 'Blocklisted');
      }

      return null;
    } catch (error) {
      console.error('[Sentinel] CuckooBlocklistDetector error:', error);
      // Fail-open on error
      return null;
    }
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
      } catch (error) {
        console.error('[Sentinel] Failed to parse cached filter:', error);
        // Cache corrupted - will reload from KV
      }
    }

    // Load from KV
    const snapshot = await this.options.kv.get(this.filterSnapshotKey, 'arrayBuffer');
    
    if (!snapshot) {
      // No filter in KV - this is OK for new deployments
      return null;
    }

    try {
      const filter = CuckooFilter.fromBuffer(new Uint8Array(snapshot));

      // Cache at edge for future requests
      await cache.put(FILTER_KEY, new Response(snapshot, {
        headers: {
          'Cache-Control': `max-age=${this.filterCacheTtl}`,
          'Content-Type': 'application/octet-stream',
        },
      }));

      return filter;
    } catch (error) {
      console.error('[Sentinel] Failed to load filter from KV:', error);
      return null;
    }
  }

  /**
   * Create block detection result
   */
  private createBlockResult(key: string, reason: string): DetectorResult {
    return this.createResult(
      AttackType.BLOCKLIST,
      SecuritySeverity.CRITICAL,
      1.0,
      { field: 'ip', value: key },
      {
        reason,
        // Prevent loop - already blocked, don't re-add
        skipBlocklistUpdate: true,
      }
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STATIC HELPER METHODS (for use in handlers/workers)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Add item to pending cache (immediate block)
   * Call this when you detect an attack and want to block immediately
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
   * Cache API does not support global invalidation.
   * 
   * For global unblock, use:
   * 1. KV.delete() - Removes from source of truth
   * 2. sendUnblockToQueue() - Removes from filter
   * 3. Pending cache will expire naturally (TTL)
   * 
   * @returns true if deleted from local cache
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
   * Invalidate cached filter (force reload from KV on next request)
   */
  static async invalidateFilterCache(): Promise<boolean> {
    const cache = caches.default;
    return cache.delete(FILTER_KEY);
  }

  /**
   * Get cache key constants (for external use)
   */
  static get cacheKeys() {
    return {
      FILTER_KEY,
      VERSION_KEY,
      PENDING_PREFIX,
    };
  }
}

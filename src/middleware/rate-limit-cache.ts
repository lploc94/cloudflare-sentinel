/**
 * In-memory cache for rate limit check results
 * Reduces redundant API calls within short time windows
 */

export interface CacheEntry {
  blocked: boolean;
  timestamp: number;
  ttl: number; // milliseconds
}

export class RateLimitCache {
  private cache: Map<string, CacheEntry>;
  private defaultTTL: number;
  private maxSize: number;

  constructor(defaultTTL: number = 1000, maxSize: number = 1000) {
    this.cache = new Map();
    this.defaultTTL = defaultTTL; // 1 second default
    this.maxSize = maxSize;
  }

  /**
   * Get cached result if valid
   */
  get(key: string): boolean | null {
    const entry = this.cache.get(key);
    
    if (!entry) return null;

    const now = Date.now();
    const age = now - entry.timestamp;

    // Check if expired
    if (age > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.blocked;
  }

  /**
   * Set cache entry
   */
  set(key: string, blocked: boolean, ttl?: number): void {
    // Enforce max size (LRU-style: remove oldest)
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(key, {
      blocked,
      timestamp: Date.now(),
      ttl: ttl || this.defaultTTL,
    });
  }

  /**
   * Clear specific key
   */
  delete(key: string): void {
    this.cache.delete(key);
  }

  /**
   * Clear all cache
   */
  clear(): void {
    this.cache.clear();
  }

  /**
   * Clean expired entries
   */
  cleanup(): void {
    const now = Date.now();
    const keysToDelete: string[] = [];

    for (const [key, entry] of this.cache.entries()) {
      const age = now - entry.timestamp;
      if (age > entry.ttl) {
        keysToDelete.push(key);
      }
    }

    for (const key of keysToDelete) {
      this.cache.delete(key);
    }
  }

  /**
   * Get cache stats
   */
  getStats() {
    return {
      size: this.cache.size,
      maxSize: this.maxSize,
      utilization: (this.cache.size / this.maxSize) * 100,
    };
  }
}

/**
 * Global cache instance for rate limit results
 * Shared across requests within same Worker instance
 */
let globalCache: RateLimitCache | null = null;

export function getGlobalCache(): RateLimitCache {
  if (!globalCache) {
    globalCache = new RateLimitCache(1000, 1000);
  }
  return globalCache;
}

export function resetGlobalCache(): void {
  globalCache = null;
}

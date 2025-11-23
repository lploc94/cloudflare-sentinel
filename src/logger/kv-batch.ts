/**
 * KV Batch operations helper
 * Reduces KV calls by batching writes
 */

export interface BatchWrite {
  key: string;
  value: string;
  expirationTtl?: number;
}

export class KVBatcher {
  private kv: KVNamespace;
  private queue: BatchWrite[];
  private maxBatchSize: number;
  private flushInterval: number;
  private timer: ReturnType<typeof setTimeout> | null;

  constructor(
    kv: KVNamespace,
    maxBatchSize: number = 10,
    flushIntervalMs: number = 1000
  ) {
    this.kv = kv;
    this.queue = [];
    this.maxBatchSize = maxBatchSize;
    this.flushInterval = flushIntervalMs;
    this.timer = null;
  }

  /**
   * Add write to batch queue
   */
  async write(key: string, value: string, expirationTtl?: number): Promise<void> {
    this.queue.push({ key, value, expirationTtl });

    // Flush if batch is full
    if (this.queue.length >= this.maxBatchSize) {
      await this.flush();
      return;
    }

    // Schedule flush if not already scheduled
    if (!this.timer) {
      this.timer = setTimeout(async () => {
        await this.flush();
      }, this.flushInterval);
    }
  }

  /**
   * Flush all pending writes
   */
  async flush(): Promise<void> {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }

    if (this.queue.length === 0) return;

    const batch = this.queue.splice(0, this.queue.length);

    try {
      // Execute all writes in parallel
      await Promise.all(
        batch.map(({ key, value, expirationTtl }) =>
          this.kv.put(key, value, expirationTtl ? { expirationTtl } : undefined)
        )
      );
    } catch (error) {
      console.error('[KVBatcher] Flush error:', error);
      // Re-queue failed writes (optional, could lead to memory growth)
      // this.queue.unshift(...batch);
    }
  }

  /**
   * Get pending writes count
   */
  getPendingCount(): number {
    return this.queue.length;
  }

  /**
   * Clear all pending writes (without flushing)
   */
  clear(): void {
    if (this.timer) {
      clearTimeout(this.timer);
      this.timer = null;
    }
    this.queue = [];
  }
}

/**
 * In-memory cache for KV reads
 * Reduces duplicate KV reads within short time windows
 */
export class KVCache {
  private cache: Map<string, { value: any; timestamp: number; ttl: number }>;
  private maxSize: number;
  private defaultTTL: number;

  constructor(maxSize: number = 500, defaultTTLMs: number = 5000) {
    this.cache = new Map();
    this.maxSize = maxSize;
    this.defaultTTL = defaultTTLMs;
  }

  /**
   * Get cached value
   */
  get<T>(key: string): T | null {
    const entry = this.cache.get(key);
    if (!entry) return null;

    const now = Date.now();
    const age = now - entry.timestamp;

    if (age > entry.ttl) {
      this.cache.delete(key);
      return null;
    }

    return entry.value as T;
  }

  /**
   * Set cached value
   */
  set(key: string, value: any, ttlMs?: number): void {
    // Enforce max size (LRU)
    if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      if (firstKey) {
        this.cache.delete(firstKey);
      }
    }

    this.cache.set(key, {
      value,
      timestamp: Date.now(),
      ttl: ttlMs || this.defaultTTL,
    });
  }

  /**
   * Delete cached value
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

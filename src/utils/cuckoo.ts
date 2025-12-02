/**
 * Cuckoo Filter - Space-efficient probabilistic data structure
 * 
 * Features:
 * - O(1) lookup, insert, delete
 * - Supports deletion (unlike Bloom filter)
 * - ~1% false positive rate with 8-bit fingerprints
 * - Serializable to/from Uint8Array for Cache API storage
 * 
 * @example
 * ```typescript
 * const filter = new CuckooFilter(10000); // capacity 10K
 * filter.add('192.168.1.1');
 * filter.contains('192.168.1.1'); // true
 * filter.remove('192.168.1.1');
 * filter.contains('192.168.1.1'); // false (probably)
 * 
 * // Serialize for storage
 * const buffer = filter.toBuffer();
 * const restored = CuckooFilter.fromBuffer(buffer);
 * ```
 */

const MAX_KICKS = 500; // Max displacement attempts before declaring filter full

export interface CuckooFilterOptions {
  /** Maximum number of items (default: 100000) */
  capacity?: number;
  /** Fingerprint bits - higher = lower false positive (default: 8) */
  fingerprintBits?: number;
  /** Entries per bucket (default: 4) */
  bucketSize?: number;
}

export class CuckooFilter {
  private buckets: Uint8Array[];
  private numBuckets: number;
  private bucketSize: number;
  private fingerprintBits: number;
  private count: number = 0;

  constructor(options: CuckooFilterOptions = {}) {
    const capacity = options.capacity ?? 100000;
    this.fingerprintBits = options.fingerprintBits ?? 8;
    this.bucketSize = options.bucketSize ?? 4;
    
    // Calculate number of buckets needed
    this.numBuckets = Math.ceil(capacity / this.bucketSize);
    
    // Initialize buckets (0 = empty slot)
    this.buckets = Array.from(
      { length: this.numBuckets },
      () => new Uint8Array(this.bucketSize)
    );
  }

  /**
   * Get current item count (approximate - may include false positives)
   */
  get size(): number {
    return this.count;
  }

  /**
   * Get filter capacity
   */
  get capacity(): number {
    return this.numBuckets * this.bucketSize;
  }

  /**
   * Add an item to the filter
   * @returns true if added, false if filter is full
   */
  add(item: string): boolean {
    const { fingerprint, index1, index2 } = this.hash(item);

    // Try to insert in bucket 1
    if (this.insertToBucket(index1, fingerprint)) {
      this.count++;
      return true;
    }

    // Try to insert in bucket 2
    if (this.insertToBucket(index2, fingerprint)) {
      this.count++;
      return true;
    }

    // Both buckets full - do cuckoo displacement
    let currentIndex = Math.random() < 0.5 ? index1 : index2;
    let currentFp = fingerprint;

    for (let kick = 0; kick < MAX_KICKS; kick++) {
      // Randomly select a slot to evict
      const slotIndex = Math.floor(Math.random() * this.bucketSize);
      
      // Swap fingerprints
      const evictedFp = this.buckets[currentIndex][slotIndex];
      this.buckets[currentIndex][slotIndex] = currentFp;
      currentFp = evictedFp;

      // Calculate alternate index for evicted fingerprint
      currentIndex = this.altIndex(currentIndex, currentFp);

      // Try to insert evicted fingerprint
      if (this.insertToBucket(currentIndex, currentFp)) {
        this.count++;
        return true;
      }
    }

    // Filter is full (or needs resizing)
    return false;
  }

  /**
   * Check if item might be in the filter
   * @returns true if item is probably in filter, false if definitely not
   */
  contains(item: string): boolean {
    const { fingerprint, index1, index2 } = this.hash(item);
    
    return (
      this.bucketContains(index1, fingerprint) ||
      this.bucketContains(index2, fingerprint)
    );
  }

  /**
   * Remove an item from the filter
   * @returns true if removed, false if not found
   */
  remove(item: string): boolean {
    const { fingerprint, index1, index2 } = this.hash(item);

    // Try to remove from bucket 1
    if (this.removeFromBucket(index1, fingerprint)) {
      this.count--;
      return true;
    }

    // Try to remove from bucket 2
    if (this.removeFromBucket(index2, fingerprint)) {
      this.count--;
      return true;
    }

    return false;
  }

  /**
   * Clear all items from the filter
   */
  clear(): void {
    for (const bucket of this.buckets) {
      bucket.fill(0);
    }
    this.count = 0;
  }

  /**
   * Serialize filter to Uint8Array for storage
   */
  toBuffer(): Uint8Array {
    // Header: 16 bytes (4 x uint32)
    // - numBuckets, bucketSize, fingerprintBits, count
    const dataSize = this.numBuckets * this.bucketSize;
    const buffer = new Uint8Array(16 + dataSize);
    const view = new DataView(buffer.buffer);

    // Write header
    view.setUint32(0, this.numBuckets, true);
    view.setUint32(4, this.bucketSize, true);
    view.setUint32(8, this.fingerprintBits, true);
    view.setUint32(12, this.count, true);

    // Write bucket data
    let offset = 16;
    for (const bucket of this.buckets) {
      buffer.set(bucket, offset);
      offset += this.bucketSize;
    }

    return buffer;
  }

  /**
   * Deserialize filter from Uint8Array
   */
  static fromBuffer(buffer: Uint8Array): CuckooFilter {
    const view = new DataView(buffer.buffer, buffer.byteOffset, buffer.byteLength);

    // Read header
    const numBuckets = view.getUint32(0, true);
    const bucketSize = view.getUint32(4, true);
    const fingerprintBits = view.getUint32(8, true);
    const count = view.getUint32(12, true);

    // Create filter with correct dimensions
    const filter = new CuckooFilter({
      capacity: numBuckets * bucketSize,
      fingerprintBits,
      bucketSize,
    });

    // Restore bucket data
    let offset = 16;
    for (let i = 0; i < numBuckets; i++) {
      filter.buckets[i] = buffer.slice(offset, offset + bucketSize);
      offset += bucketSize;
    }
    filter.count = count;

    return filter;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE METHODS
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * Hash item to get fingerprint and two bucket indices
   */
  private hash(item: string): { fingerprint: number; index1: number; index2: number } {
    // Simple but effective hash - works well for IPs and tokens
    let h1 = 0x811c9dc5; // FNV offset basis
    let h2 = 0;

    for (let i = 0; i < item.length; i++) {
      const c = item.charCodeAt(i);
      h1 ^= c;
      h1 = Math.imul(h1, 0x01000193); // FNV prime
      h2 = Math.imul(h2, 31) + c;
    }

    // Fingerprint: 1-255 (0 reserved for empty)
    const maxFp = (1 << this.fingerprintBits) - 1;
    const fingerprint = (Math.abs(h1) % maxFp) + 1;

    // Index 1: direct hash
    const index1 = Math.abs(h1) % this.numBuckets;

    // Index 2: XOR with fingerprint hash (partial-key cuckoo hashing)
    const index2 = this.altIndex(index1, fingerprint);

    return { fingerprint, index1, index2 };
  }

  /**
   * Calculate alternate index using partial-key cuckoo hashing
   */
  private altIndex(index: number, fingerprint: number): number {
    // Hash the fingerprint
    const fpHash = Math.imul(fingerprint, 0x5bd1e995);
    return Math.abs(index ^ fpHash) % this.numBuckets;
  }

  /**
   * Try to insert fingerprint into bucket
   */
  private insertToBucket(bucketIndex: number, fingerprint: number): boolean {
    const bucket = this.buckets[bucketIndex];
    for (let i = 0; i < this.bucketSize; i++) {
      if (bucket[i] === 0) { // Empty slot
        bucket[i] = fingerprint;
        return true;
      }
    }
    return false;
  }

  /**
   * Check if bucket contains fingerprint
   */
  private bucketContains(bucketIndex: number, fingerprint: number): boolean {
    const bucket = this.buckets[bucketIndex];
    for (let i = 0; i < this.bucketSize; i++) {
      if (bucket[i] === fingerprint) {
        return true;
      }
    }
    return false;
  }

  /**
   * Remove fingerprint from bucket
   */
  private removeFromBucket(bucketIndex: number, fingerprint: number): boolean {
    const bucket = this.buckets[bucketIndex];
    for (let i = 0; i < this.bucketSize; i++) {
      if (bucket[i] === fingerprint) {
        bucket[i] = 0;
        return true;
      }
    }
    return false;
  }
}

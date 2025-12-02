/**
 * Cuckoo Blocklist Handler - Add IP/user to blocklist via Cache API + Queue
 * 
 * Two-phase blocking:
 * 1. Immediate: Add to pending cache (blocks at this edge immediately)
 * 2. Global: Send to queue for filter update (blocks globally after sync)
 * 
 * @example
 * ```typescript
 * // Basic usage - immediate block only
 * pipeline.on(ActionType.BLOCK, new CuckooBlocklistHandler());
 * 
 * // With queue for global sync
 * pipeline.on(ActionType.BLOCK, new CuckooBlocklistHandler({
 *   queue: env.BLOCKLIST_QUEUE,
 * }));
 * ```
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';
import { CuckooBlocklistDetector } from '../detector/cuckoo-blocklist.detector';

export interface CuckooBlocklistHandlerOptions {
  /** Queue for global filter sync (optional) */
  queue?: Queue;
  
  /** Pending cache TTL in seconds (default: 300) */
  pendingTtl?: number;
  
  /** Key extractor - extracts identifier from action/context (default: IP) */
  keyExtractor?: (action: Action, ctx: HandlerContext) => string | null;
}

export interface BlockQueueMessage {
  /** Key to block (IP, token, user ID) */
  key: string;
  /** Action: 'add' or 'remove' */
  action: 'add' | 'remove';
  /** Reason for blocking */
  reason?: string;
  /** Timestamp when block was initiated */
  timestamp: number;
  /** Optional: expiration timestamp */
  expiresAt?: number;
  /** Optional: score that triggered the block */
  score?: number;
  /** Optional: attack types detected */
  attackTypes?: string[];
}

/**
 * CuckooBlocklistHandler - Handles blocking via Cache API and optional Queue
 * 
 * Flow:
 * 1. Add to pending cache → Immediate block at this edge
 * 2. (Optional) Send to queue → Global filter update
 */
export class CuckooBlocklistHandler implements IActionHandler {
  private pendingTtl: number;

  constructor(private options: CuckooBlocklistHandlerOptions = {}) {
    this.pendingTtl = options.pendingTtl ?? 300;
  }

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    // Check if we should skip - prevents loop when already blocked
    const allFromBlocklist = ctx.results?.every(r => r.metadata?.skipBlocklistUpdate);
    if (allFromBlocklist && ctx.results?.length > 0) {
      return;
    }

    // Extract key to block
    const key = this.extractKey(action, ctx);
    if (!key) {
      console.warn('[Sentinel] CuckooBlocklistHandler: No key to block');
      return;
    }

    const { duration, reason } = action.data || {};
    const ttl = duration || this.pendingTtl;

    try {
      // 1. Add to pending cache (immediate block)
      await CuckooBlocklistDetector.addToPending(key, ttl);

      // 2. Send to queue for global sync (if queue provided)
      if (this.options.queue) {
        const message: BlockQueueMessage = {
          key,
          action: 'add',
          reason: reason || this.buildReason(ctx),
          timestamp: Date.now(),
          expiresAt: duration ? Date.now() + (duration * 1000) : undefined,
          score: ctx.score?.score,
          attackTypes: this.getAttackTypes(ctx),
        };

        await this.options.queue.send(message);
      }

      console.log(`[Sentinel] Blocked ${key} (pending: ${ttl}s, queue: ${!!this.options.queue})`);
    } catch (error) {
      console.error('[Sentinel] CuckooBlocklistHandler error:', error);
    }
  }

  /**
   * Extract key from action or context
   */
  private extractKey(action: Action, ctx: HandlerContext): string | null {
    // Custom extractor
    if (this.options.keyExtractor) {
      return this.options.keyExtractor(action, ctx);
    }

    // From action data
    if (action.data?.key) {
      return action.data.key;
    }

    // From detection evidence
    const evidence = ctx.results?.find(r => r.evidence?.value)?.evidence;
    if (evidence?.value && evidence?.field === 'ip') {
      return evidence.value;
    }

    // From request headers
    return ctx.request?.headers.get('cf-connecting-ip') ?? null;
  }

  /**
   * Build reason string from context
   */
  private buildReason(ctx: HandlerContext): string {
    const attackTypes = this.getAttackTypes(ctx);
    if (attackTypes.length > 0) {
      return `Blocked by Sentinel: ${attackTypes.join(', ')}`;
    }
    return 'Blocked by Sentinel';
  }

  /**
   * Get unique attack types from detection results
   */
  private getAttackTypes(ctx: HandlerContext): string[] {
    if (!ctx.results || ctx.results.length === 0) {
      return [];
    }
    return [...new Set(ctx.results.map(r => r.attackType))];
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// QUEUE PRODUCER HELPERS
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Send a block request to the queue (for global sync)
 * Use this when you want to block an IP/token from anywhere
 * 
 * @example
 * ```typescript
 * import { sendBlockToQueue } from 'cloudflare-sentinel';
 * 
 * // Block immediately + queue for global sync
 * await CuckooBlocklistDetector.addToPending(ip);
 * await sendBlockToQueue(env.BLOCKLIST_QUEUE, ip, 'Spam detected');
 * ```
 */
export async function sendBlockToQueue(
  queue: Queue,
  key: string,
  reason?: string,
  options?: {
    expiresAt?: number;
    score?: number;
    attackTypes?: string[];
  }
): Promise<void> {
  const message: BlockQueueMessage = {
    key,
    action: 'add',
    reason: reason ?? 'Blocked by Sentinel',
    timestamp: Date.now(),
    ...options,
  };
  await queue.send(message);
}

/**
 * Send an unblock request to the queue
 * 
 * @example
 * ```typescript
 * import { sendUnblockToQueue } from 'cloudflare-sentinel';
 * 
 * await CuckooBlocklistDetector.removeFromPending(ip);
 * await sendUnblockToQueue(env.BLOCKLIST_QUEUE, ip);
 * ```
 */
export async function sendUnblockToQueue(
  queue: Queue,
  key: string
): Promise<void> {
  const message: BlockQueueMessage = {
    key,
    action: 'remove',
    timestamp: Date.now(),
  };
  await queue.send(message);
}

// ═══════════════════════════════════════════════════════════════════════════
// QUEUE CONSUMER HELPER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Helper to process blocklist queue messages and update Cuckoo Filter
 * 
 * Use this in your Queue Consumer worker:
 * 
 * @example
 * ```typescript
 * import { processBlocklistQueue, CuckooFilter } from 'cloudflare-sentinel';
 * 
 * export default {
 *   async queue(batch: MessageBatch<BlockQueueMessage>, env: Env) {
 *     await processBlocklistQueue(batch, env.BLOCKLIST_KV);
 *   }
 * };
 * ```
 */
export async function processBlocklistQueue(
  batch: MessageBatch<BlockQueueMessage>,
  kv: KVNamespace,
  options: {
    filterSnapshotKey?: string;
    filterVersionKey?: string;
    filterCapacity?: number;
    /** Key prefix for blocklist entries in KV (default: 'blocked:') */
    blocklistKeyPrefix?: string;
    /** Default block duration in seconds (default: 3600 = 1 hour) */
    defaultBlockDuration?: number;
  } = {}
): Promise<{ processed: number; errors: number }> {
  const { CuckooFilter } = await import('../utils/cuckoo');
  
  const snapshotKey = options.filterSnapshotKey ?? 'filter_snapshot';
  const versionKey = options.filterVersionKey ?? 'filter_version';
  const capacity = options.filterCapacity ?? 100000;
  const blocklistPrefix = options.blocklistKeyPrefix ?? 'blocked:';
  const defaultDuration = options.defaultBlockDuration ?? 3600;

  let processed = 0;
  let errors = 0;

  // Load existing filter or create new
  let filter: InstanceType<typeof CuckooFilter>;
  const existingSnapshot = await kv.get(snapshotKey, 'arrayBuffer');
  
  if (existingSnapshot) {
    filter = CuckooFilter.fromBuffer(new Uint8Array(existingSnapshot));
  } else {
    filter = new CuckooFilter({ capacity });
  }

  let isDirty = false;
  const kvOps: Promise<void>[] = [];

  // Process messages
  for (const msg of batch.messages) {
    try {
      const { key, action, reason, expiresAt, score, attackTypes } = msg.body;
      const kvKey = `${blocklistPrefix}${key}`;

      if (action === 'add') {
        // 1. Add to filter
        if (!filter.contains(key)) {
          const added = filter.add(key);
          if (added) {
            isDirty = true;
          } else {
            console.warn(`[Sentinel] Filter full, could not add: ${key}`);
          }
        }

        // 2. Add to KV (source of truth for verification)
        const blockRecord = JSON.stringify({
          blocked: true,
          reason: reason ?? 'Blocked by Sentinel',
          blockedAt: Date.now(),
          expiresAt,
          score,
          attackTypes,
        });

        // Calculate TTL from expiresAt or use default
        const ttl = expiresAt 
          ? Math.max(1, Math.floor((expiresAt - Date.now()) / 1000))
          : defaultDuration;

        kvOps.push(kv.put(kvKey, blockRecord, { expirationTtl: ttl }));
        
      } else if (action === 'remove') {
        // 1. Remove from filter
        if (filter.remove(key)) {
          isDirty = true;
        }

        // 2. Remove from KV
        kvOps.push(kv.delete(kvKey));
      }

      msg.ack();
      processed++;
    } catch (error) {
      console.error('[Sentinel] Queue message error:', error);
      msg.retry();
      errors++;
    }
  }

  // Execute KV operations in parallel
  if (kvOps.length > 0) {
    await Promise.all(kvOps);
  }

  // Save updated filter if changed
  if (isDirty) {
    const buffer = filter.toBuffer();
    const newVersion = Date.now().toString();

    await Promise.all([
      kv.put(snapshotKey, buffer),
      kv.put(versionKey, newVersion),
    ]);

    console.log(`[Sentinel] Filter updated: version=${newVersion}, processed=${processed}`);
  }

  return { processed, errors };
}

// ═══════════════════════════════════════════════════════════════════════════
// CRON REBUILD HELPER
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Rebuild Cuckoo Filter from source of truth (KV blocklist)
 * 
 * Use this in a scheduled/cron worker to periodically rebuild the filter.
 * This helps:
 * - Clean up fragmented filter after many add/remove operations
 * - Reset false positive rate to optimal level
 * - Sync filter with actual KV blocklist state
 * 
 * @example
 * ```typescript
 * import { rebuildBlocklistFilter, CuckooBlocklistDetector } from 'cloudflare-sentinel';
 * 
 * export default {
 *   async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
 *     ctx.waitUntil(rebuildBlocklistFilter(env.BLOCKLIST_KV, {
 *       blocklistPrefix: 'blocked:',
 *       filterCapacity: 100000,
 *     }));
 *   }
 * };
 * ```
 * 
 * @param kv - KV namespace containing blocklist entries
 * @param options - Rebuild options
 */
export async function rebuildBlocklistFilter(
  kv: KVNamespace,
  options: {
    /** Prefix for blocklist keys in KV (default: 'blocked:') */
    blocklistPrefix?: string;
    /** Filter snapshot key (default: 'filter_snapshot') */
    filterSnapshotKey?: string;
    /** Filter version key (default: 'filter_version') */
    filterVersionKey?: string;
    /** Filter capacity (default: 100000) */
    filterCapacity?: number;
  } = {}
): Promise<{ 
  success: boolean; 
  itemCount: number; 
  filterSize: number;
  version: string;
  error?: string;
}> {
  const { CuckooFilter } = await import('../utils/cuckoo');
  
  const prefix = options.blocklistPrefix ?? 'blocked:';
  const snapshotKey = options.filterSnapshotKey ?? 'filter_snapshot';
  const versionKey = options.filterVersionKey ?? 'filter_version';
  const capacity = options.filterCapacity ?? 100000;

  try {
    // 1. Create fresh filter
    const filter = new CuckooFilter({ capacity });
    let itemCount = 0;
    let cursor: string | undefined;

    // 2. Load all blocklist entries from KV (source of truth)
    do {
      const list = await kv.list({ prefix, cursor });
      
      for (const key of list.keys) {
        // Extract the actual key (remove prefix)
        const blockKey = key.name.substring(prefix.length);
        
        // Check if not expired (KV auto-deletes expired, but double check)
        if (key.expiration && key.expiration * 1000 < Date.now()) {
          continue;
        }

        // Add to filter
        const added = filter.add(blockKey);
        if (added) {
          itemCount++;
        } else {
          console.warn(`[Sentinel] Filter full at ${itemCount} items, some entries skipped`);
          break;
        }
      }

      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);

    // 3. Save new filter to KV
    const buffer = filter.toBuffer();
    const newVersion = `rebuild-${Date.now()}`;

    await Promise.all([
      kv.put(snapshotKey, buffer),
      kv.put(versionKey, newVersion),
    ]);

    // Note: Cache invalidation is edge-local only, not global.
    // Other edges will get new filter when their cache TTL expires.
    // This is acceptable eventual consistency (~5 min max).

    console.log(`[Sentinel] Filter rebuilt: ${itemCount} items, ${buffer.byteLength} bytes, version=${newVersion}`);

    return {
      success: true,
      itemCount,
      filterSize: buffer.byteLength,
      version: newVersion,
    };
  } catch (error) {
    console.error('[Sentinel] Filter rebuild failed:', error);
    return {
      success: false,
      itemCount: 0,
      filterSize: 0,
      version: '',
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Get blocklist statistics
 * 
 * @example
 * ```typescript
 * const stats = await getBlocklistStats(env.BLOCKLIST_KV);
 * console.log(`Blocked: ${stats.totalBlocked}, Filter size: ${stats.filterSize}`);
 * ```
 */
export async function getBlocklistStats(
  kv: KVNamespace,
  options: {
    blocklistPrefix?: string;
    filterSnapshotKey?: string;
    filterVersionKey?: string;
  } = {}
): Promise<{
  totalBlocked: number;
  filterSize: number;
  filterVersion: string | null;
  filterCapacity: number;
  filterUtilization: number;
}> {
  const { CuckooFilter } = await import('../utils/cuckoo');
  
  const prefix = options.blocklistPrefix ?? 'blocked:';
  const snapshotKey = options.filterSnapshotKey ?? 'filter_snapshot';
  const versionKey = options.filterVersionKey ?? 'filter_version';

  // Count blocked entries
  let totalBlocked = 0;
  let cursor: string | undefined;
  do {
    const list = await kv.list({ prefix, cursor });
    totalBlocked += list.keys.length;
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

  // Get filter info
  const [snapshot, version] = await Promise.all([
    kv.get(snapshotKey, 'arrayBuffer'),
    kv.get(versionKey),
  ]);

  let filterSize = 0;
  let filterCapacity = 0;
  let filterUtilization = 0;

  if (snapshot) {
    const filter = CuckooFilter.fromBuffer(new Uint8Array(snapshot));
    filterSize = snapshot.byteLength;
    filterCapacity = filter.capacity;
    filterUtilization = filter.size / filterCapacity;
  }

  return {
    totalBlocked,
    filterSize,
    filterVersion: version,
    filterCapacity,
    filterUtilization,
  };
}

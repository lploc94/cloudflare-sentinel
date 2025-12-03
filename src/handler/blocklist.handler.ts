/**
 * Blocklist Handler - Add IP/user to blocklist
 * 
 * Supports two modes:
 * - 'direct': Write to KV only (simple, immediate global sync)
 * - 'cuckoo': Write to Pending Cache + KV + Queue (fast local + eventual global)
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';
import { BlocklistDetector } from '../detector/blocklist.detector';

// Cloudflare Workers Cache API
declare const caches: { default: Cache };

export interface BlocklistHandlerOptions {
  /** KV namespace for blocklist */
  kv: KVNamespace;
  
  /**
   * Mode:
   * - 'direct': Write to KV only (simple, immediate global)
   * - 'cuckoo': Write Pending Cache + KV + Queue (fast local + eventual global)
   * 
   * Default: 'direct'
   */
  mode?: 'direct' | 'cuckoo';
  
  /** Queue for filter sync (required if mode='cuckoo') */
  queue?: Queue;
  
  /** Default block duration in seconds (default: 3600 = 1 hour) */
  defaultDuration?: number;
  
  /** Pending cache TTL - only for mode='cuckoo' (default: 300) */
  pendingTtl?: number;
  
  /** Key prefix (default: 'blocked:') */
  keyPrefix?: string;
  
  /** Key extractor - extracts identifier from action/context (default: IP) */
  keyExtractor?: (action: Action, ctx: HandlerContext) => string | null;
}

export interface BlockRecord {
  blocked: true;
  reason: string;
  blockedAt: number;
  expiresAt?: number;
  score?: number;
  attackTypes?: string[];
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
 * BlocklistHandler - Adds IP to blocklist
 * 
 * Respects `skipBlocklistUpdate` flag to prevent loops
 * (e.g., BlocklistDetector already found IP is blocked, no need to re-add)
 * 
 * @example
 * ```typescript
 * // Simple mode - KV only
 * pipeline.on(ActionType.BLOCK, new BlocklistHandler({
 *   kv: env.BLOCKLIST_KV,
 *   mode: 'direct',
 * }));
 * 
 * // Cuckoo mode - Pending Cache + KV + Queue
 * pipeline.on(ActionType.BLOCK, new BlocklistHandler({
 *   kv: env.BLOCKLIST_KV,
 *   mode: 'cuckoo',
 *   queue: env.BLOCKLIST_QUEUE,
 * }));
 * ```
 */
export class BlocklistHandler implements IActionHandler {
  private mode: 'direct' | 'cuckoo';
  private keyPrefix: string;
  private defaultDuration: number;
  private pendingTtl: number;

  constructor(private options: BlocklistHandlerOptions) {
    this.mode = options.mode ?? 'direct';
    this.keyPrefix = options.keyPrefix ?? 'blocked:';
    this.defaultDuration = options.defaultDuration ?? 3600;
    this.pendingTtl = options.pendingTtl ?? 300;
    
    // Validate cuckoo mode requirements
    if (this.mode === 'cuckoo' && !options.queue) {
      console.warn('[Sentinel] BlocklistHandler: mode=cuckoo requires queue option');
    }
  }

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    // Check if we should skip - prevents loop when IP is already blocked
    const allFromBlocklist = ctx.results?.every(r => r.metadata?.skipBlocklistUpdate);
    if (allFromBlocklist && ctx.results?.length > 0) {
      return;
    }

    // Extract key to block
    const blockKey = this.extractKey(action, ctx);
    if (!blockKey) {
      console.warn('[Sentinel] BlocklistHandler: No key to block');
      return;
    }

    const { duration, reason } = action.data || {};
    const ttl = duration || this.defaultDuration;

    try {
      if (this.mode === 'cuckoo') {
        await this.executeCuckooMode(blockKey, ttl, reason, ctx);
      } else {
        await this.executeDirectMode(blockKey, ttl, reason, ctx);
      }
    } catch (error) {
      console.error('[Sentinel] BlocklistHandler error:', error);
    }
  }

  /**
   * Direct mode: Write to KV only
   */
  private async executeDirectMode(
    blockKey: string,
    ttl: number,
    reason: string | undefined,
    ctx: HandlerContext
  ): Promise<void> {
    const fullKey = `${this.keyPrefix}${blockKey}`;
    
    const record: BlockRecord = {
      blocked: true,
      reason: reason || 'Blocked by Sentinel',
      blockedAt: Date.now(),
      expiresAt: Date.now() + (ttl * 1000),
      score: ctx.score?.score,
      attackTypes: this.getAttackTypes(ctx),
    };

    await this.options.kv.put(fullKey, JSON.stringify(record), { 
      expirationTtl: ttl,
    });

    console.log(`[Sentinel] Blocked ${blockKey} for ${ttl}s (mode: direct)`);
  }

  /**
   * Cuckoo mode: Write Pending Cache + KV + Queue
   */
  private async executeCuckooMode(
    blockKey: string,
    ttl: number,
    reason: string | undefined,
    ctx: HandlerContext
  ): Promise<void> {
    const fullKey = `${this.keyPrefix}${blockKey}`;
    const pendingTtl = Math.min(ttl, this.pendingTtl);

    // 1. Add to pending cache (immediate block at this edge)
    await BlocklistDetector.addToPending(blockKey, pendingTtl);

    // 2. Write to KV (source of truth)
    const record: BlockRecord = {
      blocked: true,
      reason: reason || this.buildReason(ctx),
      blockedAt: Date.now(),
      expiresAt: Date.now() + (ttl * 1000),
      score: ctx.score?.score,
      attackTypes: this.getAttackTypes(ctx),
    };

    await this.options.kv.put(fullKey, JSON.stringify(record), { 
      expirationTtl: ttl,
    });

    // 3. Send to queue for filter update (if queue provided)
    if (this.options.queue) {
      const message: BlockQueueMessage = {
        key: blockKey,
        action: 'add',
        reason: record.reason,
        timestamp: Date.now(),
        expiresAt: record.expiresAt,
        score: record.score,
        attackTypes: record.attackTypes,
      };

      await this.options.queue.send(message);
    }

    console.log(`[Sentinel] Blocked ${blockKey} for ${ttl}s (mode: cuckoo, queue: ${!!this.options.queue})`);
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
// QUEUE HELPERS (for mode='cuckoo')
// ═══════════════════════════════════════════════════════════════════════════

/**
 * Send a block request to the queue (for global sync)
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

/**
 * Process blocklist queue messages and update Cuckoo Filter
 * 
 * Use in your Queue Consumer worker:
 * @example
 * ```typescript
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
    blocklistKeyPrefix?: string;
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
        if (!filter.contains(key)) {
          const added = filter.add(key);
          if (added) {
            isDirty = true;
          } else {
            console.warn(`[Sentinel] Filter full, could not add: ${key}`);
          }
        }

        // KV already written by handler, but update filter
        
      } else if (action === 'remove') {
        if (filter.remove(key)) {
          isDirty = true;
        }
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

  // Execute KV operations
  if (kvOps.length > 0) {
    await Promise.all(kvOps);
  }

  // Save updated filter
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

/**
 * Rebuild Cuckoo Filter from KV source of truth
 * 
 * Use in scheduled/cron worker:
 * @example
 * ```typescript
 * export default {
 *   async scheduled(event, env, ctx) {
 *     ctx.waitUntil(rebuildBlocklistFilter(env.BLOCKLIST_KV));
 *   }
 * };
 * ```
 */
export async function rebuildBlocklistFilter(
  kv: KVNamespace,
  options: {
    blocklistPrefix?: string;
    filterSnapshotKey?: string;
    filterVersionKey?: string;
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
    const filter = new CuckooFilter({ capacity });
    let itemCount = 0;
    let cursor: string | undefined;

    do {
      const list = await kv.list({ prefix, cursor });
      
      for (const key of list.keys) {
        const blockKey = key.name.substring(prefix.length);
        
        if (key.expiration && key.expiration * 1000 < Date.now()) {
          continue;
        }

        const added = filter.add(blockKey);
        if (added) {
          itemCount++;
        } else {
          console.warn(`[Sentinel] Filter full at ${itemCount} items`);
          break;
        }
      }

      cursor = list.list_complete ? undefined : list.cursor;
    } while (cursor);

    const buffer = filter.toBuffer();
    const newVersion = `rebuild-${Date.now()}`;

    await Promise.all([
      kv.put(snapshotKey, buffer),
      kv.put(versionKey, newVersion),
    ]);

    console.log(`[Sentinel] Filter rebuilt: ${itemCount} items, version=${newVersion}`);

    return { success: true, itemCount, filterSize: buffer.byteLength, version: newVersion };
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

  let totalBlocked = 0;
  let cursor: string | undefined;
  do {
    const list = await kv.list({ prefix, cursor });
    totalBlocked += list.keys.length;
    cursor = list.list_complete ? undefined : list.cursor;
  } while (cursor);

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

  return { totalBlocked, filterSize, filterVersion: version, filterCapacity, filterUtilization };
}

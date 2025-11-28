/**
 * Blocklist Handler - Add IP/user to blocklist
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';

export interface BlocklistHandlerOptions {
  /** KV namespace for blocklist */
  kv: KVNamespace;
  /** Default block duration in seconds (default: 3600 = 1 hour) */
  defaultDuration?: number;
  /** Key prefix (default: 'blocked:') */
  keyPrefix?: string;
}

interface BlockRecord {
  blocked: true;
  reason: string;
  blockedAt: number;
  expiresAt: number;
  score?: number;
  attackTypes?: string[];
}

/**
 * BlocklistHandler - Adds IP to blocklist KV
 * 
 * Respects `skipBlocklistUpdate` flag to prevent loops
 * (e.g., BlocklistDetector already found IP is blocked, no need to re-add)
 * 
 * @example
 * ```typescript
 * pipeline.on(ActionType.BLOCK, new BlocklistHandler({ kv: env.BLOCKLIST_KV }));
 * ```
 */
export class BlocklistHandler implements IActionHandler {
  private keyPrefix: string;
  private defaultDuration: number;

  constructor(private options: BlocklistHandlerOptions) {
    this.keyPrefix = options.keyPrefix ?? 'blocked:';
    this.defaultDuration = options.defaultDuration ?? 3600;
  }

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    // Check if we should skip - prevents loop when IP is already blocked
    const allFromBlocklist = ctx.results?.every(r => r.metadata?.skipBlocklistUpdate);
    if (allFromBlocklist && ctx.results?.length > 0) {
      // All detections are from BlocklistDetector - IP already blocked
      return;
    }

    const { key, duration, reason } = action.data || {};
    
    const ip = ctx.request?.headers.get('cf-connecting-ip');
    const blockKey = key || ip;
    
    if (!blockKey) {
      console.warn('[Sentinel] BlocklistHandler: No key to block');
      return;
    }

    const fullKey = `${this.keyPrefix}${blockKey}`;
    const ttl = duration || this.defaultDuration;

    try {
      const record: BlockRecord = {
        blocked: true,
        reason: reason || 'Blocked by Sentinel',
        blockedAt: Date.now(),
        expiresAt: Date.now() + (ttl * 1000),
        score: ctx.score?.score,
        attackTypes: [...new Set(ctx.results?.map(r => r.attackType) || [])],
      };

      await this.options.kv.put(fullKey, JSON.stringify(record), { 
        expirationTtl: ttl,
      });

      console.log(`[Sentinel] Blocked ${blockKey} for ${ttl}s (reason: ${record.reason})`);
    } catch (error) {
      console.error('[Sentinel] BlocklistHandler error:', error);
    }
  }
}

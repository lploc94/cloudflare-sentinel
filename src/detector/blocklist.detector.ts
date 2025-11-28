/**
 * Blocklist Detector - Check if IP/user is blocked
 */

import { BaseDetector, type DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface BlocklistDetectorOptions {
  /** KV namespace containing blocklist */
  kv: KVNamespace;
  /** Key prefix (default: 'blocked:') - must match BlocklistHandler */
  keyPrefix?: string;
  /** Key extractor (default: IP address) */
  keyExtractor?: (request: Request) => string | null;
  /** Cache TTL in seconds for KV reads (default: 60) */
  cacheTtl?: number;
}

/**
 * BlocklistDetector - Blocks requests from blocklisted IPs/users
 * 
 * Checks KV namespace for blocked entries. Supports JSON or string values.
 * Uses edge caching to reduce KV reads.
 * 
 * @example
 * ```typescript
 * // Basic usage - block by IP (default)
 * new BlocklistDetector({ kv: env.BLOCKLIST_KV })
 * 
 * // Custom cache TTL (1 hour)
 * new BlocklistDetector({
 *   kv: env.BLOCKLIST_KV,
 *   cacheTtl: 3600,
 * })
 * 
 * // Custom key extractor (e.g., by user ID)
 * new BlocklistDetector({
 *   kv: env.BLOCKLIST_KV,
 *   keyExtractor: (req) => req.headers.get('x-user-id'),
 * })
 * ```
 * 
 * @remarks
 * KV value formats supported:
 * - JSON: `{ "reason": "Spam", "timestamp": 1234567890 }`
 * - String: `"Blocked for abuse"`
 * - Boolean: `"true"` or `"1"`
 */
export class BlocklistDetector extends BaseDetector {
  name = 'blocklist';
  phase = 'request' as const;
  priority = 100; // High priority - check first

  private keyPrefix: string;

  constructor(private options: BlocklistDetectorOptions) {
    super();
    this.keyPrefix = options.keyPrefix ?? 'blocked:';
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

    // Use same key format as BlocklistHandler
    const key = `${this.keyPrefix}${rawKey}`;

    try {
      // Use cacheTtl to reduce KV reads (cached at edge)
      const blocked = await this.options.kv.get(key, {
        cacheTtl: this.options.cacheTtl ?? 3600,
      });

      if (blocked) {
        // Safe parse - support both JSON and simple string values
        let reason = 'IP is blocklisted';
        let blockedAt: number | undefined;

        try {
          const data = JSON.parse(blocked);
          reason = data.reason || reason;
          blockedAt = data.blockedAt || data.timestamp; // Support both field names
        } catch {
          // Value is simple string, use as reason if meaningful
          if (blocked !== 'true' && blocked !== '1') {
            reason = blocked;
          }
        }

        return this.createResult(
          AttackType.BLOCKLIST,
          SecuritySeverity.CRITICAL,
          1.0,
          { field: 'ip', value: rawKey },
          { 
            reason, 
            blockedAt, 
            key,
            // Prevent loop - IP is already blocked, don't re-add
            skipBlocklistUpdate: true,
          }
        );
      }
    } catch (error) {
      console.error('[Sentinel] BlocklistDetector error:', error);
    }

    return null;
  }
}

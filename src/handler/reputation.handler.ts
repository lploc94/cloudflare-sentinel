/**
 * Reputation Handler - Update IP/user reputation score
 * 
 * Calculates reputation delta based on REAL attack detections only.
 * Detections with `skipReputationUpdate: true` are excluded to prevent
 * feedback loops.
 */

import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';
import { SecuritySeverity } from '../types';

export interface ReputationHandlerOptions {
  /** KV namespace for reputation data */
  kv: KVNamespace;
  /** TTL in seconds (default: 86400 = 24 hours) */
  ttl?: number;
  /** Delta per severity level (default: CRITICAL=-20, HIGH=-10, MEDIUM=-5, LOW=-2) */
  severityDeltas?: Partial<Record<SecuritySeverity, number>>;
  /** Key prefix (default: 'reputation:') */
  keyPrefix?: string;
  /** Minimum delta per request (default: -50) - prevents extreme drops */
  minDelta?: number;
  /** Whether to factor in confidence (default: true) */
  useConfidence?: boolean;
}

interface ReputationData {
  score: number;
  history: { delta: number; reason: string; timestamp: number }[];
  lastUpdated: number;
}

const DEFAULT_SEVERITY_DELTAS: Record<SecuritySeverity, number> = {
  [SecuritySeverity.CRITICAL]: -20,
  [SecuritySeverity.HIGH]: -10,
  [SecuritySeverity.MEDIUM]: -5,
  [SecuritySeverity.LOW]: -2,
};

/**
 * ReputationHandler - Tracks IP/user reputation over time
 * 
 * **Key concept:** Delta is calculated from real attack detections,
 * not passed via action.data. This prevents feedback loops.
 * 
 * @example
 * ```typescript
 * // Just trigger the action - handler calculates delta automatically
 * pipeline.on(ActionType.UPDATE_REPUTATION, new ReputationHandler({
 *   kv: env.REPUTATION_KV,
 * }));
 * ```
 */
export class ReputationHandler implements IActionHandler {
  private severityDeltas: Record<SecuritySeverity, number>;
  private keyPrefix: string;
  private minDelta: number;
  private useConfidence: boolean;

  constructor(private options: ReputationHandlerOptions) {
    this.severityDeltas = { ...DEFAULT_SEVERITY_DELTAS, ...options.severityDeltas };
    this.keyPrefix = options.keyPrefix ?? 'reputation:';
    this.minDelta = options.minDelta ?? -50;
    this.useConfidence = options.useConfidence ?? true;
  }

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    // Filter out detections that should not affect reputation (e.g., ReputationDetector)
    const realDetections = ctx.results?.filter(r => !r.metadata?.skipReputationUpdate) || [];
    
    // No real detections = no reputation update
    if (realDetections.length === 0) {
      return;
    }

    // Get IP from request
    const ip = ctx.request?.headers.get('cf-connecting-ip');
    if (!ip) {
      return;
    }

    // Calculate delta based on real detections
    const { delta, reasons } = this.calculateDelta(realDetections);
    if (delta === 0) {
      return;
    }

    const key = `${this.keyPrefix}${ip}`;
    const ttl = this.options.ttl ?? 86400;

    try {
      const current = await this.options.kv.get<ReputationData>(key, 'json');
      
      const newData: ReputationData = {
        score: (current?.score ?? 0) + delta,
        history: [
          ...(current?.history ?? []).slice(-9),
          { delta, reason: reasons.join(', '), timestamp: Date.now() },
        ],
        lastUpdated: Date.now(),
      };

      await this.options.kv.put(key, JSON.stringify(newData), { expirationTtl: ttl });
      
      console.log(`[Sentinel] Reputation updated for ${ip}: ${delta} (${reasons.join(', ')})`);
    } catch (error) {
      console.error('[Sentinel] ReputationHandler error:', error);
    }
  }

  /**
   * Calculate total delta from real detections
   * 
   * Formula: delta = sum(severityDelta * confidence) capped at minDelta
   */
  private calculateDelta(detections: Array<{ severity: SecuritySeverity; confidence: number; attackType: string }>): { delta: number; reasons: string[] } {
    let delta = 0;
    const reasons: string[] = [];

    for (const detection of detections) {
      const baseDelta = this.severityDeltas[detection.severity] ?? 0;
      
      // Factor in confidence if enabled (e.g., -10 * 0.8 = -8)
      const adjustedDelta = this.useConfidence 
        ? Math.round(baseDelta * detection.confidence)
        : baseDelta;
      
      delta += adjustedDelta;
      reasons.push(detection.attackType);
    }

    // Cap delta to prevent extreme drops in a single request
    // e.g., 10 CRITICAL detections = -200, but capped at -50
    delta = Math.max(delta, this.minDelta);

    return { delta, reasons: [...new Set(reasons)] };
  }
}

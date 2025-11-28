/**
 * Reputation Detector - Check IP reputation and adjust threat score
 * 
 * Works with ReputationHandler which writes reputation data.
 */

import { AttackType, SecuritySeverity } from '../types';
import { BaseDetector, type DetectorResult } from './base';

export interface ReputationDetectorOptions {
  /** KV namespace for reputation data (same as ReputationHandler) */
  kv: KVNamespace;
  /** Score threshold to block (default: -50) */
  blockThreshold?: number;
  /** Score threshold to flag as suspicious (default: -20) */
  warnThreshold?: number;
  /** Key prefix (default: 'reputation:') */
  keyPrefix?: string;
  /** Enable/disable detector */
  enabled?: boolean;
  /** Priority (default: 100 - runs first) */
  priority?: number;
  /** Decay rate: points recovered per hour (default: 5) */
  decayPerHour?: number;
}

interface ReputationData {
  score: number;
  history: { delta: number; reason: string; timestamp: number }[];
  lastUpdated: number;
}

/**
 * ReputationDetector - Checks IP reputation before other detectors
 * 
 * @example
 * ```typescript
 * new ReputationDetector({
 *   kv: env.REPUTATION_KV,
 *   blockThreshold: -50,  // Block IPs with reputation <= -50
 *   warnThreshold: -20,   // Flag IPs with reputation <= -20
 * })
 * ```
 */
export class ReputationDetector extends BaseDetector {
  readonly name = 'reputation';
  readonly phase = 'request' as const;
  readonly priority: number;
  readonly enabled: boolean;

  private kv: KVNamespace;
  private blockThreshold: number;
  private warnThreshold: number;
  private keyPrefix: string;
  private decayPerHour: number;

  constructor(options: ReputationDetectorOptions) {
    super();
    this.kv = options.kv;
    this.blockThreshold = options.blockThreshold ?? -50;
    this.warnThreshold = options.warnThreshold ?? -20;
    this.keyPrefix = options.keyPrefix ?? 'reputation:';
    this.enabled = options.enabled ?? true;
    this.priority = options.priority ?? 100; // High priority - run first
    this.decayPerHour = options.decayPerHour ?? 5; // Recover 5 points per hour
  }

  async detectRequest(request: Request): Promise<DetectorResult | null> {
    const ip = request.headers.get('cf-connecting-ip');
    if (!ip) return null;

    try {
      const key = `${this.keyPrefix}${ip}`;
      const data = await this.kv.get<ReputationData>(key, 'json');
      
      if (!data) return null; // No reputation data = clean IP

      const { history, lastUpdated } = data;
      
      // Calculate effective score with decay
      // Score recovers over time: effectiveScore = storedScore + (hoursElapsed * decayPerHour)
      const hoursElapsed = (Date.now() - lastUpdated) / (1000 * 60 * 60);
      const decay = Math.floor(hoursElapsed * this.decayPerHour);
      const score = Math.min(0, data.score + decay); // Cap at 0 (neutral)

      // If score has decayed to 0 or above, IP is clean now
      if (score >= 0) {
        return null;
      }

      // Block threshold reached
      if (score <= this.blockThreshold) {
        return this.createResult(
          AttackType.SUSPICIOUS_PATTERN,
          SecuritySeverity.CRITICAL,
          0.95,
          {
            field: 'ip',
            value: ip,
          },
          {
            detector: this.name,
            storedScore: data.score,
            effectiveScore: score,
            decayApplied: decay,
            hoursElapsed: Math.round(hoursElapsed * 10) / 10,
            threshold: this.blockThreshold,
            recentHistory: history.slice(-3),
            action: 'block',
            skipReputationUpdate: true,
          }
        );
      }

      // Warn threshold reached - add to score but don't block
      if (score <= this.warnThreshold) {
        return this.createResult(
          AttackType.SUSPICIOUS_PATTERN,
          SecuritySeverity.MEDIUM,
          0.6,
          {
            field: 'ip',
            value: ip,
          },
          {
            detector: this.name,
            storedScore: data.score,
            effectiveScore: score,
            decayApplied: decay,
            hoursElapsed: Math.round(hoursElapsed * 10) / 10,
            threshold: this.warnThreshold,
            recentHistory: history.slice(-3),
            action: 'warn',
            skipReputationUpdate: true,
          }
        );
      }

      return null; // Score above warn threshold = OK
    } catch (error) {
      console.error('[Sentinel] ReputationDetector error:', error);
      return null;
    }
  }
}

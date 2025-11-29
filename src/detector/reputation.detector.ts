/**
 * Reputation Detector - Check IP reputation and adjust threat score
 * 
 * Works with ReputationHandler which writes reputation data.
 * Score decays over time, allowing IPs to recover from temporary bad behavior.
 * 
 * **Scoring System:**
 * - Score starts at 0 (neutral)
 * - Bad behavior decreases score (negative)
 * - Score decays towards 0 over time (recovery)
 * - blockThreshold: CRITICAL severity, immediate block
 * - warnThreshold: MEDIUM severity, flag for monitoring
 * 
 * **Confidence:** Always 1.0 (reputation is calculated fact, not guess)
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
 * Runs first (priority 100) to catch repeat offenders immediately.
 * Score decays over time allowing recovery from temporary issues.
 * 
 * @example
 * ```typescript
 * // Basic usage - block repeat offenders
 * new ReputationDetector({
 *   kv: env.REPUTATION_KV,
 *   blockThreshold: -50,  // Block IPs with reputation <= -50
 *   warnThreshold: -20,   // Flag IPs with reputation <= -20
 * })
 * 
 * // Aggressive settings for sensitive endpoints
 * new ReputationDetector({
 *   kv: env.REPUTATION_KV,
 *   blockThreshold: -30,
 *   warnThreshold: -10,
 *   decayPerHour: 2,  // Slower recovery
 * })
 * 
 * // Lenient settings for public endpoints
 * new ReputationDetector({
 *   kv: env.REPUTATION_KV,
 *   blockThreshold: -100,
 *   warnThreshold: -50,
 *   decayPerHour: 10,  // Faster recovery
 * })
 * ```
 * 
 * @remarks
 * **How it works:**
 * 1. ReputationHandler decreases score when attacks detected
 * 2. ReputationDetector checks score on each request
 * 3. Score decays towards 0 over time (configurable)
 * 4. Returns CRITICAL if below blockThreshold
 * 5. Returns MEDIUM if below warnThreshold
 * 
 * **Metadata includes:**
 * - `storedScore`: Raw score from KV
 * - `effectiveScore`: After decay applied
 * - `decayApplied`: Points recovered
 * - `recentHistory`: Last 3 incidents
 * - `skipReputationUpdate`: Prevents double-counting
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
          1.0, // Reputation score is a calculated fact, not a guess
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
          1.0, // Reputation score is a calculated fact, not a guess
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

/**
 * Failure Threshold Detector
 * General detector that counts failed responses per IP and triggers when threshold exceeded
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/**
 * Common failure status presets
 */
export const FailureStatusPresets = {
  /** Auth failures only (401, 403) */
  AUTH: [401, 403],
  /** Rate limit responses (429) */
  RATE_LIMIT: [429],
  /** Client errors (4xx) */
  CLIENT_ERRORS: [400, 401, 403, 404, 422, 429],
  /** Server errors (5xx) */
  SERVER_ERRORS: [500, 502, 503, 504],
  /** All common errors */
  ALL_ERRORS: [400, 401, 403, 404, 422, 429, 500, 502, 503, 504],
} as const;

export interface FailureThresholdDetectorOptions extends BaseDetectorOptions {
  /** KV namespace for storing fail counts */
  kv: KVNamespace;
  /** Number of failed attempts to trigger detection (default: 5) */
  threshold?: number;
  /** Time window in seconds (default: 60) */
  windowSeconds?: number;
  /** Key prefix in KV (default: 'failure') */
  keyPrefix?: string;
  /** HTTP status codes to count as failures (default: [401, 403] - use FailureStatusPresets for common cases) */
  failureStatuses?: number[];
  /** Attack type to report (default: SUSPICIOUS_PATTERN) */
  attackType?: AttackType;
}

/**
 * FailureThresholdDetector - General failure rate detection
 * 
 * Counts failed responses per IP in a time window.
 * Triggers detection when threshold is exceeded.
 * Base class for specialized detectors like `BruteForceDetector`.
 * 
 * @example
 * ```typescript
 * // Monitor 404 enumeration attacks
 * new FailureThresholdDetector({
 *   kv: env.SECURITY_KV,
 *   threshold: 20,
 *   failureStatuses: [404],
 *   keyPrefix: 'enum-404',
 *   attackType: AttackType.RESOURCE_ENUMERATION,
 * })
 * 
 * // Monitor rate limit abuse (429)
 * new FailureThresholdDetector({
 *   kv: env.SECURITY_KV,
 *   threshold: 10,
 *   failureStatuses: FailureStatusPresets.RATE_LIMIT,
 *   keyPrefix: 'rate-abuse',
 *   attackType: AttackType.API_ABUSE,
 * })
 * 
 * // Monitor server errors
 * new FailureThresholdDetector({
 *   kv: env.SECURITY_KV,
 *   threshold: 5,
 *   failureStatuses: FailureStatusPresets.SERVER_ERRORS,
 *   keyPrefix: 'server-errors',
 * })
 * 
 * // Custom confidence
 * new FailureThresholdDetector({
 *   kv: env.SECURITY_KV,
 *   failureStatuses: [401, 403],
 *   baseConfidence: 0.9,  // Higher confidence
 * })
 * ```
 * 
 * @remarks
 * - Use `FailureStatusPresets` for common status code combinations
 * - KV entries auto-expire after `windowSeconds`
 * - Confidence increases with each failure above threshold
 * - For auth endpoints, use `BruteForceDetector` instead
 */
export class FailureThresholdDetector extends BaseDetector {
  name = 'failure-threshold';
  phase = 'response' as const;
  priority = 80;

  protected readonly threshold: number;
  protected readonly windowSeconds: number;
  protected readonly keyPrefix: string;
  protected readonly failureStatuses: number[];
  protected readonly attackType: AttackType;
  protected readonly baseConfidence: number;

  constructor(protected options: FailureThresholdDetectorOptions) {
    super();
    this.threshold = options.threshold ?? 5;
    this.windowSeconds = options.windowSeconds ?? 60;
    this.keyPrefix = options.keyPrefix ?? 'failure';
    this.failureStatuses = options.failureStatuses ?? [...FailureStatusPresets.AUTH];
    this.attackType = options.attackType ?? AttackType.SUSPICIOUS_PATTERN;
    // Start at 0.5 when threshold just reached, increase with more failures
    this.baseConfidence = options.baseConfidence ?? 0.5;
  }

  async detectResponse(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    // Only count configured failure statuses
    if (!this.failureStatuses.includes(response.status)) {
      return null;
    }

    // Get IP for tracking
    const ip = request.headers.get('cf-connecting-ip');
    if (!ip) {
      return null;
    }

    try {
      const count = await this.incrementFailCount(ip);

      if (count >= this.threshold) {
        const confidence = Math.min(this.baseConfidence + (count - this.threshold) * 0.1, 1.0);

        return this.createResult(
          this.attackType,
          this.getSeverityByCount(count),
          confidence,
          {
            field: 'ip',
            value: ip,
            rawContent: `${count} failed attempts (status ${response.status}) from IP within ${this.windowSeconds}s window`,
          },
          {
            failedAttempts: count,
            threshold: this.threshold,
            windowSeconds: this.windowSeconds,
            triggeredByStatus: response.status,
          }
        );
      }

      return null;
    } catch (error) {
      console.error(`[Sentinel] ${this.name} error:`, error);
      return null;
    }
  }

  protected async incrementFailCount(ip: string): Promise<number> {
    const key = `${this.keyPrefix}:${ip}`;

    // No cache - accuracy is critical
    const existing = await this.options.kv.get(key);

    const count = existing ? parseInt(existing, 10) + 1 : 1;

    await this.options.kv.put(key, count.toString(), {
      expirationTtl: this.windowSeconds,
    });

    return count;
  }

  protected getSeverityByCount(count: number): SecuritySeverity {
    if (count >= this.threshold * 3) return SecuritySeverity.CRITICAL;
    if (count >= this.threshold * 2) return SecuritySeverity.HIGH;
    return SecuritySeverity.MEDIUM;
  }
}

/**
 * Brute Force Detector
 * Specialized detector for brute force attacks on authentication endpoints
 * Extends FailureThresholdDetector with auth-specific defaults
 */

import { AttackType } from '../types';
import { FailureThresholdDetector, type FailureThresholdDetectorOptions } from './failure-threshold.detector';

export interface BruteForceDetectorOptions {
  /** KV namespace for storing fail counts */
  kv: KVNamespace;
  /** Number of failed attempts to trigger detection (default: 5) */
  threshold?: number;
  /** Time window in seconds (default: 60) */
  windowSeconds?: number;
}

/**
 * BruteForceDetector - Auth endpoint brute force detection
 * 
 * Pre-configured FailureThresholdDetector for authentication failures (401, 403).
 * Counts failed login attempts per IP and triggers when threshold exceeded.
 * 
 * **Important:** Attach to login/auth endpoints only via pipeline routing.
 * 
 * @example
 * ```typescript
 * // Basic usage - 5 fails in 60s triggers detection
 * new BruteForceDetector({ kv: env.SECURITY_KV })
 * 
 * // Stricter for admin endpoints
 * new BruteForceDetector({
 *   kv: env.SECURITY_KV,
 *   threshold: 3,        // 3 failed attempts
 *   windowSeconds: 300,  // within 5 minutes
 * })
 * 
 * // Usage with pipeline routing
 * if (url.pathname === '/api/login') {
 *   const pipeline = SentinelPipeline.sync([
 *     new BruteForceDetector({ kv: env.SECURITY_KV }),
 *   ]).score(...).resolve(...);
 *   // ...
 * }
 * ```
 * 
 * @remarks
 * - Extends `FailureThresholdDetector` with auth-specific defaults
 * - Only counts 401/403 responses
 * - KV entries auto-expire after `windowSeconds`
 * - No caching on KV reads for accuracy
 */
export class BruteForceDetector extends FailureThresholdDetector {
  name = 'brute-force';
  priority = 85;

  constructor(options: BruteForceDetectorOptions) {
    super({
      ...options,
      keyPrefix: 'brute',
      failureStatuses: [401, 403],
      attackType: AttackType.BRUTE_FORCE,
    });
  }
}

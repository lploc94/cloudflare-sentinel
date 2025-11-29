/**
 * Brute Force Detector
 * 
 * Specialized detector for brute force attacks on authentication endpoints.
 * Pre-configured FailureThresholdDetector with auth-specific defaults.
 * 
 * **Features:**
 * - Counts 401/403 responses (auth failures)
 * - Per-IP tracking with KV storage
 * - Auto-expiring counters (windowSeconds)
 * - Configurable threshold and window
 * 
 * **When to use:**
 * - Login endpoints (`/login`, `/signin`)
 * - Password reset (`/forgot-password`)
 * - 2FA verification (`/verify-otp`)
 * - API key validation endpoints
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
 * // Usage with response pipeline (must see response)
 * const responsePipeline = SentinelPipeline.response([
 *   new BruteForceDetector({ kv: env.SECURITY_KV }),
 * ]);
 * 
 * // After getting response from origin
 * const decision = await responsePipeline.process(request, response, ctx);
 * if (decision.has('block_user')) {
 *   // Block user for future requests
 * }
 * ```
 * 
 * @remarks
 * **How it works:**
 * 1. Runs on response phase (needs status code)
 * 2. Counts 401/403 responses per IP
 * 3. Triggers when count >= threshold within window
 * 4. KV entries auto-expire after `windowSeconds`
 * 
 * **Defaults:**
 * - threshold: 5 failures
 * - windowSeconds: 60 seconds
 * - failureStatuses: [401, 403]
 * - keyPrefix: 'brute'
 * 
 * **Severity:** MEDIUM when triggered
 * **AttackType:** BRUTE_FORCE
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

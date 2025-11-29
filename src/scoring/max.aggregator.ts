/**
 * Max Score Aggregator
 * 
 * Takes the highest score from all detection results.
 * Best for scenarios where any single serious threat should trigger action.
 * 
 * @module scoring
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatScore } from '../pipeline/types';
import { BaseScoreAggregator } from './base';

/**
 * MaxScoreAggregator - Returns the highest score from all detectors
 * 
 * **Use case:** Security-first approach where any serious threat
 * should be treated at its full severity, regardless of other detections.
 * 
 * **Formula:** `finalScore = max(severity × confidence)` for all results
 * 
 * **When to use:**
 * - Blocking pipelines (sync) where one critical detection should block
 * - High-security endpoints (admin, auth)
 * - When false negatives are more costly than false positives
 * 
 * **When NOT to use:**
 * - Monitoring pipelines where you want averaged risk
 * - High-traffic public endpoints (may over-block)
 * 
 * @example
 * ```typescript
 * import { SentinelPipeline, MaxScoreAggregator } from 'cloudflare-sentinel';
 * 
 * const pipeline = SentinelPipeline.sync([...detectors])
 *   .score(new MaxScoreAggregator())
 *   .resolve(...);
 * 
 * // Detection results:
 * // - SQLi: HIGH (80) × 0.9 confidence = 72
 * // - XSS: MEDIUM (50) × 0.5 confidence = 25
 * // → Final score: 72 (max)
 * ```
 * 
 * @see WeightedAggregator for averaged scoring
 */
export class MaxScoreAggregator extends BaseScoreAggregator {
  name = 'max';

  /**
   * Aggregate results by taking the maximum score
   * 
   * @param results - Detection results from all detectors
   * @returns ThreatScore with max score and corresponding level
   */
  aggregate(results: DetectorResult[]): ThreatScore {
    if (results.length === 0) {
      return { score: 0, level: 'none', results };
    }

    const scores = results.map(r => {
      const baseScore = this.severityToScore(r.severity);
      return baseScore * r.confidence;
    });

    const maxScore = Math.max(...scores);
    
    return {
      score: Math.round(maxScore),
      level: this.calculateLevel(maxScore),
      results,
    };
  }
}

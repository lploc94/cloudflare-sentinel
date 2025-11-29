/**
 * Weighted Average Aggregator
 * 
 * Calculates weighted average of all detection scores.
 * Best for monitoring scenarios where overall risk assessment matters.
 * 
 * @module scoring
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatScore } from '../pipeline/types';
import { BaseScoreAggregator } from './base';

/**
 * Detector weights configuration
 * 
 * Key: detector name (e.g., 'sql-injection', 'blocklist')
 * Value: weight multiplier (default: 1.0)
 * 
 * @example
 * ```typescript
 * const weights: DetectorWeights = {
 *   'blocklist': 2.0,      // 2x importance
 *   'sql-injection': 1.5,  // 50% more important
 *   'entropy': 0.5,        // 50% less important
 * };
 * ```
 */
export type DetectorWeights = Record<string, number>;

/**
 * WeightedAggregator - Calculates weighted average of all scores
 * 
 * **Use case:** Balanced risk assessment where multiple low-severity
 * detections shouldn't trigger the same response as one critical detection.
 * 
 * **Formula:** `finalScore = avg(severity × confidence × weight)` for all results
 * 
 * **When to use:**
 * - Async monitoring pipelines
 * - Public endpoints with high traffic
 * - When false positives are costly
 * - When you want to prioritize certain detectors
 * 
 * **When NOT to use:**
 * - Blocking pipelines where any critical should block
 * - High-security endpoints (use MaxScoreAggregator)
 * 
 * @example
 * ```typescript
 * import { SentinelPipeline, WeightedAggregator } from 'cloudflare-sentinel';
 * 
 * // Without weights (simple average)
 * const pipeline = SentinelPipeline.async([...detectors])
 *   .score(new WeightedAggregator());
 * 
 * // With detector weights
 * const pipeline = SentinelPipeline.async([...detectors])
 *   .score(new WeightedAggregator({
 *     'blocklist': 2.0,      // Blocked IPs are 2x important
 *     'sql-injection': 1.5,  // SQLi is 50% more important
 *     'entropy': 0.5,        // Entropy is less reliable
 *   }));
 * 
 * // Detection results:
 * // - SQLi: HIGH (80) × 0.9 × 1.5 = 108
 * // - XSS: MEDIUM (50) × 0.5 × 1.0 = 25
 * // → Final score: (108 + 25) / 2 = 67 (average)
 * ```
 * 
 * @see MaxScoreAggregator for max-based scoring
 */
export class WeightedAggregator extends BaseScoreAggregator {
  name = 'weighted';
  
  constructor(private weights?: DetectorWeights) {
    super();
  }

  aggregate(results: DetectorResult[]): ThreatScore {
    if (results.length === 0) {
      return { score: 0, level: 'none', results };
    }

    const totalScore = results.reduce((sum, r) => {
      const baseScore = this.severityToScore(r.severity);
      const weight = this.getWeight(r.detectorName);
      return sum + (baseScore * r.confidence * weight);
    }, 0);

    const avgScore = totalScore / results.length;
    
    return {
      score: Math.round(avgScore),
      level: this.calculateLevel(avgScore),
      results,
    };
  }
  
  /**
   * Get weight for a detector (default 1.0)
   */
  private getWeight(detectorName: string): number {
    return this.weights?.[detectorName] ?? 1.0;
  }
}

/**
 * Weighted Average Aggregator
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatScore } from '../pipeline/types';
import { BaseScoreAggregator } from './base';

/**
 * Detector weights configuration
 * Key: detector name, Value: weight multiplier (default 1.0)
 */
export type DetectorWeights = Record<string, number>;

/**
 * WeightedAggregator - Calculates weighted average of all scores
 * 
 * Supports optional detector weights for prioritizing certain detectors
 * 
 * @example
 * ```typescript
 * // Without weights (confidence only)
 * const aggregator = new WeightedAggregator();
 * 
 * // With detector weights
 * const aggregator = new WeightedAggregator({
 *   'sql-injection': 1.5,     // 50% more important
 *   'blocklist': 2.0,          // 2x more important
 *   'xss': 1.0,                // Normal weight
 * });
 * ```
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

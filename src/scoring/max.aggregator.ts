/**
 * Max Score Aggregator - takes the highest score
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatScore } from '../pipeline/types';
import { BaseScoreAggregator } from './base';

/**
 * MaxScoreAggregator - Returns the highest score from all detectors
 * 
 * Use when any serious threat should trigger action
 */
export class MaxScoreAggregator extends BaseScoreAggregator {
  name = 'max';

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

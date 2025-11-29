/**
 * Base Score Aggregator
 * 
 * Abstract base class for score aggregation strategies.
 * Provides common utilities for converting severity to scores
 * and calculating threat levels.
 * 
 * @module scoring
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatLevel, ThreatScore } from '../pipeline/types';
import type { IScoreAggregator } from './types';

/**
 * Base class for score aggregators
 * 
 * Subclasses must implement the `aggregate` method to define
 * how multiple detection results are combined into a single score.
 * 
 * **Severity to Score Mapping:**
 * | Severity | Base Score |
 * |----------|------------|
 * | CRITICAL | 100 |
 * | HIGH | 80 |
 * | MEDIUM | 50 |
 * | LOW | 25 |
 * 
 * **Score to Threat Level:**
 * | Score Range | Level |
 * |-------------|-------|
 * | 80-100 | critical |
 * | 60-79 | high |
 * | 40-59 | medium |
 * | 20-39 | low |
 * | 0-19 | none |
 * 
 * @example
 * ```typescript
 * class CustomAggregator extends BaseScoreAggregator {
 *   name = 'custom';
 *   
 *   aggregate(results: DetectorResult[]): ThreatScore {
 *     // Custom aggregation logic
 *     const score = results.reduce((sum, r) => 
 *       sum + this.severityToScore(r.severity) * r.confidence, 0);
 *     
 *     return {
 *       score: Math.round(score),
 *       level: this.calculateLevel(score),
 *       results,
 *     };
 *   }
 * }
 * ```
 */
export abstract class BaseScoreAggregator implements IScoreAggregator {
  /** Aggregator name for identification */
  abstract name: string;
  
  /** Aggregate detection results into a single threat score */
  abstract aggregate(results: DetectorResult[]): ThreatScore;

  /**
   * Calculate threat level from numeric score
   * 
   * @param score - Numeric score (0-100)
   * @returns Threat level string
   */
  protected calculateLevel(score: number): ThreatLevel {
    if (score >= 80) return 'critical';
    if (score >= 60) return 'high';
    if (score >= 40) return 'medium';
    if (score >= 20) return 'low';
    return 'none';
  }

  /**
   * Convert severity to base score
   */
  protected severityToScore(severity: string): number {
    switch (severity) {
      case 'critical': return 100;
      case 'high': return 80;
      case 'medium': return 50;
      case 'low': return 25;
      default: return 0;
    }
  }
}

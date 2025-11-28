/**
 * Base score aggregator classes
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatLevel, ThreatScore } from '../pipeline/types';
import type { IScoreAggregator } from './types';

/**
 * Base class for score aggregators
 */
export abstract class BaseScoreAggregator implements IScoreAggregator {
  abstract name: string;
  abstract aggregate(results: DetectorResult[]): ThreatScore;

  /**
   * Calculate threat level from score
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

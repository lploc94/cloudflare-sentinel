/**
 * Scoring types for Cloudflare Sentinel
 */

import type { DetectorResult } from '../detector/base';
import type { ThreatScore } from '../pipeline/types';

/**
 * Score aggregator interface
 * Combines multiple detection results into a single threat score
 */
export interface IScoreAggregator {
  /** Aggregator name */
  name: string;
  
  /**
   * Aggregate detection results into threat score
   */
  aggregate(results: DetectorResult[]): ThreatScore;
}

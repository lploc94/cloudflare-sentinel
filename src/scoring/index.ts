/**
 * Scoring exports
 */

export type { IScoreAggregator } from './types';
export { BaseScoreAggregator } from './base';

export { MaxScoreAggregator } from './max.aggregator';
export { WeightedAggregator, type DetectorWeights } from './weighted.aggregator';

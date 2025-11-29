/**
 * Max Score Aggregator tests
 */

import { describe, it, expect } from 'vitest';
import { MaxScoreAggregator } from './max.aggregator';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from '../detector/base';

function createResult(overrides: Partial<DetectorResult> = {}): DetectorResult {
  return {
    detected: true,
    attackType: AttackType.SQL_INJECTION,
    severity: SecuritySeverity.HIGH,
    confidence: 1.0,
    detectorName: 'test',
    ...overrides,
  };
}

describe('MaxScoreAggregator', () => {
  describe('Empty results', () => {
    it('should return score 0 for empty results', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([]);

      expect(result.score).toBe(0);
      expect(result.level).toBe('none');
      expect(result.results).toHaveLength(0);
    });
  });

  describe('Single result', () => {
    it('should return score based on severity and confidence', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.HIGH, confidence: 1.0 }),
      ]);

      expect(result.score).toBe(80); // HIGH = 80
    });

    it('should factor in confidence', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.HIGH, confidence: 0.5 }),
      ]);

      expect(result.score).toBe(40); // HIGH(80) * 0.5 = 40
    });
  });

  describe('Multiple results', () => {
    it('should return the highest score', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.LOW, confidence: 1.0 }),    // 40
        createResult({ severity: SecuritySeverity.CRITICAL, confidence: 1.0 }), // 100
        createResult({ severity: SecuritySeverity.MEDIUM, confidence: 1.0 }),  // 60
      ]);

      expect(result.score).toBe(100); // CRITICAL = 100
    });

    it('should consider confidence in max calculation', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.CRITICAL, confidence: 0.3 }), // 100 * 0.3 = 30
        createResult({ severity: SecuritySeverity.HIGH, confidence: 0.9 }),     // 80 * 0.9 = 72
      ]);

      expect(result.score).toBe(72); // HIGH with 0.9 confidence wins
    });
  });

  describe('Threat level calculation', () => {
    it('should return none for score 0', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([]);
      expect(result.level).toBe('none');
    });

    it('should return low for score 20-39', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.LOW, confidence: 1.0 }), // LOW=25
      ]);
      expect(result.level).toBe('low');
    });

    it('should return medium for score 40-59', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.MEDIUM, confidence: 1.0 }), // MEDIUM=50
      ]);
      expect(result.level).toBe('medium');
    });

    it('should return high for score 60-79', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.HIGH, confidence: 0.85 }), // HIGH(80) * 0.85 = 68
      ]);
      expect(result.level).toBe('high');
    });

    it('should return critical for score 80+', () => {
      const aggregator = new MaxScoreAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.CRITICAL, confidence: 0.85 }), // CRITICAL(100) * 0.85 = 85
      ]);
      expect(result.level).toBe('critical');
    });
  });

  describe('Results preservation', () => {
    it('should include all results in output', () => {
      const aggregator = new MaxScoreAggregator();
      const inputs = [
        createResult({ detectorName: 'detector1' }),
        createResult({ detectorName: 'detector2' }),
      ];
      
      const result = aggregator.aggregate(inputs);
      
      expect(result.results).toHaveLength(2);
      expect(result.results).toBe(inputs);
    });
  });
});

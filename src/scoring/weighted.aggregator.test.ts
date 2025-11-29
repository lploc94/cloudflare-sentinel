/**
 * Weighted Aggregator tests
 */

import { describe, it, expect } from 'vitest';
import { WeightedAggregator } from './weighted.aggregator';
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

describe('WeightedAggregator', () => {
  describe('Empty results', () => {
    it('should return score 0 for empty results', () => {
      const aggregator = new WeightedAggregator();
      const result = aggregator.aggregate([]);

      expect(result.score).toBe(0);
      expect(result.level).toBe('none');
    });
  });

  describe('Without weights', () => {
    it('should calculate average of scores', () => {
      const aggregator = new WeightedAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.HIGH, confidence: 1.0 }),    // HIGH=80
        createResult({ severity: SecuritySeverity.MEDIUM, confidence: 1.0 }),  // MEDIUM=50
      ]);

      expect(result.score).toBe(65); // (80 + 50) / 2 = 65
    });

    it('should factor in confidence', () => {
      const aggregator = new WeightedAggregator();
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.HIGH, confidence: 0.5 }),   // 80 * 0.5 = 40
        createResult({ severity: SecuritySeverity.HIGH, confidence: 1.0 }),   // 80 * 1.0 = 80
      ]);

      expect(result.score).toBe(60); // (40 + 80) / 2 = 60
    });
  });

  describe('With weights', () => {
    it('should apply detector weights', () => {
      const aggregator = new WeightedAggregator({
        'important': 2.0,
        'normal': 1.0,
      });
      
      const result = aggregator.aggregate([
        createResult({ detectorName: 'important', severity: SecuritySeverity.HIGH, confidence: 1.0 }), // 80 * 2.0 = 160
        createResult({ detectorName: 'normal', severity: SecuritySeverity.HIGH, confidence: 1.0 }),    // 80 * 1.0 = 80
      ]);

      expect(result.score).toBe(120); // (160 + 80) / 2 = 120
    });

    it('should use default weight 1.0 for unknown detectors', () => {
      const aggregator = new WeightedAggregator({
        'known': 2.0,
      });
      
      const result = aggregator.aggregate([
        createResult({ detectorName: 'known', severity: SecuritySeverity.HIGH, confidence: 1.0 }),   // 80 * 2.0 = 160
        createResult({ detectorName: 'unknown', severity: SecuritySeverity.HIGH, confidence: 1.0 }), // 80 * 1.0 = 80
      ]);

      expect(result.score).toBe(120); // (160 + 80) / 2 = 120
    });

    it('should support fractional weights', () => {
      const aggregator = new WeightedAggregator({
        'less-important': 0.5,
      });
      
      const result = aggregator.aggregate([
        createResult({ detectorName: 'less-important', severity: SecuritySeverity.CRITICAL, confidence: 1.0 }), // 100 * 0.5 = 50
      ]);

      expect(result.score).toBe(50);
    });
  });

  describe('Threat level calculation', () => {
    it('should calculate correct threat level', () => {
      const aggregator = new WeightedAggregator();
      
      // HIGH(80) average = 80 → critical (>= 80)
      const result = aggregator.aggregate([
        createResult({ severity: SecuritySeverity.HIGH, confidence: 1.0 }),
        createResult({ severity: SecuritySeverity.HIGH, confidence: 1.0 }),
      ]);

      expect(result.level).toBe('critical'); // 80 >= 80
    });
  });

  describe('Results preservation', () => {
    it('should include all results in output', () => {
      const aggregator = new WeightedAggregator();
      const inputs = [
        createResult({ detectorName: 'detector1' }),
        createResult({ detectorName: 'detector2' }),
        createResult({ detectorName: 'detector3' }),
      ];
      
      const result = aggregator.aggregate(inputs);
      
      expect(result.results).toHaveLength(3);
    });
  });
});

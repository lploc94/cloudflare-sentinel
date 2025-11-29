/**
 * Classifier tests
 */

import { describe, it, expect } from 'vitest';
import { LinearClassifier, MultiOutputClassifier, type ModelWeights, type MultiOutputModelWeights } from './classifier';

// Simple mock model for testing
function createMockModel(): ModelWeights {
  return {
    type: 'logistic_regression',
    classes: ['safe', 'attack'],
    weights: [
      new Array(100).fill(0).map((_, i) => i % 2 === 0 ? 0.1 : -0.1), // safe
      new Array(100).fill(0).map((_, i) => i % 2 === 0 ? -0.1 : 0.1), // attack
    ],
    bias: [0.5, -0.5],
    vectorizer: {
      nFeatures: 100,
      ngramRange: [3, 5] as [number, number],
      analyzer: 'char_wb' as const,
    },
  };
}

function createMultiClassModel(): ModelWeights {
  return {
    type: 'logistic_regression',
    classes: ['safe', 'sqli', 'xss', 'cmd_injection'],
    weights: [
      new Array(100).fill(0.1),   // safe
      new Array(100).fill(-0.1),  // sqli
      new Array(100).fill(-0.05), // xss
      new Array(100).fill(-0.02), // cmd_injection
    ],
    bias: [1.0, -0.5, -0.3, -0.2],
    vectorizer: {
      nFeatures: 100,
      ngramRange: [3, 5] as [number, number],
      analyzer: 'char_wb' as const,
    },
  };
}

describe('LinearClassifier', () => {
  describe('Constructor', () => {
    it('should create classifier from model weights', () => {
      const model = createMockModel();
      const classifier = new LinearClassifier(model);
      
      expect(classifier).toBeInstanceOf(LinearClassifier);
    });

    it('should use vectorizer config from model', () => {
      const model = createMockModel();
      const classifier = new LinearClassifier(model);
      const info = classifier.getInfo();

      expect(info.nFeatures).toBe(100);
      expect(info.classes).toEqual(['safe', 'attack']);
    });
  });

  describe('predictText()', () => {
    it('should return prediction with all fields', () => {
      const classifier = new LinearClassifier(createMockModel());
      const prediction = classifier.predictText('normal text');

      expect(prediction).toHaveProperty('class');
      expect(prediction).toHaveProperty('confidence');
      expect(prediction).toHaveProperty('probabilities');
      expect(prediction).toHaveProperty('rawScores');
    });

    it('should return confidence between 0 and 1', () => {
      const classifier = new LinearClassifier(createMockModel());
      const prediction = classifier.predictText('test input');

      expect(prediction.confidence).toBeGreaterThanOrEqual(0);
      expect(prediction.confidence).toBeLessThanOrEqual(1);
    });

    it('should return valid class', () => {
      const classifier = new LinearClassifier(createMockModel());
      const prediction = classifier.predictText('test');

      expect(['safe', 'attack']).toContain(prediction.class);
    });

    it('should return probabilities for all classes', () => {
      const classifier = new LinearClassifier(createMockModel());
      const prediction = classifier.predictText('test');

      expect(Object.keys(prediction.probabilities)).toEqual(['safe', 'attack']);
    });

    it('should have probabilities sum to 1', () => {
      const classifier = new LinearClassifier(createMockModel());
      const prediction = classifier.predictText('test');

      const sum = Object.values(prediction.probabilities).reduce((a, b) => a + b, 0);
      expect(sum).toBeCloseTo(1.0, 5);
    });
  });

  describe('predict()', () => {
    it('should work with sparse feature map', () => {
      const classifier = new LinearClassifier(createMockModel());
      const features = new Map<number, number>([
        [5, 1],
        [10, 2],
        [50, 1],
      ]);

      const prediction = classifier.predict(features);
      expect(prediction).toHaveProperty('class');
    });

    it('should handle empty features', () => {
      const classifier = new LinearClassifier(createMockModel());
      const features = new Map<number, number>();

      const prediction = classifier.predict(features);
      expect(prediction).toHaveProperty('class');
    });

    it('should ignore out-of-range features', () => {
      const classifier = new LinearClassifier(createMockModel());
      const features = new Map<number, number>([
        [5, 1],
        [999, 1], // Out of range (nFeatures=100)
      ]);

      // Should not throw
      const prediction = classifier.predict(features);
      expect(prediction).toHaveProperty('class');
    });
  });

  describe('Multi-class', () => {
    it('should handle multiple classes', () => {
      const classifier = new LinearClassifier(createMultiClassModel());
      const prediction = classifier.predictText('SELECT * FROM users');

      expect(['safe', 'sqli', 'xss', 'cmd_injection']).toContain(prediction.class);
      expect(Object.keys(prediction.probabilities)).toHaveLength(4);
    });
  });

  describe('getInfo()', () => {
    it('should return model info', () => {
      const classifier = new LinearClassifier(createMockModel());
      const info = classifier.getInfo();

      expect(info.classes).toEqual(['safe', 'attack']);
      expect(info.nFeatures).toBe(100);
    });
  });
});

describe('MultiOutputClassifier', () => {
  function createMultiOutputModel(): MultiOutputModelWeights {
    return {
      attackType: {
        type: 'logistic_regression',
        classes: ['safe', 'sqli', 'xss'],
        weights: [
          new Array(100).fill(0.1),
          new Array(100).fill(-0.1),
          new Array(100).fill(-0.05),
        ],
        bias: [1.0, -0.5, -0.3],
        vectorizer: {
          nFeatures: 100,
          ngramRange: [3, 5] as [number, number],
          analyzer: 'char_wb' as const,
        },
      },
      severity: {
        type: 'logistic_regression',
        classes: ['low', 'medium', 'high', 'critical'],
        weights: [
          new Array(100).fill(0.1),
          new Array(100).fill(0.05),
          new Array(100).fill(-0.05),
          new Array(100).fill(-0.1),
        ],
        bias: [0.5, 0.3, -0.3, -0.5],
        vectorizer: {
          nFeatures: 100,
          ngramRange: [3, 5] as [number, number],
          analyzer: 'char_wb' as const,
        },
      },
    };
  }

  describe('predict()', () => {
    it('should return attackType and severity predictions', () => {
      const classifier = new MultiOutputClassifier(createMultiOutputModel());
      const prediction = classifier.predict('test input');

      expect(prediction).toHaveProperty('attackType');
      expect(prediction).toHaveProperty('severity');
      expect(prediction).toHaveProperty('confidence');
      expect(prediction).toHaveProperty('isAttack');
    });

    it('should return valid attack type class', () => {
      const classifier = new MultiOutputClassifier(createMultiOutputModel());
      const prediction = classifier.predict('test');

      expect(['safe', 'sqli', 'xss']).toContain(prediction.attackType.class);
    });

    it('should return valid severity class', () => {
      const classifier = new MultiOutputClassifier(createMultiOutputModel());
      const prediction = classifier.predict('test');

      expect(['low', 'medium', 'high', 'critical']).toContain(prediction.severity.class);
    });

    it('should compute combined confidence', () => {
      const classifier = new MultiOutputClassifier(createMultiOutputModel());
      const prediction = classifier.predict('test');

      // Combined confidence = min of both
      expect(prediction.confidence).toBeLessThanOrEqual(prediction.attackType.confidence);
      expect(prediction.confidence).toBeLessThanOrEqual(prediction.severity.confidence);
    });

    it('should set isAttack correctly', () => {
      const classifier = new MultiOutputClassifier(createMultiOutputModel());
      const prediction = classifier.predict('test');

      // isAttack is true if class is not 'safe' and confidence > 0.5
      if (prediction.attackType.class === 'safe') {
        expect(prediction.isAttack).toBe(false);
      }
    });
  });
});

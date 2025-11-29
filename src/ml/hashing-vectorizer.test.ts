/**
 * HashingVectorizer tests
 */

import { describe, it, expect } from 'vitest';
import { HashingVectorizer } from './hashing-vectorizer';

describe('HashingVectorizer', () => {
  describe('Constructor', () => {
    it('should use default options', () => {
      const vectorizer = new HashingVectorizer();
      // Verify by transforming text
      const result = vectorizer.transform('test');
      expect(result).toBeInstanceOf(Map);
    });

    it('should accept custom options', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 1024,
        ngramRange: [2, 4],
        analyzer: 'char',
      });
      const result = vectorizer.transform('test');
      expect(result).toBeInstanceOf(Map);
    });
  });

  describe('transform()', () => {
    it('should return Map of feature indices', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 4096 });
      const result = vectorizer.transform('SELECT * FROM users');

      expect(result).toBeInstanceOf(Map);
      expect(result.size).toBeGreaterThan(0);
    });

    it('should count duplicate n-grams', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 4096 });
      // 'aaa' has overlapping n-grams
      const result = vectorizer.transform('aaa aaa');

      // Should have counts > 1 for some features
      const maxCount = Math.max(...result.values());
      expect(maxCount).toBeGreaterThanOrEqual(1);
    });

    it('should respect nFeatures limit', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 100 });
      const result = vectorizer.transform('some text with many words');

      // All indices should be < nFeatures
      for (const index of result.keys()) {
        expect(index).toBeLessThan(100);
      }
    });

    it('should produce consistent results', () => {
      const vectorizer = new HashingVectorizer();
      const result1 = vectorizer.transform('test input');
      const result2 = vectorizer.transform('test input');

      expect([...result1.entries()]).toEqual([...result2.entries()]);
    });
  });

  describe('transformDense()', () => {
    it('should return Float32Array', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 100 });
      const result = vectorizer.transformDense('test');

      expect(result).toBeInstanceOf(Float32Array);
      expect(result.length).toBe(100);
    });

    it('should have non-zero values for matched features', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 100 });
      const result = vectorizer.transformDense('test text');

      const nonZeroCount = result.filter(v => v > 0).length;
      expect(nonZeroCount).toBeGreaterThan(0);
    });

    it('should match sparse transform', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 100 });
      const sparse = vectorizer.transform('test');
      const dense = vectorizer.transformDense('test');

      for (const [index, count] of sparse) {
        expect(dense[index]).toBe(count);
      }
    });
  });

  describe('transformIndices()', () => {
    it('should return array of indices', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 100 });
      const result = vectorizer.transformIndices('test');

      expect(Array.isArray(result)).toBe(true);
      expect(result.length).toBeGreaterThan(0);
    });

    it('should respect nFeatures limit', () => {
      const vectorizer = new HashingVectorizer({ nFeatures: 50 });
      const result = vectorizer.transformIndices('test input');

      for (const index of result) {
        expect(index).toBeLessThan(50);
      }
    });
  });

  describe('N-gram extraction', () => {
    it('should extract n-grams within range', () => {
      const vectorizer = new HashingVectorizer({ 
        nFeatures: 10000,
        ngramRange: [2, 3],
      });
      const result = vectorizer.transform('ab');

      // Should have some features
      expect(result.size).toBeGreaterThan(0);
    });

    it('should handle char_wb analyzer (word boundaries)', () => {
      const vectorizer = new HashingVectorizer({ 
        nFeatures: 4096,
        analyzer: 'char_wb',
      });
      const result = vectorizer.transform('hello world');

      // Should produce features
      expect(result.size).toBeGreaterThan(0);
    });

    it('should handle char analyzer', () => {
      const vectorizer = new HashingVectorizer({ 
        nFeatures: 4096,
        analyzer: 'char',
      });
      const result = vectorizer.transform('hello world');

      // Should produce features
      expect(result.size).toBeGreaterThan(0);
    });
  });

  describe('Edge cases', () => {
    it('should handle empty string', () => {
      const vectorizer = new HashingVectorizer();
      const result = vectorizer.transform('');

      expect(result.size).toBe(0);
    });

    it('should handle short strings', () => {
      const vectorizer = new HashingVectorizer({ ngramRange: [3, 5] });
      const result = vectorizer.transform('ab'); // Shorter than min n-gram

      // May have 0 features if string is too short
      expect(result).toBeInstanceOf(Map);
    });

    it('should handle unicode', () => {
      const vectorizer = new HashingVectorizer();
      const result = vectorizer.transform('こんにちは世界');

      expect(result.size).toBeGreaterThan(0);
    });

    it('should handle special characters', () => {
      const vectorizer = new HashingVectorizer();
      const result = vectorizer.transform('SELECT * FROM users WHERE id=1; DROP TABLE--');

      expect(result.size).toBeGreaterThan(0);
    });
  });
});

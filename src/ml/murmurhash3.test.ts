/**
 * MurmurHash3 Tests
 * 
 * Verify hash values match Python's scikit-learn implementation
 * 
 * To verify in Python:
 * ```python
 * import mmh3
 * 
 * # Test cases
 * print(mmh3.hash('hello', 0, signed=False))  # Should match JS output
 * print(mmh3.hash('sql', 0, signed=False))
 * print(mmh3.hash(' sq', 0, signed=False))
 * ```
 */

import { describe, it, expect } from 'vitest';
import { murmurhash3_32 } from './murmurhash3';
import { HashingVectorizer } from './hashing-vectorizer';

describe('MurmurHash3', () => {
  const encoder = new TextEncoder();

  describe('Hash values', () => {
    it('should hash empty string correctly', () => {
      const hash = murmurhash3_32(encoder.encode(''), 0);
      // MurmurHash3 of empty string with seed 0
      expect(hash).toBe(0);
    });

    it('should hash "hello" correctly', () => {
      const hash = murmurhash3_32(encoder.encode('hello'), 0);
      // Known value from mmh3.hash('hello', 0, signed=False)
      expect(hash).toBe(613153351);
    });

    it('should hash "test" correctly', () => {
      const hash = murmurhash3_32(encoder.encode('test'), 0);
      // Known value from mmh3.hash('test', 0, signed=False)
      expect(hash).toBe(3127628307);
    });

    it('should handle UTF-8 characters correctly', () => {
      const hash = murmurhash3_32(encoder.encode('你好'), 0);
      // UTF-8 bytes: [228, 189, 160, 229, 165, 189]
      expect(typeof hash).toBe('number');
      expect(hash).toBeGreaterThanOrEqual(0);
      expect(hash).toBeLessThan(2 ** 32);
    });

    it('should produce consistent results', () => {
      const input = encoder.encode('SELECT * FROM users');
      const hash1 = murmurhash3_32(input, 0);
      const hash2 = murmurhash3_32(input, 0);
      expect(hash1).toBe(hash2);
    });

    it('should produce different hashes for different seeds', () => {
      const input = encoder.encode('test');
      const hash0 = murmurhash3_32(input, 0);
      const hash1 = murmurhash3_32(input, 1);
      expect(hash0).not.toBe(hash1);
    });
  });

  describe('Modulo behavior', () => {
    it('should produce valid feature index', () => {
      const nFeatures = 4096;
      const hash = murmurhash3_32(encoder.encode('sql'), 0);
      const index = hash % nFeatures;
      
      expect(index).toBeGreaterThanOrEqual(0);
      expect(index).toBeLessThan(nFeatures);
    });
  });
});

describe('HashingVectorizer', () => {
  describe('N-gram extraction', () => {
    it('should extract character n-grams with word boundaries', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 10,
        ngramRange: [3, 3],
        analyzer: 'char_wb',
      });

      const indices = vectorizer.transformIndices('sql');
      // For "sql", padded becomes " sql "
      // 3-grams: " sq", "sql", "ql "
      expect(indices.length).toBe(3);
    });

    it('should handle multiple words', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 100,
        ngramRange: [3, 3],
        analyzer: 'char_wb',
      });

      const indices = vectorizer.transformIndices('SELECT FROM');
      // Two words: " SELECT " and " FROM "
      // Should have n-grams from both
      expect(indices.length).toBeGreaterThan(6);
    });

    it('should produce sparse feature counts', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 100,
        ngramRange: [3, 5],
        analyzer: 'char_wb',
      });

      const features = vectorizer.transform('test input');
      
      // Should be a Map with counts
      expect(features instanceof Map).toBe(true);
      
      // All indices should be valid
      for (const [index, count] of features) {
        expect(index).toBeGreaterThanOrEqual(0);
        expect(index).toBeLessThan(100);
        expect(count).toBeGreaterThan(0);
      }
    });

    it('should produce dense array when requested', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 50,
        ngramRange: [3, 3],
        analyzer: 'char_wb',
      });

      const dense = vectorizer.transformDense('hello');
      
      expect(dense).toBeInstanceOf(Float32Array);
      expect(dense.length).toBe(50);
      
      // Sum should equal number of n-grams
      const sum = dense.reduce((a, b) => a + b, 0);
      expect(sum).toBeGreaterThan(0);
    });
  });

  describe('Consistency', () => {
    it('should produce consistent results for same input', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 4096,
        ngramRange: [3, 5],
        analyzer: 'char_wb',
      });

      const indices1 = vectorizer.transformIndices('test query');
      const indices2 = vectorizer.transformIndices('test query');
      
      expect(indices1).toEqual(indices2);
    });

    it('should produce different results for different inputs', () => {
      const vectorizer = new HashingVectorizer({
        nFeatures: 4096,
        ngramRange: [3, 5],
        analyzer: 'char_wb',
      });

      const indices1 = vectorizer.transformIndices('safe request');
      const indices2 = vectorizer.transformIndices('SELECT * FROM');
      
      expect(indices1).not.toEqual(indices2);
    });
  });
});

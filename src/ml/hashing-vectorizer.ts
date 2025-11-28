/**
 * HashingVectorizer - Pure TypeScript implementation
 * 
 * Matches scikit-learn's HashingVectorizer with:
 * - analyzer='char_wb' (character n-grams with word boundaries)
 * - alternate_sign=False
 * - norm=None
 * 
 * @example
 * ```typescript
 * const vectorizer = new HashingVectorizer({ nFeatures: 4096, ngramRange: [3, 5] });
 * const indices = vectorizer.transform('SELECT * FROM users');
 * // indices: [123, 456, 789, ...] - feature indices for ML model
 * ```
 */

import { murmurhash3_32 } from './murmurhash3';

export interface HashingVectorizerOptions {
  /** Number of features (default: 4096) */
  nFeatures?: number;
  /** N-gram range [min, max] (default: [3, 5]) */
  ngramRange?: [number, number];
  /** Analyzer type (default: 'char_wb') */
  analyzer?: 'char_wb' | 'char';
}

/**
 * HashingVectorizer compatible with scikit-learn
 * 
 * Use with sklearn config:
 * ```python
 * HashingVectorizer(
 *   n_features=4096,
 *   analyzer='char_wb',
 *   ngram_range=(3, 5),
 *   alternate_sign=False,
 *   norm=None
 * )
 * ```
 */
export class HashingVectorizer {
  private nFeatures: number;
  private ngramRange: [number, number];
  private analyzer: 'char_wb' | 'char';
  private encoder: TextEncoder;

  constructor(options: HashingVectorizerOptions = {}) {
    this.nFeatures = options.nFeatures ?? 4096;
    this.ngramRange = options.ngramRange ?? [3, 5];
    this.analyzer = options.analyzer ?? 'char_wb';
    this.encoder = new TextEncoder();
  }

  /**
   * Transform text to feature indices (sparse representation)
   * 
   * @param text - Input text to vectorize
   * @returns Array of feature indices with counts
   */
  transform(text: string): Map<number, number> {
    const ngrams = this.extractNgrams(text);
    const featureCounts = new Map<number, number>();

    for (const gram of ngrams) {
      const bytes = this.encoder.encode(gram);
      const hash = murmurhash3_32(bytes, 0);
      const index = hash % this.nFeatures;
      
      featureCounts.set(index, (featureCounts.get(index) ?? 0) + 1);
    }

    return featureCounts;
  }

  /**
   * Transform text to dense feature array
   * 
   * @param text - Input text to vectorize
   * @returns Dense array of feature counts
   */
  transformDense(text: string): Float32Array {
    const sparse = this.transform(text);
    const dense = new Float32Array(this.nFeatures);
    
    for (const [index, count] of sparse) {
      dense[index] = count;
    }
    
    return dense;
  }

  /**
   * Transform text to feature indices only (for quick lookup)
   * 
   * @param text - Input text to vectorize
   * @returns Array of feature indices (may contain duplicates)
   */
  transformIndices(text: string): number[] {
    const ngrams = this.extractNgrams(text);
    const indices: number[] = [];

    for (const gram of ngrams) {
      const bytes = this.encoder.encode(gram);
      const hash = murmurhash3_32(bytes, 0);
      const index = hash % this.nFeatures;
      indices.push(index);
    }

    return indices;
  }

  /**
   * Extract n-grams from text
   */
  private extractNgrams(text: string): string[] {
    const ngrams: string[] = [];
    const [minN, maxN] = this.ngramRange;

    if (this.analyzer === 'char_wb') {
      // Word boundary mode: pad with spaces and extract from each word
      const words = text.split(/\s+/).filter(w => w.length > 0);
      
      for (const word of words) {
        const padded = ' ' + word + ' ';
        this.extractCharNgrams(padded, minN, maxN, ngrams);
      }
    } else {
      // Simple char mode
      this.extractCharNgrams(text, minN, maxN, ngrams);
    }

    return ngrams;
  }

  /**
   * Extract character n-grams from a string
   */
  private extractCharNgrams(text: string, minN: number, maxN: number, output: string[]): void {
    const len = text.length;

    for (let n = minN; n <= maxN; n++) {
      for (let i = 0; i <= len - n; i++) {
        output.push(text.substring(i, i + n));
      }
    }
  }
}

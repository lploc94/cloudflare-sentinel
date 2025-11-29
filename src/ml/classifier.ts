/**
 * Lightweight ML Classifier
 * 
 * Pure TypeScript implementation of linear classifiers for real-time
 * request classification in Cloudflare Workers. No external dependencies.
 * 
 * **Supported Model Types:**
 * - LogisticRegression (sklearn)
 * - LinearSVC (sklearn)
 * - SGDClassifier (sklearn)
 * 
 * **Model Format (JSON):**
 * ```json
 * {
 *   "type": "logistic_regression",
 *   "classes": ["safe", "sqli", "xss", "cmd_injection"],
 *   "weights": [[...], [...], ...],  // shape: [n_classes, n_features]
 *   "bias": [0.1, -0.2, ...],         // shape: [n_classes]
 *   "vectorizer": {
 *     "nFeatures": 4096,
 *     "ngramRange": [3, 5],
 *     "analyzer": "char_wb"
 *   }
 * }
 * ```
 * 
 * **Training:** See `/scripts/training/README.md` for training custom models.
 * 
 * **Performance:**
 * - Uses Float32Array for memory efficiency
 * - Sparse dot product for fast inference
 * - ~1-5ms per prediction on Workers
 * 
 * @module ml
 * 
 * @example
 * ```typescript
 * import { LinearClassifier } from 'cloudflare-sentinel';
 * import modelJson from './models/classifier.json';
 * 
 * const classifier = new LinearClassifier(modelJson);
 * 
 * // Classify raw text
 * const prediction = classifier.predictText('SELECT * FROM users WHERE id=1');
 * console.log(prediction.class);      // 'sqli'
 * console.log(prediction.confidence); // 0.92
 * 
 * // Or use with pre-computed features
 * const features = vectorizer.transform(text);
 * const prediction = classifier.predict(features);
 * ```
 */

import { HashingVectorizer } from './hashing-vectorizer';

export interface ModelWeights {
  /** Model type */
  type: 'logistic_regression' | 'linear_svc' | 'sgd';
  /** Class labels */
  classes: string[];
  /** Weight matrix [n_classes x n_features] */
  weights: number[][];
  /** Bias vector [n_classes] */
  bias: number[];
  /** Vectorizer config */
  vectorizer?: {
    nFeatures: number;
    ngramRange: [number, number];
    analyzer: 'char_wb' | 'char';
  };
}

export interface Prediction {
  /** Predicted class */
  class: string;
  /** Confidence score (0-1) */
  confidence: number;
  /** Probabilities for each class */
  probabilities: Record<string, number>;
  /** Raw scores (before softmax) */
  rawScores: Record<string, number>;
}

/**
 * Linear classifier for binary or multi-class classification
 * 
 * Implements linear classification with softmax probabilities.
 * Compatible with scikit-learn exported models.
 * 
 * **How it works:**
 * 1. Text → HashingVectorizer → sparse features
 * 2. Features × Weights + Bias → raw scores
 * 3. Softmax(scores) → probabilities
 * 4. argmax(probabilities) → predicted class
 * 
 * @example
 * ```typescript
 * // Load model from JSON
 * import modelJson from './classifier.json';
 * const classifier = new LinearClassifier(modelJson);
 * 
 * // Predict from text
 * const result = classifier.predictText('user input');
 * if (result.class !== 'safe' && result.confidence > 0.8) {
 *   console.log('Attack detected:', result.class);
 * }
 * ```
 */
export class LinearClassifier {
  private classes: string[];
  private weights: Float32Array[];
  private bias: Float32Array;
  private nFeatures: number;
  private vectorizer: HashingVectorizer;

  /**
   * Create classifier from model weights
   * 
   * @param model - Exported model weights (from training script)
   */
  constructor(model: ModelWeights) {
    this.classes = model.classes;
    this.nFeatures = model.weights[0].length;
    
    // Convert to typed arrays for performance
    this.weights = model.weights.map(w => new Float32Array(w));
    this.bias = new Float32Array(model.bias);
    
    // Initialize vectorizer
    this.vectorizer = new HashingVectorizer(model.vectorizer ?? {
      nFeatures: this.nFeatures,
      ngramRange: [3, 5],
      analyzer: 'char_wb',
    });
  }

  /**
   * Predict class for raw text input
   */
  predictText(text: string): Prediction {
    const features = this.vectorizer.transform(text);
    return this.predict(features);
  }

  /**
   * Predict class from feature map
   */
  predict(features: Map<number, number>): Prediction {
    const scores = this.computeScores(features);
    const probabilities = this.softmax(scores);
    
    // Find max
    let maxIdx = 0;
    let maxProb = probabilities[0];
    for (let i = 1; i < probabilities.length; i++) {
      if (probabilities[i] > maxProb) {
        maxProb = probabilities[i];
        maxIdx = i;
      }
    }

    // Build result
    const rawScores: Record<string, number> = {};
    const probs: Record<string, number> = {};
    for (let i = 0; i < this.classes.length; i++) {
      rawScores[this.classes[i]] = scores[i];
      probs[this.classes[i]] = probabilities[i];
    }

    return {
      class: this.classes[maxIdx],
      confidence: maxProb,
      probabilities: probs,
      rawScores,
    };
  }

  /**
   * Compute raw scores (logits) for each class
   */
  private computeScores(features: Map<number, number>): number[] {
    const scores: number[] = new Array(this.classes.length);

    for (let c = 0; c < this.classes.length; c++) {
      let score = this.bias[c];
      const w = this.weights[c];

      // Sparse dot product
      for (const [index, count] of features) {
        if (index < this.nFeatures) {
          score += w[index] * count;
        }
      }

      scores[c] = score;
    }

    return scores;
  }

  /**
   * Softmax normalization
   */
  private softmax(scores: number[]): number[] {
    // Numerical stability: subtract max
    const max = Math.max(...scores);
    const exps = scores.map(s => Math.exp(s - max));
    const sum = exps.reduce((a, b) => a + b, 0);
    return exps.map(e => e / sum);
  }

  /**
   * Get model info
   */
  getInfo(): { classes: string[]; nFeatures: number } {
    return {
      classes: this.classes,
      nFeatures: this.nFeatures,
    };
  }
}

/**
 * Multi-output classifier for severity + attack type
 * 
 * Model format:
 * ```json
 * {
 *   "attackType": { ... },   // LinearClassifier model
 *   "severity": { ... }      // LinearClassifier model
 * }
 * ```
 */
export interface MultiOutputModelWeights {
  attackType: ModelWeights;
  severity: ModelWeights;
}

export interface MultiOutputPrediction {
  attackType: Prediction;
  severity: Prediction;
  /** Combined confidence */
  confidence: number;
  /** Is this likely an attack? */
  isAttack: boolean;
}

export class MultiOutputClassifier {
  private attackTypeClassifier: LinearClassifier;
  private severityClassifier: LinearClassifier;
  private vectorizer: HashingVectorizer;

  constructor(model: MultiOutputModelWeights) {
    this.attackTypeClassifier = new LinearClassifier(model.attackType);
    this.severityClassifier = new LinearClassifier(model.severity);
    
    // Share vectorizer config
    this.vectorizer = new HashingVectorizer(model.attackType.vectorizer ?? {
      nFeatures: model.attackType.weights[0].length,
      ngramRange: [3, 5],
      analyzer: 'char_wb',
    });
  }

  predict(text: string): MultiOutputPrediction {
    const features = this.vectorizer.transform(text);
    
    const attackType = this.attackTypeClassifier.predict(features);
    const severity = this.severityClassifier.predict(features);
    
    // Combined confidence
    const confidence = Math.min(attackType.confidence, severity.confidence);
    
    // Is attack if not "safe" class
    const isAttack = attackType.class !== 'safe' && attackType.confidence > 0.5;

    return {
      attackType,
      severity,
      confidence,
      isAttack,
    };
  }
}

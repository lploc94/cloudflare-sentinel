/**
 * ML-based Detector
 * 
 * Uses a lightweight classifier to detect suspicious requests.
 * Output: confidence (0-1) and severity based on ML score.
 * 
 * @example
 * ```typescript
 * // Use default bundled model
 * new MLDetector()
 * 
 * // Or provide custom model
 * new MLDetector({ model: customModelWeights })
 * ```
 */

import { BaseDetector, DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';
import { LinearClassifier, ModelWeights } from '../ml/classifier';
import defaultModel from '../ml/models/classifier.json';

export interface MLDetectorOptions {
  /** Custom model weights (default: bundled model) */
  model?: ModelWeights;
}

export class MLDetector extends BaseDetector {
  name = 'ml';
  private classifier: LinearClassifier;

  constructor(options: MLDetectorOptions = {}) {
    super();
    this.classifier = new LinearClassifier(options.model ?? defaultModel as ModelWeights);
  }

  async detectRequest(
    request: Request,
    context: any
  ): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    const requestText = this.buildRequestText(request, url, context?.body);
    
    const prediction = this.classifier.predictText(requestText);
    const suspiciousScore = prediction.probabilities['suspicious'] || 0;

    // Not suspicious - no detection
    if (prediction.class === 'safe' && prediction.confidence > 0.5) {
      return null;
    }

    // Return detection with score-based confidence and severity
    return this.createResult(
      AttackType.UNKNOWN,
      this.scoreToSeverity(suspiciousScore),
      suspiciousScore,  // confidence 0-1 (from ML score)
      undefined,
      {
        mlClass: prediction.class,
        mlConfidence: prediction.confidence,
        needsLLMReview: prediction.confidence < 0.9,
      }
    );
  }

  /**
   * Map ML score (0-1) to severity
   */
  private scoreToSeverity(score: number): SecuritySeverity {
    if (score >= 0.95) return SecuritySeverity.CRITICAL;
    if (score >= 0.8) return SecuritySeverity.HIGH;
    if (score >= 0.6) return SecuritySeverity.MEDIUM;
    return SecuritySeverity.LOW;
  }

  /**
   * Build request text for classification
   */
  private buildRequestText(request: Request, url: URL, body?: any): string {
    const parts = [`${request.method} ${url.pathname}`];
    
    if (url.search) parts.push(url.search);
    
    if (body) {
      const bodyStr = typeof body === 'string' ? body : JSON.stringify(body);
      parts.push(bodyStr.slice(0, 1000));
    }
    
    return parts.join(' ');
  }
}

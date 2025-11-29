/**
 * ML-based Detector
 * 
 * Uses a lightweight binary classifier to detect suspicious requests.
 * Ideal for catching unknown attack patterns not covered by rule-based detectors.
 * 
 * **Features:**
 * - Bundled model (~224KB) trained on attack payloads
 * - Binary classification: 'safe' vs 'suspicious'
 * - Confidence score 0-1 from model output
 * - Fixed HIGH severity (model doesn't know attack type)
 * - Supports both request and response phases
 * 
 * **Best used for:**
 * - Async monitoring (fire-and-forget)
 * - Pre-filtering before detailed analysis
 * - Catching novel/unknown attack patterns
 * - High-traffic endpoints needing quick triage
 * 
 * @example
 * ```typescript
 * // Basic usage with bundled model
 * new MLDetector()
 * 
 * // With custom trained model
 * new MLDetector({ model: customModelWeights })
 * 
 * // Async monitoring pipeline (recommended)
 * const mlPipeline = createMLMonitoringPipeline({ kv, system });
 * ctx.waitUntil(mlPipeline.process(request, pctx));
 * 
 * // As part of sync pipeline (adds latency)
 * const pipeline = SentinelPipeline.sync([
 *   new MLDetector(),
 *   // other detectors...
 * ]);
 * ```
 * 
 * @remarks
 * **Model training:**
 * See `scripts/training/README.md` for custom model training.
 * 
 * **Metadata includes:**
 * - `mlClass`: 'safe' | 'suspicious'
 * - `mlConfidence`: Model confidence 0-1
 * - `suspiciousScore`: Probability of suspicious class
 * 
 * **Performance:**
 * - ~1-2ms inference time
 * - No external API calls
 * - Works entirely on edge
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
  phase: 'request' | 'response' | 'both' = 'both'; // Support async monitoring
  private classifier: LinearClassifier;

  constructor(options: MLDetectorOptions = {}) {
    super();
    this.classifier = new LinearClassifier(options.model ?? defaultModel as ModelWeights);
  }

  /**
   * Response phase - reuse request detection for async monitoring
   */
  async detectResponse(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    return this.detectRequest(request, context);
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

    // Binary classifier: fixed severity, confidence from model output
    // finalScore = severityToScore(HIGH=80) × suspiciousScore
    return this.createResult(
      AttackType.UNKNOWN,
      SecuritySeverity.HIGH,  // Fixed: binary doesn't know attack type
      suspiciousScore,        // confidence 0-1 from model
      undefined,
      {
        mlClass: prediction.class,
        mlConfidence: prediction.confidence,
        suspiciousScore,
      }
    );
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

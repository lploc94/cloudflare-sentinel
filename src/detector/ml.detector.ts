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
 * // Exclude token fields from analysis (avoid false positives)
 * new MLDetector({
 *   excludeFields: ['token', 'google_token', 'refresh_token', 'access_token'],
 * })
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
  /** Fields to exclude from analysis (e.g., ['token', 'google_token', 'refresh_token']) */
  excludeFields?: string[];
}

export class MLDetector extends BaseDetector {
  name = 'ml';
  phase: 'request' | 'response' | 'both' = 'both'; // Support async monitoring
  private classifier: LinearClassifier;
  private excludeFields: Set<string>;

  constructor(options: MLDetectorOptions = {}) {
    super();
    this.classifier = new LinearClassifier(options.model ?? defaultModel as ModelWeights);
    this.excludeFields = new Set(options.excludeFields ?? ['token', 'access_token', 'refresh_token', 'google_token', 'id_token', 'jwt', 'password', 'secret']);
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
      // Filter out excluded fields from body
      const filteredBody = this.filterBody(body);
      if (filteredBody) {
        const bodyStr = typeof filteredBody === 'string' ? filteredBody : JSON.stringify(filteredBody);
        parts.push(bodyStr.slice(0, 1000));
      }
    }
    
    return parts.join(' ');
  }

  /**
   * Filter out excluded fields from body
   */
  private filterBody(body: any): any {
    if (!body || this.excludeFields.size === 0) return body;
    if (typeof body === 'string') return body;
    if (typeof body !== 'object') return body;
    
    const filtered: Record<string, any> = {};
    for (const [key, value] of Object.entries(body)) {
      if (!this.excludeFields.has(key)) {
        filtered[key] = value;
      }
    }
    
    // Return null if all fields were excluded
    return Object.keys(filtered).length > 0 ? filtered : null;
  }
}

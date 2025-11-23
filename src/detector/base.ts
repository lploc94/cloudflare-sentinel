/**
 * Base detector interface for extensibility
 */

import type { AttackType, SecuritySeverity } from '../types';

/**
 * Evidence of attack detection
 */
export interface DetectionEvidence {
  /** Field where attack was found (query, header, body field) */
  field?: string;
  /** Suspicious value */
  value?: string;
  /** Pattern that matched */
  pattern?: string;
  /** Raw content (sanitized) */
  rawContent?: string;
}

/**
 * Detection result from a detector
 */
export interface DetectorResult {
  /** Was attack detected */
  detected: boolean;
  /** Type of attack */
  attackType: AttackType;
  /** Severity level */
  severity: SecuritySeverity;
  /** Confidence score (0-1) */
  confidence: number;
  /** Evidence of attack */
  evidence?: DetectionEvidence;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * Base detector interface
 * User can implement this to create custom detectors
 */
export interface IDetector {
  /** Detector name */
  name: string;
  
  /** Priority (higher = checked first) */
  priority: number;
  
  /** Enabled */
  enabled?: boolean;
  
  /**
   * Detect attack on incoming request
   * Called BEFORE handler execution
   */
  detectRequest?(
    request: Request,
    context: any
  ): Promise<DetectorResult | null>;
  
  /**
   * Detect attack on response (behavior-based)
   * Called AFTER handler execution
   */
  detectResponse?(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null>;
}

/**
 * Base detector class for convenience
 * User can extend this
 */
export abstract class BaseDetector implements IDetector {
  abstract name: string;
  abstract priority: number;
  enabled: boolean = true;
  
  async detectRequest(
    request: Request,
    context: any
  ): Promise<DetectorResult | null> {
    return null;
  }
  
  async detectResponse(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    return null;
  }
  
  /**
   * Helper: Create detection result
   */
  protected createResult(
    attackType: AttackType,
    severity: SecuritySeverity,
    confidence: number,
    evidence?: DetectionEvidence,
    metadata?: Record<string, any>
  ): DetectorResult {
    return {
      detected: true,
      attackType,
      severity,
      confidence,
      evidence,
      metadata,
    };
  }
}

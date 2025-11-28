/**
 * Base detector interface for extensibility
 */

import { AttackType, SecuritySeverity } from '../types';

/**
 * Detector execution phase
 */
export type DetectorPhase = 'request' | 'response' | 'both';

/**
 * Base options that all detectors can accept
 */
export interface BaseDetectorOptions {
  /** Base confidence score (0-1) - detector may use this or calculate its own */
  baseConfidence?: number;
}

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
  /** Detector name (for weighted scoring and logging) */
  detectorName: string;
  /** Type of attack */
  attackType: AttackType;
  /** Severity level */
  severity: SecuritySeverity;
  /** Confidence score (0-1) */
  confidence: number;
  /** Evidence of attack */
  evidence?: DetectionEvidence;
  /** Additional metadata (phase, timestamp, processingTime, etc.) */
  metadata?: Record<string, any>;
}

/**
 * Base detector interface
 * User can implement this to create custom detectors
 */
export interface IDetector {
  /** Detector name */
  name: string;
  
  /** 
   * Detection phase
   * - request: runs on incoming request
   * - response: runs on response
   * - both: runs on both phases
   */
  phase: DetectorPhase;
  
  /** Priority (higher = checked first) */
  priority?: number;
  
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
  phase: DetectorPhase = 'request';
  priority: number = 50;
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
   * Helper: Create detection result (threat detected)
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
      detectorName: this.name,
      attackType,
      severity,
      confidence,
      evidence,
      metadata: {
        timestamp: Date.now(),
        ...metadata,
      },
    };
  }
  
  /**
   * Helper: Create non-threat result (no detection, but with metadata)
   * Use for cases like whitelisting, rate limiting, etc.
   */
  protected createNonThreatResult(
    metadata?: Record<string, any>
  ): DetectorResult {
    return {
      detected: false,
      detectorName: this.name,
      attackType: AttackType.UNKNOWN,
      severity: SecuritySeverity.LOW,
      confidence: 0,
      metadata: {
        timestamp: Date.now(),
        ...metadata,
      },
    };
  }
}

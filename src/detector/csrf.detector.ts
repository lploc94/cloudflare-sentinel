/**
 * CSRF (Cross-Site Request Forgery) Detector
 * 
 * Detects potential CSRF attacks by validating Origin/Referer headers
 * against the request host for state-changing HTTP methods.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface CSRFDetectorConfig extends BaseDetectorOptions {
  /**
   * Additional allowed origins (besides self)
   * Useful for trusted subdomains or partner sites
   * @example ['https://admin.example.com', 'https://api.example.com']
   */
  allowedOrigins?: string[];
  
  /**
   * HTTP methods to protect (default: POST, PUT, PATCH, DELETE)
   * GET, HEAD, OPTIONS are always skipped (safe methods)
   */
  protectedMethods?: string[];
  
  /**
   * Allow requests from same parent domain (e.g., api.example.com accepts from www.example.com)
   * Default: true
   */
  allowSameParentDomain?: boolean;
  
  /**
   * Require custom header for API calls (e.g., X-Requested-With)
   * Helps prevent simple form-based CSRF
   * Default: false
   */
  requireCustomHeader?: boolean;
  
  /**
   * Custom header name to require (default: 'x-requested-with')
   */
  customHeaderName?: string;
  
  /**
   * Detection mode:
   * - 'strict': Block requests with missing Origin header (recommended for APIs)
   * - 'standard': Only block requests with mismatched Origin (default, more permissive)
   */
  mode?: 'strict' | 'standard';
  
  /**
   * Allow null Origin (can happen with privacy extensions, file://, etc.)
   * Default: false in strict mode, true in standard mode
   */
  allowNullOrigin?: boolean;
}

// Safe HTTP methods that don't need CSRF protection
const SAFE_METHODS = ['GET', 'HEAD', 'OPTIONS'];

// Default protected methods
const DEFAULT_PROTECTED_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'];

/**
 * CSRFDetector - Detect Cross-Site Request Forgery attempts
 * 
 * Validates that state-changing requests come from trusted origins.
 * 
 * @example
 * ```typescript
 * // Basic usage (standard mode - recommended for most cases)
 * new CSRFDetector({})
 * 
 * // Strict mode for APIs (blocks missing Origin)
 * new CSRFDetector({
 *   mode: 'strict',
 * })
 * 
 * // Allow trusted subdomains
 * new CSRFDetector({
 *   allowedOrigins: ['https://admin.example.com'],
 *   allowSameParentDomain: true,
 * })
 * 
 * // Require X-Requested-With header (extra protection)
 * new CSRFDetector({
 *   requireCustomHeader: true,
 *   customHeaderName: 'x-requested-with',
 * })
 * 
 * // Full configuration
 * new CSRFDetector({
 *   mode: 'strict',
 *   allowedOrigins: ['https://trusted-partner.com'],
 *   allowSameParentDomain: true,
 *   requireCustomHeader: true,
 *   protectedMethods: ['POST', 'PUT', 'DELETE'],
 * })
 * ```
 * 
 * @remarks
 * **How it works:**
 * 1. Skip safe methods (GET, HEAD, OPTIONS)
 * 2. Check Origin header against request host
 * 3. Fallback to Referer if Origin missing
 * 4. Optionally require custom header
 * 
 * **Detection levels:**
 * - CRITICAL: Origin mismatch (definite CSRF attempt)
 * - HIGH: Origin from different domain
 * - MEDIUM: Missing Origin in strict mode
 * - LOW: Missing custom header
 */
export class CSRFDetector extends BaseDetector {
  name = 'csrf';
  phase = 'request' as const;
  priority = 90;

  private config: CSRFDetectorConfig;
  private protectedMethods: Set<string>;
  private allowedOrigins: Set<string>;
  private mode: 'strict' | 'standard';

  constructor(config: CSRFDetectorConfig = {}) {
    super();
    this.config = config;
    this.mode = config.mode ?? 'standard';
    this.protectedMethods = new Set(
      (config.protectedMethods ?? DEFAULT_PROTECTED_METHODS).map(m => m.toUpperCase())
    );
    this.allowedOrigins = new Set(
      (config.allowedOrigins ?? []).map(o => o.toLowerCase())
    );
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    // Skip safe methods
    if (SAFE_METHODS.includes(request.method.toUpperCase())) {
      return null;
    }

    // Skip if method not in protected list
    if (!this.protectedMethods.has(request.method.toUpperCase())) {
      return null;
    }

    const requestUrl = new URL(request.url);
    const requestOrigin = `${requestUrl.protocol}//${requestUrl.host}`.toLowerCase();
    
    // Get Origin header
    const origin = request.headers.get('origin');
    const referer = request.headers.get('referer');

    // Check custom header requirement first
    if (this.config.requireCustomHeader) {
      const headerName = this.config.customHeaderName ?? 'x-requested-with';
      const customHeader = request.headers.get(headerName);
      
      if (!customHeader) {
        return this.createResult(
          AttackType.CSRF,
          SecuritySeverity.LOW,
          0.5,
          {
            field: 'header',
            value: `Missing ${headerName}`,
            rawContent: `Request missing required header: ${headerName}`,
          },
          { 
            reason: 'missing_custom_header',
            requiredHeader: headerName,
          }
        );
      }
    }

    // Handle null/missing Origin
    if (!origin) {
      // Try Referer as fallback
      if (referer) {
        return this.checkReferer(referer, requestOrigin, requestUrl);
      }

      // No Origin and no Referer
      if (this.mode === 'strict') {
        return this.createResult(
          AttackType.CSRF,
          SecuritySeverity.MEDIUM,
          0.6,
          {
            field: 'header',
            value: 'Missing Origin',
            rawContent: 'State-changing request without Origin header',
          },
          { reason: 'missing_origin', method: request.method }
        );
      }

      // Standard mode - allow missing Origin (could be same-origin form)
      return null;
    }

    // Handle "null" origin (privacy extensions, file://, sandboxed iframes)
    if (origin === 'null') {
      const allowNull = this.config.allowNullOrigin ?? (this.mode === 'standard');
      if (!allowNull) {
        return this.createResult(
          AttackType.CSRF,
          SecuritySeverity.MEDIUM,
          0.6,
          {
            field: 'origin',
            value: 'null',
            rawContent: 'Request with null Origin (sandboxed or file://)',
          },
          { reason: 'null_origin' }
        );
      }
      return null;
    }

    // Validate Origin
    return this.checkOrigin(origin.toLowerCase(), requestOrigin, requestUrl);
  }

  private checkOrigin(
    origin: string, 
    requestOrigin: string,
    requestUrl: URL
  ): DetectorResult | null {
    // Exact match with request origin
    if (origin === requestOrigin) {
      return null;
    }

    // Check allowed origins
    if (this.allowedOrigins.has(origin)) {
      return null;
    }

    // Check same parent domain
    if (this.config.allowSameParentDomain !== false) {
      if (this.isSameParentDomain(origin, requestOrigin)) {
        return null;
      }
    }

    // Origin mismatch - CSRF detected
    return this.createResult(
      AttackType.CSRF,
      SecuritySeverity.HIGH,
      0.9,
      {
        field: 'origin',
        value: origin,
        pattern: requestOrigin,
        rawContent: `Cross-origin request: ${origin} → ${requestOrigin}`,
      },
      { 
        reason: 'origin_mismatch',
        requestOrigin,
        sourceOrigin: origin,
      }
    );
  }

  private checkReferer(
    referer: string,
    requestOrigin: string,
    requestUrl: URL
  ): DetectorResult | null {
    try {
      const refererUrl = new URL(referer);
      const refererOrigin = `${refererUrl.protocol}//${refererUrl.host}`.toLowerCase();

      // Same as Origin check
      if (refererOrigin === requestOrigin) {
        return null;
      }

      if (this.allowedOrigins.has(refererOrigin)) {
        return null;
      }

      if (this.config.allowSameParentDomain !== false) {
        if (this.isSameParentDomain(refererOrigin, requestOrigin)) {
          return null;
        }
      }

      // Referer mismatch
      return this.createResult(
        AttackType.CSRF,
        SecuritySeverity.HIGH,
        0.85,
        {
          field: 'referer',
          value: refererOrigin,
          pattern: requestOrigin,
          rawContent: `Cross-origin request (via Referer): ${refererOrigin} → ${requestOrigin}`,
        },
        { 
          reason: 'referer_mismatch',
          requestOrigin,
          sourceOrigin: refererOrigin,
        }
      );
    } catch {
      // Invalid Referer URL
      if (this.mode === 'strict') {
        return this.createResult(
          AttackType.CSRF,
          SecuritySeverity.LOW,
          0.4,
          {
            field: 'referer',
            value: referer.substring(0, 100),
            rawContent: 'Invalid Referer header',
          },
          { reason: 'invalid_referer' }
        );
      }
      return null;
    }
  }

  /**
   * Check if two origins share the same parent domain
   * e.g., api.example.com and www.example.com → true
   */
  private isSameParentDomain(origin1: string, origin2: string): boolean {
    try {
      const url1 = new URL(origin1);
      const url2 = new URL(origin2);

      // Must be same protocol
      if (url1.protocol !== url2.protocol) {
        return false;
      }

      const parts1 = url1.hostname.split('.');
      const parts2 = url2.hostname.split('.');

      // Need at least 2 parts (domain.tld)
      if (parts1.length < 2 || parts2.length < 2) {
        return false;
      }

      // Compare last 2 parts (domain + TLD)
      // Note: This is simplified, doesn't handle complex TLDs like .co.uk
      const parent1 = parts1.slice(-2).join('.');
      const parent2 = parts2.slice(-2).join('.');

      return parent1 === parent2;
    } catch {
      return false;
    }
  }
}

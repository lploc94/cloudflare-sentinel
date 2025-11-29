/**
 * JWT Attack Detector
 * 
 * Detects common JWT attack patterns at WAF level.
 * Does NOT verify signatures or expiration (backend responsibility).
 * 
 * Focuses on:
 * - alg=none attacks
 * - kid header injection
 * - jku/x5u SSRF attempts
 * - Malformed JWT structure
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface JWTDetectorConfig extends BaseDetectorOptions {
  /**
   * Header names that may contain JWT tokens
   * Default: ['authorization']
   */
  headerNames?: string[];
  
  /**
   * Also check query parameters for JWT
   * Default: false
   */
  checkQueryParams?: boolean;
  
  /**
   * Query parameter names to check
   * Default: ['token', 'access_token', 'id_token']
   */
  queryParamNames?: string[];
}

// Default headers to check
const DEFAULT_HEADER_NAMES = ['authorization'];

// Default query params to check
const DEFAULT_QUERY_PARAMS = ['token', 'access_token', 'id_token', 'jwt'];

/**
 * JWTDetector - Detect JWT attack patterns
 * 
 * WAF-level checks only. Does NOT replace backend validation.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new JWTDetector({})
 * 
 * // Check additional headers
 * new JWTDetector({
 *   headerNames: ['authorization', 'x-access-token'],
 * })
 * 
 * // Also check query params
 * new JWTDetector({
 *   checkQueryParams: true,
 * })
 * ```
 * 
 * @remarks
 * **What this detector checks:**
 * - `alg: none` attack (signature bypass)
 * - `kid` header injection (path traversal, SQLi)
 * - `jku`/`x5u` SSRF (external key URLs)
 * - Malformed JWT structure
 * 
 * **What this detector does NOT check (backend job):**
 * - Signature verification
 * - Token expiration (exp claim)
 * - Audience/issuer validation
 * - Algorithm whitelist (varies per app)
 */
export class JWTDetector extends BaseDetector {
  name = 'jwt';
  phase = 'request' as const;
  priority = 88;

  private config: JWTDetectorConfig;
  private headerNames: string[];
  private queryParamNames: string[];

  constructor(config: JWTDetectorConfig = {}) {
    super();
    this.config = config;
    this.headerNames = config.headerNames ?? DEFAULT_HEADER_NAMES;
    this.queryParamNames = config.queryParamNames ?? DEFAULT_QUERY_PARAMS;
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    // Check headers
    for (const headerName of this.headerNames) {
      const headerValue = request.headers.get(headerName);
      if (headerValue) {
        // Extract JWT from "Bearer <token>" format
        const token = this.extractToken(headerValue);
        if (token) {
          const result = this.checkJWT(token, `header.${headerName}`);
          if (result) return result;
        }
      }
    }

    // Check query params if enabled
    if (this.config.checkQueryParams) {
      const url = new URL(request.url);
      for (const paramName of this.queryParamNames) {
        const token = url.searchParams.get(paramName);
        if (token && this.looksLikeJWT(token)) {
          const result = this.checkJWT(token, `query.${paramName}`);
          if (result) return result;
        }
      }
    }

    return null;
  }

  private extractToken(headerValue: string): string | null {
    // Bearer token
    const bearerMatch = headerValue.match(/^Bearer\s+(.+)$/i);
    if (bearerMatch) {
      return bearerMatch[1];
    }

    // Raw JWT (3 parts separated by dots)
    if (this.looksLikeJWT(headerValue)) {
      return headerValue;
    }

    return null;
  }

  private looksLikeJWT(value: string): boolean {
    // JWT has 3 base64url parts separated by dots
    const parts = value.split('.');
    return parts.length === 3 && parts.every(p => p.length > 0);
  }

  private checkJWT(token: string, location: string): DetectorResult | null {
    const parts = token.split('.');
    
    // Validate structure
    if (parts.length !== 3) {
      return this.createResult(
        AttackType.JWT_ATTACK,
        SecuritySeverity.LOW,
        0.6,
        {
          field: location,
          value: this.sanitizeToken(token),
          rawContent: 'Malformed JWT structure',
        },
        { reason: 'malformed_structure', partCount: parts.length }
      );
    }

    // Decode header
    let header: Record<string, unknown>;
    try {
      header = JSON.parse(this.base64UrlDecode(parts[0]));
    } catch {
      return this.createResult(
        AttackType.JWT_ATTACK,
        SecuritySeverity.LOW,
        0.6,
        {
          field: location,
          value: this.sanitizeToken(token),
          rawContent: 'Invalid JWT header (not valid JSON)',
        },
        { reason: 'invalid_header' }
      );
    }

    const baseConfidence = this.config.baseConfidence;

    // Check for alg=none attack
    const alg = header.alg;
    if (typeof alg === 'string') {
      const algLower = alg.toLowerCase();
      if (algLower === 'none' || algLower === 'null') {
        return this.createResult(
          AttackType.JWT_ATTACK,
          SecuritySeverity.CRITICAL,
          baseConfidence ?? 1.0,
          {
            field: location,
            value: `alg: ${alg}`,
            rawContent: 'JWT alg=none attack (signature bypass)',
          },
          { reason: 'alg_none', algorithm: alg }
        );
      }
    }

    // Check kid injection
    const kid = header.kid;
    if (typeof kid === 'string') {
      // Path traversal in kid
      if (kid.includes('../') || kid.includes('..\\') || kid.includes('/etc/') || kid.includes('c:\\')) {
        return this.createResult(
          AttackType.JWT_ATTACK,
          SecuritySeverity.CRITICAL,
          baseConfidence ?? 1.0,
          {
            field: location,
            value: `kid: ${this.sanitizeValue(kid)}`,
            rawContent: 'Path traversal in JWT kid header',
          },
          { reason: 'kid_path_traversal', kid }
        );
      }

      // SQL injection in kid
      const sqlPatterns = [/['";].*(?:or|and|union|select)/i, /--/, /\/\*/];
      for (const pattern of sqlPatterns) {
        if (pattern.test(kid)) {
          return this.createResult(
            AttackType.JWT_ATTACK,
            SecuritySeverity.CRITICAL,
            baseConfidence ?? 1.0,
            {
              field: location,
              value: `kid: ${this.sanitizeValue(kid)}`,
              rawContent: 'SQL injection in JWT kid header',
            },
            { reason: 'kid_sql_injection', kid }
          );
        }
      }

      // Command injection in kid
      if (/[|;&`$]/.test(kid)) {
        return this.createResult(
          AttackType.JWT_ATTACK,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.9,
          {
            field: location,
            value: `kid: ${this.sanitizeValue(kid)}`,
            rawContent: 'Potential command injection in JWT kid header',
          },
          { reason: 'kid_command_injection', kid }
        );
      }
    }

    // Check jku (JSON Web Key Set URL) for SSRF
    const jku = header.jku;
    if (typeof jku === 'string') {
      const ssrfResult = this.checkUrlForSSRF(jku, 'jku', location, baseConfidence);
      if (ssrfResult) return ssrfResult;
    }

    // Check x5u (X.509 URL) for SSRF
    const x5u = header.x5u;
    if (typeof x5u === 'string') {
      const ssrfResult = this.checkUrlForSSRF(x5u, 'x5u', location, baseConfidence);
      if (ssrfResult) return ssrfResult;
    }

    return null;
  }

  private checkUrlForSSRF(
    url: string,
    headerName: string,
    location: string,
    baseConfidence?: number
  ): DetectorResult | null {
    // Check for internal/localhost URLs
    const internalPatterns = [
      /localhost/i,
      /127\.0\.0\.1/,
      /0\.0\.0\.0/,
      /\[::1\]/,
      /10\.\d+\.\d+\.\d+/,
      /172\.(1[6-9]|2\d|3[01])\.\d+\.\d+/,
      /192\.168\.\d+\.\d+/,
      /169\.254\.\d+\.\d+/, // AWS metadata
    ];

    for (const pattern of internalPatterns) {
      if (pattern.test(url)) {
        return this.createResult(
          AttackType.JWT_ATTACK,
          SecuritySeverity.CRITICAL,
          baseConfidence ?? 1.0,
          {
            field: location,
            value: `${headerName}: ${this.sanitizeValue(url)}`,
            rawContent: `SSRF via JWT ${headerName} header (internal URL)`,
          },
          { reason: `${headerName}_ssrf`, url }
        );
      }
    }

    // Check for file:// protocol
    if (url.toLowerCase().startsWith('file://')) {
      return this.createResult(
        AttackType.JWT_ATTACK,
        SecuritySeverity.CRITICAL,
        baseConfidence ?? 1.0,
        {
          field: location,
          value: `${headerName}: ${this.sanitizeValue(url)}`,
          rawContent: `Local file access via JWT ${headerName} header`,
        },
        { reason: `${headerName}_file_access`, url }
      );
    }

    return null;
  }

  private base64UrlDecode(str: string): string {
    // Replace URL-safe chars and add padding
    let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
    const padding = 4 - (base64.length % 4);
    if (padding !== 4) {
      base64 += '='.repeat(padding);
    }
    return atob(base64);
  }

  private sanitizeToken(token: string): string {
    // Show first part (header) only, truncated
    const parts = token.split('.');
    if (parts.length >= 1) {
      return parts[0].substring(0, 50) + '...[payload]...[signature]';
    }
    return token.substring(0, 50) + '...';
  }

  private sanitizeValue(value: string): string {
    const maxLength = 80;
    return value.substring(0, maxLength) + (value.length > maxLength ? '...' : '');
  }
}

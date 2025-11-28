/**
 * Open Redirect Detector
 * 
 * Detects potential open redirect vulnerabilities in URL parameters.
 * Open redirects can be used for phishing, credential theft, and bypassing security controls.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface OpenRedirectDetectorConfig extends BaseDetectorOptions {
  /**
   * Allowed domains for redirects (besides self)
   * @example ['trusted-partner.com', 'auth.example.com']
   */
  allowedDomains?: string[];
  
  /**
   * Parameter names to check for redirect URLs
   * Default: common redirect parameter names
   */
  parameterNames?: string[];
  
  /**
   * Allow redirects to same parent domain (e.g., example.com → sub.example.com)
   * Default: true
   */
  allowSameParentDomain?: boolean;
  
  /**
   * Allow relative URLs (e.g., /dashboard, ./page)
   * Default: true (safe)
   */
  allowRelativeUrls?: boolean;
  
  /**
   * Block all external redirects (strict mode)
   * Default: false
   */
  strictMode?: boolean;
}

// Common redirect parameter names
const DEFAULT_REDIRECT_PARAMS = [
  'url', 'redirect', 'redirect_url', 'redirect_uri',
  'return', 'return_url', 'return_to', 'returnto',
  'next', 'next_url', 'goto', 'go', 'to',
  'destination', 'dest', 'target', 'link',
  'continue', 'continue_url', 'forward', 'forward_url',
  'callback', 'callback_url', 'success_url', 'error_url',
  'login_url', 'logout_url', 'out', 'view', 'ref',
  'u', 'r', 'l', 'rurl', 'redir',
];

// Dangerous patterns in redirect URLs
const DANGEROUS_PATTERNS = [
  // JavaScript protocol - XSS via redirect
  { pattern: /^javascript:/i, description: 'JavaScript protocol', severity: SecuritySeverity.CRITICAL, confidence: 0.99 },
  { pattern: /^vbscript:/i, description: 'VBScript protocol', severity: SecuritySeverity.CRITICAL, confidence: 0.99 },
  
  // Data URL - potential XSS
  { pattern: /^data:/i, description: 'Data URL', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  
  // Protocol-relative URL (//evil.com)
  { pattern: /^\/\/[^/]/, description: 'Protocol-relative URL', severity: SecuritySeverity.HIGH, confidence: 0.85 },
  
  // Backslash tricks (browser normalization)
  { pattern: /^\/\\/, description: 'Backslash URL trick', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  { pattern: /^\\\\/, description: 'Double backslash', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  
  // URL with credentials (user:pass@evil.com)
  { pattern: /@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/, description: 'URL with @ (credential trick)', severity: SecuritySeverity.HIGH, confidence: 0.85 },
  
  // Null byte injection
  { pattern: /%00/, description: 'Null byte injection', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  
  // Tab/newline injection
  { pattern: /%09|%0a|%0d/i, description: 'Tab/newline injection', severity: SecuritySeverity.MEDIUM, confidence: 0.8 },
];

/**
 * OpenRedirectDetector - Detect open redirect vulnerabilities
 * 
 * Checks URL parameters for potentially malicious redirect targets.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new OpenRedirectDetector({})
 * 
 * // Allow specific domains
 * new OpenRedirectDetector({
 *   allowedDomains: ['auth.example.com', 'partner.com'],
 * })
 * 
 * // Strict mode - block all external redirects
 * new OpenRedirectDetector({
 *   strictMode: true,
 * })
 * 
 * // Custom parameter names
 * new OpenRedirectDetector({
 *   parameterNames: ['redirect', 'next', 'return_url'],
 * })
 * 
 * // Disallow same parent domain
 * new OpenRedirectDetector({
 *   allowSameParentDomain: false,
 * })
 * ```
 * 
 * @remarks
 * **What Open Redirect enables:**
 * - Phishing attacks (redirect to fake login)
 * - OAuth token theft
 * - Bypassing URL validation
 * - XSS via javascript: URLs
 * 
 * **Detection levels:**
 * - CRITICAL: javascript:/vbscript: protocol
 * - HIGH: External domain redirect, protocol tricks
 * - MEDIUM: Suspicious patterns
 */
export class OpenRedirectDetector extends BaseDetector {
  name = 'open-redirect';
  phase = 'request' as const;
  priority = 85;

  private config: OpenRedirectDetectorConfig;
  private redirectParams: Set<string>;
  private allowedDomains: Set<string>;

  constructor(config: OpenRedirectDetectorConfig = {}) {
    super();
    this.config = config;
    this.redirectParams = new Set(
      (config.parameterNames ?? DEFAULT_REDIRECT_PARAMS).map(p => p.toLowerCase())
    );
    this.allowedDomains = new Set(
      (config.allowedDomains ?? []).map(d => d.toLowerCase())
    );
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const requestUrl = new URL(request.url);
    const requestHost = requestUrl.hostname.toLowerCase();

    // Check query parameters
    for (const [key, value] of requestUrl.searchParams) {
      if (this.isRedirectParam(key)) {
        const result = this.checkRedirectUrl(value, `query.${key}`, requestHost);
        if (result) return result;
      }
    }

    // Check form body for POST requests
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const contentType = request.headers.get('content-type') || '';
      
      if (contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const formData = await request.clone().text();
          const params = new URLSearchParams(formData);
          
          for (const [key, value] of params) {
            if (this.isRedirectParam(key)) {
              const result = this.checkRedirectUrl(value, `form.${key}`, requestHost);
              if (result) return result;
            }
          }
        } catch {
          // Cannot read form
        }
      }

      if (contentType.includes('application/json')) {
        try {
          const body = await request.clone().json() as Record<string, unknown>;
          const result = this.checkJsonBody(body, 'body', requestHost);
          if (result) return result;
        } catch {
          // Cannot parse JSON
        }
      }
    }

    return null;
  }

  private isRedirectParam(name: string): boolean {
    return this.redirectParams.has(name.toLowerCase());
  }

  private checkJsonBody(
    obj: Record<string, unknown>,
    prefix: string,
    requestHost: string
  ): DetectorResult | null {
    for (const [key, value] of Object.entries(obj)) {
      const path = `${prefix}.${key}`;
      
      if (typeof value === 'string' && this.isRedirectParam(key)) {
        const result = this.checkRedirectUrl(value, path, requestHost);
        if (result) return result;
      } else if (typeof value === 'object' && value !== null) {
        const result = this.checkJsonBody(value as Record<string, unknown>, path, requestHost);
        if (result) return result;
      }
    }
    return null;
  }

  private checkRedirectUrl(
    url: string,
    location: string,
    requestHost: string
  ): DetectorResult | null {
    if (!url || typeof url !== 'string') return null;

    // URL decode
    let decoded = url;
    try {
      decoded = decodeURIComponent(url);
      if (decoded.includes('%')) {
        decoded = decodeURIComponent(decoded);
      }
    } catch {
      // Use original
    }

    const baseConfidence = this.config.baseConfidence;

    // Check dangerous patterns first
    for (const { pattern, description, severity, confidence } of DANGEROUS_PATTERNS) {
      if (pattern.test(decoded)) {
        return this.createResult(
          AttackType.OPEN_REDIRECT,
          severity,
          baseConfidence ?? confidence,
          {
            field: location,
            value: this.sanitizeUrl(decoded),
            pattern: pattern.source,
            rawContent: `Dangerous redirect: ${description}`,
          },
          { reason: 'dangerous_pattern', pattern: description }
        );
      }
    }

    // Allow relative URLs by default
    if (this.config.allowRelativeUrls !== false) {
      if (this.isRelativeUrl(decoded)) {
        return null;
      }
    }

    // Parse and check the target URL
    try {
      // Handle protocol-relative URLs
      const targetUrl = decoded.startsWith('//') 
        ? new URL(`https:${decoded}`)
        : new URL(decoded);
      
      const targetHost = targetUrl.hostname.toLowerCase();

      // Same host is always allowed
      if (targetHost === requestHost) {
        return null;
      }

      // Check allowed domains
      if (this.allowedDomains.has(targetHost)) {
        return null;
      }

      // Check same parent domain
      if (this.config.allowSameParentDomain !== false) {
        if (this.isSameParentDomain(targetHost, requestHost)) {
          return null;
        }
      }

      // External redirect detected
      const severity = this.config.strictMode 
        ? SecuritySeverity.HIGH 
        : SecuritySeverity.MEDIUM;
      
      return this.createResult(
        AttackType.OPEN_REDIRECT,
        severity,
        baseConfidence ?? 0.85,
        {
          field: location,
          value: this.sanitizeUrl(decoded),
          rawContent: `External redirect: ${requestHost} → ${targetHost}`,
        },
        { 
          reason: 'external_redirect',
          sourceHost: requestHost,
          targetHost,
        }
      );
    } catch {
      // Invalid URL - might be attempt with malformed URL
      // Check if it looks like a URL attempt
      if (decoded.includes('.') && (decoded.includes('http') || decoded.includes('//'))) {
        return this.createResult(
          AttackType.OPEN_REDIRECT,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.7,
          {
            field: location,
            value: this.sanitizeUrl(decoded),
            rawContent: 'Malformed redirect URL',
          },
          { reason: 'malformed_url' }
        );
      }
    }

    return null;
  }

  private isRelativeUrl(url: string): boolean {
    // Relative URLs: /path, ./path, ../path, path (no protocol or //)
    return (
      url.startsWith('/') && !url.startsWith('//') ||
      url.startsWith('./') ||
      url.startsWith('../') ||
      (!url.includes('://') && !url.startsWith('//') && !url.includes(':'))
    );
  }

  private isSameParentDomain(host1: string, host2: string): boolean {
    const parts1 = host1.split('.');
    const parts2 = host2.split('.');

    if (parts1.length < 2 || parts2.length < 2) {
      return false;
    }

    // Compare last 2 parts (domain + TLD)
    const parent1 = parts1.slice(-2).join('.');
    const parent2 = parts2.slice(-2).join('.');

    return parent1 === parent2;
  }

  private sanitizeUrl(url: string): string {
    const maxLength = 150;
    let sanitized = url.substring(0, maxLength);
    
    // Mask potential credentials
    sanitized = sanitized.replace(/\/\/[^:]+:[^@]+@/g, '//***:***@');
    
    return sanitized + (url.length > maxLength ? '...' : '');
  }
}

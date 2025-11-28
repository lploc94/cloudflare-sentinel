/**
 * HTTP Smuggling Detector
 * 
 * Detects HTTP Request Smuggling attempts by analyzing request headers.
 * HTTP Smuggling exploits discrepancies between how front-end and back-end
 * servers parse HTTP requests (Content-Length vs Transfer-Encoding).
 * 
 * Note: Cloudflare handles many smuggling attacks at edge, but this detector
 * provides additional layer of defense and logging.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface HTTPSmugglingDetectorConfig extends BaseDetectorOptions {
  /**
   * Check for duplicate critical headers
   * Default: true
   */
  checkDuplicateHeaders?: boolean;
  
  /**
   * Check for conflicting Content-Length and Transfer-Encoding
   * Default: true
   */
  checkConflictingHeaders?: boolean;
  
  /**
   * Check for obfuscated Transfer-Encoding values
   * Default: true
   */
  checkObfuscatedTE?: boolean;
  
  /**
   * Check for header injection attempts (CRLF)
   * Default: true
   */
  checkHeaderInjection?: boolean;
  
  /**
   * Check for invalid Content-Length values
   * Default: true
   */
  checkInvalidCL?: boolean;
  
  /**
   * Check for Host header abuse (override, mismatch, invalid format)
   * Default: true
   */
  checkHostAbuse?: boolean;
  
  /**
   * Check for X-Forwarded header abuse
   * Default: true
   */
  checkXForwardedAbuse?: boolean;
}

// Transfer-Encoding obfuscation patterns
const TE_OBFUSCATION_PATTERNS = [
  // Whitespace variations
  { pattern: /transfer-encoding\s*:\s*chunked\s+/i, description: 'TE with trailing space' },
  { pattern: /transfer-encoding\s*:\s+chunked/i, description: 'TE with leading space' },
  { pattern: /transfer-encoding\s*:\s*chunked,/i, description: 'TE with trailing comma' },
  
  // Case variations (used to confuse parsers)
  { pattern: /transfer-encoding\s*:\s*Chunked/i, description: 'TE mixed case' },
  { pattern: /transfer-encoding\s*:\s*CHUNKED/i, description: 'TE uppercase' },
  
  // Multiple values
  { pattern: /transfer-encoding\s*:.*,.*chunked/i, description: 'TE with multiple values' },
  { pattern: /transfer-encoding\s*:\s*chunked\s*,\s*identity/i, description: 'TE chunked,identity' },
  
  // Null byte
  { pattern: /transfer-encoding.*\x00/i, description: 'TE with null byte' },
  
  // Tab character
  { pattern: /transfer-encoding\s*:\t/i, description: 'TE with tab' },
];

// Headers that shouldn't be duplicated
const CRITICAL_HEADERS = [
  'content-length',
  'transfer-encoding',
  'host',
  'content-type',
];

/**
 * HTTPSmugglingDetector - Detect HTTP Request Smuggling attempts
 * 
 * Checks for common smuggling techniques:
 * - CL.TE: Content-Length + Transfer-Encoding conflict
 * - TE.CL: Transfer-Encoding + Content-Length conflict
 * - TE.TE: Obfuscated Transfer-Encoding
 * - Header injection via CRLF
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new HTTPSmugglingDetector({})
 * 
 * // Disable specific checks
 * new HTTPSmugglingDetector({
 *   checkObfuscatedTE: false,
 * })
 * 
 * // Minimal checks (only critical)
 * new HTTPSmugglingDetector({
 *   checkDuplicateHeaders: false,
 *   checkObfuscatedTE: false,
 * })
 * ```
 * 
 * @remarks
 * **What HTTP Smuggling enables:**
 * - Bypass security controls (WAF, auth)
 * - Cache poisoning
 * - Request hijacking
 * - Credential theft
 * 
 * **Note:** Cloudflare normalizes many of these at edge, but detecting
 * attempts is still valuable for logging and defense-in-depth.
 */
export class HTTPSmugglingDetector extends BaseDetector {
  name = 'http-smuggling';
  phase = 'request' as const;
  priority = 98; // Very high - check early

  private config: HTTPSmugglingDetectorConfig;

  constructor(config: HTTPSmugglingDetectorConfig = {}) {
    super();
    this.config = {
      checkDuplicateHeaders: true,
      checkConflictingHeaders: true,
      checkObfuscatedTE: true,
      checkHeaderInjection: true,
      checkInvalidCL: true,
      checkHostAbuse: true,
      checkXForwardedAbuse: true,
      ...config,
    };
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const baseConfidence = this.config.baseConfidence;

    // Check for conflicting CL + TE headers
    if (this.config.checkConflictingHeaders) {
      const result = this.checkConflictingHeaders(request, baseConfidence);
      if (result) return result;
    }

    // Check for header injection (CRLF)
    if (this.config.checkHeaderInjection) {
      const result = this.checkHeaderInjection(request, baseConfidence);
      if (result) return result;
    }

    // Check for invalid Content-Length
    if (this.config.checkInvalidCL) {
      const result = this.checkInvalidContentLength(request, baseConfidence);
      if (result) return result;
    }

    // Check for obfuscated Transfer-Encoding
    // Note: This checks raw header access which may be normalized by runtime
    if (this.config.checkObfuscatedTE) {
      const result = this.checkObfuscatedTE(request, baseConfidence);
      if (result) return result;
    }

    // Check for Host header abuse
    if (this.config.checkHostAbuse) {
      const result = this.checkHostAbuse(request, baseConfidence);
      if (result) return result;
    }

    // Check for X-Forwarded header abuse
    if (this.config.checkXForwardedAbuse) {
      const result = this.checkXForwardedAbuse(request, baseConfidence);
      if (result) return result;
    }

    return null;
  }

  /**
   * CL.TE and TE.CL detection
   * Both Content-Length and Transfer-Encoding present is suspicious
   */
  private checkConflictingHeaders(
    request: Request,
    baseConfidence?: number
  ): DetectorResult | null {
    const contentLength = request.headers.get('content-length');
    const transferEncoding = request.headers.get('transfer-encoding');

    // Both headers present - classic smuggling setup
    if (contentLength && transferEncoding) {
      return this.createResult(
        AttackType.HTTP_SMUGGLING,
        SecuritySeverity.CRITICAL,
        baseConfidence ?? 0.95,
        {
          field: 'headers',
          value: `CL: ${contentLength}, TE: ${transferEncoding}`,
          rawContent: 'Both Content-Length and Transfer-Encoding present',
        },
        { 
          reason: 'conflicting_headers',
          contentLength,
          transferEncoding,
          technique: 'CL.TE or TE.CL',
        }
      );
    }

    return null;
  }

  /**
   * Check for CRLF injection in headers
   */
  private checkHeaderInjection(
    request: Request,
    baseConfidence?: number
  ): DetectorResult | null {
    // Check common headers for injection
    const headersToCheck = [
      'host', 'x-forwarded-for', 'x-forwarded-host',
      'x-original-url', 'x-rewrite-url', 'referer',
    ];

    for (const headerName of headersToCheck) {
      const value = request.headers.get(headerName);
      if (value) {
        // Check for CRLF sequences
        if (value.includes('\r') || value.includes('\n') || 
            value.includes('%0d') || value.includes('%0a') ||
            value.includes('%0D') || value.includes('%0A')) {
          return this.createResult(
            AttackType.HTTP_SMUGGLING,
            SecuritySeverity.CRITICAL,
            baseConfidence ?? 0.98,
            {
              field: `header.${headerName}`,
              value: this.sanitizeValue(value),
              rawContent: 'CRLF injection detected in header',
            },
            { 
              reason: 'header_injection',
              headerName,
              technique: 'CRLF injection',
            }
          );
        }

        // Check for null bytes
        if (value.includes('\x00') || value.includes('%00')) {
          return this.createResult(
            AttackType.HTTP_SMUGGLING,
            SecuritySeverity.HIGH,
            baseConfidence ?? 0.9,
            {
              field: `header.${headerName}`,
              value: this.sanitizeValue(value),
              rawContent: 'Null byte in header',
            },
            { 
              reason: 'null_byte_injection',
              headerName,
            }
          );
        }
      }
    }

    return null;
  }

  /**
   * Check for invalid Content-Length values
   */
  private checkInvalidContentLength(
    request: Request,
    baseConfidence?: number
  ): DetectorResult | null {
    const contentLength = request.headers.get('content-length');
    
    if (contentLength) {
      // Check for non-numeric characters
      if (!/^\d+$/.test(contentLength.trim())) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.9,
          {
            field: 'header.content-length',
            value: contentLength,
            rawContent: 'Invalid Content-Length value',
          },
          { 
            reason: 'invalid_content_length',
            value: contentLength,
          }
        );
      }

      // Check for negative value
      const clValue = parseInt(contentLength, 10);
      if (clValue < 0) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.95,
          {
            field: 'header.content-length',
            value: contentLength,
            rawContent: 'Negative Content-Length',
          },
          { 
            reason: 'negative_content_length',
            value: clValue,
          }
        );
      }

      // Check for leading zeros (parser confusion)
      if (/^0+\d/.test(contentLength)) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.7,
          {
            field: 'header.content-length',
            value: contentLength,
            rawContent: 'Content-Length with leading zeros',
          },
          { 
            reason: 'leading_zeros_cl',
            value: contentLength,
          }
        );
      }

      // Check for multiple values (e.g., "5, 10")
      if (contentLength.includes(',')) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.CRITICAL,
          baseConfidence ?? 0.95,
          {
            field: 'header.content-length',
            value: contentLength,
            rawContent: 'Multiple Content-Length values',
          },
          { 
            reason: 'multiple_content_length',
            value: contentLength,
          }
        );
      }
    }

    return null;
  }

  /**
   * Check for obfuscated Transfer-Encoding
   */
  private checkObfuscatedTE(
    request: Request,
    baseConfidence?: number
  ): DetectorResult | null {
    const transferEncoding = request.headers.get('transfer-encoding');
    
    if (transferEncoding) {
      // Check for suspicious values (not just "chunked" or "identity")
      const normalizedTE = transferEncoding.toLowerCase().trim();
      
      // Check for multiple encodings
      if (normalizedTE.includes(',')) {
        // "chunked, identity" or similar
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.85,
          {
            field: 'header.transfer-encoding',
            value: transferEncoding,
            rawContent: 'Multiple Transfer-Encoding values',
          },
          { 
            reason: 'multiple_transfer_encoding',
            value: transferEncoding,
          }
        );
      }

      // Check for unknown encoding
      if (!['chunked', 'identity', 'gzip', 'deflate', 'compress'].includes(normalizedTE)) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.7,
          {
            field: 'header.transfer-encoding',
            value: transferEncoding,
            rawContent: 'Unknown Transfer-Encoding value',
          },
          { 
            reason: 'unknown_transfer_encoding',
            value: transferEncoding,
          }
        );
      }

      // Check for whitespace obfuscation
      if (transferEncoding !== normalizedTE) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.75,
          {
            field: 'header.transfer-encoding',
            value: transferEncoding,
            rawContent: 'Transfer-Encoding with whitespace obfuscation',
          },
          { 
            reason: 'whitespace_obfuscation',
            original: transferEncoding,
            normalized: normalizedTE,
          }
        );
      }
    }

    return null;
  }

  /**
   * Check for Host header abuse
   * - Host override via X-Host, X-Forwarded-Host
   * - Host mismatch with request URL
   * - Invalid Host format
   */
  private checkHostAbuse(
    request: Request,
    baseConfidence?: number
  ): DetectorResult | null {
    const host = request.headers.get('host');
    const xHost = request.headers.get('x-host');
    const xForwardedHost = request.headers.get('x-forwarded-host');
    const xOriginalHost = request.headers.get('x-original-host');
    
    // Check for Host override attempts
    const overrideHeaders = [
      { name: 'x-host', value: xHost },
      { name: 'x-forwarded-host', value: xForwardedHost },
      { name: 'x-original-host', value: xOriginalHost },
    ].filter(h => h.value && h.value !== host);

    if (overrideHeaders.length > 0 && host) {
      const override = overrideHeaders[0];
      return this.createResult(
        AttackType.HTTP_SMUGGLING,
        SecuritySeverity.HIGH,
        baseConfidence ?? 0.85,
        {
          field: `header.${override.name}`,
          value: override.value!,
          rawContent: `Host override attempt: ${host} → ${override.value}`,
        },
        { 
          reason: 'host_override',
          originalHost: host,
          overrideHeader: override.name,
          overrideValue: override.value,
        }
      );
    }

    // Check Host header format
    if (host) {
      // Check for port injection (multiple ports)
      const portMatches = host.match(/:\d+/g);
      if (portMatches && portMatches.length > 1) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.9,
          {
            field: 'header.host',
            value: host,
            rawContent: 'Multiple ports in Host header',
          },
          { reason: 'multiple_ports_host', value: host }
        );
      }

      // Check for @ in Host (URL authority confusion)
      if (host.includes('@')) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.9,
          {
            field: 'header.host',
            value: host,
            rawContent: 'URL authority injection in Host',
          },
          { reason: 'host_authority_injection', value: host }
        );
      }

      // Check for path in Host
      if (host.includes('/')) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.HIGH,
          baseConfidence ?? 0.95,
          {
            field: 'header.host',
            value: host,
            rawContent: 'Path injection in Host header',
          },
          { reason: 'host_path_injection', value: host }
        );
      }

      // Check for whitespace (routing confusion)
      if (/\s/.test(host)) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.8,
          {
            field: 'header.host',
            value: this.sanitizeValue(host),
            rawContent: 'Whitespace in Host header',
          },
          { reason: 'host_whitespace', value: host }
        );
      }
    }

    return null;
  }

  /**
   * Check for X-Forwarded header abuse
   * - Multiple IPs in X-Forwarded-For (IP spoofing)
   * - Invalid IP formats
   * - Injection attempts
   */
  private checkXForwardedAbuse(
    request: Request,
    baseConfidence?: number
  ): DetectorResult | null {
    const xff = request.headers.get('x-forwarded-for');
    const xfp = request.headers.get('x-forwarded-proto');
    const xfPort = request.headers.get('x-forwarded-port');
    
    // Check X-Forwarded-For
    if (xff) {
      // Check for obviously fake IPs
      const suspiciousPatterns = [
        { pattern: /127\.0\.0\.1/i, description: 'localhost in XFF' },
        { pattern: /0\.0\.0\.0/i, description: 'zero IP in XFF' },
        { pattern: /::1/i, description: 'IPv6 localhost in XFF' },
        { pattern: /internal|private|local/i, description: 'reserved keyword in XFF' },
      ];

      for (const { pattern, description } of suspiciousPatterns) {
        if (pattern.test(xff)) {
          return this.createResult(
            AttackType.HTTP_SMUGGLING,
            SecuritySeverity.MEDIUM,
            baseConfidence ?? 0.7,
            {
              field: 'header.x-forwarded-for',
              value: xff,
              rawContent: `Suspicious X-Forwarded-For: ${description}`,
            },
            { reason: 'suspicious_xff', pattern: description, value: xff }
          );
        }
      }

      // Check for excessively long XFF chain (potential abuse)
      const ipCount = xff.split(',').length;
      if (ipCount > 10) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.6,
          {
            field: 'header.x-forwarded-for',
            value: this.sanitizeValue(xff),
            rawContent: `Excessive X-Forwarded-For chain: ${ipCount} IPs`,
          },
          { reason: 'excessive_xff_chain', ipCount }
        );
      }
    }

    // Check X-Forwarded-Proto
    if (xfp) {
      const validProtos = ['http', 'https', 'ws', 'wss'];
      const proto = xfp.toLowerCase().trim();
      if (!validProtos.includes(proto)) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.75,
          {
            field: 'header.x-forwarded-proto',
            value: xfp,
            rawContent: 'Invalid X-Forwarded-Proto value',
          },
          { reason: 'invalid_xfp', value: xfp }
        );
      }
    }

    // Check X-Forwarded-Port
    if (xfPort) {
      const port = parseInt(xfPort, 10);
      if (isNaN(port) || port < 1 || port > 65535 || xfPort.includes(',')) {
        return this.createResult(
          AttackType.HTTP_SMUGGLING,
          SecuritySeverity.MEDIUM,
          baseConfidence ?? 0.75,
          {
            field: 'header.x-forwarded-port',
            value: xfPort,
            rawContent: 'Invalid X-Forwarded-Port value',
          },
          { reason: 'invalid_xf_port', value: xfPort }
        );
      }
    }

    return null;
  }

  private sanitizeValue(value: string): string {
    const maxLength = 100;
    // Replace control characters for safe display
    let sanitized = value
      .replace(/\r/g, '\\r')
      .replace(/\n/g, '\\n')
      .replace(/\x00/g, '\\0')
      .substring(0, maxLength);
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

/**
 * XXE (XML External Entity) Detector
 * 
 * Detects XML External Entity injection attempts in request bodies.
 * XXE can lead to: file disclosure, SSRF, DoS, and remote code execution.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/** XXE pattern definition */
export interface XXEPattern {
  pattern: RegExp;
  description: string;
  confidence: number;
  severity: SecuritySeverity;
}

export interface XXEDetectorConfig extends BaseDetectorOptions {
  /**
   * Content types to check (default: XML types)
   * Set to ['*'] to check all content types
   */
  contentTypes?: string[];
  
  /**
   * Also check query parameters and form fields for XML
   * Default: true
   */
  checkParams?: boolean;
  
  /**
   * Custom patterns - if provided, OVERRIDES built-in patterns
   */
  patterns?: XXEPattern[];
  
  /**
   * Fields to exclude from checking (exact match)
   */
  excludeFields?: string[];
}

// XXE Attack Patterns
// Confidence guidelines:
// - 0.95-0.99: Almost certainly XXE attack
// - 0.85-0.94: Highly suspicious
// - 0.70-0.84: Suspicious, could be legitimate in some cases
const XXE_PATTERNS: XXEPattern[] = [
  // === CRITICAL - External Entity Declaration (definite XXE) ===
  {
    pattern: /<!ENTITY\s+\S+\s+SYSTEM\s+["'][^"']*["']/i,
    description: 'SYSTEM entity declaration',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<!ENTITY\s+\S+\s+PUBLIC\s+["'][^"']*["']/i,
    description: 'PUBLIC entity declaration',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === CRITICAL - Parameter Entity (definite XXE) ===
  {
    pattern: /<!ENTITY\s+%\s*\S+\s+SYSTEM/i,
    description: 'Parameter entity with SYSTEM',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<!ENTITY\s+%\s*\S+\s+["'].*%.*["']/i,
    description: 'Parameter entity reference in value',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === CRITICAL - File Protocol (definite LFI) ===
  {
    pattern: /<!ENTITY[^>]*file:\/\//i,
    description: 'file:// protocol in entity',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /SYSTEM\s+["']file:\/\//i,
    description: 'SYSTEM with file:// protocol',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === CRITICAL - Common XXE Payloads (definite attack) ===
  {
    pattern: /<!ENTITY[^>]*\/etc\/passwd/i,
    description: 'XXE targeting /etc/passwd',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<!ENTITY[^>]*\/etc\/shadow/i,
    description: 'XXE targeting /etc/shadow',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<!ENTITY[^>]*c:\\windows/i,
    description: 'XXE targeting Windows files',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === HIGH - Network Protocols (SSRF via XXE) ===
  {
    pattern: /<!ENTITY[^>]*https?:\/\//i,
    description: 'HTTP(S) protocol in entity',
    confidence: 0.95,
    severity: SecuritySeverity.HIGH,
  },
  {
    pattern: /<!ENTITY[^>]*ftp:\/\//i,
    description: 'FTP protocol in entity',
    confidence: 0.95,
    severity: SecuritySeverity.HIGH,
  },
  {
    pattern: /<!ENTITY[^>]*gopher:\/\//i,
    description: 'Gopher protocol in entity',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === CRITICAL - PHP Wrappers (definite attack) ===
  {
    pattern: /<!ENTITY[^>]*php:\/\/filter/i,
    description: 'PHP filter wrapper in entity',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<!ENTITY[^>]*expect:\/\//i,
    description: 'Expect wrapper in entity',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === HIGH - DOCTYPE with Entity ===
  {
    pattern: /<!DOCTYPE[^>]*\[[\s\S]*<!ENTITY/i,
    description: 'DOCTYPE with inline ENTITY',
    confidence: 0.9,
    severity: SecuritySeverity.HIGH,
  },
  
  // === MEDIUM - Suspicious DOCTYPE ===
  {
    pattern: /<!DOCTYPE[^>]*SYSTEM\s+["']https?:\/\//i,
    description: 'DOCTYPE with external DTD URL',
    confidence: 0.85,
    severity: SecuritySeverity.MEDIUM,
  },
  {
    pattern: /<!DOCTYPE[^>]*SYSTEM\s+["']file:\/\//i,
    description: 'DOCTYPE with local DTD file',
    confidence: 0.9,
    severity: SecuritySeverity.HIGH,
  },
  
  // === MEDIUM - Entity Reference Patterns ===
  {
    pattern: /&[a-zA-Z_][a-zA-Z0-9_-]*;/,
    description: 'Entity reference (needs DOCTYPE context)',
    confidence: 0.5,
    severity: SecuritySeverity.LOW,
  },
  
  // === CRITICAL - Billion Laughs DoS ===
  {
    pattern: /<!ENTITY\s+\S+\s+["'](&\S+;){3,}["']/i,
    description: 'Potential Billion Laughs attack',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === HIGH - XInclude ===
  {
    pattern: /<xi:include[^>]*href\s*=/i,
    description: 'XInclude directive',
    confidence: 0.9,
    severity: SecuritySeverity.HIGH,
  },
  {
    pattern: /xmlns:xi\s*=\s*["']http:\/\/www\.w3\.org\/2001\/XInclude["']/i,
    description: 'XInclude namespace declaration',
    confidence: 0.85,
    severity: SecuritySeverity.MEDIUM,
  },
];

// Default XML content types
const XML_CONTENT_TYPES = [
  'application/xml',
  'text/xml',
  'application/xhtml+xml',
  'application/soap+xml',
  'application/rss+xml',
  'application/atom+xml',
  'application/xslt+xml',
  'application/mathml+xml',
  'image/svg+xml',
];

/**
 * XXEDetector - Detect XML External Entity injection attempts
 * 
 * Checks for XXE patterns in:
 * - XML request bodies
 * - Query parameters (optional)
 * - Form fields (optional)
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new XXEDetector({})
 * 
 * // Check all content types (not just XML)
 * new XXEDetector({
 *   contentTypes: ['*'],
 * })
 * 
 * // Also check params and form fields
 * new XXEDetector({
 *   checkParams: true,
 * })
 * 
 * // Exclude certain fields
 * new XXEDetector({
 *   excludeFields: ['xml_template'],
 * })
 * 
 * // Access built-in patterns
 * XXEDetector.PATTERNS
 * ```
 * 
 * @remarks
 * **What XXE can do:**
 * - Read local files (/etc/passwd, C:\Windows\...)
 * - SSRF via external entity URLs
 * - DoS via Billion Laughs attack
 * - Remote code execution (with expect://)
 * 
 * **Detection levels:**
 * - CRITICAL: Direct XXE payload (file://, SYSTEM entity)
 * - HIGH: Suspicious patterns (external DTD, XInclude)
 * - MEDIUM: Potential XXE indicators
 */
export class XXEDetector extends BaseDetector {
  name = 'xxe';
  phase = 'request' as const;
  priority = 90;

  private config: XXEDetectorConfig;
  private activePatterns: XXEPattern[];
  private contentTypes: Set<string>;
  private excludeFields: Set<string>;
  private checkAll: boolean;

  /** Built-in XXE patterns */
  static readonly PATTERNS = XXE_PATTERNS;

  constructor(config: XXEDetectorConfig = {}) {
    super();
    this.config = config;
    this.activePatterns = config.patterns ?? XXE_PATTERNS;
    this.checkAll = config.contentTypes?.includes('*') ?? false;
    this.contentTypes = new Set(
      config.contentTypes?.filter(t => t !== '*') ?? XML_CONTENT_TYPES
    );
    this.excludeFields = new Set(
      (config.excludeFields ?? []).map(f => f.toLowerCase())
    );
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    // Check query parameters if enabled
    if (this.config.checkParams !== false) {
      const url = new URL(request.url);
      for (const [key, value] of url.searchParams) {
        if (this.isFieldExcluded(key)) continue;
        const result = this.checkForXXE(value, `query.${key}`);
        if (result) return result;
      }
    }

    // Check request body
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const contentType = request.headers.get('content-type') || '';
      
      // Check if we should inspect this content type
      const shouldCheck = this.checkAll || 
        Array.from(this.contentTypes).some(ct => contentType.includes(ct));

      if (shouldCheck) {
        try {
          const body = await request.clone().text();
          if (body) {
            const result = this.checkForXXE(body, 'body');
            if (result) return result;
          }
        } catch {
          // Cannot read body
        }
      }

      // Check form fields if enabled and content is form
      if (this.config.checkParams !== false && 
          contentType.includes('application/x-www-form-urlencoded')) {
        try {
          const formData = await request.clone().text();
          const params = new URLSearchParams(formData);
          for (const [key, value] of params) {
            if (this.isFieldExcluded(key)) continue;
            const result = this.checkForXXE(value, `form.${key}`);
            if (result) return result;
          }
        } catch {
          // Cannot read form
        }
      }
    }

    return null;
  }

  private isFieldExcluded(field: string): boolean {
    return this.excludeFields.has(field.toLowerCase());
  }

  private checkForXXE(input: string, location: string): DetectorResult | null {
    if (!input || typeof input !== 'string') return null;

    // Quick check - skip if no XML indicators
    if (!input.includes('<!') && !input.includes('<?') && !input.includes('<')) {
      return null;
    }

    // URL decode for encoded payloads
    let decoded = input;
    try {
      decoded = decodeURIComponent(input);
      if (decoded.includes('%')) {
        decoded = decodeURIComponent(decoded);
      }
    } catch {
      // Use original
    }

    const baseConfidence = this.config.baseConfidence;

    for (const { pattern, description, confidence, severity } of this.activePatterns) {
      if (pattern.test(decoded)) {
        // Skip low-confidence patterns unless there's DOCTYPE context
        if (confidence < 0.6 && !decoded.includes('<!DOCTYPE')) {
          continue;
        }

        return this.createResult(
          AttackType.XXE,
          severity,
          baseConfidence ?? confidence,
          {
            field: location,
            value: this.sanitizeValue(decoded),
            pattern: pattern.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'xxe', matchedPattern: description }
        );
      }
    }

    return null;
  }

  private sanitizeValue(value: string): string {
    const maxLength = 200;
    let sanitized = value.substring(0, maxLength);
    
    // Mask potential sensitive data in file paths
    sanitized = sanitized.replace(/\/etc\/\w+/gi, '/etc/***');
    sanitized = sanitized.replace(/c:\\[^\s"'<>]+/gi, 'c:\\***');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

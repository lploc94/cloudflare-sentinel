/**
 * XSS Request Detector
 * Detects XSS attack patterns in incoming requests
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/** XSS pattern definition */
export interface XSSPattern {
  regex: RegExp;
  description: string;
  confidence: number;
  severity: SecuritySeverity;
}

export interface XSSRequestDetectorConfig extends BaseDetectorOptions {
  /** Fields to exclude from checking (exact match) */
  excludeFields?: string[];
  /** Headers to check (default: referer, user-agent) */
  checkHeaders?: string[];
  /** Custom patterns - if provided, OVERRIDES built-in patterns */
  patterns?: XSSPattern[];
}

// === XSS PATTERNS ===
// Confidence guidelines:
// - 0.95-0.99: Almost certainly XSS (very specific attack patterns)
// - 0.85-0.94: Highly suspicious (uncommon in legitimate traffic)
// - 0.70-0.84: Suspicious (could be legitimate in some contexts)
const XSS_PATTERNS: XSSPattern[] = [
  // === CRITICAL - Script injection (very specific) ===
  { regex: /<script[^>]*>[\s\S]*?<\/script>/i, description: 'Full script tag', confidence: 0.99, severity: SecuritySeverity.CRITICAL },
  { regex: /<script[\s>]/i, description: 'Script tag open', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /<\/script>/i, description: 'Script tag close', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  
  // === CRITICAL - Event handlers (very specific XSS vectors) ===
  { regex: /\bon(load|error|abort)\s*=/i, description: 'onload/onerror handler', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /\bon(click|dblclick|mousedown|mouseup|mouseover|mouseout|mousemove)\s*=/i, description: 'Mouse event handler', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /\bon(keydown|keyup|keypress)\s*=/i, description: 'Keyboard event handler', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /\bon(focus|blur|change|submit|reset)\s*=/i, description: 'Form event handler', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /\bon(drag|drop|dragstart|dragend|dragover)\s*=/i, description: 'Drag event handler', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /\bon(copy|cut|paste)\s*=/i, description: 'Clipboard event handler', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /\bon(animationstart|animationend|transitionend)\s*=/i, description: 'Animation event handler', confidence: 0.92, severity: SecuritySeverity.HIGH },
  { regex: /\bon(pointerover|pointerenter|pointerleave)\s*=/i, description: 'Pointer event handler', confidence: 0.9, severity: SecuritySeverity.HIGH },
  
  // === CRITICAL - Protocol handlers ===
  { regex: /javascript\s*:/i, description: 'JavaScript protocol', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /vbscript\s*:/i, description: 'VBScript protocol', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  { regex: /livescript\s*:/i, description: 'LiveScript protocol', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  
  // === HIGH - HTML injection (dangerous tags) ===
  { regex: /<iframe[\s>]/i, description: 'iframe injection', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /<frame[\s>]/i, description: 'frame injection', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /<object[\s>]/i, description: 'object tag injection', confidence: 0.85, severity: SecuritySeverity.HIGH },
  { regex: /<embed[\s>]/i, description: 'embed tag injection', confidence: 0.85, severity: SecuritySeverity.HIGH },
  { regex: /<applet[\s>]/i, description: 'applet tag injection', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /<base[\s]+href/i, description: 'base tag injection', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /<link[\s]+.*href\s*=\s*['"]?javascript:/i, description: 'link with JavaScript', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  
  // === HIGH - SVG-based XSS ===
  { regex: /<svg[^>]*\s+on\w+\s*=/i, description: 'SVG with event handler', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /<svg[^>]*>[\s\S]*?<script/i, description: 'SVG with script', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  { regex: /<svg[\s>]/i, description: 'SVG tag', confidence: 0.6, severity: SecuritySeverity.LOW },
  
  // === HIGH - Data URL attacks ===
  { regex: /data\s*:\s*text\/html/i, description: 'data:text/html URL', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /data\s*:\s*image\/svg\+xml/i, description: 'data:image/svg+xml URL', confidence: 0.85, severity: SecuritySeverity.HIGH },
  { regex: /data\s*:\s*[^,]*base64/i, description: 'data:base64 URL', confidence: 0.7, severity: SecuritySeverity.MEDIUM },
  
  // === HIGH - Style-based XSS ===
  { regex: /<style[^>]*>[\s\S]*?(expression|javascript:|@import)/i, description: 'Style with expression/JS', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /expression\s*\([^)]*\)/i, description: 'CSS expression() (IE)', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /behavior\s*:\s*url/i, description: 'CSS behavior (IE)', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /-moz-binding\s*:/i, description: 'CSS -moz-binding', confidence: 0.9, severity: SecuritySeverity.HIGH },
  
  // === MEDIUM - Meta/template injection ===
  { regex: /<meta[^>]*http-equiv\s*=\s*['"]?refresh/i, description: 'Meta refresh', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /<template[\s>]/i, description: 'Template tag', confidence: 0.7, severity: SecuritySeverity.MEDIUM },
  
  // === MEDIUM - Encoding bypasses ===
  { regex: /&#x?0*(?:74|4a|106|6a);/i, description: 'Encoded "j" (javascript)', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /&#x?0*(?:60|3c);/i, description: 'Encoded "<"', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /%3c\s*script/i, description: 'URL encoded <script', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /%3c\s*img/i, description: 'URL encoded <img', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /\\u003c/i, description: 'Unicode encoded <', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /\\x3c/i, description: 'Hex encoded <', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  
  // === MEDIUM - Framework-specific ===
  { regex: /\{\{.*?\}\}/i, description: 'Template expression {{}}', confidence: 0.6, severity: SecuritySeverity.LOW },
  { regex: /\$\{.*?\}/i, description: 'Template literal ${}', confidence: 0.5, severity: SecuritySeverity.LOW },
  { regex: /ng-\w+\s*=/i, description: 'Angular directive', confidence: 0.5, severity: SecuritySeverity.LOW },
  { regex: /v-\w+\s*=/i, description: 'Vue directive', confidence: 0.5, severity: SecuritySeverity.LOW },
  
  // === MEDIUM - IMG tag attacks ===
  { regex: /<img[^>]+\s+on\w+\s*=/i, description: 'IMG with event handler', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /<img[^>]+src\s*=\s*['"]?javascript:/i, description: 'IMG with javascript: src', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  { regex: /<img[^>]+src\s*=\s*['"]?data:/i, description: 'IMG with data: src', confidence: 0.75, severity: SecuritySeverity.MEDIUM },
  
  // === LOW - Form injection (context dependent) ===
  { regex: /<form[^>]+action\s*=/i, description: 'Form with action', confidence: 0.65, severity: SecuritySeverity.LOW },
  { regex: /<input[^>]+type\s*=\s*['"]?hidden/i, description: 'Hidden input', confidence: 0.5, severity: SecuritySeverity.LOW },
];

// Default headers to check
const DEFAULT_CHECK_HEADERS = ['referer', 'user-agent'];

/**
 * XSSRequestDetector - Detect Cross-Site Scripting attacks in requests
 * 
 * Checks for XSS patterns in:
 * - Query parameters
 * - URL path
 * - Request body (JSON, form-urlencoded)
 * - Headers (referer, user-agent by default)
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new XSSRequestDetector({})
 * 
 * // Exclude certain fields
 * new XSSRequestDetector({
 *   excludeFields: ['html_content', 'rich_text'],
 * })
 * 
 * // Custom headers to check
 * new XSSRequestDetector({
 *   checkHeaders: ['referer', 'x-custom-header'],
 * })
 * 
 * // Access built-in patterns
 * XSSRequestDetector.PATTERNS
 * ```
 */
export class XSSRequestDetector extends BaseDetector {
  name = 'xss-request';
  phase = 'request' as const;
  priority = 95;

  private config: XSSRequestDetectorConfig;
  private activePatterns: XSSPattern[];
  private excludeFields: Set<string>;
  private checkHeaders: string[];

  /** Built-in XSS patterns */
  static readonly PATTERNS = XSS_PATTERNS;

  constructor(config: XSSRequestDetectorConfig = {}) {
    super();
    this.config = config;
    this.activePatterns = config.patterns ?? XSS_PATTERNS;
    this.excludeFields = new Set(
      (config.excludeFields ?? []).map(f => f.toLowerCase())
    );
    this.checkHeaders = config.checkHeaders ?? DEFAULT_CHECK_HEADERS;
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check query parameters
    for (const [key, value] of url.searchParams.entries()) {
      if (this.isFieldExcluded(key)) continue;
      const detection = this.checkForXSS(value, `query.${key}`);
      if (detection) return detection;
    }

    // Check URL path
    const pathDetection = this.checkForXSS(url.pathname, 'path');
    if (pathDetection) return pathDetection;

    // Check request body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        const contentType = request.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
          const body = await request.clone().text();
          const bodyDetection = this.checkForXSS(body, 'body');
          if (bodyDetection) return bodyDetection;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const body = await request.clone().text();
          const params = new URLSearchParams(body);
          for (const [key, value] of params.entries()) {
            if (this.isFieldExcluded(key)) continue;
            const formDetection = this.checkForXSS(value, `form.${key}`);
            if (formDetection) return formDetection;
          }
        } else if (contentType.includes('text/html') || contentType.includes('text/plain')) {
          const body = await request.clone().text();
          const textDetection = this.checkForXSS(body, 'body');
          if (textDetection) return textDetection;
        }
      } catch {
        // Cannot read body, skip
      }
    }

    // Check configured headers
    for (const headerName of this.checkHeaders) {
      const headerValue = request.headers.get(headerName);
      if (headerValue) {
        const headerDetection = this.checkForXSS(headerValue, `header.${headerName}`);
        if (headerDetection) return headerDetection;
      }
    }

    return null;
  }

  private isFieldExcluded(field: string): boolean {
    return this.excludeFields.has(field.toLowerCase());
  }

  private checkForXSS(input: string, field: string): DetectorResult | null {
    // Decode HTML entities and URL encoding
    let decodedInput = input;
    try {
      decodedInput = decodeURIComponent(input);
      // Try double decode
      if (decodedInput.includes('%')) {
        decodedInput = decodeURIComponent(decodedInput);
      }
      decodedInput = this.decodeHTMLEntities(decodedInput);
    } catch {
      // Invalid encoding, use original
    }

    const baseConfidence = this.config.baseConfidence;

    for (const { regex, description, confidence, severity } of this.activePatterns) {
      if (regex.test(decodedInput)) {
        const finalConfidence = baseConfidence ?? confidence;
        
        return this.createResult(
          AttackType.XSS,
          severity,
          finalConfidence,
          {
            field,
            value: this.sanitizeValue(decodedInput),
            pattern: regex.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'xss', matchedPattern: description }
        );
      }
    }

    return null;
  }

  private decodeHTMLEntities(text: string): string {
    const entities: Record<string, string> = {
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&#x27;': "'",
      '&#x2F;': '/',
      '&amp;': '&',
      '&#39;': "'",
      '&#34;': '"',
      '&#60;': '<',
      '&#62;': '>',
    };

    return text.replace(/&[#\w]+;/g, (entity) => entities[entity.toLowerCase()] || entity);
  }

  private sanitizeValue(value: string): string {
    const maxLength = 100;
    let sanitized = value.substring(0, maxLength);
    
    // Remove actual script content for safety in logs
    sanitized = sanitized.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '<script>***</script>');
    sanitized = sanitized.replace(/javascript:/gi, 'javascript:***');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

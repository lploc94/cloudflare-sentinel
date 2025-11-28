/**
 * Command Injection Detector
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/** Custom pattern definition */
export interface CommandPattern {
  pattern: RegExp;
  description: string;
  severity: SecuritySeverity;
  confidence: number;
}

export interface CommandInjectionDetectorConfig extends BaseDetectorOptions {
  enabled?: boolean;
  priority?: number;
  excludeFields?: string[];
  checkHeaders?: string[];
  /** Custom patterns - if provided, OVERRIDES all built-in patterns */
  patterns?: CommandPattern[];
}

// Characters that indicate potential shell command
const SHELL_METACHARACTERS = [';', '|', '&', '`', '$(', '\n', '\r', '>', '<'];

// High confidence patterns - clearly malicious
const COMMAND_PATTERNS: Array<{ pattern: RegExp; description: string; severity: SecuritySeverity; confidence: number }> = [
  // Critical - Clear command injection
  { pattern: /[;&|]{1,2}\s*(ls|cat|dir|type|whoami|id|uname|pwd|echo|ping|curl|wget|nc|ncat|bash|sh|zsh|cmd|powershell)\b/i, description: 'Command chaining', severity: SecuritySeverity.CRITICAL, confidence: 0.95 },
  { pattern: /\b(rm\s+-rf|chmod\s+777|mkfs|dd\s+if=)\b/i, description: 'Dangerous system commands', severity: SecuritySeverity.CRITICAL, confidence: 0.95 },
  { pattern: /\b(bash|sh|nc|ncat)\s+.*\s+-[ie]/i, description: 'Potential reverse shell', severity: SecuritySeverity.CRITICAL, confidence: 0.95 },
  { pattern: /\|\s*base64\s+-d/i, description: 'Base64 decode pipe', severity: SecuritySeverity.CRITICAL, confidence: 0.9 },
  
  // High - Likely malicious
  { pattern: /\$\(\s*(cat|ls|id|whoami|uname|pwd|curl|wget|nc)\b/i, description: '$() with command', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  { pattern: /`\s*(cat|ls|id|whoami|uname|pwd|curl|wget|nc)\b[^`]*`/i, description: 'Backtick with command', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  { pattern: /\b(curl|wget)\s+[^\s]*\s*\|/i, description: 'Download and pipe', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  { pattern: /\b(nc|ncat|netcat)\s+(-e|-c|--exec)/i, description: 'Netcat with exec', severity: SecuritySeverity.CRITICAL, confidence: 0.95 },
  { pattern: /\b(cmd\.exe|powershell\.exe|certutil|bitsadmin)\s+/i, description: 'Windows command execution', severity: SecuritySeverity.HIGH, confidence: 0.9 },
  { pattern: />\s*\/?(tmp|dev|etc)\//i, description: 'Redirect to system path', severity: SecuritySeverity.HIGH, confidence: 0.85 },
  { pattern: /<\s*\/?(etc|proc)\//i, description: 'Read from system path', severity: SecuritySeverity.HIGH, confidence: 0.85 },
  
  // Medium - Suspicious but could be legitimate
  { pattern: /\/bin\/(sh|bash)\s/i, description: 'Direct shell path', severity: SecuritySeverity.MEDIUM, confidence: 0.8 },
  { pattern: /\/etc\/(passwd|shadow|hosts)/i, description: 'Sensitive file path', severity: SecuritySeverity.MEDIUM, confidence: 0.8 },
  { pattern: /\|\|\s*(curl|wget|sh|bash)/i, description: 'OR operator with command', severity: SecuritySeverity.MEDIUM, confidence: 0.8 },
  { pattern: /&&\s*(curl|wget|sh|bash)/i, description: 'AND operator with command', severity: SecuritySeverity.MEDIUM, confidence: 0.8 },
  
  // Note: Removed generic ${} and `` patterns - too many false positives
  // Only match when combined with known commands
];

/**
 * CommandInjectionDetector - Detect shell command injection attempts
 * 
 * Scans query params, headers, and request body for command injection patterns.
 * Uses pre-filter with shell metacharacters for performance.
 * 
 * @example
 * ```typescript
 * // Basic usage - built-in patterns
 * new CommandInjectionDetector({})
 * 
 * // Exclude specific paths
 * new CommandInjectionDetector({
 *   excludePaths: ['/api/admin/*', '/health'],
 *   excludeFields: ['password', 'token'],
 * })
 * 
 * // Override with custom patterns only
 * new CommandInjectionDetector({
 *   patterns: [
 *     {
 *       pattern: /my-custom-pattern/i,
 *       description: 'My app specific',
 *       severity: SecuritySeverity.HIGH,
 *       confidence: 0.9,
 *     },
 *   ],
 * })
 * 
 * // Custom confidence for all detections
 * new CommandInjectionDetector({
 *   baseConfidence: 0.95,
 * })
 * ```
 * 
 * @remarks
 * - Built-in patterns detect: command chaining, reverse shells, dangerous commands
 * - If `patterns` provided, built-in patterns are completely replaced
 * - Pre-filters with metacharacters: ; | & \` $( \\n \\r > <
 * - Recursively checks nested JSON objects
 */
export class CommandInjectionDetector extends BaseDetector {
  name = 'command-injection';
  phase = 'request' as const;
  priority: number;
  enabled: boolean;
  private config: CommandInjectionDetectorConfig;
  private baseConfidence: number;
  private activePatterns: CommandPattern[];

  constructor(config: CommandInjectionDetectorConfig = {}) {
    super();
    this.config = {
      enabled: true,
      priority: 85,
      excludeFields: ['password', 'token', 'secret', 'key'],
      checkHeaders: ['x-forwarded-for', 'user-agent', 'referer'],
      ...config,
    };
    this.priority = this.config.priority!;
    this.enabled = this.config.enabled!;
    this.baseConfidence = config.baseConfidence ?? 0.85;

    // Use custom patterns if provided, otherwise use built-in
    this.activePatterns = config.patterns ?? COMMAND_PATTERNS;
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);

    for (const [key, value] of url.searchParams) {
      if (this.isFieldExcluded(key)) continue;
      const result = this.checkValue(value, `query.${key}`);
      if (result) return result;
    }

    for (const header of this.config.checkHeaders || []) {
      const value = request.headers.get(header);
      if (value) {
        const result = this.checkValue(value, `header.${header}`);
        if (result) return result;
      }
    }

    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const contentType = request.headers.get('content-type') || '';
      try {
        if (contentType.includes('application/json')) {
          const body = await request.clone().json();
          const result = this.checkObject(body, 'body');
          if (result) return result;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const formData = await request.clone().text();
          const params = new URLSearchParams(formData);
          for (const [key, value] of params) {
            if (this.isFieldExcluded(key)) continue;
            const result = this.checkValue(value, `form.${key}`);
            if (result) return result;
          }
        }
      } catch { /* ignore */ }
    }
    return null;
  }

  private isFieldExcluded(field: string): boolean {
    const lf = field.toLowerCase();
    // Use exact match only - avoid matching "api_key_id" when excluding "key"
    return (this.config.excludeFields || []).some(f => lf === f.toLowerCase());
  }

  private checkValue(value: string, location: string): DetectorResult | null {
    if (!value || typeof value !== 'string') return null;
    
    // Quick check for shell metacharacters
    const hasMetachar = SHELL_METACHARACTERS.some(char => value.includes(char));
    if (!hasMetachar) return null;

    for (const { pattern, description, severity, confidence: patternConfidence } of this.activePatterns) {
      if (pattern.test(value)) {
        // Use pattern confidence or baseConfidence override
        const confidence = this.config.baseConfidence ?? patternConfidence;
        return this.createResult(
          AttackType.COMMAND_INJECTION,
          severity,
          confidence,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
            rawContent: `Matched: ${description}`,
          },
          { matchedPattern: description }
        );
      }
    }
    return null;
  }

  private checkObject(obj: any, prefix: string): DetectorResult | null {
    if (!obj || typeof obj !== 'object') return null;
    for (const [key, value] of Object.entries(obj)) {
      const path = `${prefix}.${key}`;
      if (this.isFieldExcluded(key)) continue;
      if (typeof value === 'string') {
        const result = this.checkValue(value, path);
        if (result) return result;
      } else if (typeof value === 'object' && value !== null) {
        const result = this.checkObject(value, path);
        if (result) return result;
      }
    }
    return null;
  }
}

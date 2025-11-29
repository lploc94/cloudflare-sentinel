/**
 * SQL Injection Request Detector
 * Detects SQL injection patterns in incoming requests
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/** Pattern for detecting SQL injection in requests */
export interface SQLInjectionPattern {
  regex: RegExp;
  description: string;
  confidence: number;
  severity: SecuritySeverity;
}

/**
 * Sanitizer function for masking sensitive data in evidence/logs
 * @param value - The matched value to sanitize
 * @returns Sanitized value safe for logging
 */
export type SQLInjectionSanitizer = (value: string) => string;

export interface SQLInjectionRequestDetectorConfig extends BaseDetectorOptions {
  /** Custom patterns - if provided, OVERRIDES built-in patterns */
  patterns?: SQLInjectionPattern[];
  /** Headers to check for SQL injection (default: common API headers) */
  checkHeaders?: string[];
  /** Fields to exclude from checking (exact match) */
  excludeFields?: string[];
  /**
   * Custom sanitizer for evidence values (masks sensitive data in logs/reports)
   * 
   * NOTE: This is for masking sensitive data in LOGS/EVIDENCE, NOT for
   * sanitizing input to prevent attacks. Attack prevention is handled by executors.
   */
  sanitizer?: SQLInjectionSanitizer;
  /** Max length for evidence value (default: 100) */
  maxEvidenceLength?: number;
}

// === SQL INJECTION PATTERNS ===
// Confidence guidelines:
// - 0.95-0.99: Almost certainly malicious (very specific attack patterns)
// - 0.85-0.94: Highly suspicious (uncommon in legitimate traffic)
// - 0.70-0.84: Suspicious (could be legitimate in some contexts)
// - 0.50-0.69: Low confidence (high false positive risk)
const SQL_INJECTION_PATTERNS: SQLInjectionPattern[] = [
  // === CRITICAL - Destructive operations (definite attack) ===
  { regex: /;\s*DROP\s+(TABLE|DATABASE|INDEX|VIEW)\s+/i, description: 'DROP statement', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /;\s*TRUNCATE\s+TABLE\s+/i, description: 'TRUNCATE statement', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /INTO\s+(OUT|DUMP)FILE\s+['"]/i, description: 'File write attempt', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /LOAD_FILE\s*\(\s*['"]/i, description: 'File read attempt', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // === CRITICAL - UNION-based injection (definite attack) ===
  { regex: /UNION\s+(ALL\s+)?SELECT\s+NULL/i, description: 'UNION SELECT NULL (column probing)', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /UNION\s+(ALL\s+)?SELECT\s+\d+\s*,/i, description: 'UNION SELECT with numbers', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /UNION\s+(ALL\s+)?SELECT\s+/i, description: 'UNION SELECT injection', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  
  // === HIGH - Classic SQL injection (specific patterns) ===
  { regex: /'\s*OR\s+['"]?1['"]?\s*=\s*['"]?1/i, description: "OR 1=1 injection", confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /'\s*OR\s+['"]['"]?\s*=\s*['"]/i, description: "OR ''='' injection", confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /'\s*OR\s+['"]?true['"]?\s*=\s*['"]?true/i, description: "OR true=true injection", confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /'\s*AND\s+['"]?1['"]?\s*=\s*['"]?2/i, description: "AND 1=2 (false) injection", confidence: 0.9, severity: SecuritySeverity.HIGH },
  
  // === HIGH - Time-based blind injection (definite attack) ===
  { regex: /SLEEP\s*\(\s*\d+\s*\)/i, description: 'SLEEP(n) blind injection', confidence: 1.0, severity: SecuritySeverity.HIGH },
  { regex: /WAITFOR\s+DELAY\s+['"]0:/i, description: 'WAITFOR DELAY (MSSQL)', confidence: 1.0, severity: SecuritySeverity.HIGH },
  { regex: /pg_sleep\s*\(\s*\d/i, description: 'pg_sleep() (PostgreSQL)', confidence: 1.0, severity: SecuritySeverity.HIGH },
  { regex: /BENCHMARK\s*\(\s*\d{4,}/i, description: 'BENCHMARK with large iterations', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // === HIGH - Stacked queries (DML operations are more suspicious) ===
  { regex: /;\s*(UPDATE|DELETE)\s+\w+\s+(SET|WHERE)/i, description: 'Stacked UPDATE/DELETE', confidence: 0.92, severity: SecuritySeverity.HIGH },
  { regex: /;\s*INSERT\s+INTO\s+/i, description: 'Stacked INSERT', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /;\s*EXEC(UTE)?\s+/i, description: 'Stacked EXEC (MSSQL)', confidence: 0.92, severity: SecuritySeverity.HIGH },
  { regex: /;\s*SELECT\s+.*\s+FROM\s+/i, description: 'Stacked SELECT with FROM', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  
  // === HIGH - Schema/data extraction ===
  { regex: /information_schema\.(tables|columns|schemata)/i, description: 'Schema enumeration', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /sys\.(databases|objects|columns)/i, description: 'MSSQL system table access', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /mysql\.(user|db)/i, description: 'MySQL privilege tables', confidence: 0.98, severity: SecuritySeverity.HIGH },
  
  // === MEDIUM - Boolean-based blind ===
  { regex: /'\s*AND\s+\d+\s*=\s*\d+/i, description: 'Boolean blind (AND n=n)', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /'\s*AND\s+SUBSTRING\s*\(/i, description: 'SUBSTRING blind injection', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /'\s*AND\s+ASCII\s*\(/i, description: 'ASCII blind injection', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  
  // === MEDIUM - Comment injection (context required) ===
  { regex: /'\s*--\s*$/i, description: 'SQL comment at end of input', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /'\s*--\s+/i, description: 'SQL comment after quote', confidence: 0.7, severity: SecuritySeverity.MEDIUM },
  { regex: /'\s*#\s*$/i, description: 'MySQL comment at end', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /'\s*\/\*.*?\*\//i, description: 'Block comment after quote', confidence: 0.7, severity: SecuritySeverity.MEDIUM },
  
  // === MEDIUM - XML-based injection (can be legitimate XML functions) ===
  { regex: /EXTRACTVALUE\s*\([^)]*SELECT/i, description: 'EXTRACTVALUE with SELECT', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /UPDATEXML\s*\([^)]*SELECT/i, description: 'UPDATEXML with SELECT', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /EXTRACTVALUE\s*\(/i, description: 'EXTRACTVALUE function', confidence: 0.6, severity: SecuritySeverity.LOW },
  { regex: /UPDATEXML\s*\(/i, description: 'UPDATEXML function', confidence: 0.6, severity: SecuritySeverity.LOW },
  
  // === LOW - SQL functions (high false positive risk) ===
  { regex: /CONCAT\s*\([^)]*SELECT/i, description: 'CONCAT with SELECT', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /GROUP_CONCAT\s*\([^)]*SELECT/i, description: 'GROUP_CONCAT with SELECT', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { regex: /GROUP_CONCAT\s*\(/i, description: 'GROUP_CONCAT function', confidence: 0.5, severity: SecuritySeverity.LOW },
  { regex: /CHAR\s*\(\s*\d+\s*(,\s*\d+\s*){3,}\)/i, description: 'CHAR() evasion (4+ chars)', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  
  // === LOW - Version disclosure (can be legitimate) ===
  { regex: /@@version/i, description: 'MSSQL @@version', confidence: 0.6, severity: SecuritySeverity.LOW },
  { regex: /version\s*\(\s*\)/i, description: 'VERSION() function', confidence: 0.5, severity: SecuritySeverity.LOW },
  
  // === LOW - Generic patterns (high false positive, use as signals) ===
  { regex: /information_schema\./i, description: 'Information schema access', confidence: 0.65, severity: SecuritySeverity.MEDIUM },
  { regex: /;\s*ALTER\s+TABLE/i, description: 'ALTER TABLE (could be admin)', confidence: 0.7, severity: SecuritySeverity.MEDIUM },
  { regex: /;\s*SELECT\s+/i, description: 'Stacked SELECT', confidence: 0.6, severity: SecuritySeverity.LOW },
];

// Default headers to check
const DEFAULT_CHECK_HEADERS = [
  'x-api-key', 'x-auth-token', 'x-user-id', 'x-request-id',
  'authorization', 'x-forwarded-for', 'x-custom-header',
];

/**
 * SQLInjectionRequestDetector - Detect SQL injection in requests
 * 
 * Checks query parameters, request body, and headers for SQL injection patterns.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new SQLInjectionRequestDetector({})
 * 
 * // Custom headers to check
 * new SQLInjectionRequestDetector({
 *   checkHeaders: ['x-user-input', 'x-search-query'],
 * })
 * 
 * // Exclude certain fields
 * new SQLInjectionRequestDetector({
 *   excludeFields: ['password', 'token'],
 * })
 * 
 * // Custom sanitizer for logs
 * new SQLInjectionRequestDetector({
 *   sanitizer: (value) => value.replace(/api_key=\S+/gi, 'api_key=***'),
 * })
 * 
 * // Override patterns
 * new SQLInjectionRequestDetector({
 *   patterns: [...SQLInjectionRequestDetector.PATTERNS],
 * })
 * ```
 */
export class SQLInjectionRequestDetector extends BaseDetector {
  name = 'sql-injection-request';
  phase = 'request' as const;
  priority = 100;

  private config: SQLInjectionRequestDetectorConfig;
  private activePatterns: SQLInjectionPattern[];
  private checkHeaders: string[];
  private excludeFields: Set<string>;

  /** Built-in patterns */
  static readonly PATTERNS = SQL_INJECTION_PATTERNS;

  constructor(config: SQLInjectionRequestDetectorConfig = {}) {
    super();
    this.config = config;
    this.activePatterns = config.patterns ?? SQL_INJECTION_PATTERNS;
    this.checkHeaders = config.checkHeaders ?? DEFAULT_CHECK_HEADERS;
    this.excludeFields = new Set(
      (config.excludeFields ?? ['token', 'access_token', 'refresh_token', 'google_token', 'id_token', 'jwt', 'password', 'secret']).map(f => f.toLowerCase())
    );
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check each query parameter
    for (const [key, value] of url.searchParams.entries()) {
      if (this.isFieldExcluded(key)) continue;
      const detection = this.checkForSQLInjection(value, `query.${key}`);
      if (detection) return detection;
    }

    // Check request body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        const contentType = request.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
          const body = await request.clone().text();
          const detection = this.checkForSQLInjection(body, 'body');
          if (detection) return detection;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const body = await request.clone().text();
          const params = new URLSearchParams(body);
          for (const [key, value] of params.entries()) {
            if (this.isFieldExcluded(key)) continue;
            const detection = this.checkForSQLInjection(value, `form.${key}`);
            if (detection) return detection;
          }
        }
      } catch {
        // Cannot read body, skip
      }
    }

    // Check configured headers
    for (const headerName of this.checkHeaders) {
      const value = request.headers.get(headerName);
      if (value) {
        const detection = this.checkForSQLInjection(value, `header.${headerName}`);
        if (detection) return detection;
      }
    }

    return null;
  }

  private isFieldExcluded(field: string): boolean {
    return this.excludeFields.has(field.toLowerCase());
  }

  private checkForSQLInjection(input: string, field: string): DetectorResult | null {
    // Decode URL-encoded strings
    let decodedInput = input;
    try {
      decodedInput = decodeURIComponent(input);
      // Try double decode
      if (decodedInput.includes('%')) {
        decodedInput = decodeURIComponent(decodedInput);
      }
    } catch {
      // Invalid encoding, use original
    }

    for (const { regex, description, confidence, severity } of this.activePatterns) {
      if (regex.test(decodedInput)) {
        const match = decodedInput.match(regex);
        const finalConfidence = this.config.baseConfidence ?? confidence;
        
        return this.createResult(
          AttackType.SQL_INJECTION,
          severity,
          finalConfidence,
          {
            field,
            value: this.sanitizeValue(decodedInput),
            pattern: regex.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'sql_injection', matchedPattern: description }
        );
      }
    }

    return null;
  }

  /**
   * Sanitize value for safe logging/evidence
   * Uses custom sanitizer if provided, otherwise applies default masking
   */
  private sanitizeValue(value: string): string {
    const maxLength = this.config.maxEvidenceLength ?? 100;
    let sanitized = value.substring(0, maxLength);
    
    if (this.config.sanitizer) {
      // Use custom sanitizer
      sanitized = this.config.sanitizer(sanitized);
    } else {
      // Default: mask common sensitive fields
      sanitized = sanitized.replace(/password[=:]\s*\S+/gi, 'password=***');
      sanitized = sanitized.replace(/token[=:]\s*\S+/gi, 'token=***');
      sanitized = sanitized.replace(/secret[=:]\s*\S+/gi, 'secret=***');
      sanitized = sanitized.replace(/api[_-]?key[=:]\s*\S+/gi, 'api_key=***');
    }
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

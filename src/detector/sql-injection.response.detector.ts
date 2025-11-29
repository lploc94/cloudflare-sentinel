/**
 * SQL Injection Response Detector
 * Detects SQL error leaks and query structures in responses
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/** Pattern for detecting SQL leaks in response */
export interface SQLLeakPattern {
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
export type EvidenceSanitizer = (value: string) => string;

export interface SQLInjectionResponseDetectorConfig extends BaseDetectorOptions {
  /** Custom patterns - if provided, OVERRIDES built-in patterns */
  patterns?: SQLLeakPattern[];
  /** Only scan error responses (default: true) */
  errorResponsesOnly?: boolean;
  /**
   * Custom sanitizer for evidence values (masks sensitive data in logs/reports)
   * 
   * NOTE: This is for masking sensitive data in LOGS/EVIDENCE, NOT for
   * sanitizing input to prevent attacks. Attack prevention is handled by executors.
   * 
   * Default: masks passwords, tokens, and User IDs
   * 
   * @example
   * ```typescript
   * sanitizer: (value) => {
   *   // Mask your service-specific secrets
   *   return value
   *     .replace(/API_KEY=\S+/gi, 'API_KEY=***')
   *     .replace(/my_secret_field=\S+/gi, 'my_secret_field=***');
   * }
   * ```
   */
  sanitizer?: EvidenceSanitizer;
  /** Max length for evidence value (default: 100) */
  maxEvidenceLength?: number;
}

// === SQL ERROR LEAK PATTERNS ===
const SQL_LEAK_PATTERNS: SQLLeakPattern[] = [
  // === CRITICAL - Database error messages (definite leak) ===
  
  // MySQL
  { regex: /You have an error in your SQL syntax/i, description: 'MySQL syntax error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /mysql_fetch_/i, description: 'MySQL function leak', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /mysqli?::/i, description: 'MySQLi leak', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /MySQL server version for the right syntax/i, description: 'MySQL version leak', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // PostgreSQL
  { regex: /PostgreSQL.*?ERROR/i, description: 'PostgreSQL error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /pg_query\(\)/i, description: 'pg_query leak', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /psycopg2\.(DatabaseError|OperationalError)/i, description: 'Python psycopg2 error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Oracle
  { regex: /ORA-\d{5}/i, description: 'Oracle error code', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /Oracle.*?Driver/i, description: 'Oracle driver leak', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // SQL Server
  { regex: /Microsoft SQL Server.*?error/i, description: 'MSSQL error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /\[Microsoft\]\[ODBC SQL Server Driver\]/i, description: 'MSSQL ODBC error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /System\.Data\.SqlClient/i, description: '.NET SqlClient error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // SQLite
  { regex: /SQLite.*?error/i, description: 'SQLite error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /sqlite3\.(DatabaseError|OperationalError)/i, description: 'Python sqlite3 error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Generic SQL
  { regex: /SQLSTATE\[\w+\]/i, description: 'SQLSTATE error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /SQL\s+syntax.*?error/i, description: 'SQL syntax error', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // === HIGH - ORM/Framework errors ===
  
  // PHP PDO
  { regex: /PDOException/i, description: 'PHP PDO exception', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /SQLSTATE\[HY\d+\]/i, description: 'PDO SQLSTATE', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // Java JDBC
  { regex: /java\.sql\.SQLException/i, description: 'Java SQLException', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /JDBCException/i, description: 'JDBC exception', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /org\.hibernate\.exception/i, description: 'Hibernate exception', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // Node.js ORMs
  { regex: /PrismaClientKnownRequestError/i, description: 'Prisma error', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /SequelizeDatabaseError/i, description: 'Sequelize error', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /TypeORMError/i, description: 'TypeORM error', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /QueryFailedError/i, description: 'TypeORM query failed', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // Python ORMs
  { regex: /sqlalchemy\.exc\./i, description: 'SQLAlchemy error', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /django\.db\.utils/i, description: 'Django DB error', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // === MEDIUM - Query structure leaks ===
  { regex: /SELECT\s+.*?\s+FROM\s+\w+/i, description: 'SELECT query leak', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /UPDATE\s+\w+\s+SET/i, description: 'UPDATE query leak', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /INSERT\s+INTO\s+\w+/i, description: 'INSERT query leak', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /DELETE\s+FROM\s+\w+/i, description: 'DELETE query leak', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  
  // === MEDIUM - Schema leaks ===
  { regex: /table\s+['"]\w+['"].*?doesn't exist/i, description: 'Table name leak', confidence: 0.9, severity: SecuritySeverity.MEDIUM },
  { regex: /unknown\s+column\s+['"]\w+['"]/i, description: 'Column name leak', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /column\s+['"]\w+['"].*?not found/i, description: 'Column not found', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  
  // === CRITICAL - Connection string leaks (definite leak) ===
  { regex: /(Server|Database|User\s*ID|Password)\s*=\s*[^;\s]+/i, description: 'Connection string leak', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { regex: /Data Source\s*=\s*[^;\s]+/i, description: 'Data source leak', confidence: 0.98, severity: SecuritySeverity.HIGH },
];

/**
 * SQLInjectionResponseDetector - Detect SQL error leaks in responses
 * 
 * Detects database error messages and query structures that may indicate
 * SQL injection vulnerabilities or information disclosure.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new SQLInjectionResponseDetector({})
 * 
 * // Scan all responses (not just errors)
 * new SQLInjectionResponseDetector({
 *   errorResponsesOnly: false,
 * })
 * 
 * // Override patterns
 * new SQLInjectionResponseDetector({
 *   patterns: [
 *     { regex: /CustomDBError/, description: 'Custom DB', confidence: 0.9, severity: SecuritySeverity.HIGH },
 *   ],
 * })
 * 
 * // Access built-in patterns
 * SQLInjectionResponseDetector.PATTERNS
 * ```
 */
export class SQLInjectionResponseDetector extends BaseDetector {
  name = 'sql-injection-response';
  phase = 'response' as const;
  priority = 100;

  private config: SQLInjectionResponseDetectorConfig;
  private activePatterns: SQLLeakPattern[];

  /** Built-in patterns */
  static readonly PATTERNS = SQL_LEAK_PATTERNS;

  constructor(config: SQLInjectionResponseDetectorConfig = {}) {
    super();
    this.config = {
      errorResponsesOnly: true,
      ...config,
    };
    this.activePatterns = config.patterns ?? SQL_LEAK_PATTERNS;
  }

  async detectResponse(request: Request, response: Response, context: any): Promise<DetectorResult | null> {
    // Check if we should only scan error responses
    if (this.config.errorResponsesOnly && response.status < 400) {
      return null;
    }
    
    try {
      const contentType = response.headers.get('content-type') || '';
      
      // Only scan text-based responses
      if (!contentType.includes('text/') && 
          !contentType.includes('application/json') &&
          !contentType.includes('application/xml')) {
        return null;
      }
      
      const body = await response.clone().text();
      return this.checkForSQLLeaks(body);
      
    } catch (error) {
      // Cannot read response body
      return null;
    }
  }

  private checkForSQLLeaks(body: string): DetectorResult | null {
    for (const { regex, description, confidence, severity } of this.activePatterns) {
      const match = body.match(regex);
      if (match) {
        const finalConfidence = this.config.baseConfidence ?? confidence;
        return this.createResult(
          AttackType.SQL_INJECTION,
          severity,
          finalConfidence,
          {
            field: 'response_body',
            value: this.sanitizeValue(match[0]),
            pattern: regex.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'sql_leak', matchedPattern: description }
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
      sanitized = sanitized.replace(/User\s*ID\s*=\s*\S+/gi, 'User ID=***');
      sanitized = sanitized.replace(/secret[=:]\s*\S+/gi, 'secret=***');
    }
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

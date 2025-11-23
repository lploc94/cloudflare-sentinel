/**
 * SQL Injection Response Detector
 * Detects SQL error leaks and query structures in responses
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class SQLInjectionResponseDetector extends BaseDetector {
  name = 'sql-injection-response';
  priority = 100;

  async detectResponse(request: Request, response: Response, context: any): Promise<DetectorResult | null> {
    // Only scan error responses (4xx, 5xx)
    if (response.status < 400) return null;
    
    try {
      const contentType = response.headers.get('content-type') || '';
      
      // Only scan text-based responses
      if (!contentType.includes('text/') && 
          !contentType.includes('application/json') &&
          !contentType.includes('application/xml')) {
        return null;
      }
      
      const body = await response.clone().text();
      
      // Detect SQL error messages and query leaks
      const detection = this.checkForSQLLeaks(body);
      if (detection) return detection;
      
    } catch (error) {
      // Cannot read response body
    }
    
    return null;
  }

  private checkForSQLLeaks(body: string): DetectorResult | null {
    const leakPatterns = [
      // Database error messages
      { regex: /SQL\s+syntax.*?error/i, confidence: 0.95, type: 'sql_syntax_error' },
      { regex: /mysql_fetch_/i, confidence: 0.98, type: 'mysql_function_leak' },
      { regex: /mysqli?::/i, confidence: 0.95, type: 'mysqli_leak' },
      { regex: /PostgreSQL.*?ERROR/i, confidence: 0.95, type: 'postgresql_error' },
      { regex: /ORA-\d{5}/i, confidence: 0.98, type: 'oracle_error' },
      { regex: /SQLSTATE\[\w+\]/i, confidence: 0.95, type: 'sqlstate_error' },
      { regex: /SQLite.*?error/i, confidence: 0.95, type: 'sqlite_error' },
      { regex: /Microsoft SQL Server.*?error/i, confidence: 0.95, type: 'mssql_error' },
      
      // Query structure leaks
      { regex: /SELECT\s+.*?\s+FROM\s+\w+/i, confidence: 0.9, type: 'query_structure_leak' },
      { regex: /UPDATE\s+\w+\s+SET/i, confidence: 0.9, type: 'update_query_leak' },
      { regex: /INSERT\s+INTO\s+\w+/i, confidence: 0.9, type: 'insert_query_leak' },
      { regex: /DELETE\s+FROM\s+\w+/i, confidence: 0.9, type: 'delete_query_leak' },
      
      // Table/column name leaks
      { regex: /table\s+['"]\w+['"].*?doesn't exist/i, confidence: 0.9, type: 'table_name_leak' },
      { regex: /column\s+['"]\w+['"].*?not found/i, confidence: 0.85, type: 'column_name_leak' },
      { regex: /unknown\s+column\s+['"]\w+['"]/i, confidence: 0.85, type: 'column_leak' },
      
      // Connection string leaks
      { regex: /(Server|Database|User\s*ID|Password)\s*=\s*\S+/i, confidence: 0.98, type: 'connection_string_leak' },
      
      // Stack traces with SQL
      { regex: /at\s+.*?(query|execute|prepare).*?\.php:\d+/i, confidence: 0.8, type: 'sql_stack_trace' },
    ];
    
    for (const { regex, confidence, type } of leakPatterns) {
      const match = body.match(regex);
      if (match) {
        return {
          detected: true,
          attackType: AttackType.SQL_INJECTION,
          severity: this.getSeverity(confidence),
          confidence,
          evidence: {
            field: 'response_body',
            value: this.sanitizeValue(match[0]),
            rawContent: this.getContext(body, match.index || 0),
          },
          metadata: {
            detectionType: 'response_leak',
            leakType: type,
            statusCode: 'error',
          },
        };
      }
    }
    
    return null;
  }

  private getContext(text: string, position: number, contextSize: number = 100): string {
    const start = Math.max(0, position - contextSize);
    const end = Math.min(text.length, position + contextSize);
    let context = text.substring(start, end);
    
    // Sanitize sensitive data in context
    context = context.replace(/password[=:]\s*\S+/gi, 'password=***');
    context = context.replace(/token[=:]\s*\S+/gi, 'token=***');
    
    return '...' + context + '...';
  }

  private getSeverity(confidence: number): SecuritySeverity {
    if (confidence >= 0.95) return SecuritySeverity.CRITICAL;
    if (confidence >= 0.85) return SecuritySeverity.HIGH;
    if (confidence >= 0.7) return SecuritySeverity.MEDIUM;
    return SecuritySeverity.LOW;
  }

  private sanitizeValue(value: string): string {
    const maxLength = 100;
    let sanitized = value.substring(0, maxLength);
    
    // Mask potential passwords or tokens
    sanitized = sanitized.replace(/password[=:]\s*\S+/gi, 'password=***');
    sanitized = sanitized.replace(/token[=:]\s*\S+/gi, 'token=***');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

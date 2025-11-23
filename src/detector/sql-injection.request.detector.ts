/**
 * SQL Injection Request Detector
 * Detects SQL injection patterns in incoming requests
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class SQLInjectionRequestDetector extends BaseDetector {
  name = 'sql-injection-request';
  priority = 100;

  private readonly patterns = [
    // Destructive operations (highest priority)
    { regex: /;\s*DROP\s+(TABLE|DATABASE)/i, confidence: 1.0 },
    { regex: /;\s*(DELETE|UPDATE|INSERT)\s+/i, confidence: 0.85 },
    
    // Classic SQL injection
    { regex: /(\bOR\b|\bAND\b)\s+['"]?\d+['"]?\s*=\s*['"]?\d+/i, confidence: 0.95 },
    { regex: /(\bOR\b|\bAND\b)\s+['"]\w+['"]\s*=\s*['"]\w+/i, confidence: 0.9 },
    
    // UNION-based injection
    { regex: /UNION\s+(ALL\s+)?SELECT/i, confidence: 0.98 },
    
    // Comment-based injection (lower priority)
    { regex: /(--|#|\/\*|\*\/)/i, confidence: 0.7 },
    
    // Time-based blind injection
    { regex: /SLEEP\s*\(/i, confidence: 0.9 },
    { regex: /WAITFOR\s+DELAY/i, confidence: 0.95 },
    { regex: /BENCHMARK\s*\(/i, confidence: 0.9 },
    
    // Boolean-based blind injection
    { regex: /\b(AND|OR)\b\s+\d+\s*[<>=]/i, confidence: 0.75 },
    
    // Stacked queries
    { regex: /;\s*(SELECT|UPDATE|DELETE|INSERT|DROP|CREATE)/i, confidence: 0.9 },
    
    // SQL keywords in suspicious positions
    { regex: /['"][\s]*(OR|AND)[\s]+['"]?[\w\d]+['"]?[\s]*=/i, confidence: 0.85 },
    
    // Encoded SQL injection
    { regex: /%27|%22|%2D%2D|%23/i, confidence: 0.6 },
    
    // Always true conditions
    { regex: /['"]?\s*(OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1/i, confidence: 0.95 },
    { regex: /['"]?\s*(OR|AND)\s+['"]?true['"]?\s*=\s*['"]?true/i, confidence: 0.9 },
  ];

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check query parameters
    const queryString = url.search;
    if (queryString) {
      const detection = this.checkForSQLInjection(queryString, 'query');
      if (detection) return detection;
    }

    // Check each query parameter separately
    for (const [key, value] of url.searchParams.entries()) {
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
          const detection = this.checkForSQLInjection(body, 'form_body');
          if (detection) return detection;
        }
      } catch (error) {
        // Cannot read body, skip
      }
    }

    // Check headers (especially custom headers)
    const headerKeys = ['x-api-key', 'x-auth-token', 'x-user-id', 'x-custom'];
    for (const key of headerKeys) {
      const value = request.headers.get(key);
      if (value) {
        const detection = this.checkForSQLInjection(value, `header.${key}`);
        if (detection) return detection;
      }
    }

    return null;
  }

  private checkForSQLInjection(input: string, field: string): DetectorResult | null {
    // Decode URL-encoded strings
    let decodedInput = input;
    try {
      decodedInput = decodeURIComponent(input);
    } catch {
      // Invalid encoding, use original
    }

    for (const { regex, confidence } of this.patterns) {
      if (regex.test(decodedInput)) {
        const match = decodedInput.match(regex);
        
        return this.createResult(
          AttackType.SQL_INJECTION,
          this.getSeverity(confidence),
          confidence,
          {
            field,
            value: this.sanitizeValue(decodedInput),
            pattern: regex.source,
            rawContent: match ? match[0].substring(0, 50) : undefined,
          }
        );
      }
    }

    return null;
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

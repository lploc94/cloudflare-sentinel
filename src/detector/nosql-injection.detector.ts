/**
 * NoSQL Injection Detector
 * 
 * Detects NoSQL injection attempts, primarily targeting MongoDB.
 * Catches query operators, JavaScript injection, and common payloads.
 */

import { BaseDetector } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface NoSQLInjectionDetectorConfig {
  /** Enable/disable detector */
  enabled?: boolean;
  /** Priority (0-100, higher = checked first) */
  priority?: number;
  /** Paths to exclude from detection */
  excludePaths?: string[];
  /** Fields to exclude from checking */
  excludeFields?: string[];
}

// MongoDB query operators that could be malicious
// IMPORTANT: Order matters - CRITICAL patterns should be checked first
const MONGODB_OPERATORS: Array<{ pattern: RegExp; description: string; severity: SecuritySeverity }> = [
  // Always true conditions (authentication bypass) - CHECK FIRST
  {
    pattern: /["']?\$(?:ne|gt|gte)["']?\s*:\s*["']?["']?\s*[}\]]/i,
    description: 'Always-true condition (auth bypass)',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Where clause (JavaScript execution)
  {
    pattern: /["']?\$where["']?\s*:/i,
    description: 'MongoDB $where clause (JavaScript execution)',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Comparison operators (dangerous when user-controlled)
  {
    pattern: /["']?\$(?:eq|ne|gt|gte|lt|lte|in|nin)["']?\s*:/i,
    description: 'MongoDB comparison operator',
    severity: SecuritySeverity.HIGH,
  },
  
  // Logical operators
  {
    pattern: /["']?\$(?:and|or|not|nor)["']?\s*:/i,
    description: 'MongoDB logical operator',
    severity: SecuritySeverity.HIGH,
  },
  
  // Update operators (data modification) - CRITICAL, check before HIGH patterns
  {
    pattern: /["']?\$(?:set|unset|inc|push|pull|addToSet|pop|rename)["']?\s*:/i,
    description: 'MongoDB update operator',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Regex injection
  {
    pattern: /["']?\$regex["']?\s*:/i,
    description: 'MongoDB regex injection',
    severity: SecuritySeverity.HIGH,
  },
  
  // Evaluation operators (dangerous)
  {
    pattern: /["']?\$(?:expr|jsonSchema|mod|text)["']?\s*:/i,
    description: 'MongoDB evaluation operator',
    severity: SecuritySeverity.HIGH,
  },
  
  // Aggregation operators
  {
    pattern: /["']?\$(?:lookup|graphLookup|merge|out)["']?\s*:/i,
    description: 'MongoDB aggregation operator',
    severity: SecuritySeverity.HIGH,
  },
  
  // Type confusion
  {
    pattern: /["']?\$type["']?\s*:/i,
    description: 'MongoDB type operator',
    severity: SecuritySeverity.MEDIUM,
  },
];

// JavaScript injection patterns (for $where, $function, etc.)
const JS_INJECTION_PATTERNS: Array<{ pattern: RegExp; description: string; severity: SecuritySeverity }> = [
  // Function execution
  {
    pattern: /function\s*\([^)]*\)\s*\{/i,
    description: 'JavaScript function definition',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Sleep/DoS attacks
  {
    pattern: /sleep\s*\(\d+\)/i,
    description: 'JavaScript sleep (DoS attack)',
    severity: SecuritySeverity.HIGH,
  },
  
  // Process/require (RCE)
  {
    pattern: /(?:process|require|eval|exec)\s*\(/i,
    description: 'JavaScript dangerous function',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // this.password/this.username extraction
  {
    pattern: /this\.(password|username|email|token|secret)/i,
    description: 'Field extraction via this reference',
    severity: SecuritySeverity.HIGH,
  },
  
  // Return true (auth bypass)
  {
    pattern: /return\s+true/i,
    description: 'Return true (auth bypass)',
    severity: SecuritySeverity.CRITICAL,
  },
];

// Common NoSQL injection payloads
const NOSQL_PAYLOADS: Array<{ pattern: RegExp; description: string; severity: SecuritySeverity }> = [
  // JSON object injection
  {
    pattern: /\{\s*["']?\$[a-z]+["']?\s*:/i,
    description: 'JSON object with MongoDB operator',
    severity: SecuritySeverity.HIGH,
  },
  
  // Array with operator
  {
    pattern: /\[\s*\{\s*["']?\$[a-z]+/i,
    description: 'Array with MongoDB operator',
    severity: SecuritySeverity.HIGH,
  },
  
  // Empty object injection (bypass)
  {
    pattern: /\{\s*\}/,
    description: 'Empty object (potential bypass)',
    severity: SecuritySeverity.LOW,
  },
  
  // Null injection
  {
    pattern: /["']?\s*:\s*null\s*[,}]/i,
    description: 'Null value injection',
    severity: SecuritySeverity.LOW,
  },
];

export class NoSQLInjectionDetector extends BaseDetector {
  name = 'nosql_injection';
  priority: number;
  enabled: boolean;
  
  private config: NoSQLInjectionDetectorConfig;
  private excludePathPatterns: RegExp[];

  constructor(config: NoSQLInjectionDetectorConfig = {}) {
    super();
    this.config = {
      enabled: true,
      priority: 80,  // High priority
      excludePaths: [],
      excludeFields: ['password', 'token', 'secret', 'key'],
      ...config,
    };
    
    this.priority = this.config.priority!;
    this.enabled = this.config.enabled!;
    
    // Compile exclude path patterns
    this.excludePathPatterns = (this.config.excludePaths || []).map(p => {
      const regexPattern = p
        .replace(/\*\*/g, '.*')
        .replace(/\*/g, '[^/]*')
        .replace(/\?/g, '.');
      return new RegExp(`^${regexPattern}$`);
    });
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check if path is excluded
    if (this.isPathExcluded(url.pathname)) {
      return null;
    }
    
    // Check query parameters
    for (const [key, value] of url.searchParams) {
      if (this.isFieldExcluded(key)) continue;
      
      const result = this.checkValue(value, `query.${key}`);
      if (result) return result;
    }
    
    // Check body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const contentType = request.headers.get('content-type') || '';
      
      try {
        if (contentType.includes('application/json')) {
          const clonedRequest = request.clone();
          const bodyText = await clonedRequest.text();
          
          // Check parsed JSON first (key detection is CRITICAL)
          try {
            const body = JSON.parse(bodyText);
            const result = this.checkObject(body, 'body');
            if (result) return result;
          } catch {
            // Not valid JSON, check raw body
          }
          
          // Then check raw body for injection patterns
          const rawResult = this.checkValue(bodyText, 'body.raw');
          if (rawResult) return rawResult;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const clonedRequest = request.clone();
          const formData = await clonedRequest.text();
          const params = new URLSearchParams(formData);
          for (const [key, value] of params) {
            if (this.isFieldExcluded(key)) continue;
            const result = this.checkValue(value, `form.${key}`);
            if (result) return result;
          }
        }
      } catch {
        // Ignore parse errors
      }
    }
    
    return null;
  }

  private isPathExcluded(path: string): boolean {
    return this.excludePathPatterns.some(pattern => pattern.test(path));
  }

  private isFieldExcluded(field: string): boolean {
    const lowerField = field.toLowerCase();
    return (this.config.excludeFields || []).some(f => 
      lowerField === f.toLowerCase() || lowerField.includes(f.toLowerCase())
    );
  }

  private checkValue(value: string, location: string): DetectorResult | null {
    if (!value || typeof value !== 'string') return null;
    
    // Quick check for $ sign (MongoDB operators start with $)
    if (!value.includes('$') && !value.includes('function') && !value.includes('return')) {
      return null;
    }
    
    // Check MongoDB operators
    for (const { pattern, description, severity } of MONGODB_OPERATORS) {
      if (pattern.test(value)) {
        return this.createResult(
          AttackType.NOSQL_INJECTION,
          severity,
          severity === SecuritySeverity.CRITICAL ? 0.95 : 0.85,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
          },
          {
            detector: this.name,
            description,
            type: 'mongodb_operator',
          },
        );
      }
    }
    
    // Check JavaScript injection
    for (const { pattern, description, severity } of JS_INJECTION_PATTERNS) {
      if (pattern.test(value)) {
        return this.createResult(
          AttackType.NOSQL_INJECTION,
          severity,
          severity === SecuritySeverity.CRITICAL ? 0.95 : 0.85,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
          },
          {
            detector: this.name,
            description,
            type: 'javascript_injection',
          },
        );
      }
    }
    
    // Check common payloads
    for (const { pattern, description, severity } of NOSQL_PAYLOADS) {
      if (pattern.test(value)) {
        // Skip low severity for short strings (likely false positives)
        if (severity === SecuritySeverity.LOW && value.length < 10) continue;
        
        return this.createResult(
          AttackType.NOSQL_INJECTION,
          severity,
          severity === SecuritySeverity.HIGH ? 0.8 : 0.6,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
          },
          {
            detector: this.name,
            description,
            type: 'nosql_payload',
          },
        );
      }
    }
    
    return null;
  }

  private checkObject(obj: any, prefix: string): DetectorResult | null {
    if (!obj || typeof obj !== 'object') return null;
    
    for (const [key, value] of Object.entries(obj)) {
      const path = `${prefix}.${key}`;
      
      // Check if key itself contains MongoDB operator
      if (key.startsWith('$')) {
        return this.createResult(
          AttackType.NOSQL_INJECTION,
          SecuritySeverity.CRITICAL,
          0.95,
          {
            field: path,
            value: JSON.stringify(obj).substring(0, 200),
          },
          {
            detector: this.name,
            description: `MongoDB operator in field name: ${key}`,
            type: 'operator_key',
          },
        );
      }
      
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

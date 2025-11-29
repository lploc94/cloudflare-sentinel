/**
 * NoSQL Injection Detector
 * 
 * Detects NoSQL injection attempts, primarily targeting MongoDB.
 * Catches query operators, JavaScript injection, and common payloads.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/** Pattern definition for NoSQL injection */
export interface NoSQLPattern {
  pattern: RegExp;
  description: string;
  severity: SecuritySeverity;
  /** How certain this pattern indicates an attack (0-1) */
  confidence: number;
}

export interface NoSQLInjectionDetectorConfig extends BaseDetectorOptions {
  /** Enable/disable detector */
  enabled?: boolean;
  /** Priority (0-100, higher = checked first) */
  priority?: number;
  /** Fields to exclude from checking (exact match) */
  excludeFields?: string[];
  /** Custom patterns - if provided, OVERRIDES all built-in patterns */
  patterns?: NoSQLPattern[];
}

// MongoDB query operators that could be malicious
// IMPORTANT: Order matters - CRITICAL patterns should be checked first
const MONGODB_OPERATORS: NoSQLPattern[] = [
  // Always true conditions (authentication bypass) - very specific pattern
  {
    pattern: /["']?\$(?:ne|gt|gte)["']?\s*:\s*["']?["']?\s*[}\]]/i,
    description: 'Always-true condition (auth bypass)',
    severity: SecuritySeverity.CRITICAL,
    confidence: 1.0,  // Definite attack
  },
  
  // Where clause (JavaScript execution)
  {
    pattern: /["']?\$where["']?\s*:/i,
    description: 'MongoDB $where clause (JavaScript execution)',
    severity: SecuritySeverity.CRITICAL,
    confidence: 0.95,  // JS execution - very dangerous
  },
  
  // Update operators (data modification)
  {
    pattern: /["']?\$(?:set|unset|inc|push|pull|addToSet|pop|rename)["']?\s*:/i,
    description: 'MongoDB update operator',
    severity: SecuritySeverity.CRITICAL,
    confidence: 0.9,  // Data modification - dangerous
  },
  
  // Comparison operators (dangerous when user-controlled)
  {
    pattern: /["']?\$(?:eq|ne|gt|gte|lt|lte|in|nin)["']?\s*:/i,
    description: 'MongoDB comparison operator',
    severity: SecuritySeverity.HIGH,
    confidence: 0.7,  // Common in query strings, need context
  },
  
  // Logical operators
  {
    pattern: /["']?\$(?:and|or|not|nor)["']?\s*:/i,
    description: 'MongoDB logical operator',
    severity: SecuritySeverity.HIGH,
    confidence: 0.7,
  },
  
  // Regex injection
  {
    pattern: /["']?\$regex["']?\s*:/i,
    description: 'MongoDB regex injection',
    severity: SecuritySeverity.HIGH,
    confidence: 0.75,
  },
  
  // Evaluation operators (dangerous)
  {
    pattern: /["']?\$(?:expr|jsonSchema|mod|text)["']?\s*:/i,
    description: 'MongoDB evaluation operator',
    severity: SecuritySeverity.HIGH,
    confidence: 0.85,
  },
  
  // Aggregation operators
  {
    pattern: /["']?\$(?:lookup|graphLookup|merge|out)["']?\s*:/i,
    description: 'MongoDB aggregation operator',
    severity: SecuritySeverity.HIGH,
    confidence: 0.85,
  },
  
  // Type confusion
  {
    pattern: /["']?\$type["']?\s*:/i,
    description: 'MongoDB type operator',
    severity: SecuritySeverity.MEDIUM,
    confidence: 0.5,  // Often legitimate
  },
];

// JavaScript injection patterns (for $where, $function, etc.)
const JS_INJECTION_PATTERNS: NoSQLPattern[] = [
  // Function execution - very specific
  {
    pattern: /function\s*\([^)]*\)\s*\{/i,
    description: 'JavaScript function definition',
    severity: SecuritySeverity.CRITICAL,
    confidence: 1.0,  // Definite JS injection
  },
  
  // Process/require (RCE)
  {
    pattern: /(?:process|require|eval|exec)\s*\(/i,
    description: 'JavaScript dangerous function',
    severity: SecuritySeverity.CRITICAL,
    confidence: 1.0,  // RCE attempt
  },
  
  // Return true (auth bypass)
  {
    pattern: /return\s+true/i,
    description: 'Return true (auth bypass)',
    severity: SecuritySeverity.CRITICAL,
    confidence: 0.95,
  },
  
  // Sleep/DoS attacks
  {
    pattern: /sleep\s*\(\d+\)/i,
    description: 'JavaScript sleep (DoS attack)',
    severity: SecuritySeverity.HIGH,
    confidence: 0.95,
  },
  
  // this.password/this.username extraction
  {
    pattern: /this\.(password|username|email|token|secret)/i,
    description: 'Field extraction via this reference',
    severity: SecuritySeverity.HIGH,
    confidence: 0.9,
  },
];

// Common NoSQL injection payloads
const NOSQL_PAYLOADS: NoSQLPattern[] = [
  // JSON object injection - specific pattern
  {
    pattern: /\{\s*["']?\$[a-z]+["']?\s*:/i,
    description: 'JSON object with MongoDB operator',
    severity: SecuritySeverity.HIGH,
    confidence: 0.85,
  },
  
  // Array with operator
  {
    pattern: /\[\s*\{\s*["']?\$[a-z]+/i,
    description: 'Array with MongoDB operator',
    severity: SecuritySeverity.HIGH,
    confidence: 0.85,
  },
  
  // Empty object injection (bypass) - very common false positive
  {
    pattern: /\{\s*\}/,
    description: 'Empty object (potential bypass)',
    severity: SecuritySeverity.LOW,
    confidence: 0.2,  // Very low - often legitimate
  },
  
  // Null injection - often legitimate
  {
    pattern: /["']?\s*:\s*null\s*[,}]/i,
    description: 'Null value injection',
    severity: SecuritySeverity.LOW,
    confidence: 0.1,  // Very low - very common in normal JSON
  },
];

/**
 * NoSQLInjectionDetector - Detect NoSQL injection attempts
 * 
 * Primarily targets MongoDB. Catches query operators, JavaScript injection,
 * and common payloads.
 * 
 * @example
 * ```typescript
 * // Basic usage - built-in patterns
 * new NoSQLInjectionDetector({})
 * 
 * // Custom exclude fields
 * new NoSQLInjectionDetector({
 *   excludeFields: ['password', 'hash'],
 * })
 * 
 * // Override with custom patterns
 * new NoSQLInjectionDetector({
 *   patterns: [
 *     { pattern: /\$where/i, description: 'Where clause', severity: SecuritySeverity.CRITICAL },
 *   ],
 * })
 * ```
 */
export class NoSQLInjectionDetector extends BaseDetector {
  name = 'nosql-injection';
  phase = 'request' as const;
  priority: number;
  enabled: boolean;
  
  private config: NoSQLInjectionDetectorConfig;
  private activePatterns: NoSQLPattern[];

  /** Built-in patterns - all MongoDB operators, JS injection, and payloads */
  static readonly PATTERNS: NoSQLPattern[] = [
    ...MONGODB_OPERATORS,
    ...JS_INJECTION_PATTERNS,
    ...NOSQL_PAYLOADS,
  ];

  constructor(config: NoSQLInjectionDetectorConfig = {}) {
    super();
    this.config = {
      enabled: true,
      priority: 80,
      excludeFields: ['password', 'token', 'secret', 'key'],
      ...config,
    };
    
    this.priority = this.config.priority!;
    this.enabled = this.config.enabled!;
    
    // Use custom patterns if provided, otherwise built-in
    this.activePatterns = config.patterns ?? NoSQLInjectionDetector.PATTERNS;
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
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

  private isFieldExcluded(field: string): boolean {
    const lowerField = field.toLowerCase();
    // Exact match only
    return (this.config.excludeFields || []).some(f => 
      lowerField === f.toLowerCase()
    );
  }

  private checkValue(value: string, location: string): DetectorResult | null {
    if (!value || typeof value !== 'string') return null;
    
    // Quick check for $ sign (MongoDB operators start with $)
    if (!value.includes('$') && !value.includes('function') && !value.includes('return')) {
      return null;
    }
    
    // Check all active patterns
    for (const { pattern, description, severity, confidence } of this.activePatterns) {
      if (pattern.test(value)) {
        // Skip low severity for short strings (likely false positives)
        if (severity === SecuritySeverity.LOW && value.length < 10) continue;
        
        // Use baseConfidence if provided, otherwise use pattern's confidence
        const finalConfidence = this.config.baseConfidence ?? confidence;
        
        return this.createResult(
          AttackType.NOSQL_INJECTION,
          severity,
          finalConfidence,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
            rawContent: `Matched: ${description}`,
          },
          { matchedPattern: description },
        );
      }
    }
    
    return null;
  }

  private checkObject(obj: any, prefix: string): DetectorResult | null {
    if (!obj || typeof obj !== 'object') return null;
    
    for (const [key, value] of Object.entries(obj)) {
      const path = `${prefix}.${key}`;
      
      // Check if key itself contains MongoDB operator - definite attack
      if (key.startsWith('$')) {
        return this.createResult(
          AttackType.NOSQL_INJECTION,
          SecuritySeverity.CRITICAL,
          1.0,
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

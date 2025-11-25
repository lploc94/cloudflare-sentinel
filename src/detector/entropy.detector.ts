/**
 * Shannon Entropy Detector
 * Detects obfuscated/encoded payloads using entropy analysis
 * 
 * USE CASES:
 * - Detect base64/hex encoded SQL injection, XSS payloads
 * - Detect encrypted data in unexpected places
 * - Detect data exfiltration attempts (encoded sensitive data)
 * - Complement pattern-based detectors by catching obfuscated attacks
 * 
 * WHEN TO USE:
 * - API endpoints that should NOT receive encoded data
 * - Login forms where high-entropy passwords might indicate injection
 * - Query parameters that should contain simple values
 * - File uploads with suspicious metadata
 * 
 * WHEN NOT TO USE (or whitelist these):
 * - Endpoints that legitimately receive JWT tokens
 * - Image upload endpoints (base64 images)
 * - Encryption/crypto endpoints
 * - OAuth callback endpoints
 * 
 * Shannon Entropy scale (0-8 bits):
 * - 0-3: Normal text, English words
 * - 3-5: URL parameters, JSON data
 * - 5-8: Base64, hex, encrypted, obfuscated data (SUSPICIOUS)
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/**
 * Configuration for Entropy Detector
 */
export interface EntropyDetectorConfig {
  /**
   * Minimum entropy threshold to trigger detection (0-8)
   * Default: 5.0 (catches most base64/hex encoded data)
   * 
   * Recommended thresholds:
   * - 4.5: More sensitive, may have false positives
   * - 5.0: Balanced (default)
   * - 5.5: Less sensitive, catches mostly obfuscated payloads
   * - 6.0: Very strict, only highly randomized data
   */
  entropyThreshold?: number;
  
  /**
   * Minimum string length to analyze
   * Short strings don't have meaningful entropy
   * Default: 16 characters
   */
  minLength?: number;
  
  /**
   * Paths to exclude from entropy check (glob patterns)
   * Use for endpoints that legitimately receive encoded data
   * Example: ['/api/auth/token', '/api/upload/*', '/oauth/*']
   */
  excludePaths?: string[];
  
  /**
   * Fields to exclude from entropy check
   * Example: ['token', 'jwt', 'access_token', 'refresh_token', 'image']
   */
  excludeFields?: string[];
  
  /**
   * Check query parameters
   * Default: true
   */
  checkQuery?: boolean;
  
  /**
   * Check request body
   * Default: true
   */
  checkBody?: boolean;
  
  /**
   * Check specific headers
   * Default: ['x-api-key', 'x-auth-token', 'authorization']
   */
  checkHeaders?: string[];
  
  /**
   * Only flag if combined with other suspicious signals
   * Reduces false positives by requiring multiple indicators
   * Default: false
   */
  requireAdditionalSignals?: boolean;
}

export class EntropyDetector extends BaseDetector {
  name = 'entropy-detector';
  priority = 50; // Lower priority than pattern-based detectors
  
  private config: Required<EntropyDetectorConfig>;
  
  constructor(config: EntropyDetectorConfig = {}) {
    super();
    this.config = {
      entropyThreshold: config.entropyThreshold ?? 5.0,
      minLength: config.minLength ?? 16,
      excludePaths: config.excludePaths ?? [],
      excludeFields: config.excludeFields ?? ['token', 'jwt', 'access_token', 'refresh_token', 'id_token', 'image', 'file', 'data'],
      checkQuery: config.checkQuery ?? true,
      checkBody: config.checkBody ?? true,
      checkHeaders: config.checkHeaders ?? ['x-api-key', 'x-auth-token'],
      requireAdditionalSignals: config.requireAdditionalSignals ?? false,
    };
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check if path is excluded
    if (this.isPathExcluded(url.pathname)) {
      return null;
    }
    
    // Collect all suspicious findings
    const findings: Array<{ field: string; value: string; entropy: number }> = [];
    
    // Check query parameters
    if (this.config.checkQuery) {
      for (const [key, value] of url.searchParams.entries()) {
        if (this.isFieldExcluded(key)) continue;
        
        const entropy = this.calculateEntropy(value);
        if (entropy >= this.config.entropyThreshold && value.length >= this.config.minLength) {
          findings.push({ field: `query.${key}`, value, entropy });
        }
      }
    }
    
    // Check request body
    if (this.config.checkBody && ['POST', 'PUT', 'PATCH'].includes(request.method)) {
      const bodyFindings = await this.checkBody(request);
      findings.push(...bodyFindings);
    }
    
    // Check headers
    for (const header of this.config.checkHeaders) {
      const value = request.headers.get(header);
      if (value && !this.isFieldExcluded(header)) {
        const entropy = this.calculateEntropy(value);
        if (entropy >= this.config.entropyThreshold && value.length >= this.config.minLength) {
          findings.push({ field: `header.${header}`, value, entropy });
        }
      }
    }
    
    // No high-entropy data found
    if (findings.length === 0) {
      return null;
    }
    
    // If requiring additional signals, check for other suspicious patterns
    if (this.config.requireAdditionalSignals) {
      const hasAdditionalSignals = findings.some(f => this.hasAdditionalSignals(f.value));
      if (!hasAdditionalSignals) {
        return null;
      }
    }
    
    // Return detection for the highest entropy finding
    const highest = findings.reduce((a, b) => a.entropy > b.entropy ? a : b);
    
    return this.createResult(
      AttackType.OBFUSCATED_PAYLOAD,
      this.getSeverity(highest.entropy),
      this.getConfidence(highest.entropy),
      {
        field: highest.field,
        value: this.sanitizeValue(highest.value),
        pattern: `entropy=${highest.entropy.toFixed(2)}`,
        rawContent: highest.value.substring(0, 50),
      },
      {
        entropy: highest.entropy,
        threshold: this.config.entropyThreshold,
        totalFindings: findings.length,
        suspiciousFields: findings.map(f => f.field),
      }
    );
  }

  /**
   * Calculate Shannon entropy of a string
   * Returns value between 0 and 8 bits
   */
  private calculateEntropy(str: string): number {
    if (!str || str.length === 0) return 0;
    
    // Count character frequencies
    const freq: Map<string, number> = new Map();
    for (const char of str) {
      freq.set(char, (freq.get(char) || 0) + 1);
    }
    
    // Calculate entropy
    const len = str.length;
    let entropy = 0;
    
    for (const count of freq.values()) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  /**
   * Check request body for high-entropy values
   */
  private async checkBody(request: Request): Promise<Array<{ field: string; value: string; entropy: number }>> {
    const findings: Array<{ field: string; value: string; entropy: number }> = [];
    
    try {
      const contentType = request.headers.get('content-type') || '';
      const body = await request.clone().text();
      
      if (contentType.includes('application/json')) {
        // Parse JSON and check each field
        try {
          const json = JSON.parse(body);
          this.checkJsonObject(json, 'body', findings);
        } catch {
          // Invalid JSON, check raw body
          const entropy = this.calculateEntropy(body);
          if (entropy >= this.config.entropyThreshold && body.length >= this.config.minLength) {
            findings.push({ field: 'body', value: body, entropy });
          }
        }
      } else if (contentType.includes('application/x-www-form-urlencoded')) {
        // Parse form data
        const params = new URLSearchParams(body);
        for (const [key, value] of params.entries()) {
          if (this.isFieldExcluded(key)) continue;
          
          const entropy = this.calculateEntropy(value);
          if (entropy >= this.config.entropyThreshold && value.length >= this.config.minLength) {
            findings.push({ field: `form.${key}`, value, entropy });
          }
        }
      } else {
        // Raw body check
        const entropy = this.calculateEntropy(body);
        if (entropy >= this.config.entropyThreshold && body.length >= this.config.minLength) {
          findings.push({ field: 'body', value: body, entropy });
        }
      }
    } catch {
      // Cannot read body, skip
    }
    
    return findings;
  }

  /**
   * Recursively check JSON object for high-entropy values
   */
  private checkJsonObject(
    obj: any,
    path: string,
    findings: Array<{ field: string; value: string; entropy: number }>
  ): void {
    if (typeof obj === 'string') {
      if (!this.isFieldExcluded(path)) {
        const entropy = this.calculateEntropy(obj);
        if (entropy >= this.config.entropyThreshold && obj.length >= this.config.minLength) {
          findings.push({ field: path, value: obj, entropy });
        }
      }
    } else if (Array.isArray(obj)) {
      obj.forEach((item, index) => {
        this.checkJsonObject(item, `${path}[${index}]`, findings);
      });
    } else if (obj && typeof obj === 'object') {
      for (const [key, value] of Object.entries(obj)) {
        if (!this.isFieldExcluded(key)) {
          this.checkJsonObject(value, `${path}.${key}`, findings);
        }
      }
    }
  }

  /**
   * Check if path should be excluded
   */
  private isPathExcluded(pathname: string): boolean {
    return this.config.excludePaths.some(pattern => {
      const regex = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
      return regex.test(pathname);
    });
  }

  /**
   * Check if field should be excluded
   */
  private isFieldExcluded(field: string): boolean {
    const fieldLower = field.toLowerCase();
    return this.config.excludeFields.some(excluded => 
      fieldLower.includes(excluded.toLowerCase())
    );
  }

  /**
   * Check for additional suspicious signals
   */
  private hasAdditionalSignals(value: string): boolean {
    // Check for common encoding patterns
    const signals = [
      /^[A-Za-z0-9+/]+=*$/, // Base64 pattern
      /^[0-9a-fA-F]+$/, // Hex pattern
      /\\x[0-9a-fA-F]{2}/, // Hex escape sequences
      /\\u[0-9a-fA-F]{4}/, // Unicode escape sequences
      /%[0-9a-fA-F]{2}/, // URL encoding
      /&#\d+;/, // HTML entity encoding
      /&#x[0-9a-fA-F]+;/, // HTML hex entity encoding
    ];
    
    return signals.some(pattern => pattern.test(value));
  }

  /**
   * Get severity based on entropy level
   */
  private getSeverity(entropy: number): SecuritySeverity {
    if (entropy >= 7.0) return SecuritySeverity.HIGH;
    if (entropy >= 6.0) return SecuritySeverity.MEDIUM;
    return SecuritySeverity.LOW;
  }

  /**
   * Get confidence based on entropy level
   */
  private getConfidence(entropy: number): number {
    // Higher entropy = higher confidence
    // Scale from 0.5 (at threshold) to 0.95 (at max entropy)
    const normalizedEntropy = (entropy - this.config.entropyThreshold) / (8 - this.config.entropyThreshold);
    return Math.min(0.95, 0.5 + normalizedEntropy * 0.45);
  }

  /**
   * Sanitize value for logging
   */
  private sanitizeValue(value: string): string {
    const maxLength = 100;
    let sanitized = value.substring(0, maxLength);
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

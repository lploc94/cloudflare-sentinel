/**
 * Path Traversal Request Detector
 * Detects path traversal attack patterns in requests
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/** Pattern definition for path traversal */
export interface PathTraversalPattern {
  regex: RegExp;
  description: string;
  confidence: number;
}

export interface PathTraversalRequestDetectorConfig extends BaseDetectorOptions {
  /** File-related parameter names to check (exact match) */
  fileParameters?: string[];
  /** Custom patterns - if provided, OVERRIDES all built-in patterns */
  patterns?: PathTraversalPattern[];
}

// Built-in patterns with confidence
const PATH_TRAVERSAL_PATTERNS: PathTraversalPattern[] = [
  // === CRITICAL - Definite attack patterns (confidence: 1.0) ===
  
  // Sensitive Linux files - definite attack
  { regex: /\/etc\/shadow/, description: 'Linux shadow file', confidence: 1.0 },
  { regex: /\/etc\/passwd/, description: 'Linux passwd file', confidence: 1.0 },
  { regex: /\/\.ssh\//, description: 'SSH directory', confidence: 1.0 },
  { regex: /id_rsa/, description: 'SSH private key', confidence: 1.0 },
  { regex: /\/\.env/, description: 'Environment file', confidence: 1.0 },
  { regex: /\/\.git\/config/, description: 'Git config', confidence: 1.0 },
  
  // Windows sensitive - definite attack
  { regex: /\/windows\/system32/i, description: 'Windows system32', confidence: 1.0 },
  { regex: /c:[\/\\]windows/i, description: 'Windows path', confidence: 1.0 },
  { regex: /boot\.ini/i, description: 'Windows boot.ini', confidence: 1.0 },
  
  // === HIGH - Encoded traversal (evasion attempts) ===
  
  // URL encoded
  { regex: /%2e%2e[/\\%]/i, description: 'URL encoded traversal', confidence: 0.95 },
  { regex: /%252e%252e/i, description: 'Double URL encoded', confidence: 0.95 },
  
  // UTF-8 overlong encoding (bypass attempts)
  { regex: /%c0%ae/i, description: 'UTF-8 overlong dot', confidence: 0.95 },
  { regex: /%c0%af/i, description: 'UTF-8 overlong slash', confidence: 0.95 },
  { regex: /%c1%9c/i, description: 'UTF-8 overlong backslash', confidence: 0.95 },
  
  // Backslash variants
  { regex: /\.\.%5c/i, description: 'Encoded backslash traversal', confidence: 0.92 },
  { regex: /\.\.\\\\/, description: 'Double backslash traversal', confidence: 0.9 },
  
  // Java/Tomcat path parameter bypass
  { regex: /\.\.;\//, description: 'Semicolon path bypass (Java)', confidence: 0.92 },
  
  // PHP LFI wrappers - very specific
  { regex: /php:\/\/filter/i, description: 'PHP filter wrapper', confidence: 0.95 },
  { regex: /php:\/\/input/i, description: 'PHP input wrapper', confidence: 0.95 },
  { regex: /file:\/\//i, description: 'File protocol', confidence: 0.85 },
  { regex: /data:\/\//i, description: 'Data protocol', confidence: 0.8 },
  
  // === MEDIUM - Classic patterns ===
  
  // Classic path traversal
  { regex: /\.\.[/\\]/, description: 'Directory traversal (../)', confidence: 0.9 },
  { regex: /\.\.\.\.\/\//, description: 'Normalization bypass (....//)', confidence: 0.9 },
  
  // Null byte injection
  { regex: /%00/, description: 'Null byte injection', confidence: 0.9 },
  
  // Linux paths
  { regex: /\/proc\/self/, description: 'Linux proc self', confidence: 0.9 },
  { regex: /\/etc\/hosts/, description: 'Linux hosts file', confidence: 0.85 },
  { regex: /\/var\/log\//, description: 'Linux log directory', confidence: 0.8 },
  
  // Combined traversal + target
  { regex: /\.\..*?(etc|passwd|shadow|boot|win|sys|ssh|env|git)/i, description: 'Traversal to system path', confidence: 0.92 },
];

// Default file-related parameters (exact match)
const DEFAULT_FILE_PARAMS = [
  'file', 'filename', 'path', 'filepath', 'dir', 'directory',
  'folder', 'doc', 'document', 'page', 'template', 'include',
  'require', 'load', 'download', 'upload', 'attachment', 'src',
];

/**
 * PathTraversalRequestDetector - Detect path traversal attacks in requests
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new PathTraversalRequestDetector({})
 * 
 * // Custom file parameters
 * new PathTraversalRequestDetector({
 *   fileParameters: ['asset', 'resource', 'img'],
 * })
 * 
 * // Override patterns
 * new PathTraversalRequestDetector({
 *   patterns: [
 *     { regex: /\.\./, description: 'Traversal', confidence: 0.9 },
 *   ],
 * })
 * ```
 */
export class PathTraversalRequestDetector extends BaseDetector {
  name = 'path-traversal-request';
  phase = 'request' as const;
  priority = 90;

  private config: PathTraversalRequestDetectorConfig;
  private activePatterns: PathTraversalPattern[];
  private fileParams: Set<string>;

  /** Built-in patterns */
  static readonly PATTERNS = PATH_TRAVERSAL_PATTERNS;

  constructor(config: PathTraversalRequestDetectorConfig = {}) {
    super();
    this.config = config;
    this.activePatterns = config.patterns ?? PATH_TRAVERSAL_PATTERNS;
    this.fileParams = new Set(
      (config.fileParameters ?? DEFAULT_FILE_PARAMS).map(p => p.toLowerCase())
    );
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);

    // Check URL path
    const pathDetection = this.checkForPathTraversal(url.pathname, 'path');
    if (pathDetection) return pathDetection;

    // Check query parameters (common in file download/include endpoints)
    for (const [key, value] of url.searchParams.entries()) {
      if (this.isFileParameter(key)) {
        const detection = this.checkForPathTraversal(value, `query.${key}`);
        if (detection) return detection;
      }
    }

    // Check all query params for traversal patterns
    const fullQuery = url.search;
    if (fullQuery) {
      const queryDetection = this.checkForPathTraversal(fullQuery, 'query');
      if (queryDetection) return queryDetection;
    }

    // Check request body
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        const contentType = request.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
          const body = await request.clone().text();
          const bodyDetection = this.checkForPathTraversal(body, 'body');
          if (bodyDetection) return bodyDetection;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const body = await request.clone().text();
          const params = new URLSearchParams(body);
          for (const [key, value] of params.entries()) {
            if (this.isFileParameter(key)) {
              const formDetection = this.checkForPathTraversal(value, `form.${key}`);
              if (formDetection) return formDetection;
            }
          }
        }
      } catch (error) {
        // Cannot read body, skip
      }
    }

    return null;
  }

  private isFileParameter(paramName: string): boolean {
    // Exact match only - avoid false positives like "profile_file_id"
    return this.fileParams.has(paramName.toLowerCase());
  }

  private checkForPathTraversal(input: string, field: string): DetectorResult | null {
    // Decode URL encoding
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

    for (const { regex, description, confidence } of this.activePatterns) {
      const matches = decodedInput.match(new RegExp(regex, 'gi'));
      if (matches) {
        const occurrences = matches.length;
        // Use baseConfidence if provided, otherwise pattern confidence
        const baseConf = this.config.baseConfidence ?? confidence;
        const adjustedConfidence = Math.min(baseConf + (occurrences - 1) * 0.05, 1.0);

        return this.createResult(
          AttackType.PATH_TRAVERSAL,
          this.getSeverity(adjustedConfidence),
          adjustedConfidence,
          {
            field,
            value: this.sanitizeValue(decodedInput),
            pattern: regex.source,
            rawContent: `Matched: ${description}`,
          },
          { matchedPattern: description, occurrences }
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
    
    // Mask sensitive paths
    sanitized = sanitized.replace(/\/etc\/shadow/gi, '/etc/***');
    sanitized = sanitized.replace(/\/root\//gi, '/****/');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

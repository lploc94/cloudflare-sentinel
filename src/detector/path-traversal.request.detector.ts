/**
 * Path Traversal Request Detector
 * Detects path traversal attack patterns in requests
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class PathTraversalRequestDetector extends BaseDetector {
  name = 'path-traversal-request';
  priority = 90;

  private readonly patterns = [
    // Classic path traversal
    { regex: /\.\.[\/\\]/i, confidence: 0.9 },
    { regex: /\.\.\./i, confidence: 0.85 },
    
    // URL encoded
    { regex: /%2e%2e[\/\\]/i, confidence: 0.95 },
    { regex: /%2e%2e%2f/i, confidence: 0.95 },
    { regex: /%252e%252e/i, confidence: 0.9 },  // Double encoding
    
    // Unicode/UTF-8 encoding
    { regex: /\.\./u, confidence: 0.8 },
    { regex: /\u002e\u002e/i, confidence: 0.9 },
    
    // Absolute paths to sensitive files
    { regex: /\/etc\/passwd/i, confidence: 0.98 },
    { regex: /\/etc\/shadow/i, confidence: 0.99 },
    { regex: /\/windows\/system32/i, confidence: 0.95 },
    { regex: /c:\\windows\\/i, confidence: 0.95 },
    { regex: /\/proc\/self/i, confidence: 0.9 },
    
    // Null byte injection
    { regex: /%00/i, confidence: 0.85 },
    { regex: /\x00/i, confidence: 0.9 },
    
    // Path traversal with specific targets
    { regex: /\.\..*?(etc|boot|win|sys)/i, confidence: 0.92 },
  ];

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
    const fileParams = [
      'file', 'filename', 'path', 'filepath', 'dir', 'directory',
      'folder', 'doc', 'document', 'page', 'template', 'include',
      'require', 'load', 'download', 'upload', 'attachment'
    ];
    
    return fileParams.some(param => paramName.toLowerCase().includes(param));
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

    for (const { regex, confidence } of this.patterns) {
      const matches = decodedInput.match(new RegExp(regex, 'gi'));
      if (matches) {
        const occurrences = matches.length;
        const adjustedConfidence = Math.min(confidence + (occurrences - 1) * 0.05, 1.0);

        return this.createResult(
          AttackType.PATH_TRAVERSAL,
          this.getSeverity(adjustedConfidence),
          adjustedConfidence,
          {
            field,
            value: this.sanitizeValue(decodedInput),
            pattern: regex.source,
            rawContent: matches[0].substring(0, 50),
          },
          {
            attackSubType: 'path_traversal',
            occurrences,
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
    
    // Mask sensitive paths
    sanitized = sanitized.replace(/\/etc\/shadow/gi, '/etc/***');
    sanitized = sanitized.replace(/\/root\//gi, '/****/');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

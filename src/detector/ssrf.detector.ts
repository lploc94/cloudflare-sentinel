/**
 * SSRF (Server-Side Request Forgery) Detector
 * 
 * Detects attempts to access internal resources through URL parameters.
 * Catches localhost, internal IPs, cloud metadata endpoints, and file:// URLs.
 */

import { BaseDetector } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface SSRFDetectorConfig {
  /** Enable/disable detector */
  enabled?: boolean;
  /** Priority (0-100, higher = checked first) */
  priority?: number;
  /** Paths to exclude from detection */
  excludePaths?: string[];
  /** Fields to exclude from checking (e.g., 'callback_url' if legitimate) */
  excludeFields?: string[];
  /** Additional internal IP ranges to check */
  additionalInternalRanges?: string[];
  /** Allow localhost in certain environments */
  allowLocalhost?: boolean;
}

// Internal/Private IP patterns
const INTERNAL_IP_PATTERNS = [
  // Localhost variants
  /^localhost$/i,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^\[?::1\]?$/,
  /^0\.0\.0\.0$/,
  
  // Private networks (RFC 1918)
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  
  // Link-local
  /^169\.254\.\d{1,3}\.\d{1,3}$/,
  /^fe80::/i,
  
  // Docker default
  /^172\.17\.\d{1,3}\.\d{1,3}$/,
  
  // Kubernetes
  /^10\.(0|96|244)\.\d{1,3}\.\d{1,3}$/,
];

// Cloud metadata endpoints
const CLOUD_METADATA_PATTERNS: Array<{ pattern: RegExp; description: string; severity: SecuritySeverity }> = [
  // AWS metadata
  {
    pattern: /169\.254\.169\.254/,
    description: 'AWS metadata endpoint',
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /metadata\.google\.internal/i,
    description: 'GCP metadata endpoint',
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /169\.254\.169\.253/,
    description: 'AWS ECS metadata endpoint',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Azure metadata
  {
    pattern: /169\.254\.169\.254.*metadata/i,
    description: 'Azure metadata endpoint',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Digital Ocean
  {
    pattern: /169\.254\.169\.254.*droplet/i,
    description: 'Digital Ocean metadata endpoint',
    severity: SecuritySeverity.CRITICAL,
  },
  
  // Kubernetes
  {
    pattern: /kubernetes\.default/i,
    description: 'Kubernetes default service',
    severity: SecuritySeverity.HIGH,
  },
];

// Dangerous URL schemes
const DANGEROUS_SCHEMES = [
  'file://',
  'gopher://',
  'dict://',
  'php://',
  'data://',
  'expect://',
  'jar://',
];

// SSRF bypass techniques
const BYPASS_PATTERNS: Array<{ pattern: RegExp; description: string }> = [
  // URL encoding bypass
  { pattern: /%2f%2f/i, description: 'URL encoded slashes' },
  { pattern: /%00/i, description: 'Null byte injection' },
  
  // DNS rebinding
  { pattern: /xip\.io|nip\.io|sslip\.io/i, description: 'DNS rebinding service' },
  
  // IP address tricks
  { pattern: /0x[0-9a-f]+/i, description: 'Hex encoded IP' },
  { pattern: /\d{10,}/i, description: 'Decimal IP representation' },
  
  // URL tricks
  { pattern: /@.*@/, description: 'Double @ sign' },
  { pattern: /\\\\/, description: 'Backslash in URL' },
];

export class SSRFDetector extends BaseDetector {
  name = 'ssrf';
  priority: number;
  enabled: boolean;
  
  private config: SSRFDetectorConfig;
  private excludePathPatterns: RegExp[];

  constructor(config: SSRFDetectorConfig = {}) {
    super();
    this.config = {
      enabled: true,
      priority: 85,  // High priority - critical attack
      excludePaths: [],
      excludeFields: [],
      additionalInternalRanges: [],
      allowLocalhost: false,
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
          const body = await clonedRequest.json();
          const result = this.checkObject(body, 'body');
          if (result) return result;
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
    
    // Check for dangerous URL schemes
    const lowerValue = value.toLowerCase();
    for (const scheme of DANGEROUS_SCHEMES) {
      if (lowerValue.includes(scheme)) {
        return this.createResult(
          AttackType.SSRF,
          SecuritySeverity.CRITICAL,
          0.95,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: scheme,
          },
          {
            detector: this.name,
            description: `Dangerous URL scheme: ${scheme}`,
          },
        );
      }
    }
    
    // Check for cloud metadata endpoints
    for (const { pattern, description, severity } of CLOUD_METADATA_PATTERNS) {
      if (pattern.test(value)) {
        return this.createResult(
          AttackType.SSRF,
          severity,
          0.95,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
          },
          {
            detector: this.name,
            description,
          },
        );
      }
    }
    
    // Extract hostname from URL-like strings
    const hostname = this.extractHostname(value);
    if (hostname) {
      // Check for internal IPs
      if (!this.config.allowLocalhost && this.isInternalIP(hostname)) {
        return this.createResult(
          AttackType.SSRF,
          SecuritySeverity.HIGH,
          0.9,
          {
            field: location,
            value: value.substring(0, 200),
          },
          {
            detector: this.name,
            description: `Internal IP address detected: ${hostname}`,
          },
        );
      }
    }
    
    // Check for SSRF bypass techniques
    for (const { pattern, description } of BYPASS_PATTERNS) {
      if (pattern.test(value)) {
        return this.createResult(
          AttackType.SSRF,
          SecuritySeverity.MEDIUM,
          0.7,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
          },
          {
            detector: this.name,
            description: `SSRF bypass technique: ${description}`,
          },
        );
      }
    }
    
    return null;
  }

  private extractHostname(value: string): string | null {
    try {
      // Try to parse as URL
      if (value.includes('://')) {
        const url = new URL(value);
        return url.hostname;
      }
      
      // Check if it looks like an IP address
      if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
        return value;
      }
      
      return null;
    } catch {
      return null;
    }
  }

  private isInternalIP(hostname: string): boolean {
    for (const pattern of INTERNAL_IP_PATTERNS) {
      if (pattern.test(hostname)) {
        return true;
      }
    }
    return false;
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

/**
 * SSRF (Server-Side Request Forgery) Detector
 * 
 * Detects attempts to access internal resources through URL parameters.
 * Catches localhost, internal IPs, cloud metadata endpoints, and file:// URLs.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/** Cloud metadata pattern definition */
export interface CloudMetadataPattern {
  pattern: RegExp;
  description: string;
  confidence: number;
  severity: SecuritySeverity;
}

/** SSRF bypass pattern definition */
export interface SSRFBypassPattern {
  pattern: RegExp;
  description: string;
  confidence: number;
  severity: SecuritySeverity;
}

export interface SSRFDetectorConfig extends BaseDetectorOptions {
  /** Fields to exclude from checking - exact match (e.g., 'callback_url' if legitimate) */
  excludeFields?: string[];
  /** Custom cloud metadata patterns - if provided, OVERRIDES built-in */
  cloudMetadataPatterns?: CloudMetadataPattern[];
  /** Custom bypass patterns - if provided, OVERRIDES built-in */
  bypassPatterns?: SSRFBypassPattern[];
  /** Custom dangerous URL schemes - if provided, OVERRIDES built-in */
  dangerousSchemes?: string[];
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

// Cloud metadata endpoints with confidence levels
const CLOUD_METADATA_PATTERNS: CloudMetadataPattern[] = [
  // AWS - definite SSRF
  { pattern: /169\.254\.169\.254/, description: 'AWS EC2 metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { pattern: /169\.254\.169\.253/, description: 'AWS ECS metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { pattern: /169\.254\.170\.2/, description: 'AWS ECS task metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // GCP - definite SSRF
  { pattern: /metadata\.google\.internal/i, description: 'GCP metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  { pattern: /169\.254\.169\.254.*computeMetadata/i, description: 'GCP compute metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Azure - definite SSRF
  { pattern: /169\.254\.169\.254.*metadata.*instance/i, description: 'Azure IMDS', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Digital Ocean - definite SSRF
  { pattern: /169\.254\.169\.254.*metadata.*droplet/i, description: 'DigitalOcean metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Alibaba Cloud - definite SSRF
  { pattern: /100\.100\.100\.200/i, description: 'Alibaba Cloud metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Oracle Cloud - definite SSRF
  { pattern: /169\.254\.169\.254.*opc/i, description: 'Oracle Cloud metadata', confidence: 1.0, severity: SecuritySeverity.CRITICAL },
  
  // Kubernetes
  { pattern: /kubernetes\.default\.svc/i, description: 'Kubernetes API server', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { pattern: /kubernetes\.default/i, description: 'Kubernetes service', confidence: 0.95, severity: SecuritySeverity.HIGH },
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

// SSRF bypass techniques with confidence levels
// Lower confidence for patterns that could be legitimate
const BYPASS_PATTERNS: SSRFBypassPattern[] = [
  // DNS rebinding - definite attack tool
  { pattern: /\.(xip|nip|sslip)\.io/i, description: 'DNS rebinding service', confidence: 1.0, severity: SecuritySeverity.HIGH },
  { pattern: /\.burpcollaborator\.net/i, description: 'Burp Collaborator', confidence: 1.0, severity: SecuritySeverity.HIGH },
  { pattern: /\.oastify\.com/i, description: 'OAST service', confidence: 1.0, severity: SecuritySeverity.HIGH },
  
  // Null byte - very suspicious
  { pattern: /%00/i, description: 'Null byte injection', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // IP address tricks - uncommon in legitimate traffic
  { pattern: /0x7f\d{6}/i, description: 'Hex localhost (0x7f...)', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { pattern: /0177\.0+\.0+\.\d+/i, description: 'Octal IP (0177...)', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { pattern: /21307064\d{2}/i, description: 'Decimal localhost', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  
  // URL tricks - suspicious
  { pattern: /@.*@/, description: 'Double @ sign in URL', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
  { pattern: /\\\\[^\\]/, description: 'Backslash in URL', confidence: 0.75, severity: SecuritySeverity.MEDIUM },
  
  // Encoded characters - can be legitimate, lower confidence
  { pattern: /%2f%2flocalhost/i, description: 'Encoded localhost URL', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { pattern: /%2f%2f127\./i, description: 'Encoded 127.x URL', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { pattern: /%2f%2f10\./i, description: 'Encoded private IP URL', confidence: 0.8, severity: SecuritySeverity.MEDIUM },
];

/**
 * SSRFDetector - Detect Server-Side Request Forgery attempts
 * 
 * Checks for:
 * - Internal/private IP addresses (localhost, 10.x, 172.16-31.x, 192.168.x)
 * - Cloud metadata endpoints (AWS, GCP, Azure, etc.)
 * - Dangerous URL schemes (file://, gopher://, etc.)
 * - SSRF bypass techniques (DNS rebinding, IP encoding, etc.)
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new SSRFDetector({})
 * 
 * // Exclude specific fields (e.g., legitimate webhook endpoints)
 * new SSRFDetector({
 *   excludeFields: ['webhook_url', 'callback_url'],
 * })
 * 
 * // Access built-in patterns
 * SSRFDetector.CLOUD_METADATA_PATTERNS
 * SSRFDetector.BYPASS_PATTERNS
 * ```
 */
export class SSRFDetector extends BaseDetector {
  name = 'ssrf';
  phase = 'request' as const;
  priority = 85; // High priority - critical attack

  private config: SSRFDetectorConfig;
  private excludeFields: Set<string>;
  private activeCloudPatterns: CloudMetadataPattern[];
  private activeBypassPatterns: SSRFBypassPattern[];
  private activeDangerousSchemes: string[];

  /** Built-in cloud metadata patterns */
  static readonly CLOUD_METADATA_PATTERNS = CLOUD_METADATA_PATTERNS;
  /** Built-in bypass patterns */
  static readonly BYPASS_PATTERNS = BYPASS_PATTERNS;
  /** Built-in dangerous schemes */
  static readonly DANGEROUS_SCHEMES = DANGEROUS_SCHEMES;

  constructor(config: SSRFDetectorConfig = {}) {
    super();
    this.config = config;
    
    this.excludeFields = new Set(
      (config.excludeFields ?? ['token', 'access_token', 'refresh_token', 'google_token', 'id_token', 'jwt', 'password', 'secret']).map(f => f.toLowerCase())
    );
    this.activeCloudPatterns = config.cloudMetadataPatterns ?? CLOUD_METADATA_PATTERNS;
    this.activeBypassPatterns = config.bypassPatterns ?? BYPASS_PATTERNS;
    this.activeDangerousSchemes = config.dangerousSchemes ?? DANGEROUS_SCHEMES;
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
          const body = await request.clone().json();
          const result = this.checkObject(body, 'body');
          if (result) return result;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const formData = await request.clone().text();
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
    // Exact match only
    return this.excludeFields.has(field.toLowerCase());
  }

  private checkValue(value: string, location: string): DetectorResult | null {
    if (!value || typeof value !== 'string') return null;
    
    const lowerValue = value.toLowerCase();
    const baseConfidence = this.config.baseConfidence;
    
    // Check for dangerous URL schemes (highest priority) - definite attack
    for (const scheme of this.activeDangerousSchemes) {
      if (lowerValue.includes(scheme)) {
        return this.createResult(
          AttackType.SSRF,
          SecuritySeverity.CRITICAL,
          baseConfidence ?? 1.0,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: scheme,
            rawContent: `Dangerous URL scheme: ${scheme}`,
          },
          { detectionType: 'dangerous_scheme', scheme }
        );
      }
    }
    
    // Check for cloud metadata endpoints
    for (const { pattern, description, confidence, severity } of this.activeCloudPatterns) {
      if (pattern.test(value)) {
        return this.createResult(
          AttackType.SSRF,
          severity,
          baseConfidence ?? confidence,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'cloud_metadata', matchedPattern: description }
        );
      }
    }
    
    // Extract hostname from URL-like strings and check for internal IPs
    const hostname = this.extractHostname(value);
    if (hostname && this.isInternalIP(hostname)) {
      return this.createResult(
        AttackType.SSRF,
        SecuritySeverity.HIGH,
        baseConfidence ?? 1.0,
        {
          field: location,
          value: value.substring(0, 200),
          rawContent: `Internal IP detected: ${hostname}`,
        },
        { detectionType: 'internal_ip', hostname }
      );
    }
    
    // Check for SSRF bypass techniques
    for (const { pattern, description, confidence, severity } of this.activeBypassPatterns) {
      if (pattern.test(value)) {
        return this.createResult(
          AttackType.SSRF,
          severity,
          baseConfidence ?? confidence,
          {
            field: location,
            value: value.substring(0, 200),
            pattern: pattern.source,
            rawContent: `Bypass technique: ${description}`,
          },
          { detectionType: 'bypass_technique', matchedPattern: description }
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

/**
 * Path Traversal Response Detector
 * Detects directory listing and file content leaks in responses
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

/** Pattern for detecting leaks in response */
export interface ResponseLeakPattern {
  regex: RegExp;
  description: string;
  confidence: number;
  severity: SecuritySeverity;
}

export interface PathTraversalResponseDetectorConfig extends BaseDetectorOptions {
  /** Custom directory listing patterns - if provided, OVERRIDES built-in */
  directoryPatterns?: ResponseLeakPattern[];
  /** Custom file leak patterns - if provided, OVERRIDES built-in */
  fileLeakPatterns?: ResponseLeakPattern[];
}

// === DIRECTORY LISTING PATTERNS ===
const DIRECTORY_LISTING_PATTERNS: ResponseLeakPattern[] = [
  // Apache
  { regex: /<title>Index of \//i, description: 'Apache directory listing', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /\[To Parent Directory\]/i, description: 'IIS directory listing', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // Nginx
  { regex: /<h1>Index of/i, description: 'Nginx directory listing', confidence: 0.98, severity: SecuritySeverity.HIGH },
  
  // Generic
  { regex: /Parent Directory.*Size.*Modified/is, description: 'Generic directory listing', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /<pre>.*?drwx.*?<\/pre>/is, description: 'Unix directory listing', confidence: 0.92, severity: SecuritySeverity.HIGH },
];

// === FILE CONTENT LEAK PATTERNS ===
const FILE_LEAK_PATTERNS: ResponseLeakPattern[] = [
  // === CRITICAL - Private keys & secrets ===
  { regex: /-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/, description: 'Private key exposed', confidence: 0.99, severity: SecuritySeverity.CRITICAL },
  { regex: /-----BEGIN OPENSSH PRIVATE KEY-----/, description: 'SSH private key', confidence: 0.99, severity: SecuritySeverity.CRITICAL },
  { regex: /-----BEGIN PGP PRIVATE KEY-----/, description: 'PGP private key', confidence: 0.99, severity: SecuritySeverity.CRITICAL },
  
  // Linux shadow file
  { regex: /root:\$[156y]\$[^\s:]+:[0-9]+:/, description: 'Shadow file hash', confidence: 0.99, severity: SecuritySeverity.CRITICAL },
  
  // === HIGH - System files ===
  // Linux passwd
  { regex: /root:x:\d+:\d+:root:\/root:/, description: 'Linux passwd file', confidence: 0.98, severity: SecuritySeverity.HIGH },
  { regex: /nobody:x:\d+:\d+:/, description: 'Linux passwd file', confidence: 0.95, severity: SecuritySeverity.HIGH },
  
  // === HIGH - Cloud credentials ===
  { regex: /AKIA[0-9A-Z]{16}/, description: 'AWS Access Key', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  { regex: /aws_secret_access_key\s*[=:]\s*[A-Za-z0-9\/+=]{40}/i, description: 'AWS Secret Key', confidence: 0.98, severity: SecuritySeverity.CRITICAL },
  { regex: /AZURE_[A-Z_]+\s*[=:]\s*["']?[A-Za-z0-9+\/=]{20,}/i, description: 'Azure credential', confidence: 0.9, severity: SecuritySeverity.CRITICAL },
  { regex: /service_account.*private_key.*-----BEGIN/is, description: 'GCP service account', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  
  // === HIGH - Database credentials ===
  { regex: /mongodb(\+srv)?:\/\/[^:]+:[^@]+@/i, description: 'MongoDB connection string', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /postgres:\/\/[^:]+:[^@]+@/i, description: 'PostgreSQL connection string', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /mysql:\/\/[^:]+:[^@]+@/i, description: 'MySQL connection string', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /redis:\/\/:[^@]+@/i, description: 'Redis connection string', confidence: 0.9, severity: SecuritySeverity.HIGH },
  
  // === HIGH - Environment & config files ===
  { regex: /DB_PASSWORD\s*[=:]\s*["']?[^\s"']+/i, description: 'Database password in env', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /JWT_SECRET\s*[=:]\s*["']?[^\s"']+/i, description: 'JWT secret exposed', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  { regex: /API_KEY\s*[=:]\s*["']?[A-Za-z0-9_-]{20,}/i, description: 'API key exposed', confidence: 0.9, severity: SecuritySeverity.HIGH },
  { regex: /SECRET_KEY\s*[=:]\s*["']?[^\s"']+/i, description: 'Secret key exposed', confidence: 0.9, severity: SecuritySeverity.HIGH },
  
  // === MEDIUM - Config files ===
  { regex: /\[mysqld\][\s\S]*?datadir\s*=/i, description: 'MySQL config file', confidence: 0.9, severity: SecuritySeverity.MEDIUM },
  { regex: /ServerRoot[\s\S]*?DocumentRoot/i, description: 'Apache config', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /server\s*\{[\s\S]*?root\s+[^;]+;/i, description: 'Nginx config', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /<VirtualHost[\s\S]*?<\/VirtualHost>/i, description: 'Apache VirtualHost', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  
  // htaccess
  { regex: /RewriteEngine\s+On[\s\S]*?RewriteRule/i, description: '.htaccess file', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /AuthType\s+Basic[\s\S]*?AuthUserFile/i, description: '.htaccess auth config', confidence: 0.9, severity: SecuritySeverity.HIGH },
  
  // PHP/WordPress
  { regex: /\$_SERVER\[['"]DOCUMENT_ROOT['"]\]/i, description: 'PHP source code', confidence: 0.85, severity: SecuritySeverity.MEDIUM },
  { regex: /define\s*\(\s*['"]DB_PASSWORD['"]/i, description: 'wp-config.php', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
  
  // Windows
  { regex: /\[boot loader\][\s\S]*?timeout\s*=/i, description: 'Windows boot.ini', confidence: 0.95, severity: SecuritySeverity.HIGH },
  { regex: /<connectionStrings>[\s\S]*?<\/connectionStrings>/i, description: 'ASP.NET connection strings', confidence: 0.9, severity: SecuritySeverity.HIGH },
];

/**
 * PathTraversalResponseDetector - Detect sensitive data leaks in responses
 * 
 * Detects directory listings and file content exposure that may indicate
 * successful path traversal attacks.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new PathTraversalResponseDetector({})
 * 
 * // Custom confidence threshold
 * new PathTraversalResponseDetector({
 *   baseConfidence: 0.9,
 * })
 * 
 * // Override file leak patterns
 * new PathTraversalResponseDetector({
 *   fileLeakPatterns: [
 *     { regex: /MY_SECRET_KEY/, description: 'Custom secret', confidence: 0.95, severity: SecuritySeverity.CRITICAL },
 *   ],
 * })
 * 
 * // Access built-in patterns
 * PathTraversalResponseDetector.DIRECTORY_PATTERNS
 * PathTraversalResponseDetector.FILE_LEAK_PATTERNS
 * ```
 */
export class PathTraversalResponseDetector extends BaseDetector {
  name = 'path-traversal-response';
  phase = 'response' as const;
  priority = 90;

  private config: PathTraversalResponseDetectorConfig;
  private directoryPatterns: ResponseLeakPattern[];
  private fileLeakPatterns: ResponseLeakPattern[];

  /** Built-in directory listing patterns */
  static readonly DIRECTORY_PATTERNS = DIRECTORY_LISTING_PATTERNS;
  /** Built-in file leak patterns */
  static readonly FILE_LEAK_PATTERNS = FILE_LEAK_PATTERNS;

  constructor(config: PathTraversalResponseDetectorConfig = {}) {
    super();
    this.config = config;
    this.directoryPatterns = config.directoryPatterns ?? DIRECTORY_LISTING_PATTERNS;
    this.fileLeakPatterns = config.fileLeakPatterns ?? FILE_LEAK_PATTERNS;
  }

  async detectResponse(request: Request, response: Response, context: any): Promise<DetectorResult | null> {
    const contentType = response.headers.get('content-type') || '';
    if (!contentType.includes('text/') &&
        !contentType.includes('application/json') &&
        !contentType.includes('application/xml')) {
      return null;
    }
    
    try {
      const body = await response.clone().text();
      
      // Check for directory listing leaks
      const dirDetection = this.checkForDirectoryListing(body);
      if (dirDetection) return dirDetection;
      
      // Check for file content leaks
      const fileDetection = this.checkForFileContentLeaks(body);
      if (fileDetection) return fileDetection;
      
    } catch (error) {
      // Cannot read response body
    }
    
    return null;
  }

  private checkForDirectoryListing(body: string): DetectorResult | null {
    for (const { regex, description, confidence, severity } of this.directoryPatterns) {
      if (regex.test(body)) {
        const finalConfidence = this.config.baseConfidence ?? confidence;
        return this.createResult(
          AttackType.PATH_TRAVERSAL,
          severity,
          finalConfidence,
          {
            field: 'response_body',
            value: 'Directory listing detected',
            pattern: regex.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'directory_listing', matchedPattern: description }
        );
      }
    }
    return null;
  }

  private checkForFileContentLeaks(body: string): DetectorResult | null {
    for (const { regex, description, confidence, severity } of this.fileLeakPatterns) {
      const match = body.match(regex);
      if (match) {
        const finalConfidence = this.config.baseConfidence ?? confidence;
        return this.createResult(
          AttackType.PATH_TRAVERSAL,
          severity,
          finalConfidence,
          {
            field: 'response_body',
            value: this.sanitizeValue(match[0]),
            pattern: regex.source,
            rawContent: `Matched: ${description}`,
          },
          { detectionType: 'file_content_leak', matchedPattern: description }
        );
      }
    }
    return null;
  }

  private sanitizeValue(value: string): string {
    const maxLength = 100;
    let sanitized = value.substring(0, maxLength);
    
    // Mask sensitive paths
    sanitized = sanitized.replace(/\/etc\/shadow/gi, '/etc/***');
    sanitized = sanitized.replace(/\/root\//gi, '/****/');
    
    // Mask private keys
    sanitized = sanitized.replace(/-----BEGIN.*?PRIVATE KEY-----[\s\S]*?-----END.*?PRIVATE KEY-----/gi, '***PRIVATE KEY***');
    
    // Mask passwords
    sanitized = sanitized.replace(/password[=:]\s*\S+/gi, 'password=***');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

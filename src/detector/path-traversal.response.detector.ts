/**
 * Path Traversal Response Detector
 * Detects directory listing and file content leaks in responses
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class PathTraversalResponseDetector extends BaseDetector {
  name = 'path-traversal-response';
  priority = 90;

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
    const listingPatterns = [
      // Apache-style directory listing
      { regex: /<title>Index of \//i, confidence: 0.98, type: 'apache_dir_listing' },
      { regex: /\[To Parent Directory\]/i, confidence: 0.95, type: 'dir_listing' },
      
      // Nginx-style directory listing
      { regex: /<h1>Index of/i, confidence: 0.98, type: 'nginx_dir_listing' },
      
      // Generic directory listing indicators
      { regex: /Parent Directory.*Size.*Modified/i, confidence: 0.9, type: 'generic_dir_listing' },
      { regex: /<table>.*?<tr>.*?Name.*?Size.*?Date/i, confidence: 0.85, type: 'table_dir_listing' },
    ];
    
    for (const { regex, confidence, type } of listingPatterns) {
      if (regex.test(body)) {
        return {
          detected: true,
          attackType: AttackType.PATH_TRAVERSAL,
          severity: SecuritySeverity.HIGH,
          confidence,
          evidence: {
            field: 'response_body',
            value: 'Directory listing detected',
            rawContent: body.substring(0, 200),
          },
          metadata: {
            detectionType: 'directory_listing_leak',
            listingType: type,
          },
        };
      }
    }
    
    return null;
  }

  private checkForFileContentLeaks(body: string): DetectorResult | null {
    const fileLeakPatterns = [
      // Linux system files
      { regex: /root:x:\d+:\d+:root:\/root:/i, confidence: 0.98, type: 'passwd_file' },
      { regex: /root:\$\w+\$/i, confidence: 0.99, type: 'shadow_file' },
      
      // Config files
      { regex: /\[mysqld\].*?datadir/i, confidence: 0.9, type: 'mysql_config' },
      { regex: /ServerRoot.*?DocumentRoot/i, confidence: 0.9, type: 'apache_config' },
      { regex: /DB_PASSWORD.*?DB_HOST/i, confidence: 0.95, type: 'env_config' },
      
      // Application files
      { regex: /<\?php.*?require.*?include/i, confidence: 0.85, type: 'php_source' },
      { regex: /package\.json.*?"scripts"/i, confidence: 0.8, type: 'package_json' },
      
      // Private keys
      { regex: /-----BEGIN (RSA |EC )?PRIVATE KEY-----/i, confidence: 0.99, type: 'private_key' },
      { regex: /-----BEGIN OPENSSH PRIVATE KEY-----/i, confidence: 0.99, type: 'ssh_key' },
      
      // Windows system files
      { regex: /\[boot loader\].*?timeout/i, confidence: 0.95, type: 'boot_ini' },
      { regex: /\[System\.ServiceModel\]/i, confidence: 0.9, type: 'web_config' },
    ];
    
    for (const { regex, confidence, type } of fileLeakPatterns) {
      const match = body.match(regex);
      if (match) {
        return {
          detected: true,
          attackType: AttackType.PATH_TRAVERSAL,
          severity: type.includes('key') || type.includes('shadow') || type.includes('password') 
            ? SecuritySeverity.CRITICAL 
            : SecuritySeverity.HIGH,
          confidence,
          evidence: {
            field: 'response_body',
            value: this.sanitizeValue(match[0]),
            rawContent: `Sensitive file content leaked: ${type}`,
          },
          metadata: {
            detectionType: 'file_content_leak',
            fileType: type,
            severity: 'sensitive_data_exposure',
          },
        };
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

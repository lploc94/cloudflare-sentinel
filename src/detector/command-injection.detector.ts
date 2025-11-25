/**
 * Command Injection Detector
 */

import { BaseDetector } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export interface CommandInjectionDetectorConfig {
  enabled?: boolean;
  priority?: number;
  excludePaths?: string[];
  excludeFields?: string[];
  checkHeaders?: string[];
}

const SHELL_METACHARACTERS = [';', '|', '&', '`', '$(', '${', '\n', '\r'];

const COMMAND_PATTERNS: Array<{ pattern: RegExp; description: string; severity: SecuritySeverity }> = [
  { pattern: /[;&|]\s*(ls|cat|dir|type|whoami|id|uname|pwd|echo|ping|curl|wget|nc|ncat|bash|sh|cmd|powershell)/i, description: 'Command chaining', severity: SecuritySeverity.CRITICAL },
  { pattern: /`[^`]*`/, description: 'Backtick command substitution', severity: SecuritySeverity.HIGH },
  { pattern: /\$\([^)]+\)/, description: '$() command substitution', severity: SecuritySeverity.HIGH },
  { pattern: /\b(rm\s+-rf|chmod\s+777|mkfs|dd\s+if=|\/etc\/passwd|\/etc\/shadow)\b/i, description: 'Dangerous system commands', severity: SecuritySeverity.CRITICAL },
  { pattern: /\b(curl|wget|nc|ncat|netcat)\s+[^\s]+/i, description: 'Network command', severity: SecuritySeverity.HIGH },
  { pattern: /\b(bash|sh|nc|ncat)\s+.*\s+-[ie]/i, description: 'Potential reverse shell', severity: SecuritySeverity.CRITICAL },
  { pattern: /\$\{[^}]+\}/, description: 'Environment variable expansion', severity: SecuritySeverity.MEDIUM },
  { pattern: /\b(cmd\.exe|powershell\.exe|certutil|bitsadmin)\b/i, description: 'Windows command injection', severity: SecuritySeverity.HIGH },
  { pattern: /\/bin\/(sh|bash|cat|ls|nc)|\/usr\/bin\//i, description: 'Unix executable path', severity: SecuritySeverity.HIGH },
];

export class CommandInjectionDetector extends BaseDetector {
  name = 'command_injection';
  priority: number;
  enabled: boolean;
  private config: CommandInjectionDetectorConfig;
  private excludePathPatterns: RegExp[];

  constructor(config: CommandInjectionDetectorConfig = {}) {
    super();
    this.config = {
      enabled: true,
      priority: 85,
      excludePaths: [],
      excludeFields: ['password', 'token', 'secret', 'key'],
      checkHeaders: ['x-forwarded-for', 'user-agent', 'referer'],
      ...config,
    };
    this.priority = this.config.priority!;
    this.enabled = this.config.enabled!;
    this.excludePathPatterns = (this.config.excludePaths || []).map(p => {
      const regexPattern = p.replace(/\*\*/g, '.*').replace(/\*/g, '[^/]*').replace(/\?/g, '.');
      return new RegExp(`^${regexPattern}$`);
    });
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    if (this.isPathExcluded(url.pathname)) return null;

    for (const [key, value] of url.searchParams) {
      if (this.isFieldExcluded(key)) continue;
      const result = this.checkValue(value, `query.${key}`);
      if (result) return result;
    }

    for (const header of this.config.checkHeaders || []) {
      const value = request.headers.get(header);
      if (value) {
        const result = this.checkValue(value, `header.${header}`);
        if (result) return result;
      }
    }

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
      } catch { /* ignore */ }
    }
    return null;
  }

  private isPathExcluded(path: string): boolean {
    return this.excludePathPatterns.some(p => p.test(path));
  }

  private isFieldExcluded(field: string): boolean {
    const lf = field.toLowerCase();
    return (this.config.excludeFields || []).some(f => lf === f.toLowerCase() || lf.includes(f.toLowerCase()));
  }

  private checkValue(value: string, location: string): DetectorResult | null {
    if (!value || typeof value !== 'string') return null;
    const hasMetachar = SHELL_METACHARACTERS.some(char => value.includes(char));
    if (!hasMetachar) return null;

    for (const { pattern, description, severity } of COMMAND_PATTERNS) {
      if (pattern.test(value)) {
        const confidence = severity === SecuritySeverity.CRITICAL ? 0.95 : 0.85;
        return this.createResult(AttackType.COMMAND_INJECTION, severity, confidence,
          { field: location, value: value.substring(0, 200), pattern: pattern.source },
          { detector: this.name, matchedPattern: description }
        );
      }
    }
    return null;
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

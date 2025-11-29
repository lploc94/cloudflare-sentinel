/**
 * SSTI (Server-Side Template Injection) Detector
 * 
 * Detects template injection attacks that can lead to Remote Code Execution (RCE).
 * Covers major template engines: Jinja2, Twig, Freemarker, Velocity, ERB, Pebble, etc.
 */

import { BaseDetector, type BaseDetectorOptions } from './base';
import type { DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/** SSTI pattern definition */
export interface SSTIPattern {
  pattern: RegExp;
  description: string;
  engine: string;
  confidence: number;
  severity: SecuritySeverity;
}

export interface SSTIDetectorConfig extends BaseDetectorOptions {
  /**
   * Fields to exclude from checking (exact match)
   */
  excludeFields?: string[];
  
  /**
   * Custom patterns - if provided, OVERRIDES built-in patterns
   */
  patterns?: SSTIPattern[];
  
  /**
   * Headers to check (default: none - SSTI usually in body/params)
   */
  checkHeaders?: string[];
}

// SSTI Patterns by template engine
// Confidence guidelines:
// - 0.95-0.99: Almost certainly SSTI (RCE patterns)
// - 0.85-0.94: Highly suspicious (object access patterns)
// - 0.70-0.84: Suspicious (basic template syntax with suspicious content)
const SSTI_PATTERNS: SSTIPattern[] = [
  // === JINJA2 / TWIG (Python/PHP) - Very common ===
  {
    pattern: /\{\{\s*config\s*\}\}/i,
    description: 'Jinja2 config access',
    engine: 'Jinja2',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{\s*self\._?[a-z]/i,
    description: 'Jinja2 self object access',
    engine: 'Jinja2',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*__class__.*\}\}/i,
    description: 'Jinja2 class introspection',
    engine: 'Jinja2',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*__mro__.*\}\}/i,
    description: 'Jinja2 MRO access (RCE path)',
    engine: 'Jinja2',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*__globals__.*\}\}/i,
    description: 'Jinja2 globals access (RCE)',
    engine: 'Jinja2',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*__builtins__.*\}\}/i,
    description: 'Jinja2 builtins access (RCE)',
    engine: 'Jinja2',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*__subclasses__.*\}\}/i,
    description: 'Jinja2 subclasses access (RCE)',
    engine: 'Jinja2',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*\|attr\s*\(/i,
    description: 'Jinja2 attr filter bypass',
    engine: 'Jinja2',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{%.*import.*os.*%\}/i,
    description: 'Jinja2 os import',
    engine: 'Jinja2',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === TWIG (PHP) ===
  {
    pattern: /\{\{\s*_self\.env\./i,
    description: 'Twig _self.env access',
    engine: 'Twig',
    confidence: 0.98,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{.*\|filter\s*\(\s*['"]system['"]\s*\)/i,
    description: 'Twig system filter',
    engine: 'Twig',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\{\s*['"]['"]\s*\|filter\(/i,
    description: 'Twig filter exploitation',
    engine: 'Twig',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === FREEMARKER (Java) ===
  {
    pattern: /<#assign\s+\w+\s*=\s*["'].*\.getRuntime/i,
    description: 'Freemarker Runtime access',
    engine: 'Freemarker',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\$\{.*\.getClass\(\).*\}/i,
    description: 'Freemarker class access',
    engine: 'Freemarker',
    confidence: 0.98,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\$\{.*freemarker\.template\.utility\.Execute/i,
    description: 'Freemarker Execute utility',
    engine: 'Freemarker',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<#assign\s+ex\s*=\s*["']freemarker/i,
    description: 'Freemarker class instantiation',
    engine: 'Freemarker',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === VELOCITY (Java) ===
  {
    pattern: /#set\s*\(\s*\$\w+\s*=\s*.*\.getClass\(\)/i,
    description: 'Velocity class access',
    engine: 'Velocity',
    confidence: 0.98,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /#set\s*\(\s*\$\w+\s*=\s*.*\.getRuntime\(\)/i,
    description: 'Velocity Runtime access',
    engine: 'Velocity',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\$class\.inspect/i,
    description: 'Velocity class inspection',
    engine: 'Velocity',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === ERB (Ruby) ===
  {
    pattern: /<%=?\s*`[^`]+`\s*%>/i,
    description: 'ERB backtick command execution',
    engine: 'ERB',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<%=?\s*system\s*\(/i,
    description: 'ERB system() call',
    engine: 'ERB',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<%=?\s*exec\s*\(/i,
    description: 'ERB exec() call',
    engine: 'ERB',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<%=?\s*IO\.popen/i,
    description: 'ERB IO.popen',
    engine: 'ERB',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /<%=?\s*eval\s*\(/i,
    description: 'ERB eval() call',
    engine: 'ERB',
    confidence: 0.98,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === PEBBLE (Java) ===
  {
    pattern: /\{\{\s*beans\./i,
    description: 'Pebble beans access',
    engine: 'Pebble',
    confidence: 0.9,
    severity: SecuritySeverity.HIGH,
  },
  {
    pattern: /\{\{.*\.invoke\s*\(/i,
    description: 'Pebble method invocation',
    engine: 'Pebble',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === THYMELEAF (Java/Spring) ===
  {
    pattern: /\$\{T\s*\(\s*java\.lang\.Runtime\s*\)/i,
    description: 'Thymeleaf Runtime access',
    engine: 'Thymeleaf',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\$\{T\s*\(\s*java\.lang\.ProcessBuilder/i,
    description: 'Thymeleaf ProcessBuilder',
    engine: 'Thymeleaf',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\*\{T\s*\(\s*java\./i,
    description: 'Thymeleaf selection variable exploit',
    engine: 'Thymeleaf',
    confidence: 0.98,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === SMARTY (PHP) ===
  {
    pattern: /\{php\}.*\{\/php\}/is,
    description: 'Smarty PHP tag',
    engine: 'Smarty',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\{\$smarty\.now\|/i,
    description: 'Smarty variable access',
    engine: 'Smarty',
    confidence: 0.7,
    severity: SecuritySeverity.MEDIUM,
  },
  
  // === MAKO (Python) ===
  {
    pattern: /<%!?\s*import\s+os/i,
    description: 'Mako os import',
    engine: 'Mako',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\$\{.*os\.popen/i,
    description: 'Mako os.popen',
    engine: 'Mako',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  
  // === GENERIC / EXPRESSION EVALUATION ===
  {
    pattern: /\$\{\s*\d+\s*\*\s*\d+\s*\}/,
    description: 'Expression evaluation test (${7*7})',
    engine: 'Generic',
    confidence: 0.85,
    severity: SecuritySeverity.HIGH,
  },
  {
    pattern: /\{\{\s*\d+\s*\*\s*\d+\s*\}\}/,
    description: 'Expression evaluation test ({{7*7}})',
    engine: 'Generic',
    confidence: 0.85,
    severity: SecuritySeverity.HIGH,
  },
  {
    pattern: /#\{\s*\d+\s*\*\s*\d+\s*\}/,
    description: 'Expression evaluation test (#{7*7})',
    engine: 'Generic',
    confidence: 0.85,
    severity: SecuritySeverity.HIGH,
  },
  
  // === JAVA EXPRESSION LANGUAGE (EL) ===
  {
    pattern: /\$\{.*Runtime\.getRuntime\(\)/i,
    description: 'Java EL Runtime access',
    engine: 'Java EL',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /\$\{.*ProcessBuilder/i,
    description: 'Java EL ProcessBuilder',
    engine: 'Java EL',
    confidence: 1.0,
    severity: SecuritySeverity.CRITICAL,
  },
  {
    pattern: /#\{.*\.getClass\(\)/i,
    description: 'Java EL class access',
    engine: 'Java EL',
    confidence: 0.95,
    severity: SecuritySeverity.CRITICAL,
  },
];

/**
 * SSTIDetector - Detect Server-Side Template Injection attacks
 * 
 * SSTI can lead to Remote Code Execution (RCE) on the server.
 * 
 * @example
 * ```typescript
 * // Basic usage
 * new SSTIDetector({})
 * 
 * // Exclude certain fields (e.g., rich text editors)
 * new SSTIDetector({
 *   excludeFields: ['content', 'description'],
 * })
 * 
 * // Access built-in patterns
 * SSTIDetector.PATTERNS
 * ```
 * 
 * @remarks
 * **Supported Template Engines:**
 * - Jinja2 (Python)
 * - Twig (PHP)
 * - Freemarker (Java)
 * - Velocity (Java)
 * - ERB (Ruby)
 * - Pebble (Java)
 * - Thymeleaf (Java/Spring)
 * - Smarty (PHP)
 * - Mako (Python)
 * - Java Expression Language (EL)
 * 
 * **What SSTI enables:**
 * - Remote Code Execution (RCE)
 * - Server file access
 * - Environment variable leaks
 * - Full system compromise
 */
export class SSTIDetector extends BaseDetector {
  name = 'ssti';
  phase = 'request' as const;
  priority = 92; // High priority - RCE risk

  private config: SSTIDetectorConfig;
  private activePatterns: SSTIPattern[];
  private excludeFields: Set<string>;
  private checkHeaders: string[];

  /** Built-in SSTI patterns */
  static readonly PATTERNS = SSTI_PATTERNS;

  constructor(config: SSTIDetectorConfig = {}) {
    super();
    this.config = config;
    this.activePatterns = config.patterns ?? SSTI_PATTERNS;
    this.excludeFields = new Set(
      (config.excludeFields ?? []).map(f => f.toLowerCase())
    );
    this.checkHeaders = config.checkHeaders ?? [];
  }

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);

    // Check query parameters
    for (const [key, value] of url.searchParams) {
      if (this.isFieldExcluded(key)) continue;
      const result = this.checkForSSTI(value, `query.${key}`);
      if (result) return result;
    }

    // Check URL path (template in URL)
    const pathResult = this.checkForSSTI(url.pathname, 'path');
    if (pathResult) return pathResult;

    // Check request body
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        const contentType = request.headers.get('content-type') || '';

        if (contentType.includes('application/json')) {
          const body = await request.clone().json();
          const result = this.checkObject(body, 'body');
          if (result) return result;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const formData = await request.clone().text();
          const params = new URLSearchParams(formData);
          for (const [key, value] of params) {
            if (this.isFieldExcluded(key)) continue;
            const result = this.checkForSSTI(value, `form.${key}`);
            if (result) return result;
          }
        } else if (contentType.includes('text/')) {
          const body = await request.clone().text();
          const result = this.checkForSSTI(body, 'body');
          if (result) return result;
        }
      } catch {
        // Cannot read body
      }
    }

    // Check configured headers
    for (const headerName of this.checkHeaders) {
      const value = request.headers.get(headerName);
      if (value) {
        const result = this.checkForSSTI(value, `header.${headerName}`);
        if (result) return result;
      }
    }

    return null;
  }

  private isFieldExcluded(field: string): boolean {
    return this.excludeFields.has(field.toLowerCase());
  }

  private checkObject(obj: unknown, prefix: string): DetectorResult | null {
    if (!obj || typeof obj !== 'object') return null;

    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      const path = `${prefix}.${key}`;
      if (this.isFieldExcluded(key)) continue;

      if (typeof value === 'string') {
        const result = this.checkForSSTI(value, path);
        if (result) return result;
      } else if (typeof value === 'object' && value !== null) {
        const result = this.checkObject(value, path);
        if (result) return result;
      }
    }

    return null;
  }

  private checkForSSTI(input: string, location: string): DetectorResult | null {
    if (!input || typeof input !== 'string') return null;

    // Quick check - skip if no template indicators
    // Include $ for Velocity/Freemarker, % for URL-encoded
    if (!input.includes('{') && !input.includes('<') && !input.includes('#') && 
        !input.includes('$') && !input.includes('%')) {
      return null;
    }

    // URL decode
    let decoded = input;
    try {
      decoded = decodeURIComponent(input);
      if (decoded.includes('%')) {
        decoded = decodeURIComponent(decoded);
      }
    } catch {
      // Use original
    }

    const baseConfidence = this.config.baseConfidence;

    for (const { pattern, description, engine, confidence, severity } of this.activePatterns) {
      if (pattern.test(decoded)) {
        return this.createResult(
          AttackType.SSTI,
          severity,
          baseConfidence ?? confidence,
          {
            field: location,
            value: this.sanitizeValue(decoded),
            pattern: pattern.source,
            rawContent: `${engine}: ${description}`,
          },
          { 
            detectionType: 'ssti',
            engine,
            matchedPattern: description,
          }
        );
      }
    }

    return null;
  }

  private sanitizeValue(value: string): string {
    const maxLength = 150;
    let sanitized = value.substring(0, maxLength);
    
    // Mask potential RCE commands
    sanitized = sanitized.replace(/system\s*\([^)]*\)/gi, 'system(***)');
    sanitized = sanitized.replace(/exec\s*\([^)]*\)/gi, 'exec(***)');
    sanitized = sanitized.replace(/`[^`]+`/g, '`***`');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

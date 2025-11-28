/**
 * XSS Response Detector
 * Detects reflected XSS and XSS vulnerabilities in responses
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class XSSResponseDetector extends BaseDetector {
  name = 'xss-response';
  priority = 95;

  async detectResponse(request: Request, response: Response, context: any): Promise<DetectorResult | null> {
    try {
      const contentType = response.headers.get('content-type') || '';
      
      // Only scan HTML/XML responses
      if (!contentType.includes('text/html') && 
          !contentType.includes('text/xml') &&
          !contentType.includes('application/xhtml')) {
        return null;
      }
      
      const body = await response.clone().text();
      const url = new URL(request.url);
      
      // Check for reflected XSS
      const detection = this.checkForReflectedXSS(url, body);
      if (detection) return detection;
      
      // Check for unescaped dangerous content
      const leakDetection = this.checkForXSSLeaks(body);
      if (leakDetection) return leakDetection;
      
    } catch (error) {
      // Cannot read response body
    }
    
    return null;
  }

  private checkForReflectedXSS(requestUrl: URL, responseBody: string): DetectorResult | null {
    // Check if query parameters are reflected unescaped
    for (const [key, value] of requestUrl.searchParams.entries()) {
      if (value.length < 3) continue;
      
      const decodedValue = this.decodeHTMLEntities(value);
      
      // Dangerous patterns in reflected content
      const dangerousPatterns = [
        /<script/i,
        /on\w+\s*=/i,
        /javascript:/i,
      ];
      
      for (const pattern of dangerousPatterns) {
        if (pattern.test(decodedValue) && responseBody.includes(value)) {
          return this.createResult(
            AttackType.XSS,
            SecuritySeverity.CRITICAL,
            0.95,
            {
              field: `reflected_param.${key}`,
              value: this.sanitizeValue(value),
              rawContent: `Parameter "${key}" reflected unescaped in response`,
            },
            {
              detectionType: 'reflected_xss',
              parameter: key,
              reflectedValue: this.sanitizeValue(value),
            }
          );
        }
      }
    }
    
    return null;
  }

  private checkForXSSLeaks(body: string): DetectorResult | null {
    const leakPatterns = [
      // Unescaped user input indicators
      { regex: /\{\{.*?<script/i, confidence: 0.9, type: 'template_xss' },
      { regex: /<%.*?<script/i, confidence: 0.9, type: 'template_xss' },
      
      // Inline script with user data
      { regex: /<script>.*?document\.write\(.*?\)/i, confidence: 0.85, type: 'inline_write' },
      { regex: /<script>.*?innerHTML[\s]*=[\s]*['"]?[^'"]*</i, confidence: 0.85, type: 'inner_html_xss' },
      
      // CSP bypass indicators
      { regex: /<script.*?src[\s]*=[\s]*['"]?(data:|blob:)/i, confidence: 0.9, type: 'csp_bypass' },
      
      // Dangerous eval
      { regex: /eval\s*\(.*?(location|document\.)/i, confidence: 0.95, type: 'eval_xss' },
      
      // Unescaped JSON in script
      { regex: /<script[^>]*>.*?var.*?=.*?<\/.*?>/i, confidence: 0.75, type: 'json_script_leak' },
    ];
    
    for (const { regex, confidence, type } of leakPatterns) {
      const match = body.match(regex);
      if (match) {
        return this.createResult(
          AttackType.XSS,
          this.getSeverity(confidence),
          confidence,
          {
            field: 'response_body',
            value: this.sanitizeValue(match[0]),
            rawContent: `Potential XSS vulnerability: ${type}`,
          },
          {
            detectionType: 'xss_leak',
            leakType: type,
            evidence: this.sanitizeValue(match[0]),
          }
        );
      }
    }
    
    return null;
  }

  private decodeHTMLEntities(text: string): string {
    const entities: Record<string, string> = {
      '&lt;': '<',
      '&gt;': '>',
      '&quot;': '"',
      '&#x27;': "'",
      '&#x2F;': '/',
      '&amp;': '&',
    };

    return text.replace(/&[#\w]+;/g, (entity) => entities[entity] || entity);
  }

  private getSeverity(confidence: number): SecuritySeverity {
    if (confidence >= 0.9) return SecuritySeverity.CRITICAL;
    if (confidence >= 0.8) return SecuritySeverity.HIGH;
    if (confidence >= 0.7) return SecuritySeverity.MEDIUM;
    return SecuritySeverity.LOW;
  }

  private sanitizeValue(value: string): string {
    const maxLength = 100;
    let sanitized = value.substring(0, maxLength);
    
    // Remove actual script content
    sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '<script>***</script>');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

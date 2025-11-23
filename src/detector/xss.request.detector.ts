/**
 * XSS Request Detector
 * Detects XSS attack patterns in incoming requests
 */

import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

export class XSSRequestDetector extends BaseDetector {
  name = 'xss-request';
  priority = 95;

  private readonly patterns = [
    // Script tags
    { regex: /<script[\s>]/i, confidence: 0.95 },
    { regex: /<\/script>/i, confidence: 0.95 },
    
    // Event handlers
    { regex: /on(load|error|click|mouse|focus|blur|change|submit)[\s]*=/i, confidence: 0.9 },
    
    // JavaScript protocol
    { regex: /javascript:/i, confidence: 0.85 },
    { regex: /vbscript:/i, confidence: 0.9 },
    
    // Data URLs with script
    { regex: /data:text\/html/i, confidence: 0.8 },
    
    // HTML injection
    { regex: /<iframe[\s>]/i, confidence: 0.9 },
    { regex: /<object[\s>]/i, confidence: 0.85 },
    { regex: /<embed[\s>]/i, confidence: 0.85 },
    { regex: /<applet[\s>]/i, confidence: 0.9 },
    
    // SVG-based XSS
    { regex: /<svg[\s>]/i, confidence: 0.7 },
    { regex: /<svg.*onload/i, confidence: 0.95 },
    
    // Meta refresh
    { regex: /<meta[\s]+http-equiv[\s]*=[\s]*['"]?refresh/i, confidence: 0.8 },
    
    // Base tag injection
    { regex: /<base[\s]+href/i, confidence: 0.85 },
    
    // Form injection
    { regex: /<form[\s]+action/i, confidence: 0.75 },
    
    // IMG tag with event handlers or data URLs
    { regex: /<img[\s]+.*on\w+/i, confidence: 0.9 },
    { regex: /<img[\s]+.*src[\s]*=[\s]*['"]?data:/i, confidence: 0.8 },
    
    // Encoded script tags
    { regex: /&lt;script/i, confidence: 0.7 },
    { regex: /%3Cscript/i, confidence: 0.75 },
    
    // Expression injection (IE)
    { regex: /expression\s*\(/i, confidence: 0.9 },
    
    // Style with expression or import
    { regex: /<style.*(@import|expression|behavior)/i, confidence: 0.85 },
    
    // Link with JavaScript
    { regex: /<link.*href[\s]*=[\s]*['"]?javascript:/i, confidence: 0.9 },
  ];

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Check query parameters
    for (const [key, value] of url.searchParams.entries()) {
      const detection = this.checkForXSS(value, `query.${key}`);
      if (detection) return detection;
    }

    // Check URL path
    const detection = this.checkForXSS(url.pathname, 'path');
    if (detection) return detection;

    // Check request body for POST/PUT/PATCH
    if (['POST', 'PUT', 'PATCH'].includes(request.method)) {
      try {
        const contentType = request.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
          const body = await request.clone().text();
          const bodyDetection = this.checkForXSS(body, 'body');
          if (bodyDetection) return bodyDetection;
        } else if (contentType.includes('application/x-www-form-urlencoded')) {
          const body = await request.clone().text();
          const params = new URLSearchParams(body);
          for (const [key, value] of params.entries()) {
            const formDetection = this.checkForXSS(value, `form.${key}`);
            if (formDetection) return formDetection;
          }
        } else if (contentType.includes('text/html') || contentType.includes('text/plain')) {
          const body = await request.clone().text();
          const textDetection = this.checkForXSS(body, 'body');
          if (textDetection) return textDetection;
        }
      } catch (error) {
        // Cannot read body, skip
      }
    }

    // Check Referer and User-Agent
    const referer = request.headers.get('referer');
    if (referer) {
      const refererDetection = this.checkForXSS(referer, 'header.referer');
      if (refererDetection) return refererDetection;
    }

    const userAgent = request.headers.get('user-agent');
    if (userAgent) {
      const uaDetection = this.checkForXSS(userAgent, 'header.user-agent');
      if (uaDetection) return uaDetection;
    }

    return null;
  }

  private checkForXSS(input: string, field: string): DetectorResult | null {
    // Decode HTML entities and URL encoding
    let decodedInput = input;
    try {
      decodedInput = decodeURIComponent(input);
      decodedInput = this.decodeHTMLEntities(decodedInput);
    } catch {
      // Invalid encoding, use original
    }

    for (const { regex, confidence } of this.patterns) {
      if (regex.test(decodedInput)) {
        const match = decodedInput.match(regex);
        
        return this.createResult(
          AttackType.XSS,
          this.getSeverity(confidence),
          confidence,
          {
            field,
            value: this.sanitizeValue(decodedInput),
            pattern: regex.source,
            rawContent: match ? match[0].substring(0, 50) : undefined,
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
    
    // Remove actual script content for safety
    sanitized = sanitized.replace(/<script[^>]*>.*?<\/script>/gi, '<script>***</script>');
    
    return sanitized + (value.length > maxLength ? '...' : '');
  }
}

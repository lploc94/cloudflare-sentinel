/**
 * Example: How to create custom detector
 * User can copy và modify này
 */

import { BaseDetector, type DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

/**
 * Example 1: Custom Request Detector
 * Detect suspicious patterns in request
 */
export class MyCustomDetector extends BaseDetector {
  name = 'my-custom-detector';
  priority = 50;  // Medium priority
  
  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    // Example: Detect specific patterns
    const suspiciousPatterns = [
      /admin-console/i,
      /phpmyadmin/i,
      /\.env/i,
    ];
    
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(url.pathname)) {
        return this.createResult(
          'suspicious_pattern' as AttackType,
          SecuritySeverity.MEDIUM,
          0.8,
          {
            field: 'path',
            value: url.pathname,
            pattern: pattern.source,
          }
        );
      }
    }
    
    // Example: Check custom header
    const customHeader = request.headers.get('X-Custom-Auth');
    if (customHeader && customHeader.includes('malicious')) {
      return this.createResult(
        'suspicious_pattern' as AttackType,
        SecuritySeverity.HIGH,
        0.9,
        {
          field: 'X-Custom-Auth',
          value: 'blocked',
        }
      );
    }
    
    return null;  // No attack detected
  }
}

/**
 * Example 2: Custom Response Detector (Behavior)
 * Detect suspicious patterns in response
 */
export class DataLeakDetector extends BaseDetector {
  name = 'data-leak-detector';
  priority = 30;
  
  async detectResponse(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    
    // Only check non-error responses
    if (response.status >= 400) return null;
    
    try {
      // Clone response to read body
      const clone = response.clone();
      const text = await clone.text();
      
      // Example: Detect leaked credentials
      const leakPatterns = [
        /password\s*[:=]\s*['"][^'"]+['"]/i,
        /api[_-]?key\s*[:=]\s*['"][^'"]+['"]/i,
        /secret\s*[:=]\s*['"][^'"]+['"]/i,
      ];
      
      for (const pattern of leakPatterns) {
        if (pattern.test(text)) {
          return this.createResult(
            'logic_abuse' as AttackType,
            SecuritySeverity.CRITICAL,
            0.95,
            {
              field: 'response_body',
              pattern: pattern.source,
              rawContent: text.substring(0, 100),  // First 100 chars
            },
            {
              responseStatus: response.status,
              contentType: response.headers.get('content-type'),
            }
          );
        }
      }
    } catch (error) {
      // Cannot read body, skip
    }
    
    return null;
  }
}

/**
 * Example 3: Business Logic Detector
 * Detect violations of business rules
 */
export class PriceManipulationDetector extends BaseDetector {
  name = 'price-manipulation';
  priority = 80;  // High priority
  
  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    // Only check POST/PUT to order endpoints
    if (!['POST', 'PUT'].includes(request.method)) return null;
    
    const url = new URL(request.url);
    if (!url.pathname.includes('/order')) return null;
    
    try {
      const body = await request.clone().json() as any;
      
      // Example: Check price manipulation
      if (body.price !== undefined) {
        const price = parseFloat(body.price);
        
        // Suspicious: Negative price
        if (price < 0) {
          return this.createResult(
            'logic_abuse' as AttackType,
            SecuritySeverity.CRITICAL,
            1.0,
            {
              field: 'price',
              value: price.toString(),
            },
            {
              reason: 'negative_price',
            }
          );
        }
        
        // Suspicious: Price too low
        if (price < 0.01 && price > 0) {
          return this.createResult(
            'logic_abuse' as AttackType,
            SecuritySeverity.HIGH,
            0.9,
            {
              field: 'price',
              value: price.toString(),
            },
            {
              reason: 'suspiciously_low_price',
            }
          );
        }
      }
      
      // Example: Check quantity manipulation
      if (body.quantity !== undefined) {
        const quantity = parseInt(body.quantity);
        
        if (quantity > 10000) {
          return this.createResult(
            'logic_abuse' as AttackType,
            SecuritySeverity.MEDIUM,
            0.7,
            {
              field: 'quantity',
              value: quantity.toString(),
            },
            {
              reason: 'excessive_quantity',
            }
          );
        }
      }
    } catch (error) {
      // Not JSON or cannot parse, skip
    }
    
    return null;
  }
}

/**
 * Usage Example:
 * 
 * const sentinel = new Sentinel({
 *   rateLimiter: env.RATE_LIMITER,
 *   analytics: env.ANALYTICS,
 *   
 *   // Register custom detectors
 *   detectors: [
 *     new MyCustomDetector(),
 *     new DataLeakDetector(),
 *     new PriceManipulationDetector(),
 *   ],
 *   
 *   // Configure limits for custom attack types
 *   // Note: Cloudflare Rate Limiting API only supports 10s or 60s periods
 *   attackLimits: {
 *     logic_abuse: {
 *       limit: 3,
 *       period: RateLimitPeriod.ONE_MINUTE,  // 3 times per 60s window
 *       action: 'block'
 *     },
 *     suspicious_pattern: {
 *       limit: 10,
 *       period: RateLimitPeriod.TEN_SECONDS,  // 10 times per 10s window
 *       action: 'log_only'
 *     }
 *   }
 * });
 */

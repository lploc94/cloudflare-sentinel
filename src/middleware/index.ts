/**
 * Sentinel - Attack-based rate limiting middleware
 * Optimized flow with pluggable detectors
 */

import type { SentinelConfig, AttackTypeOrWildcard } from '../types';
import type { IDetector, DetectorResult } from '../detector/base';
import { AttackLimiter } from './attack-limiter';
import { SecurityLogger } from '../logger';
import { BehaviorTracker } from '../logger/behavior-tracker';
import { AttackType, DetectionMethod, EventCategory, RateLimitAction } from '../types';
import { createLogger, type SentinelLogger } from '../utils/logger';
import { validateAttackLimits } from '../types/validation';
import { Whitelist } from '../utils/whitelist';

/**
 * Sentinel middleware class
 */
export class Sentinel {
  private config: SentinelConfig;
  private attackLimiter: AttackLimiter;
  private logger: SecurityLogger;
  private appLogger: SentinelLogger;
  private detectors: IDetector[];
  private behaviorTracker?: BehaviorTracker;
  private whitelist?: Whitelist;

  constructor(config: SentinelConfig) {
    // Validate attack limits if provided
    if (config.attackLimits) {
      const validation = validateAttackLimits(config.attackLimits);
      if (!validation.valid) {
        throw new Error(
          `Invalid attack limits configuration:\n${validation.errors.join('\n')}`
        );
      }
    }

    // Set defaults
    this.config = {
      debug: false,
      enableAnalytics: true,
      enableD1: true,
      enableBehaviorTracking: true,
      enableEarlyBlockCheck: true,
      ...config,
    };

    // Initialize logger
    this.appLogger = createLogger(this.config.debug);

    // Initialize components
    this.attackLimiter = new AttackLimiter(this.config);
    this.logger = new SecurityLogger(this.config);
    
    // Initialize detectors
    this.detectors = (this.config.detectors || [])
      .filter(d => d.enabled !== false)
      .sort((a, b) => (b.priority || 0) - (a.priority || 0));  // Higher priority first
    
    // Initialize behavior tracker if enabled
    if (this.config.enableBehaviorTracking && this.config.kv) {
      this.behaviorTracker = new BehaviorTracker(this.config.kv, {
        failureThreshold: this.config.behaviorFailureThreshold || 5,
        timeWindowSeconds: this.config.behaviorTimeWindow || 60,
        maxTrackedPaths: this.config.behaviorMaxPaths || 20,
      });
    }

    // Initialize whitelist if provided
    if (this.config.whitelist) {
      this.whitelist = new Whitelist(this.config.whitelist);
      const stats = this.whitelist.getStats();
      this.appLogger.info(`Whitelist initialized`, {
        component: 'Sentinel',
        ...stats,
      });
    }

    this.appLogger.info(`Initialized with ${this.detectors.length} detectors`, {
      component: 'Sentinel',
      detectorsCount: this.detectors.length,
    });
  }


  /**
   * Main protect method
   */
  protect = async (
    request: Request,
    next: () => Promise<Response>
  ): Promise<Response> => {
    const startTime = Date.now();
    
    try {
      // Get identifier and endpoint
      const identifier = await this.attackLimiter.getIdentifier(request, {});
      const url = new URL(request.url);
      const endpoint = url.pathname;

      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // Whitelist Check (Bypass all security for trusted sources)
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      if (this.whitelist) {
        const isWhitelisted = await this.whitelist.isWhitelisted(identifier, {});
        if (isWhitelisted) {
          this.appLogger.debug('Whitelisted identifier - bypassing security', {
            component: 'Sentinel',
            identifier: identifier.value,
            type: identifier.type,
          });
          
          // Bypass whitelist
          const response = await next();
          return response;
        }
      }

      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // Step 0: Early Block Check (Optimization)
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      if (this.config.enableEarlyBlockCheck) {
        const blockCheck = await this.attackLimiter.isBlocked(identifier, endpoint);
        
        if (blockCheck.blocked) {
          this.appLogger.debug('Early block check triggered', {
            component: 'Sentinel',
            ip: identifier.value,
            attackType: blockCheck.attackType,
            endpoint: blockCheck.endpoint,
          });
          
          return this.createBlockedResponse(blockCheck.attackType!, blockCheck.reason!);
        }
      }

      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // Step 1: Request Detection
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      const requestDetection = await this.runRequestDetectors(request, {});
      
      if (requestDetection) {
        // Attack detected in request
        
        const limit = this.config.attackLimits?.[requestDetection.attackType];
        
        if (limit) {
          // Check rate limit for this attack (layered)
          const { allowed, retryAfter } = await this.attackLimiter.checkAndIncrement(
            identifier,
            requestDetection.attackType,
            endpoint
          );

          // Log attack
          await this.logAttack(
            request,
            null,  // No response yet
            requestDetection,
            identifier,
            !allowed,  // blocked
            startTime
          );

          if (!allowed) {
            // Rate limit exceeded
            this.appLogger.warn('Rate limit exceeded', {
              component: 'Sentinel',
              attackType: requestDetection.attackType,
              ip: identifier.value,
              endpoint,
            });
            
            return this.createBlockedResponse(
              requestDetection.attackType,
              `Attack limit exceeded: ${requestDetection.attackType}`
            );
          }

          // Within limit, check action
          if (limit.action === 'block' && !limit.logOnly) {
            // Block immediately
            this.appLogger.warn('Blocking attack', {
              component: 'Sentinel',
              attackType: requestDetection.attackType,
              ip: identifier.value,
              endpoint,
            });
            
            return this.createBlockedResponse(
              requestDetection.attackType,
              requestDetection.evidence?.value || 'Attack detected'
            );
          }
          
          // Log only, continue
        } else {
          // No limit configured, just log
          await this.logAttack(request, null, requestDetection, identifier, false, startTime);
        }
      }

      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // Step 2: Process Request
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      const response = await next();

      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // Step 3: Response Detection (Behavior)
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      const responseDetection = await this.runResponseDetectors(request, response, {});
      
      if (responseDetection) {
        // Behavior attack detected
        const limit = this.config.attackLimits?.[responseDetection.attackType];
        
        if (limit) {
          await this.attackLimiter.checkAndIncrement(identifier, responseDetection.attackType, endpoint);
        }
        
        // Log (don't block response, already sent)
        await this.logAttack(request, response, responseDetection, identifier, false, startTime);
      }

      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      // Step 4: Behavior Tracking (errors only)
      // ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
      if (this.behaviorTracker && response.status >= 400) {
        const url = new URL(request.url);
        const detection = await this.behaviorTracker.trackAndDetect(
          identifier.value,
          url.pathname,
          response.status,
          {}
        );

        if (detection.detected) {
          // Log behavior attack
          await this.logBehaviorAttack(request, response, detection, identifier, startTime);
        }
      }

      return response;
      
    } catch (error: any) {
      this.appLogger.error('Middleware error - failing open', {
        component: 'Sentinel',
        error: error as Error,
      });
      
      // Fail-open: Allow request on error
      return next();
    }
  };

  /**
   * Run all request detectors (global + endpoint-specific)
   */
  private async runRequestDetectors(
    request: Request,
    context: any
  ): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    const endpoint = url.pathname;
    
    // Get endpoint-specific detectors
    const endpointDetectors = this.getEndpointDetectors(endpoint);
    
    // Combine global + endpoint-specific detectors
    const allDetectors = [...this.detectors, ...endpointDetectors];
    
    for (const detector of allDetectors) {
      if (!detector.detectRequest) continue;
      
      try {
        const result = await detector.detectRequest(request, context);
        
        const detected = !!(result && result.detected);
        
        if (detected) {
          this.appLogger.info('Attack detected by detector', {
            component: 'Sentinel:RequestDetection',
            detector: detector.name,
            attackType: result.attackType,
            confidence: result.confidence,
            endpoint,
          });
          return result;  // Stop on first detection
        }
      } catch (error: any) {
        this.appLogger.error(`Detector ${detector.name} error`, {
          component: 'Sentinel',
          error: error as Error,
        });
      }
    }
    
    return null;
  }

  /**
   * Run all response detectors (global + endpoint-specific)
   */
  private async runResponseDetectors(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    const endpoint = url.pathname;
    
    // Get endpoint-specific detectors
    const endpointDetectors = this.getEndpointDetectors(endpoint);
    
    // Combine global + endpoint-specific detectors
    const allDetectors = [...this.detectors, ...endpointDetectors];
    
    for (const detector of allDetectors) {
      if (!detector.detectResponse) continue;
      
      try {
        const result = await detector.detectResponse(request, response, context);
        
        const detected = !!(result && result.detected);
        
        if (detected) {
          this.appLogger.info('Attack detected in response', {
            component: 'Sentinel:ResponseDetection',
            detector: detector.name,
            attackType: result.attackType,
            confidence: result.confidence,
            endpoint,
          });
          return result;
        }
      } catch (error: any) {
        this.appLogger.error(`Detector ${detector.name} error`, {
          component: 'Sentinel',
          error: error as Error,
        });
      }
    }
    
    return null;
  }

  /**
   * Get endpoint-specific detectors that match the given endpoint
   */
  private getEndpointDetectors(endpoint: string): IDetector[] {
    if (!this.config.endpointDetectors) return [];
    
    const matchedDetectors: IDetector[] = [];
    
    for (const [pattern, detectors] of Object.entries(this.config.endpointDetectors)) {
      if (this.matchEndpoint(endpoint, pattern)) {
        // Filter enabled detectors and add to list
        const enabledDetectors = (detectors as IDetector[])
          .filter(d => d.enabled !== false);
        matchedDetectors.push(...enabledDetectors);
      }
    }
    
    // Sort by priority (higher first)
    return matchedDetectors.sort((a, b) => (b.priority || 0) - (a.priority || 0));
  }

  /**
   * Check if endpoint matches glob pattern
   */
  private matchEndpoint(endpoint: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*\*/g, '{{DOUBLESTAR}}')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '.')
      .replace(/{{DOUBLESTAR}}/g, '.*');
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(endpoint);
  }

  /**
   * Log attack to Analytics Engine + D1
   */
  private async logAttack(
    request: Request,
    response: Response | null,
    detection: DetectorResult,
    identifier: any,
    blocked: boolean,
    startTime: number
  ): Promise<void> {
    
    const url = new URL(request.url);
    
    // Write to Analytics Engine
    if (this.config.analytics) {
      this.config.analytics.writeDataPoint({
        blobs: [
          identifier.value,                              // Identifier (IP, user, etc.)
          identifier.type,                               // Identifier type
          detection.attackType,                          // Attack type
          url.pathname,                                  // Endpoint
          this.normalizeEndpoint(url.pathname),          // Normalized endpoint
          request.method,                                // Method
          response?.status.toString() || 'blocked',      // Status
          blocked ? 'blocked' : 'logged',                // Action
          '',                                            // Country (TODO: get from request.cf)
          detection.evidence?.field || '',               // Field
        ],
        doubles: [
          1,                                             // Count
          detection.confidence,                          // Confidence
          blocked ? 1 : 0,                               // Blocked
          0,                                             // Violations (deprecated)
          0,                                             // Sequential failures
          Date.now() - startTime,                        // Response time
        ],
        indexes: [detection.severity],                   // Severity
      });
    }

    // Write to D1 if critical
    if (this.config.db && this.shouldWriteToD1(detection, blocked)) {
      await this.config.db.prepare(`
        INSERT INTO security_events (
          event_id, timestamp, attack_type, severity, confidence,
          path, method, status_code, ip_address, user_agent, country,
          user_id, rule_id, action, blocked, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `).bind(
        crypto.randomUUID(),
        Date.now(),
        detection.attackType,
        detection.severity,
        detection.confidence,
        url.pathname,
        request.method,
        response?.status || 0,
        identifier.value,
        request.headers.get('user-agent'),
        null,  // country
        null,  // user_id
        null,  // rule_id
        blocked ? 'blocked' : 'logged',
        blocked ? 1 : 0,
        JSON.stringify({
          identifierType: identifier.type,
          evidence: detection.evidence,
          metadata: detection.metadata,
        })
      ).run();
    }
  }

  /**
   * Log behavior attack
   */
  private async logBehaviorAttack(
    request: Request,
    response: Response,
    detection: any,
    identifier: any,
    startTime: number
  ): Promise<void> {
    
    const url = new URL(request.url);
    
    if (this.config.analytics) {
      this.config.analytics.writeDataPoint({
        blobs: [
          identifier.value,
          identifier.type,
          detection.attackType,
          url.pathname,
          this.normalizeEndpoint(url.pathname),
          request.method,
          response.status.toString(),
          'logged',
          '',
          'behavior',
        ],
        doubles: [
          1,
          detection.confidence,
          0,
          0,
          detection.sequentialFailures,
          Date.now() - startTime,
        ],
        indexes: [detection.severity],
      });
    }
  }

  /**
   * Check if should write to D1
   */
  private shouldWriteToD1(detection: DetectorResult, blocked: boolean): boolean {
    return (
      blocked ||
      detection.severity === 'critical' ||
      detection.severity === 'high' ||
      detection.confidence >= 0.9
    );
  }

  /**
   * Normalize endpoint for grouping
   */
  private normalizeEndpoint(path: string): string {
    return path
      .replace(/\/\d+/g, '/{id}')
      .replace(/\/[a-f0-9-]{36}/g, '/{uuid}')
      .replace(/\/[a-f0-9]{24,}/g, '/{hash}');
  }

  /**
   * Create blocked response
   */
  private createBlockedResponse(attackType: AttackTypeOrWildcard, reason: string): Response {
    return new Response(
      JSON.stringify({
        error: 'Request blocked',
        code: 'SECURITY_VIOLATION',
        attackType,
        reason,
      }),
      {
        status: 403,
        headers: {
          'Content-Type': 'application/json',
          'X-Blocked-Reason': attackType,
        },
      }
    );
  }
}

// Re-export for convenience
export * from './attack-limiter';
export * from './parallel-limiter';
export * from './rate-limit-cache';

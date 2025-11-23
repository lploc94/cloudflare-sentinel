/**
 * Security event logger - writes to D1 and Analytics Engine
 * Optimized for Cloudflare Workers (stateless)
 */

import type {
  SecurityEvent,
  SentinelConfig,
  DetectionMethod,
  EventCategory,
  SecuritySeverity,
} from '../types';

/**
 * Logging decision
 */
interface LogDecision {
  shouldLog: boolean;
  destination: 'analytics' | 'd1' | 'both' | 'none';
  reason: string;
}

/**
 * Logger class for security events
 * Stateless design for Cloudflare Workers
 */
export class SecurityLogger {
  private config: SentinelConfig;

  constructor(config: SentinelConfig) {
    this.config = config;
  }

  /**
   * Log if needed based on smart filtering
   * Only logs errors, attacks, and suspicious behavior
   */
  async logIfNeeded(
    request: Request,
    response: Response,
    context: any
  ): Promise<void> {
    const decision = this.decideLogging(request, response, context);

    if (!decision.shouldLog) {
      return; // Skip logging
    }

    // Check rate limit for logging (prevent spam)
    if (this.config.kv) {
      const canLog = await this.checkLogRateLimit(context.ip);
      if (!canLog) {
        if (this.config.debug) {
          this.config.logger?.(`[Sentinel] Log rate limit exceeded for IP: ${context.ip}`);
        }
        return;
      }
    }

    // Create security event
    const event = this.createEvent(request, response, context);

    // Log to console if debug
    if (this.config.debug) {
      this.config.logger?.(
        `[Sentinel] ${decision.reason}: ${event.attackType} (${event.statusCode})`,
        event
      );
    }

    // Write based on destination
    if (decision.destination === 'analytics' || decision.destination === 'both') {
      await this.writeToAnalytics(event);
    }

    if (decision.destination === 'd1' || decision.destination === 'both') {
      await this.writeToD1Single(event);
    }
  }

  /**
   * Legacy method for backwards compatibility
   */
  async log(event: SecurityEvent): Promise<void> {
    // Debug log
    if (this.config.debug) {
      this.config.logger?.(
        `[Sentinel] Security event: ${event.attackType}`,
        event
      );
    }

    // Write to Analytics
    if (this.config.enableAnalytics !== false && this.config.analytics) {
      await this.writeToAnalytics(event);
    }

    // Write to D1 if critical
    if (this.shouldWriteToD1(event) && this.config.enableD1 !== false && this.config.db) {
      await this.writeToD1Single(event);
    }
  }

  /**
   * Write event to Analytics Engine
   */
  private async writeToAnalytics(event: SecurityEvent): Promise<void> {
    if (!this.config.analytics) return;

    try {
      this.config.analytics.writeDataPoint({
        blobs: [
          this.normalizeEndpoint(event.path),
          event.attackType,
          event.detectionMethod,
          event.eventCategory,
          event.method,
          event.statusCode.toString(),
          event.ipAddress,
          event.country || 'unknown',
          event.action,
          event.userAgent || '',
        ],
        doubles: [
          1, // count
          event.confidence,
          event.blocked ? 1 : 0,
          event.violations || 0,
          event.sequentialFailures || 0,
          event.responseTime || 0,
        ],
        indexes: [event.severity],
      });
    } catch (error: any) {
      this.config.logger?.(
        `[Sentinel] Analytics Engine error: ${error.message}`
      );
    }
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
   * Convert severity to index number
   */
  private severityToIndex(severity: SecuritySeverity): number {
    const map: Record<SecuritySeverity, number> = {
      low: 1,
      medium: 2,
      high: 3,
      critical: 4,
    };
    return map[severity] || 0;
  }

  /**
   * Write events to D1 database (batch insert with prepared statements)
   */
  private async writeToD1(events: SecurityEvent[]): Promise<void> {
    if (!this.config.db || events.length === 0) return;

    try {
      // Use batch insert with prepared statements to prevent SQL injection
      const batch = events.map(event => {
        return this.config.db!.prepare(`
          INSERT INTO security_events (
            event_id, timestamp, attack_type, severity, confidence,
            path, method, status_code, ip_address, user_agent, country,
            user_id, rule_id, action, blocked, metadata
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `).bind(
          event.eventId,
          event.timestamp,
          event.attackType,
          event.severity,
          event.confidence,
          event.path,
          event.method,
          event.statusCode,
          event.ipAddress,
          event.userAgent || null,
          event.country || null,
          event.userId || null,
          event.ruleId || null,
          event.action,
          event.blocked ? 1 : 0,
          event.metadata ? JSON.stringify(event.metadata) : null
        );
      });

      await this.config.db.batch(batch);

      if (this.config.debug) {
        this.config.logger?.(
          `[Sentinel] Wrote ${events.length} events to D1 (batch)`
        );
      }
    } catch (error: any) {
      this.config.logger?.(
        `[Sentinel] D1 batch write error: ${error.message}`
      );
    }
  }

  /**
   * Decide if and where to log
   */
  private decideLogging(
    request: Request,
    response: Response,
    context: any
  ): LogDecision {
    // Success → Skip (unless logic error)
    if (response.status < 400) {
      if (context?.hasValidationError || context?.hasBusinessLogicError) {
        return { shouldLog: true, destination: 'analytics', reason: 'logic_error' };
      }
      return { shouldLog: false, destination: 'none', reason: 'success' };
    }

    // Pattern attack detected → Both D1 + Analytics
    if (context?.attackDetected && context?.detectionMethod === 'pattern') {
      return { shouldLog: true, destination: 'both', reason: 'pattern_attack' };
    }

    // Behavior attack detected → Both D1 + Analytics
    if (context?.behaviorDetected) {
      return { shouldLog: true, destination: 'both', reason: 'behavior_attack' };
    }

    // High violations → D1 + Analytics
    if (context?.violations >= 5) {
      return { shouldLog: true, destination: 'both', reason: 'high_violations' };
    }

    // Blocked request → D1 + Analytics
    if (context?.blocked) {
      return { shouldLog: true, destination: 'both', reason: 'blocked' };
    }

    // Regular error → Analytics only
    if (response.status >= 400) {
      return { shouldLog: true, destination: 'analytics', reason: 'error_response' };
    }

    return { shouldLog: false, destination: 'none', reason: 'unknown' };
  }

  /**
   * Check if can log (rate limit per IP)
   */
  private async checkLogRateLimit(ip: string): Promise<boolean> {
    if (!this.config.kv) return true;

    const key = `log:ratelimit:${ip}:${Math.floor(Date.now() / 60000)}`;
    const count = await this.config.kv.get(key);
    const currentCount = count ? parseInt(count) : 0;

    // Max 100 logs per IP per minute
    if (currentCount >= 100) {
      return false;
    }

    await this.config.kv.put(key, (currentCount + 1).toString(), {
      expirationTtl: 60,
    });

    return true;
  }

  /**
   * Create security event from context
   */
  private createEvent(
    request: Request,
    response: Response,
    context: any
  ): SecurityEvent {
    const url = new URL(request.url);
    
    return {
      eventId: crypto.randomUUID(),
      timestamp: Date.now(),
      attackType: context.attackType || 'unknown',
      detectionMethod: context.detectionMethod || 'rate_limit',
      eventCategory: context.eventCategory || 'abuse',
      severity: context.severity || 'low',
      confidence: context.confidence || 0.5,
      path: url.pathname,
      method: request.method,
      statusCode: response.status,
      ipAddress: context.ip || 'unknown',
      userAgent: request.headers.get('user-agent') || undefined,
      country: context.cf?.country,
      asn: context.cf?.asn,
      userId: context.userId,
      ruleId: context.ruleId,
      action: context.action || 'log_only',
      blocked: context.blocked || false,
      violations: context.violations,
      sequentialFailures: context.sequentialFailures,
      responseTime: context.responseTime,
      metadata: context.metadata,
    };
  }

  /**
   * Check if event should be written to D1
   */
  private shouldWriteToD1(event: SecurityEvent): boolean {
    // Only critical events
    return (
      event.blocked ||
      event.severity === 'critical' ||
      event.severity === 'high' ||
      (event.violations && event.violations >= 5) ||
      event.detectionMethod === 'pattern' ||
      event.detectionMethod === 'behavior'
    );
  }

  /**
   * Write single event to D1 (direct write)
   */
  private async writeToD1Single(event: SecurityEvent): Promise<void> {
    if (!this.config.db) return;

    try {
      const sql = `
        INSERT INTO security_events (
          event_id, timestamp, attack_type, severity, confidence,
          path, method, status_code, ip_address, user_agent, country,
          user_id, rule_id, action, blocked, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `;

      await this.config.db
        .prepare(sql)
        .bind(
          event.eventId,
          event.timestamp,
          event.attackType,
          event.severity,
          event.confidence,
          event.path,
          event.method,
          event.statusCode,
          event.ipAddress,
          event.userAgent || null,
          event.country || null,
          event.userId || null,
          event.ruleId || null,
          event.action,
          event.blocked ? 1 : 0,
          event.metadata ? JSON.stringify(event.metadata) : null
        )
        .run();

      if (this.config.debug) {
        this.config.logger?.(`[Sentinel] Wrote event to D1: ${event.eventId}`);
      }
    } catch (error: any) {
      this.config.logger?.(`[Sentinel] D1 write error: ${error.message}`);
    }
  }


  /**
   * Get attack statistics from D1
   */
  async getStatistics(options: {
    startTime?: number;
    endTime?: number;
    attackType?: string;
    limit?: number;
  }): Promise<any[]> {
    if (!this.config.db) {
      throw new Error('D1 database not configured');
    }

    const conditions: string[] = [];
    const bindings: any[] = [];
    
    if (options.startTime) {
      conditions.push('timestamp >= ?');
      bindings.push(options.startTime);
    }
    if (options.endTime) {
      conditions.push('timestamp <= ?');
      bindings.push(options.endTime);
    }
    if (options.attackType) {
      conditions.push('attack_type = ?');
      bindings.push(options.attackType);
    }

    const whereClause = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = Math.min(options.limit || 100, 1000); // Cap at 1000

    const sql = `
      SELECT 
        attack_type,
        severity,
        COUNT(*) as count,
        AVG(confidence) as avg_confidence,
        COUNT(DISTINCT ip_address) as unique_ips
      FROM security_events
      ${whereClause}
      GROUP BY attack_type, severity
      ORDER BY count DESC
      LIMIT ?
    `;

    bindings.push(limit);
    const result = await this.config.db.prepare(sql).bind(...bindings).all();
    return result.results || [];
  }

  /**
   * Get top attacking IPs
   */
  async getTopAttackers(options: {
    startTime?: number;
    limit?: number;
  }): Promise<any[]> {
    if (!this.config.db) {
      throw new Error('D1 database not configured');
    }

    const bindings: any[] = [];
    const whereClause = options.startTime ? 'WHERE timestamp >= ?' : '';
    if (options.startTime) {
      bindings.push(options.startTime);
    }

    const limit = Math.min(options.limit || 50, 1000); // Cap at 1000

    const sql = `
      SELECT 
        ip_address,
        country,
        COUNT(*) as total_events,
        COUNT(DISTINCT attack_type) as attack_types,
        SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked_requests,
        MAX(timestamp) as last_seen
      FROM security_events
      ${whereClause}
      GROUP BY ip_address, country
      ORDER BY total_events DESC
      LIMIT ?
    `;

    bindings.push(limit);
    const result = await this.config.db.prepare(sql).bind(...bindings).all();
    return result.results || [];
  }

  /**
   * Get most targeted endpoints
   */
  async getTopTargets(options: {
    startTime?: number;
    limit?: number;
  }): Promise<any[]> {
    if (!this.config.db) {
      throw new Error('D1 database not configured');
    }

    const bindings: any[] = [];
    const whereClause = options.startTime ? 'WHERE timestamp >= ?' : '';
    if (options.startTime) {
      bindings.push(options.startTime);
    }

    const limit = Math.min(options.limit || 50, 1000); // Cap at 1000

    const sql = `
      SELECT 
        path,
        method,
        COUNT(*) as total_attacks,
        COUNT(DISTINCT attack_type) as attack_types,
        COUNT(DISTINCT ip_address) as unique_attackers,
        MAX(timestamp) as last_attack
      FROM security_events
      ${whereClause}
      GROUP BY path, method
      ORDER BY total_attacks DESC
      LIMIT ?
    `;

    bindings.push(limit);
    const result = await this.config.db.prepare(sql).bind(...bindings).all();
    return result.results || [];
  }
}

export * from './migration';
export * from './behavior-tracker';

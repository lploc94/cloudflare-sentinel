/**
 * Sentinel Metrics Collector
 * Query metrics from D1, KV, and Analytics Engine without needing Sentinel instance
 */

export interface MetricsOptions {
  period?: '1h' | '24h' | '7d' | '30d';
  includeTopTargets?: boolean;
  topLimit?: number;
}

export interface SentinelMetricsData {
  requests: {
    total: number;
    blocked: number;
    allowed: number;
    blockRate: string;
    recentActivity?: number;
  };
  attacks: {
    total: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
  };
  topTargets?: {
    paths: Array<{ path: string; attacks: number }>;
    ips: Array<{ ip: string; attacks: number }>;
    countries?: Array<{ country: string; attacks: number }>;
  };
  period: string;
  timestamp: string;
}

/**
 * Standalone metrics collector - không cần Sentinel instance
 */
export class SentinelMetricsCollector {
  constructor(
    private db: D1Database,
    private kv?: KVNamespace,
    private analytics?: AnalyticsEngineDataset
  ) {}

  /**
   * Get comprehensive metrics from all sources
   */
  async getMetrics(options: MetricsOptions = {}): Promise<SentinelMetricsData> {
    const period = options.period || '24h';
    const includeTopTargets = options.includeTopTargets ?? true;
    const topLimit = options.topLimit || 10;
    
    const periodMs = this.getPeriodMs(period);
    const now = Date.now();
    const startTime = now - periodMs;
    
    // Query từ D1
    const [
      totalQuery,
      blockedQuery,
      attacksByType,
      attacksBySeverity,
      recentActivity,
      topPaths,
      topIPs,
      topCountries,
    ] = await Promise.all([
      this.queryTotal(startTime),
      this.queryBlocked(startTime),
      this.queryAttacksByType(startTime),
      this.queryAttacksBySeverity(startTime),
      this.queryRecentActivity(now - 3600000), // Last 1h
      includeTopTargets ? this.queryTopPaths(startTime, topLimit) : null,
      includeTopTargets ? this.queryTopIPs(startTime, topLimit) : null,
      includeTopTargets ? this.queryTopCountries(startTime, topLimit) : null,
    ]);
    
    const total = totalQuery || 0;
    const blocked = blockedQuery || 0;
    const allowed = total - blocked;
    
    return {
      requests: {
        total,
        blocked,
        allowed,
        blockRate: total > 0 ? ((blocked / total) * 100).toFixed(2) + '%' : '0%',
        recentActivity,
      },
      attacks: {
        total: blocked,
        byType: attacksByType,
        bySeverity: attacksBySeverity,
      },
      topTargets: includeTopTargets ? {
        paths: topPaths || [],
        ips: topIPs || [],
        countries: topCountries || [],
      } : undefined,
      period,
      timestamp: new Date().toISOString(),
    };
  }

  /**
   * Get KV-specific metrics (behavior tracking stats)
   */
  async getKVMetrics(): Promise<{ trackedIPs: number; estimatedSize: string }> {
    if (!this.kv) {
      return { trackedIPs: 0, estimatedSize: '0' };
    }
    
    // KV doesn't support counting, estimate from list
    try {
      const list = await this.kv.list({ limit: 1000 });
      return {
        trackedIPs: list.keys.length,
        estimatedSize: list.list_complete ? 'exact' : 'partial (1000+)',
      };
    } catch {
      return { trackedIPs: 0, estimatedSize: 'error' };
    }
  }

  // Private query methods
  
  private async queryTotal(startTime: number): Promise<number> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as total 
      FROM security_events 
      WHERE timestamp >= ?
    `).bind(startTime).first<{ total: number }>();
    
    return result?.total || 0;
  }
  
  private async queryBlocked(startTime: number): Promise<number> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as blocked 
      FROM security_events 
      WHERE timestamp >= ? AND blocked = 1
    `).bind(startTime).first<{ blocked: number }>();
    
    return result?.blocked || 0;
  }
  
  private async queryAttacksByType(startTime: number): Promise<Record<string, number>> {
    const result = await this.db.prepare(`
      SELECT attack_type, COUNT(*) as count 
      FROM security_events 
      WHERE timestamp >= ?
      GROUP BY attack_type
      ORDER BY count DESC
    `).bind(startTime).all<{ attack_type: string; count: number }>();
    
    const map: Record<string, number> = {};
    result.results.forEach(row => {
      map[row.attack_type] = row.count;
    });
    
    return map;
  }
  
  private async queryAttacksBySeverity(startTime: number): Promise<Record<string, number>> {
    const result = await this.db.prepare(`
      SELECT severity, COUNT(*) as count 
      FROM security_events 
      WHERE timestamp >= ?
      GROUP BY severity
      ORDER BY count DESC
    `).bind(startTime).all<{ severity: string; count: number }>();
    
    const map: Record<string, number> = {};
    result.results.forEach(row => {
      map[row.severity] = row.count;
    });
    
    return map;
  }
  
  private async queryRecentActivity(startTime: number): Promise<number> {
    const result = await this.db.prepare(`
      SELECT COUNT(*) as recent 
      FROM security_events 
      WHERE timestamp >= ?
    `).bind(startTime).first<{ recent: number }>();
    
    return result?.recent || 0;
  }
  
  private async queryTopPaths(
    startTime: number, 
    limit: number
  ): Promise<Array<{ path: string; attacks: number }>> {
    const result = await this.db.prepare(`
      SELECT path, COUNT(*) as count 
      FROM security_events 
      WHERE timestamp >= ?
      GROUP BY path 
      ORDER BY count DESC 
      LIMIT ?
    `).bind(startTime, limit).all<{ path: string; count: number }>();
    
    return result.results.map(r => ({ path: r.path, attacks: r.count }));
  }
  
  private async queryTopIPs(
    startTime: number, 
    limit: number
  ): Promise<Array<{ ip: string; attacks: number }>> {
    const result = await this.db.prepare(`
      SELECT ip_address, COUNT(*) as count 
      FROM security_events 
      WHERE timestamp >= ?
      GROUP BY ip_address 
      ORDER BY count DESC 
      LIMIT ?
    `).bind(startTime, limit).all<{ ip_address: string; count: number }>();
    
    return result.results.map(r => ({ ip: r.ip_address, attacks: r.count }));
  }
  
  private async queryTopCountries(
    startTime: number, 
    limit: number
  ): Promise<Array<{ country: string; attacks: number }>> {
    const result = await this.db.prepare(`
      SELECT country, COUNT(*) as count 
      FROM security_events 
      WHERE timestamp >= ? AND country IS NOT NULL
      GROUP BY country 
      ORDER BY count DESC 
      LIMIT ?
    `).bind(startTime, limit).all<{ country: string; count: number }>();
    
    return result.results.map(r => ({ country: r.country, attacks: r.count }));
  }
  
  private getPeriodMs(period: string): number {
    switch (period) {
      case '1h': return 60 * 60 * 1000;
      case '24h': return 24 * 60 * 60 * 1000;
      case '7d': return 7 * 24 * 60 * 60 * 1000;
      case '30d': return 30 * 24 * 60 * 60 * 1000;
      default: return 24 * 60 * 60 * 1000;
    }
  }
}

/**
 * Helper function - create metrics instance quickly
 */
export function createMetricsCollector(
  db: D1Database,
  kv?: KVNamespace,
  analytics?: AnalyticsEngineDataset
): SentinelMetricsCollector {
  return new SentinelMetricsCollector(db, kv, analytics);
}

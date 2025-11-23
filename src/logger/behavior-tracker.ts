/**
 * Behavior tracker - Detects logic-based attacks through failure patterns
 */

import type { AttackType, SecuritySeverity } from '../types';

/**
 * Failure state tracked in KV
 */
export interface FailureState {
  /** Total failure count */
  count: number;
  /** Timestamps of recent failures */
  timestamps: number[];
  /** Status codes seen */
  statuses: Record<number, number>;
  /** First seen timestamp */
  firstSeen: number;
  /** Paths attempted */
  paths: string[];
}

/**
 * Behavior detection result
 */
export interface BehaviorDetection {
  detected: boolean;
  attackType?: AttackType;
  severity?: SecuritySeverity;
  confidence: number;
  sequentialFailures: number;
  metadata?: Record<string, any>;
}

/**
 * Behavior tracker for detecting logic-based attacks
 */
export class BehaviorTracker {
  private kv: KVNamespace;
  private config: {
    failureThreshold: number;      // Number of failures to trigger
    timeWindowSeconds: number;     // Time window for failures
    maxTrackedPaths: number;       // Max paths to track per IP
  };

  constructor(kv: KVNamespace, config?: Partial<typeof BehaviorTracker.prototype.config>) {
    this.kv = kv;
    this.config = {
      failureThreshold: config?.failureThreshold || 5,
      timeWindowSeconds: config?.timeWindowSeconds || 60,
      maxTrackedPaths: config?.maxTrackedPaths || 20,
    };
  }

  /**
   * Track a request outcome and detect patterns
   */
  async trackAndDetect(
    ip: string,
    endpoint: string,
    statusCode: number,
    context?: any
  ): Promise<BehaviorDetection> {
    
    // Only track errors
    if (statusCode < 400) {
      return { detected: false, confidence: 0, sequentialFailures: 0 };
    }

    const normalizedEndpoint = this.normalizeEndpoint(endpoint);
    const endpointKey = `behavior:${ip}:${normalizedEndpoint}`;
    const globalKey = `behavior:${ip}:__global__`;

    // Get current states (both endpoint-specific and global)
    const endpointState = await this.getState(endpointKey);
    const globalState = await this.getState(globalKey);

    // Update states
    const now = Date.now();
    const windowStart = now - (this.config.timeWindowSeconds * 1000);
    
    // Update endpoint-specific state
    endpointState.count++;
    endpointState.timestamps.push(now);
    endpointState.statuses[statusCode] = (endpointState.statuses[statusCode] || 0) + 1;
    if (endpointState.paths.length < this.config.maxTrackedPaths) {
      endpointState.paths.push(endpoint);
    }
    endpointState.timestamps = endpointState.timestamps.filter(t => t > windowStart);
    endpointState.count = endpointState.timestamps.length;

    // Update global state (tracks across all endpoints)
    globalState.count++;
    globalState.timestamps.push(now);
    globalState.statuses[statusCode] = (globalState.statuses[statusCode] || 0) + 1;
    if (globalState.paths.length < this.config.maxTrackedPaths) {
      globalState.paths.push(endpoint);
    }
    globalState.timestamps = globalState.timestamps.filter(t => t > windowStart);
    globalState.count = globalState.timestamps.length;

    // Detect attack pattern (check both endpoint and global state)
    const endpointDetection = this.detectPattern(endpointState, endpoint, statusCode);
    const globalDetection = this.detectPattern(globalState, endpoint, statusCode);

    // Use global detection for cross-endpoint attacks, endpoint detection for focused attacks
    const detection = globalDetection.detected ? globalDetection : endpointDetection;

    // Save both states
    await this.setState(endpointKey, endpointState);
    await this.setState(globalKey, globalState);

    return detection;
  }

  /**
   * Get failure state from KV
   */
  private async getState(key: string): Promise<FailureState> {
    const stored = await this.kv.get<FailureState>(key, 'json');
    return stored || {
      count: 0,
      timestamps: [],
      statuses: {},
      firstSeen: Date.now(),
      paths: [],
    };
  }

  /**
   * Save failure state to KV
   */
  private async setState(key: string, state: FailureState): Promise<void> {
    await this.kv.put(key, JSON.stringify(state), {
      expirationTtl: this.config.timeWindowSeconds * 2, // Auto cleanup
    });
  }

  /**
   * Detect attack pattern from failure state
   */
  private detectPattern(
    state: FailureState,
    currentPath: string,
    statusCode: number
  ): BehaviorDetection {
    
    const recentFailures = state.count;

    // Not enough failures yet
    if (recentFailures < this.config.failureThreshold) {
      return { 
        detected: false, 
        confidence: 0, 
        sequentialFailures: recentFailures 
      };
    }

    // Pattern 1: Resource Enumeration (many 404s)
    if (state.statuses[404] >= this.config.failureThreshold) {
      const isSequential = this.isSequentialIds(state.paths);
      return {
        detected: true,
        attackType: 'resource_enumeration' as AttackType,
        severity: 'medium' as SecuritySeverity,
        confidence: isSequential ? 0.9 : 0.7,
        sequentialFailures: recentFailures,
        metadata: {
          pattern: isSequential ? 'sequential_ids' : 'random_probing',
          unique_paths: new Set(state.paths).size,
        },
      };
    }

    // Pattern 2: Unauthorized Access (many 403s)
    if (state.statuses[403] >= this.config.failureThreshold) {
      return {
        detected: true,
        attackType: 'unauthorized_access_attempt' as AttackType,
        severity: 'high' as SecuritySeverity,
        confidence: 0.85,
        sequentialFailures: recentFailures,
        metadata: {
          pattern: 'permission_probing',
          unique_paths: new Set(state.paths).size,
        },
      };
    }

    // Pattern 3: Endpoint Probing (mixed errors, sensitive paths)
    const hasSensitivePaths = this.hasSensitivePathProbing(state.paths);
    if (hasSensitivePaths && recentFailures >= this.config.failureThreshold) {
      return {
        detected: true,
        attackType: 'endpoint_probing' as AttackType,
        severity: 'high' as SecuritySeverity,
        confidence: 0.8,
        sequentialFailures: recentFailures,
        metadata: {
          pattern: 'sensitive_path_scanning',
          paths_attempted: state.paths.slice(0, 10),
        },
      };
    }

    // Pattern 4: Generic Sequential Failures
    if (recentFailures >= this.config.failureThreshold * 2) {
      return {
        detected: true,
        attackType: 'sequential_failure' as AttackType,
        severity: 'low' as SecuritySeverity,
        confidence: 0.6,
        sequentialFailures: recentFailures,
        metadata: {
          status_distribution: state.statuses,
        },
      };
    }

    return { 
      detected: false, 
      confidence: 0, 
      sequentialFailures: recentFailures 
    };
  }

  /**
   * Normalize endpoint to group similar paths
   */
  private normalizeEndpoint(path: string): string {
    try {
      const url = new URL(path, 'http://dummy');
      return url.pathname
        // UUID format: 8-4-4-4-12
        .replace(/\/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '/{uuid}')
        // Numeric IDs
        .replace(/\/\d+/g, '/{id}')
        // Long hashes (24+ hex chars)
        .replace(/\/[a-f0-9]{24,}/gi, '/{hash}');
    } catch {
      return path;
    }
  }

  /**
   * Check if paths show sequential ID enumeration
   */
  private isSequentialIds(paths: string[]): boolean {
    const ids: number[] = [];
    
    for (const path of paths) {
      const matches = path.match(/\/(\d+)(?:\/|$)/);
      if (matches) {
        ids.push(parseInt(matches[1]));
      }
    }

    if (ids.length < 3) return false;

    // Check if IDs are sequential or close together
    ids.sort((a, b) => a - b);
    let sequential = 0;
    for (let i = 1; i < ids.length; i++) {
      if (ids[i] - ids[i-1] <= 5) {
        sequential++;
      }
    }

    return sequential >= ids.length * 0.5;
  }

  /**
   * Check if probing sensitive paths
   */
  private hasSensitivePathProbing(paths: string[]): boolean {
    const sensitivePaths = [
      /\/admin/i,
      /\/api\/admin/i,
      /\/api\/internal/i,
      /\/api\/private/i,
      /\/backup/i,
      /\/config/i,
      /\/secret/i,
      /\/\.env/i,
      /\/\.git/i,
      /\/phpmyadmin/i,
      /\/wp-admin/i,
    ];

    let sensitiveCount = 0;
    for (const path of paths) {
      if (sensitivePaths.some(pattern => pattern.test(path))) {
        sensitiveCount++;
      }
    }

    return sensitiveCount >= 2;
  }

  /**
   * Get statistics for an IP
   */
  async getIpStatistics(ip: string): Promise<{
    totalFailures: number;
    endpoints: Record<string, number>;
  }> {
    const prefix = `behavior:${ip}:`;
    const keys = await this.kv.list({ prefix });
    
    let totalFailures = 0;
    const endpoints: Record<string, number> = {};

    for (const key of keys.keys) {
      const state = await this.kv.get<FailureState>(key.name, 'json');
      if (state) {
        totalFailures += state.count;
        const endpoint = key.name.replace(prefix, '');
        endpoints[endpoint] = state.count;
      }
    }

    return { totalFailures, endpoints };
  }

  /**
   * Clear tracking for an IP
   */
  async clearIp(ip: string): Promise<void> {
    const prefix = `behavior:${ip}:`;
    const keys = await this.kv.list({ prefix });
    
    for (const key of keys.keys) {
      await this.kv.delete(key.name);
    }
  }
}

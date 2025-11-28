/**
 * Configuration types for Sentinel Proxy
 */

import type { IDetector } from 'cloudflare-sentinel';

// ══════════════════════════════════════════════════════════════════════════════
// MAIN CONFIG TYPE
// ══════════════════════════════════════════════════════════════════════════════

export interface SentinelConfig {
  /** Whitelist - skip security for trusted sources */
  whitelist?: {
    ips?: string[];
    ipRanges?: string[];
    paths?: string[];
  };
  
  /** Route-specific settings with detectors */
  routes?: Record<string, RouteConfig>;
  
  /** Response detectors for data leak detection */
  responseDetectors?: IDetector[];
  
  /** Enable response detection */
  enableResponseDetection?: boolean;
  
  /** Notification settings */
  notifications?: NotificationConfig;
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTE CONFIG
// ══════════════════════════════════════════════════════════════════════════════

export interface RouteConfig {
  /** Skip all security checks for this route */
  skip?: boolean;
  
  /** Detectors to run for this route */
  detectors?: IDetector[];
  
  /** Block threshold (0-100). Lower = stricter */
  blockThreshold?: number;
  
  /** Rate limit for this route */
  rateLimit?: {
    requests: number;
    period: number;
  };
}

// ══════════════════════════════════════════════════════════════════════════════
// NOTIFICATION CONFIG
// ══════════════════════════════════════════════════════════════════════════════

export interface NotificationConfig {
  slack?: boolean;
  blockedOnly?: boolean;
  minSeverity?: 'low' | 'medium' | 'high' | 'critical';
}

// ══════════════════════════════════════════════════════════════════════════════
// ENVIRONMENT BINDINGS
// ══════════════════════════════════════════════════════════════════════════════

export interface Env {
  // KV bindings
  BLOCKLIST_KV: KVNamespace;
  RATE_LIMIT_KV: KVNamespace;
  REPUTATION_KV: KVNamespace;
  ESCALATION_KV: KVNamespace;  // Track repeat offenders
  
  // Optional bindings
  ANALYTICS?: AnalyticsEngineDataset;
  
  // Config (from wrangler.toml)
  ORIGIN_URL: string;
  DEBUG?: string;
  ORIGIN_TIMEOUT?: string;
  SLACK_WEBHOOK?: string;
}

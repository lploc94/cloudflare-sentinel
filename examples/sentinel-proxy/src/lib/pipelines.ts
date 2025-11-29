/**
 * Pipeline Builder
 * 
 * Multi-level threat response with cascading actions:
 * - normal:     score < suspicious  → increment rate limit
 * - suspicious: score < likely      → inherit normal + log + escalate
 * - likely:     score >= likely     → inherit suspicious + block
 */

import {
  SentinelPipeline,
  MaxScoreAggregator,
  MultiLevelResolver,
  DefaultResolver,
  LogHandler,
  NotifyHandler,
  BlocklistHandler,
  ReputationHandler,
  ActionType,
} from 'cloudflare-sentinel';

import type { Env } from './types';
import type { ProxyConfig } from '../sentinel.config';

// ══════════════════════════════════════════════════════════════════════════════
// TYPES
// ══════════════════════════════════════════════════════════════════════════════

interface ThresholdLevel {
  maxScore: number;
  actions: string[];
}

interface RouteConfig {
  detectors?: any[];
  thresholds?: ThresholdLevel[];
  skip?: boolean;
}

// ══════════════════════════════════════════════════════════════════════════════
// BUILD PIPELINE
// ══════════════════════════════════════════════════════════════════════════════

export function buildPipeline(
  config: ProxyConfig,
  routeConfig: RouteConfig | undefined,
  env: Env
) {
  // Use route config or global
  const detectors = routeConfig?.detectors ?? config.global.detectors;
  const thresholds = routeConfig?.thresholds ?? config.global.thresholds;
  
  // Build cascading actions - each level inherits from previous
  const levels = thresholds.map((level, index) => {
    // Collect all actions from previous levels + current
    const inheritedActions = thresholds
      .slice(0, index)
      .flatMap(l => l.actions);
    
    return {
      maxScore: level.maxScore,
      actions: [...new Set([...inheritedActions, ...level.actions])],
    };
  });
  
  // Build pipeline with configurable levels
  let pipeline = SentinelPipeline.sync(detectors)
    .score(new MaxScoreAggregator())
    .resolve(new MultiLevelResolver({ levels }))
    // Handlers for each action type
    .on(ActionType.LOG, new LogHandler({
      console: env.DEBUG === 'true',
    }))
    .on(ActionType.UPDATE_REPUTATION, new ReputationHandler({
      kv: env.REPUTATION_KV,
    }))
    .on(ActionType.BLOCK, new BlocklistHandler({
      kv: env.BLOCKLIST_KV,
      defaultDuration: 3600,  // 1 hour
    }));
  
  // Add Slack notification
  if (env.SLACK_WEBHOOK) {
    pipeline = pipeline.on(ActionType.NOTIFY, new NotifyHandler({
      webhookUrl: env.SLACK_WEBHOOK,
    }));
  }
  
  return pipeline;
}

// ══════════════════════════════════════════════════════════════════════════════
// BUILD RESPONSE PIPELINE
// ══════════════════════════════════════════════════════════════════════════════

export function buildResponsePipeline(config: ProxyConfig, env: Env) {
  if (!config.response.enabled || !config.response.detectors.length) {
    return null;
  }
  
  return SentinelPipeline.sync(config.response.detectors)
    .score(new MaxScoreAggregator())
    .resolve(new DefaultResolver({ blockThreshold: 80 }))
    .on('log', new LogHandler({ console: env.DEBUG === 'true' }));
}

// ══════════════════════════════════════════════════════════════════════════════
// ROUTE MATCHER
// ══════════════════════════════════════════════════════════════════════════════

/**
 * Match URL path to route config using glob patterns
 */
export function matchRoute<T>(
  pathname: string, 
  routes: Record<string, T>
): { pattern: string; config: T } | null {
  // Sort by specificity (longer patterns first)
  const patterns = Object.keys(routes).sort((a, b) => b.length - a.length);
  
  for (const pattern of patterns) {
    if (matchPattern(pathname, pattern)) {
      return { pattern, config: routes[pattern] };
    }
  }
  
  return null;
}

/**
 * Simple glob pattern matching
 */
function matchPattern(path: string, pattern: string): boolean {
  if (pattern === path) return true;
  
  const regex = new RegExp(
    '^' + pattern
      .replace(/\*\*/g, '{{GLOBSTAR}}')
      .replace(/\*/g, '[^/]*')
      .replace(/\?/g, '[^/]')
      .replace(/{{GLOBSTAR}}/g, '.*') + '$'
  );
  
  return regex.test(path);
}

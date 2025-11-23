/**
 * Check if notification thresholds are met
 */

import type { AttackSummary } from 'cloudflare-sentinel';

export interface ThresholdConfig {
  minAttacks?: number;
  minBlocked?: number;
  minCritical?: number;
  severities?: string[];
}

/**
 * Check if summary meets notification thresholds
 */
export function shouldNotify(
  summary: AttackSummary,
  config: ThresholdConfig
): boolean {
  // Check minimum attacks
  if (config.minAttacks !== undefined && summary.totals.attacks < config.minAttacks) {
    return false;
  }

  // Check minimum blocked
  if (config.minBlocked !== undefined && summary.totals.blocked < config.minBlocked) {
    return false;
  }

  // Check minimum critical
  if (config.minCritical !== undefined && summary.bySeverity.critical < config.minCritical) {
    return false;
  }

  // Check severities
  if (config.severities && config.severities.length > 0) {
    const hasRelevantSeverity = config.severities.some(sev => {
      const key = sev as keyof typeof summary.bySeverity;
      return summary.bySeverity[key] > 0;
    });
    
    if (!hasRelevantSeverity) {
      return false;
    }
  }

  return true;
}

/**
 * Check if metrics meet notification thresholds
 */
export function shouldNotifyMetrics(
  metrics: any,
  config: { minRequests?: number }
): boolean {
  if (config.minRequests !== undefined && metrics.requests.total < config.minRequests) {
    return false;
  }

  return true;
}

/**
 * Parallel rate limit checker
 * Optimizes rate limit checks by running independent checks in parallel
 */

import type { Identifier, AttackType } from '../types';

export interface ParallelCheckResult {
  success: boolean;
  failedRules: string[];
  violations: number;
}

/**
 * Check multiple rate limits in parallel
 * Used when rules are independent (different attack types or endpoints)
 */
export async function checkRateLimitsParallel(
  rateLimiter: any,
  checks: Array<{
    key: string;
    limit: number;
    period: number;
    ruleId: string;
  }>
): Promise<ParallelCheckResult> {
  if (!rateLimiter || checks.length === 0) {
    return { success: true, failedRules: [], violations: 0 };
  }

  try {
    // Run all checks in parallel
    const results = await Promise.allSettled(
      checks.map(async (check) => {
        const result = await rateLimiter.limit({
          key: check.key,
          limit: check.limit,
          period: check.period,
        });
        return {
          ruleId: check.ruleId,
          success: result.success,
        };
      })
    );

    // Collect failed rules
    const failedRules: string[] = [];
    let violations = 0;

    for (const result of results) {
      if (result.status === 'fulfilled') {
        if (!result.value.success) {
          failedRules.push(result.value.ruleId);
          violations++;
        }
      } else {
        // Handle rejected promises (errors)
        console.error('[Sentinel] Parallel check error:', result.reason);
      }
    }

    return {
      success: failedRules.length === 0,
      failedRules,
      violations,
    };
  } catch (error) {
    console.error('[Sentinel] Parallel check failed:', error);
    return { success: true, failedRules: [], violations: 0 }; // Fail-open
  }
}

/**
 * Check if rules can be checked in parallel
 * Rules can be parallel if they target different rate limit keys
 */
export function canCheckInParallel(
  rules: Array<{ endpoint?: string; attackType: string }>
): boolean {
  // If all rules have the same endpoint and attack type, they must be sequential
  // Otherwise, they can be checked in parallel
  
  if (rules.length <= 1) return false;

  const uniqueKeys = new Set(
    rules.map(r => `${r.endpoint || 'global'}:${r.attackType}`)
  );

  // Can parallelize if targeting different keys
  return uniqueKeys.size > 1;
}

/**
 * Group rules by dependencies
 * Returns groups that can be checked in parallel
 */
export function groupRulesForParallel<T extends { endpoint?: string; attackType: string }>(
  rules: T[]
): T[][] {
  if (rules.length === 0) return [];
  if (rules.length === 1) return [rules];

  // Group by endpoint + attack type (same key = sequential, different = parallel)
  const groups = new Map<string, T[]>();

  for (const rule of rules) {
    const key = `${rule.endpoint || 'global'}:${rule.attackType}`;
    if (!groups.has(key)) {
      groups.set(key, []);
    }
    groups.get(key)!.push(rule);
  }

  // Convert to array of groups
  return Array.from(groups.values());
}

/**
 * Optimize rate limit checking strategy
 * Determines if should use parallel or sequential checking
 */
export function shouldUseParallel(ruleCount: number): boolean {
  // Use parallel for 3+ rules to benefit from concurrency
  // Sequential is fine for 1-2 rules (overhead not worth it)
  return ruleCount >= 3;
}

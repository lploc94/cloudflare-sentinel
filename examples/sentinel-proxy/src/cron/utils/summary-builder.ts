/**
 * Build attack summaries from D1 data
 */

import type { AttackSummary } from 'cloudflare-sentinel';

/**
 * Build attack summary for a given period
 */
export async function buildAttackSummary(
  db: D1Database,
  period: string
): Promise<AttackSummary> {
  const { start, end, duration } = parsePeriod(period);
  
  // Query security_events from D1
  const events = await db.prepare(`
    SELECT 
      attack_type,
      severity,
      blocked,
      ip_address,
      country,
      path,
      timestamp
    FROM security_events
    WHERE timestamp >= ? AND timestamp <= ?
    ORDER BY timestamp DESC
  `).bind(start, end).all();

  const rows = events.results || [];

  // Calculate totals
  const totals = {
    attacks: rows.length,
    blocked: rows.filter((r: any) => r.blocked === 1).length,
    allowed: rows.filter((r: any) => r.blocked === 0).length,
    uniqueIPs: new Set(rows.map((r: any) => r.ip_address)).size,
    affectedEndpoints: new Set(rows.map((r: any) => r.path)).size,
  };

  // Attacks by type
  const byType: Record<string, any> = {};
  for (const row of rows as any[]) {
    if (!byType[row.attack_type]) {
      byType[row.attack_type] = {
        count: 0,
        blocked: 0,
        severity: row.severity,
      };
    }
    byType[row.attack_type].count++;
    if (row.blocked === 1) {
      byType[row.attack_type].blocked++;
    }
  }

  // Top attackers
  const attackerMap = new Map<string, any>();
  for (const row of rows as any[]) {
    const ip = row.ip_address;
    if (!attackerMap.has(ip)) {
      attackerMap.set(ip, {
        ip,
        country: row.country,
        attacks: 0,
        blocked: 0,
        types: new Set(),
      });
    }
    const attacker = attackerMap.get(ip)!;
    attacker.attacks++;
    if (row.blocked === 1) attacker.blocked++;
    attacker.types.add(row.attack_type);
  }
  
  const topAttackers = Array.from(attackerMap.values())
    .map(a => ({ ...a, types: Array.from(a.types) }))
    .sort((a, b) => b.attacks - a.attacks)
    .slice(0, 10);

  // Top targets
  const targetMap = new Map<string, any>();
  for (const row of rows as any[]) {
    const endpoint = row.path;
    if (!targetMap.has(endpoint)) {
      targetMap.set(endpoint, {
        endpoint,
        attacks: 0,
        blocked: 0,
        types: new Set(),
      });
    }
    const target = targetMap.get(endpoint)!;
    target.attacks++;
    if (row.blocked === 1) target.blocked++;
    target.types.add(row.attack_type);
  }

  const topTargets = Array.from(targetMap.values())
    .map(t => ({ ...t, types: Array.from(t.types) }))
    .sort((a, b) => b.attacks - a.attacks)
    .slice(0, 10);

  // Severity breakdown
  const bySeverity = {
    critical: rows.filter((r: any) => r.severity === 'critical').length,
    high: rows.filter((r: any) => r.severity === 'high').length,
    medium: rows.filter((r: any) => r.severity === 'medium').length,
    low: rows.filter((r: any) => r.severity === 'low').length,
  };

  return {
    period: {
      start: new Date(start).toISOString(),
      end: new Date(end).toISOString(),
      duration,
    },
    totals,
    byType,
    topAttackers,
    topTargets,
    bySeverity,
  };
}

/**
 * Parse period string to timestamps
 */
function parsePeriod(period: string): {
  start: number;
  end: number;
  duration: string;
} {
  const now = Date.now();
  const match = period.match(/^(\d+)(m|h|d)$/);
  
  if (!match) {
    throw new Error(`Invalid period format: ${period}`);
  }

  const value = parseInt(match[1]);
  const unit = match[2];

  let milliseconds = 0;
  switch (unit) {
    case 'm':
      milliseconds = value * 60 * 1000;
      break;
    case 'h':
      milliseconds = value * 60 * 60 * 1000;
      break;
    case 'd':
      milliseconds = value * 24 * 60 * 60 * 1000;
      break;
  }

  return {
    start: now - milliseconds,
    end: now,
    duration: period,
  };
}

/**
 * Get attack count for a period
 */
export async function getAttackCount(
  db: D1Database,
  period: string
): Promise<number> {
  const { start, end } = parsePeriod(period);
  
  const result = await db.prepare(`
    SELECT COUNT(*) as count
    FROM security_events
    WHERE timestamp >= ? AND timestamp <= ?
  `).bind(start, end).first();

  return (result as any)?.count || 0;
}

/**
 * Get average attack count for baseline
 */
export async function getAverageAttackCount(
  db: D1Database,
  period: string
): Promise<number> {
  const { start, end, duration } = parsePeriod(period);
  const periodMs = end - start;
  
  // Get count for the baseline period
  const result = await db.prepare(`
    SELECT COUNT(*) as count
    FROM security_events
    WHERE timestamp >= ? AND timestamp <= ?
  `).bind(start, end).first();

  const count = (result as any)?.count || 0;
  
  // Calculate average per check period (assume 15min checks)
  const checkPeriodMs = 15 * 60 * 1000;
  const numPeriods = periodMs / checkPeriodMs;
  
  return count / numPeriods;
}

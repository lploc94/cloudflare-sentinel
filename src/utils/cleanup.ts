/**
 * Cleanup utilities for Sentinel logs and data
 * Helps optimize storage costs and maintain performance
 */

export interface CleanupConfig {
  /** Retention period in days */
  retentionDays: number;
  /** Batch size for deletion operations */
  batchSize: number;
  /** Archive to R2 before deleting */
  archiveBeforeDelete: boolean;
  /** R2 bucket for archiving (required if archiveBeforeDelete=true) */
  r2Bucket?: R2Bucket;
  /** Retention by severity (overrides retentionDays) */
  retentionBySeverity?: {
    critical?: number;
    high?: number;
    medium?: number;
    low?: number;
  };
}

export interface CleanupResult {
  success: boolean;
  deleted: number;
  archived?: number;
  errors?: string[];
  duration: number;
}

/**
 * Clean up old D1 security events
 * Optionally archives to R2 before deleting
 */
export async function cleanupD1Logs(
  db: D1Database,
  config: CleanupConfig
): Promise<CleanupResult> {
  const startTime = Date.now();
  const errors: string[] = [];
  let totalDeleted = 0;
  let totalArchived = 0;

  try {
    // Step 1: Archive to R2 if enabled
    if (config.archiveBeforeDelete) {
      if (!config.r2Bucket) {
        throw new Error('archiveBeforeDelete=true requires r2Bucket in config');
      }

      // Import archive utilities
      const { archiveLogsToR2, ARCHIVE_CONFIGS } = await import('./archive');
      
      // Calculate cutoff timestamp (use the longest retention if severity-based)
      let cutoffTimestamp: number;
      if (config.retentionBySeverity) {
        const maxRetention = Math.max(...Object.values(config.retentionBySeverity));
        cutoffTimestamp = Date.now() - (maxRetention * 24 * 60 * 60 * 1000);
      } else {
        cutoffTimestamp = Date.now() - (config.retentionDays * 24 * 60 * 60 * 1000);
      }

      // Archive logs
      const archiveResult = await archiveLogsToR2(
        db,
        config.r2Bucket,
        cutoffTimestamp,
        ARCHIVE_CONFIGS.BALANCED
      );

      if (!archiveResult.success) {
        errors.push(...(archiveResult.errors || ['Archive failed']));
        // Don't proceed with deletion if archive failed
        return {
          success: false,
          deleted: 0,
          archived: archiveResult.archived,
          errors,
          duration: Date.now() - startTime,
        };
      }

      totalArchived = archiveResult.archived;
    }

    // Step 2: Delete old logs
    if (config.retentionBySeverity) {
      // Use severity-based retention
      for (const [severity, days] of Object.entries(config.retentionBySeverity)) {
        const result = await cleanupBySeverity(db, severity, days, config.batchSize);
        totalDeleted += result.deleted;
        if (result.errors) {
          errors.push(...result.errors);
        }
      }
    } else {
      // Single retention period for all
      const cutoffTimestamp = Date.now() - (config.retentionDays * 24 * 60 * 60 * 1000);
      const result = await deleteOldLogs(db, cutoffTimestamp, config.batchSize);
      totalDeleted = result.deleted;
      if (result.errors) {
        errors.push(...result.errors);
      }
    }

    return {
      success: errors.length === 0,
      deleted: totalDeleted,
      archived: totalArchived > 0 ? totalArchived : undefined,
      errors: errors.length > 0 ? errors : undefined,
      duration: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      success: false,
      deleted: totalDeleted,
      archived: totalArchived > 0 ? totalArchived : undefined,
      errors: [error.message],
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Delete logs by severity level
 */
async function cleanupBySeverity(
  db: D1Database,
  severity: string,
  retentionDays: number,
  batchSize: number
): Promise<{ deleted: number; errors?: string[] }> {
  const cutoffTimestamp = Date.now() - (retentionDays * 24 * 60 * 60 * 1000);
  const errors: string[] = [];

  try {
    // Count logs to delete
    const countResult = await db.prepare(`
      SELECT COUNT(*) as total
      FROM security_events
      WHERE severity = ?
        AND timestamp < ?
    `).bind(severity, cutoffTimestamp).first();

    const total = (countResult?.total as number) || 0;
    if (total === 0) {
      return { deleted: 0 };
    }

    // Delete in batches
    let deleted = 0;
    while (deleted < total) {
      const result = await db.prepare(`
        DELETE FROM security_events
        WHERE rowid IN (
          SELECT rowid FROM security_events
          WHERE severity = ?
            AND timestamp < ?
          LIMIT ?
        )
      `).bind(severity, cutoffTimestamp, batchSize).run();

      const changes = result.meta?.changes || 0;
      deleted += changes;

      // Prevent timeout - small delay between batches
      if (deleted < total) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }

    return { deleted };
  } catch (error: any) {
    errors.push(`Severity ${severity}: ${error.message}`);
    return { deleted: 0, errors };
  }
}

/**
 * Delete old logs with single cutoff timestamp
 */
async function deleteOldLogs(
  db: D1Database,
  cutoffTimestamp: number,
  batchSize: number
): Promise<{ deleted: number; errors?: string[] }> {
  const errors: string[] = [];

  try {
    // Count logs to delete
    const countResult = await db.prepare(`
      SELECT COUNT(*) as total
      FROM security_events
      WHERE timestamp < ?
    `).bind(cutoffTimestamp).first();

    const total = (countResult?.total as number) || 0;
    if (total === 0) {
      return { deleted: 0 };
    }

    // Delete in batches
    let deleted = 0;
    while (deleted < total) {
      const result = await db.prepare(`
        DELETE FROM security_events
        WHERE rowid IN (
          SELECT rowid FROM security_events
          WHERE timestamp < ?
          LIMIT ?
        )
      `).bind(cutoffTimestamp, batchSize).run();

      const changes = result.meta?.changes || 0;
      deleted += changes;

      // Prevent timeout
      if (deleted < total) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
    }

    return { deleted };
  } catch (error: any) {
    errors.push(error.message);
    return { deleted: 0, errors };
  }
}

/**
 * Clean up stale KV behavior tracking keys
 */
export async function cleanupKVStaleKeys(
  kv: KVNamespace,
  maxAgeMs: number = 3600000 // 1 hour default
): Promise<CleanupResult> {
  const startTime = Date.now();
  let deleted = 0;
  const errors: string[] = [];

  try {
    // List all behavior tracking keys
    const behaviorKeys = await kv.list({ prefix: 'behavior:' });
    
    for (const key of behaviorKeys.keys) {
      try {
        const data = await kv.get(key.name, 'json');
        
        if (!data) {
          // Orphaned key - delete
          await kv.delete(key.name);
          deleted++;
          continue;
        }

        // Check if data is stale
        const state = data as any;
        if (state.timestamps && Array.isArray(state.timestamps)) {
          const lastActivity = Math.max(...state.timestamps);
          const age = Date.now() - lastActivity;

          if (age > maxAgeMs) {
            await kv.delete(key.name);
            deleted++;
          }
        }
      } catch (error: any) {
        errors.push(`Key ${key.name}: ${error.message}`);
      }
    }

    // Also clean log rate limit keys (old ones)
    const logKeys = await kv.list({ prefix: 'log:ratelimit:' });
    
    for (const key of logKeys.keys) {
      try {
        // Log keys have TTL, but check for orphaned ones
        const value = await kv.get(key.name);
        if (!value) {
          await kv.delete(key.name);
          deleted++;
        }
      } catch (error: any) {
        errors.push(`Log key ${key.name}: ${error.message}`);
      }
    }

    return {
      success: errors.length === 0,
      deleted,
      errors: errors.length > 0 ? errors : undefined,
      duration: Date.now() - startTime,
    };
  } catch (error: any) {
    return {
      success: false,
      deleted,
      errors: [error.message],
      duration: Date.now() - startTime,
    };
  }
}

/**
 * Get storage statistics
 */
export async function getStorageStats(
  db: D1Database,
  kv?: KVNamespace
): Promise<{
  d1: {
    totalEvents: number;
    eventsBySeverity: Record<string, number>;
    oldestEvent: number;
    newestEvent: number;
  };
  kv?: {
    behaviorKeys: number;
    logKeys: number;
  };
}> {
  // D1 stats
  const totalResult = await db.prepare(`
    SELECT COUNT(*) as total FROM security_events
  `).first();

  const severityResult = await db.prepare(`
    SELECT severity, COUNT(*) as count
    FROM security_events
    GROUP BY severity
  `).all();

  const rangeResult = await db.prepare(`
    SELECT MIN(timestamp) as oldest, MAX(timestamp) as newest
    FROM security_events
  `).first();

  const eventsBySeverity: Record<string, number> = {};
  for (const row of severityResult.results || []) {
    eventsBySeverity[(row as any).severity] = (row as any).count;
  }

  const stats: any = {
    d1: {
      totalEvents: (totalResult?.total as number) || 0,
      eventsBySeverity,
      oldestEvent: (rangeResult?.oldest as number) || 0,
      newestEvent: (rangeResult?.newest as number) || 0,
    },
  };

  // KV stats (if provided)
  if (kv) {
    const behaviorKeys = await kv.list({ prefix: 'behavior:' });
    const logKeys = await kv.list({ prefix: 'log:ratelimit:' });

    stats.kv = {
      behaviorKeys: behaviorKeys.keys.length,
      logKeys: logKeys.keys.length,
    };
  }

  return stats;
}

/**
 * Recommended cleanup configurations
 */
export const CLEANUP_CONFIGS = {
  /** Aggressive - minimize storage */
  MINIMAL: {
    retentionDays: 30,
    batchSize: 1000,
    archiveBeforeDelete: false,
    retentionBySeverity: {
      critical: 90,
      high: 60,
      medium: 30,
      low: 7,
    },
  },

  /** Balanced - good for most use cases */
  BALANCED: {
    retentionDays: 90,
    batchSize: 1000,
    archiveBeforeDelete: true,
    retentionBySeverity: {
      critical: 180,
      high: 90,
      medium: 60,
      low: 30,
    },
  },

  /** Conservative - keep more data */
  CONSERVATIVE: {
    retentionDays: 180,
    batchSize: 500,
    archiveBeforeDelete: true,
    retentionBySeverity: {
      critical: 365,
      high: 180,
      medium: 90,
      low: 60,
    },
  },
};

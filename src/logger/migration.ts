/**
 * D1 database migration for security events table
 */

export const SECURITY_EVENTS_TABLE_SQL = `
CREATE TABLE IF NOT EXISTS security_events (
  event_id TEXT PRIMARY KEY,
  timestamp INTEGER NOT NULL,
  attack_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  path TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER NOT NULL,
  ip_address TEXT NOT NULL,
  user_agent TEXT,
  country TEXT,
  user_id TEXT,
  rule_id TEXT,
  action TEXT NOT NULL,
  blocked INTEGER DEFAULT 0,
  metadata TEXT,
  created_at INTEGER DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_security_events_timestamp ON security_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_security_events_attack_type ON security_events(attack_type);
CREATE INDEX IF NOT EXISTS idx_security_events_ip_address ON security_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id);
CREATE INDEX IF NOT EXISTS idx_security_events_path ON security_events(path);
CREATE INDEX IF NOT EXISTS idx_security_events_blocked ON security_events(blocked);
`;

/**
 * Run migration to create security_events table
 */
export async function runMigration(db: D1Database): Promise<void> {
  try {
    await db.exec(SECURITY_EVENTS_TABLE_SQL);
    console.log('[Sentinel] Migration completed successfully');
  } catch (error: any) {
    console.error('[Sentinel] Migration failed:', error.message);
    throw error;
  }
}

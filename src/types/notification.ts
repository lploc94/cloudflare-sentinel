/**
 * Notification system types
 * Supports real-time and scheduled attack notifications via email, Slack, Telegram
 */

export type NotificationChannel = 'email' | 'slack' | 'telegram' | 'webhook';
export type NotificationSeverity = 'critical' | 'high' | 'medium' | 'low';
export type NotificationType = 'realtime_attack' | 'attack_summary' | 'detailed_report' | 'attack_spike' | 'metrics_summary';

/**
 * Base notification channel interface (pluggable like detectors)
 */
export interface INotificationChannel {
  /** Channel name */
  name: string;
  /** Priority (higher = send first) */
  priority: number;
  /** Send notification */
  send(notification: NotificationPayload): Promise<void>;
}

/**
 * Attack event notification (real-time)
 */
export interface AttackNotification {
  /** Unique notification ID */
  id: string;
  /** When the attack was detected */
  timestamp: string;
  /** Attack type */
  attackType: string;
  /** Severity level */
  severity: NotificationSeverity;
  /** Was the attack blocked? */
  blocked: boolean;
  /** Confidence score (0-1) */
  confidence: number;
  /** Attacker information */
  attacker: {
    ip: string;
    country?: string;
    userAgent?: string;
  };
  /** Target information */
  target: {
    endpoint: string;
    method: string;
  };
  /** Attack evidence */
  evidence?: {
    field: string;
    value: string;
    pattern?: string;
  };
  /** Additional context */
  metadata?: Record<string, any>;
}

/**
 * Aggregated attack summary (scheduled)
 */
export interface AttackSummary {
  /** Summary period */
  period: {
    start: string;
    end: string;
    duration: string; // e.g., "1h", "24h"
  };
  /** Total statistics */
  totals: {
    attacks: number;
    blocked: number;
    allowed: number;
    uniqueIPs: number;
    affectedEndpoints: number;
  };
  /** Attacks by type */
  byType: Record<string, {
    count: number;
    blocked: number;
    severity: NotificationSeverity;
  }>;
  /** Top attackers */
  topAttackers: Array<{
    ip: string;
    country?: string;
    attacks: number;
    blocked: number;
    types: string[];
  }>;
  /** Top targeted endpoints */
  topTargets: Array<{
    endpoint: string;
    attacks: number;
    blocked: number;
    types: string[];
  }>;
  /** Severity breakdown */
  bySeverity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

/**
 * Attack spike alert
 */
export interface AttackSpikeAlert {
  /** Current attack count */
  current: number;
  /** Baseline (average) */
  baseline: number;
  /** Increase percentage */
  increase: string;
  /** Threshold multiplier */
  threshold: number;
  /** Check period */
  period: string;
  /** Timestamp */
  timestamp: string;
}

/**
 * Metrics summary
 */
export interface MetricsSummary {
  /** Summary period */
  period: string;
  /** Total requests */
  requests: {
    total: number;
    blocked: number;
    allowed: number;
    blockRate: string;
  };
  /** Performance metrics */
  performance?: {
    avgResponseTime: string;
    minResponseTime: string;
    maxResponseTime: string;
  };
  /** Cache metrics */
  cache?: {
    hits: number;
    misses: number;
    hitRate: string;
  };
}

/**
 * Notification payload (union type)
 */
export type NotificationPayload = {
  type: 'realtime_attack';
  data: AttackNotification;
} | {
  type: 'attack_summary';
  data: AttackSummary;
} | {
  type: 'detailed_report';
  data: AttackSummary; // Same structure but different formatting
} | {
  type: 'attack_spike';
  data: AttackSpikeAlert;
} | {
  type: 'metrics_summary';
  data: MetricsSummary;
};

/**
 * Real-time notification configuration
 */
export interface RealtimeNotificationConfig {
  /** Enable real-time notifications */
  enabled: boolean;
  /** Only notify for these severities */
  severities?: NotificationSeverity[];
  /** Only notify for these attack types */
  attackTypes?: string[];
  /** Only notify if blocked */
  blockedOnly?: boolean;
  /** Minimum confidence threshold (0-1) */
  minConfidence?: number;
  /** Rate limit: max notifications per period */
  rateLimit?: {
    limit: number;
    period: number; // seconds
  };
}

/**
 * Notification configuration
 */
export interface NotificationConfig {
  /** Enable/disable notifications */
  enabled?: boolean;
  
  /** NotificationManager instance */
  manager?: any; // NotificationManager (avoid circular dependency)
  
  /** Real-time notification settings */
  realtime?: RealtimeNotificationConfig;
}

/**
 * Email channel configuration
 */
export interface EmailChannelConfig {
  /** Email API key (Resend, SendGrid, etc.) */
  apiKey: string;
  /** From email address */
  from: string;
  /** To email addresses */
  to: string[];
  /** Email provider (default: resend) */
  provider?: 'resend' | 'sendgrid';
}

/**
 * Slack channel configuration
 */
export interface SlackChannelConfig {
  /** Slack webhook URL */
  webhookUrl: string;
  /** Optional: Slack channel to post to */
  channel?: string;
  /** Optional: Bot username */
  username?: string;
  /** Optional: Icon emoji */
  iconEmoji?: string;
}

/**
 * Telegram channel configuration
 */
export interface TelegramChannelConfig {
  /** Telegram bot token */
  botToken: string;
  /** Telegram chat ID */
  chatId: string;
}

/**
 * Webhook channel configuration
 */
export interface WebhookChannelConfig {
  /** Webhook URL */
  url: string;
  /** HTTP method (default: POST) */
  method?: 'POST' | 'PUT';
  /** Additional headers */
  headers?: Record<string, string>;
}

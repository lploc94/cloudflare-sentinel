/**
 * Metrics Aggregator - Aggregate basic metrics
 * User controls schedule via wrangler.toml cron
 */

import { NotificationManager } from 'cloudflare-sentinel';
import type { MetricsSummary } from 'cloudflare-sentinel';
import { shouldNotifyMetrics } from '../utils/threshold-checker';

export async function handleMetricsAggregator(env: any, period: string): Promise<void> {
  console.log(`[MetricsAggregator] Running for period: ${period}`);

  if (!env.DB) {
    console.error('[MetricsAggregator] No D1 database configured');
    return;
  }

  try {
    // Build metrics
    const metrics = await buildMetrics(env.DB, period);

    // Check threshold
    const minRequests = parseInt(env.METRICS_AGGREGATOR_MIN_REQUESTS || '100');
    
    if (!shouldNotifyMetrics(metrics, { minRequests })) {
      console.log('[MetricsAggregator] Low traffic, skipping notification');
      console.log(`  - Total requests: ${metrics.requests.total} (min: ${minRequests})`);
      return;
    }

    // Get notification manager
    const notificationManager = await createNotificationManager(env);
    if (!notificationManager) {
      console.error('[MetricsAggregator] No notification channels configured');
      return;
    }

    // Send notification
    await notificationManager.notify({
      type: 'metrics_summary',
      data: metrics,
    });

    console.log('[MetricsAggregator] Metrics sent successfully');
    console.log(`  - Total requests: ${metrics.requests.total}`);
    console.log(`  - Block rate: ${metrics.requests.blockRate}`);
  } catch (error: any) {
    console.error('[MetricsAggregator] Error:', error.message);
  }
}

/**
 * Build metrics from D1
 */
async function buildMetrics(db: D1Database, period: string): Promise<MetricsSummary> {
  // This is a simplified version - you can enhance with Analytics Engine data
  const result = await db.prepare(`
    SELECT 
      COUNT(*) as total,
      SUM(CASE WHEN blocked = 1 THEN 1 ELSE 0 END) as blocked
    FROM security_events
    WHERE timestamp >= ?
  `).bind(Date.now() - parsePeriodMs(period)).first();

  const total = (result as any)?.total || 0;
  const blocked = (result as any)?.blocked || 0;
  const allowed = total - blocked;
  const blockRate = total > 0 ? ((blocked / total) * 100).toFixed(2) + '%' : '0%';

  return {
    period,
    requests: {
      total,
      blocked,
      allowed,
      blockRate,
    },
  };
}

function parsePeriodMs(period: string): number {
  const match = period.match(/^(\d+)(m|h|d)$/);
  if (!match) return 0;

  const value = parseInt(match[1]);
  const unit = match[2];

  switch (unit) {
    case 'm': return value * 60 * 1000;
    case 'h': return value * 60 * 60 * 1000;
    case 'd': return value * 24 * 60 * 60 * 1000;
    default: return 0;
  }
}

/**
 * Create notification manager from env config
 */
async function createNotificationManager(env: any): Promise<NotificationManager | null> {
  const manager = new NotificationManager({
    rateLimit: {
      enabled: false, // No rate limit for metrics
      limit: 10,
      period: 300,
    },
    debug: env.DEBUG === 'true',
  });

  let hasChannels = false;

  // Add email channel
  if (env.EMAIL_ENABLED === 'true' && env.RESEND_API_KEY) {
    const { EmailChannel } = await import('cloudflare-sentinel');
    manager.addChannel(new EmailChannel({
      apiKey: env.RESEND_API_KEY,
      from: env.EMAIL_FROM || 'sentinel@yourdomain.com',
      to: (env.EMAIL_TO || '').split(',').filter(Boolean),
      provider: env.EMAIL_PROVIDER || 'resend',
    }));
    hasChannels = true;
  }

  // Add Slack channel
  if (env.SLACK_ENABLED === 'true' && env.SLACK_WEBHOOK_URL) {
    const { SlackChannel } = await import('cloudflare-sentinel');
    manager.addChannel(new SlackChannel({
      webhookUrl: env.SLACK_WEBHOOK_URL,
      channel: env.SLACK_CHANNEL,
      username: env.SLACK_USERNAME || 'Sentinel Metrics',
      iconEmoji: ':chart_with_upwards_trend:',
    }));
    hasChannels = true;
  }

  return hasChannels ? manager : null;
}

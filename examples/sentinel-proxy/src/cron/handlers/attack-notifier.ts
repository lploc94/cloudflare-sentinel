/**
 * Attack Notifier - Aggregate attacks and notify if threshold met
 * User controls schedule via wrangler.toml cron
 */

import { NotificationManager } from 'cloudflare-sentinel';
import type { AttackSummary } from 'cloudflare-sentinel';
import { buildAttackSummary } from '../utils/summary-builder';
import { shouldNotify, type ThresholdConfig } from '../utils/threshold-checker';

export async function handleAttackNotifier(env: any, period: string): Promise<void> {
  console.log(`[AttackNotifier] Running for period: ${period}`);

  if (!env.DB) {
    console.error('[AttackNotifier] No D1 database configured');
    return;
  }

  try {
    // Build summary
    const summary = await buildAttackSummary(env.DB, period);

    // Get config from env
    const config: ThresholdConfig = {
      minAttacks: parseInt(env.ATTACK_NOTIFIER_MIN_ATTACKS || '5'),
      minBlocked: parseInt(env.ATTACK_NOTIFIER_MIN_BLOCKED || '2'),
      minCritical: parseInt(env.ATTACK_NOTIFIER_MIN_CRITICAL || '1'),
      severities: env.ATTACK_NOTIFIER_SEVERITIES?.split(',') || ['critical', 'high'],
    };

    // Check thresholds
    if (!shouldNotify(summary, config)) {
      console.log('[AttackNotifier] No notification needed (below threshold)');
      console.log(`  - Total attacks: ${summary.totals.attacks} (min: ${config.minAttacks})`);
      console.log(`  - Blocked: ${summary.totals.blocked} (min: ${config.minBlocked})`);
      console.log(`  - Critical: ${summary.bySeverity.critical} (min: ${config.minCritical})`);
      return;
    }

    // Get notification manager
    const notificationManager = await createNotificationManager(env);
    if (!notificationManager) {
      console.error('[AttackNotifier] No notification channels configured');
      return;
    }

    // Send notification
    await notificationManager.notify({
      type: 'attack_summary',
      data: summary,
    });

    console.log('[AttackNotifier] Notification sent successfully');
    console.log(`  - Total attacks: ${summary.totals.attacks}`);
    console.log(`  - Blocked: ${summary.totals.blocked}`);
    console.log(`  - Critical: ${summary.bySeverity.critical}`);
  } catch (error: any) {
    console.error('[AttackNotifier] Error:', error.message);
  }
}

/**
 * Create notification manager from env config
 */
async function createNotificationManager(env: any): Promise<NotificationManager | null> {
  const manager = new NotificationManager({
    rateLimit: {
      enabled: true,
      limit: parseInt(env.NOTIFICATION_RATE_LIMIT || '10'),
      period: parseInt(env.NOTIFICATION_RATE_PERIOD || '300'),
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
    console.log('[AttackNotifier] Email channel enabled');
  }

  // Add Slack channel
  if (env.SLACK_ENABLED === 'true' && env.SLACK_WEBHOOK_URL) {
    const { SlackChannel } = await import('cloudflare-sentinel');
    manager.addChannel(new SlackChannel({
      webhookUrl: env.SLACK_WEBHOOK_URL,
      channel: env.SLACK_CHANNEL,
      username: env.SLACK_USERNAME || 'Sentinel',
      iconEmoji: env.SLACK_ICON_EMOJI || ':shield:',
    }));
    hasChannels = true;
    console.log('[AttackNotifier] Slack channel enabled');
  }

  return hasChannels ? manager : null;
}

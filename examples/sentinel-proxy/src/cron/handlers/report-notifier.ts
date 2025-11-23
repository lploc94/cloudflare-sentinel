/**
 * Report Notifier - Send detailed report (always send, no threshold)
 * User controls schedule via wrangler.toml cron
 */

import { NotificationManager } from 'cloudflare-sentinel';
import { buildAttackSummary } from '../utils/summary-builder';

export async function handleReportNotifier(env: any, period: string): Promise<void> {
  console.log(`[ReportNotifier] Running for period: ${period}`);

  if (!env.DB) {
    console.error('[ReportNotifier] No D1 database configured');
    return;
  }

  try {
    // Build detailed report
    const report = await buildAttackSummary(env.DB, period);

    // Filter by severities if configured
    const includeAll = env.REPORT_NOTIFIER_INCLUDE_ALL === 'true';
    const severities = env.REPORT_NOTIFIER_SEVERITIES?.split(',') || ['critical', 'high', 'medium'];

    if (!includeAll) {
      // Filter attacks by severity (note: this is for display, not filtering DB results)
      console.log(`[ReportNotifier] Including severities: ${severities.join(', ')}`);
    }

    // Get notification manager
    const notificationManager = await createNotificationManager(env);
    if (!notificationManager) {
      console.error('[ReportNotifier] No notification channels configured');
      return;
    }

    // Always send report (no threshold check)
    await notificationManager.notify({
      type: 'detailed_report',
      data: report,
    });

    console.log('[ReportNotifier] Report sent successfully');
    console.log(`  - Period: ${report.period.duration}`);
    console.log(`  - Total attacks: ${report.totals.attacks}`);
    console.log(`  - Unique IPs: ${report.totals.uniqueIPs}`);
  } catch (error: any) {
    console.error('[ReportNotifier] Error:', error.message);
  }
}

/**
 * Create notification manager from env config
 */
async function createNotificationManager(env: any): Promise<NotificationManager | null> {
  const manager = new NotificationManager({
    rateLimit: {
      enabled: false, // No rate limit for scheduled reports
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
      username: env.SLACK_USERNAME || 'Sentinel Report',
      iconEmoji: env.SLACK_ICON_EMOJI || ':bar_chart:',
    }));
    hasChannels = true;
  }

  return hasChannels ? manager : null;
}

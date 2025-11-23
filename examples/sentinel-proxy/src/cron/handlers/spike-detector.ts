/**
 * Spike Detector - Detect attack spikes vs baseline
 * User controls schedule via wrangler.toml cron
 */

import { NotificationManager } from 'cloudflare-sentinel';
import type { AttackSpikeAlert } from 'cloudflare-sentinel';
import { getAttackCount, getAverageAttackCount } from '../utils/summary-builder';

export async function handleSpikeDetector(env: any): Promise<void> {
  console.log('[SpikeDetector] Checking for attack spikes');

  if (!env.DB) {
    console.error('[SpikeDetector] No D1 database configured');
    return;
  }

  try {
    // Get config
    const config = {
      baselinePeriod: env.SPIKE_DETECTOR_BASELINE_PERIOD || '1h',
      checkPeriod: env.SPIKE_DETECTOR_CHECK_PERIOD || '15m',
      threshold: parseFloat(env.SPIKE_DETECTOR_THRESHOLD || '3'),
      minAttacks: parseInt(env.SPIKE_DETECTOR_MIN_ATTACKS || '10'),
    };

    // Get current attack count
    const current = await getAttackCount(env.DB, config.checkPeriod);

    // Get baseline (average)
    const baseline = await getAverageAttackCount(env.DB, config.baselinePeriod);

    console.log(`[SpikeDetector] Current: ${current}, Baseline: ${baseline.toFixed(1)}`);

    // Check if spike
    const isSpike = current > baseline * config.threshold && current >= config.minAttacks;

    if (!isSpike) {
      console.log('[SpikeDetector] No spike detected');
      return;
    }

    const increase = ((current - baseline) / baseline * 100).toFixed(1);
    console.log(`[SpikeDetector] ⚠️  Spike detected! +${increase}%`);

    // Get notification manager
    const notificationManager = await createNotificationManager(env);
    if (!notificationManager) {
      console.error('[SpikeDetector] No notification channels configured');
      return;
    }

    // Send spike alert
    const alert: AttackSpikeAlert = {
      current,
      baseline: Math.round(baseline),
      increase: `${increase}%`,
      threshold: config.threshold,
      period: config.checkPeriod,
      timestamp: new Date().toISOString(),
    };

    await notificationManager.notify({
      type: 'attack_spike',
      data: alert,
    });

    console.log('[SpikeDetector] Spike alert sent');
  } catch (error: any) {
    console.error('[SpikeDetector] Error:', error.message);
  }
}

/**
 * Create notification manager from env config
 */
async function createNotificationManager(env: any): Promise<NotificationManager | null> {
  const manager = new NotificationManager({
    rateLimit: {
      enabled: true,
      limit: 3, // Max 3 spike alerts
      period: 900, // per 15 minutes
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
      username: env.SLACK_USERNAME || 'Sentinel Alert',
      iconEmoji: ':rotating_light:',
    }));
    hasChannels = true;
  }

  return hasChannels ? manager : null;
}

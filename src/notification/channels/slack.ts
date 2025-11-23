/**
 * Slack notification channel
 * Uses Slack Incoming Webhooks
 */

import { BaseNotificationChannel } from '../base';
import type { SlackChannelConfig, NotificationPayload } from '../../types/notification';
import {
  formatSlackAttackNotification,
  formatSlackAttackSummary,
  formatSlackAttackSpike,
  formatSlackMetricsSummary,
} from '../formatters/slack';

export class SlackChannel extends BaseNotificationChannel {
  name = 'slack';
  priority = 90;

  constructor(private config: SlackChannelConfig) {
    super();
  }

  async send(notification: NotificationPayload): Promise<void> {
    try {
      // Format notification based on type
      const payload = this.formatNotification(notification);

      // Add optional config
      if (this.config.channel) {
        payload.channel = this.config.channel;
      }
      if (this.config.username) {
        payload.username = this.config.username;
      }
      if (this.config.iconEmoji) {
        payload.icon_emoji = this.config.iconEmoji;
      }

      // Send to Slack
      const response = await fetch(this.config.webhookUrl, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      });

      if (!response.ok) {
        const error = await response.text();
        throw new Error(`Slack webhook error: ${response.status} ${error}`);
      }

      this.log(`Slack notification sent: ${notification.type}`);
    } catch (error: any) {
      await this.handleError(error, 'send');
      throw error; // Re-throw for NotificationManager
    }
  }

  private formatNotification(notification: NotificationPayload): any {
    switch (notification.type) {
      case 'realtime_attack':
        return formatSlackAttackNotification(notification.data);

      case 'attack_summary':
      case 'detailed_report':
        return formatSlackAttackSummary(notification.data);

      case 'attack_spike':
        return formatSlackAttackSpike(notification.data);

      case 'metrics_summary':
        return formatSlackMetricsSummary(notification.data);

      default:
        throw new Error(`Unknown notification type: ${(notification as any).type}`);
    }
  }
}

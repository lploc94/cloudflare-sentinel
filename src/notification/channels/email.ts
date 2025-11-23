/**
 * Email notification channel
 * Supports Resend and SendGrid
 */

import { BaseNotificationChannel } from '../base';
import type { EmailChannelConfig, NotificationPayload } from '../../types/notification';
import {
  formatAttackNotification,
  formatAttackSummary,
  formatAttackSpikeAlert,
  formatMetricsSummary,
} from '../formatters';

export class EmailChannel extends BaseNotificationChannel {
  name = 'email';
  priority = 100;

  constructor(private config: EmailChannelConfig) {
    super();
  }

  async send(notification: NotificationPayload): Promise<void> {
    try {
      // Format notification based on type
      const formatted = this.formatNotification(notification);

      // Send email via provider
      if (this.config.provider === 'sendgrid') {
        await this.sendViaSendGrid(formatted);
      } else {
        // Default: Resend
        await this.sendViaResend(formatted);
      }

      this.log(`Email sent: ${formatted.subject}`);
    } catch (error: any) {
      await this.handleError(error, 'send');
      throw error; // Re-throw for NotificationManager
    }
  }

  private formatNotification(notification: NotificationPayload): {
    subject: string;
    text: string;
    html: string;
  } {
    switch (notification.type) {
      case 'realtime_attack':
        return formatAttackNotification(notification.data);

      case 'attack_summary':
        return formatAttackSummary(notification.data, false);

      case 'detailed_report':
        return formatAttackSummary(notification.data, true);

      case 'attack_spike':
        return formatAttackSpikeAlert(notification.data);

      case 'metrics_summary':
        return formatMetricsSummary(notification.data);

      default:
        throw new Error(`Unknown notification type: ${(notification as any).type}`);
    }
  }

  private async sendViaResend(email: {
    subject: string;
    text: string;
    html: string;
  }): Promise<void> {
    const response = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: this.config.from,
        to: this.config.to,
        subject: email.subject,
        text: email.text,
        html: email.html,
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`Resend API error: ${response.status} ${error}`);
    }

    const result = await response.json();
    this.log('Resend response', result);
  }

  private async sendViaSendGrid(email: {
    subject: string;
    text: string;
    html: string;
  }): Promise<void> {
    const response = await fetch('https://api.sendgrid.com/v3/mail/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${this.config.apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        personalizations: [
          {
            to: this.config.to.map(email => ({ email })),
          },
        ],
        from: {
          email: this.config.from,
        },
        subject: email.subject,
        content: [
          {
            type: 'text/plain',
            value: email.text,
          },
          {
            type: 'text/html',
            value: email.html,
          },
        ],
      }),
    });

    if (!response.ok) {
      const error = await response.text();
      throw new Error(`SendGrid API error: ${response.status} ${error}`);
    }

    this.log('SendGrid email sent');
  }
}

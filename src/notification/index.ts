/**
 * NotificationManager - Core notification orchestrator
 * Manages multiple notification channels (email, slack, etc.)
 */

import type { INotificationChannel, NotificationPayload } from '../types/notification';
import { NotificationRateLimiter } from './rate-limiter';

export interface NotificationManagerConfig {
  /** Rate limiting config */
  rateLimit?: {
    enabled: boolean;
    limit: number;
    period: number; // seconds
  };
  /** Enable debug logging */
  debug?: boolean;
}

export class NotificationManager {
  private channels: INotificationChannel[] = [];
  private rateLimiter?: NotificationRateLimiter;
  private debug: boolean = false;

  constructor(config?: NotificationManagerConfig) {
    // Setup rate limiter if enabled
    if (config?.rateLimit?.enabled) {
      this.rateLimiter = new NotificationRateLimiter(
        config.rateLimit.limit,
        config.rateLimit.period
      );
    }

    this.debug = config?.debug || false;
  }

  /**
   * Add notification channel (pluggable)
   */
  addChannel(channel: INotificationChannel): void {
    this.channels.push(channel);
    
    // Sort by priority (higher first)
    this.channels.sort((a, b) => b.priority - a.priority);
    
    if (this.debug) {
      console.log(`[NotificationManager] Channel added: ${channel.name} (priority: ${channel.priority})`);
    }
  }

  /**
   * Remove channel by name
   */
  removeChannel(name: string): void {
    const index = this.channels.findIndex(c => c.name === name);
    if (index >= 0) {
      this.channels.splice(index, 1);
      if (this.debug) {
        console.log(`[NotificationManager] Channel removed: ${name}`);
      }
    }
  }

  /**
   * Get all registered channels
   */
  getChannels(): INotificationChannel[] {
    return [...this.channels];
  }

  /**
   * Send notification to all channels
   */
  async notify(notification: NotificationPayload): Promise<void> {
    // Check rate limit
    if (this.rateLimiter && !this.rateLimiter.check()) {
      console.warn('[NotificationManager] Rate limit exceeded, skipping notification');
      return;
    }

    if (this.channels.length === 0) {
      console.warn('[NotificationManager] No channels configured');
      return;
    }

    if (this.debug) {
      console.log(`[NotificationManager] Sending notification type: ${notification.type} to ${this.channels.length} channels`);
    }

    // Send to all channels in parallel
    const results = await Promise.allSettled(
      this.channels.map(channel => 
        this.sendToChannel(channel, notification)
      )
    );

    // Log results
    const succeeded = results.filter(r => r.status === 'fulfilled').length;
    const failed = results.filter(r => r.status === 'rejected').length;

    if (this.debug) {
      console.log(`[NotificationManager] Results: ${succeeded} succeeded, ${failed} failed`);
    }

    // Log failures
    results.forEach((result, index) => {
      if (result.status === 'rejected') {
        console.error(
          `[NotificationManager] Channel ${this.channels[index].name} failed:`,
          result.reason
        );
      }
    });
  }

  /**
   * Send to specific channel with error handling
   */
  private async sendToChannel(
    channel: INotificationChannel,
    notification: NotificationPayload
  ): Promise<void> {
    try {
      await channel.send(notification);
      
      if (this.debug) {
        console.log(`[NotificationManager] Sent to channel: ${channel.name}`);
      }
    } catch (error: any) {
      console.error(`[NotificationManager] Channel ${channel.name} error:`, error.message);
      // Don't throw - continue with other channels (fail-open)
    }
  }

  /**
   * Check if rate limit allows notification
   */
  checkRateLimit(): boolean {
    if (!this.rateLimiter) {
      return true; // No rate limiter = always allow
    }
    return this.rateLimiter.check();
  }

  /**
   * Get current rate limit count
   */
  getRateLimitCount(): number {
    if (!this.rateLimiter) {
      return 0;
    }
    return this.rateLimiter.getCount();
  }

  /**
   * Reset rate limiter
   */
  resetRateLimit(): void {
    if (this.rateLimiter) {
      this.rateLimiter.reset();
    }
  }
}

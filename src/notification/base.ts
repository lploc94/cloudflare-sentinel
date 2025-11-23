/**
 * Base notification channel
 * Similar to BaseDetector pattern - pluggable & extensible
 */

import type { INotificationChannel, NotificationPayload } from '../types/notification';

export abstract class BaseNotificationChannel implements INotificationChannel {
  abstract name: string;
  abstract priority: number;

  /**
   * Send notification to this channel
   */
  abstract send(notification: NotificationPayload): Promise<void>;

  /**
   * Helper: Check if channel should handle this notification type
   */
  protected shouldHandle(notification: NotificationPayload): boolean {
    // By default, handle all types
    // Subclasses can override for specific filtering
    return true;
  }

  /**
   * Helper: Log notification activity
   */
  protected log(message: string, data?: any): void {
    console.log(`[NotificationChannel:${this.name}] ${message}`, data || '');
  }

  /**
   * Helper: Handle errors gracefully
   */
  protected async handleError(error: Error, context: string): Promise<void> {
    console.error(`[NotificationChannel:${this.name}] Error in ${context}:`, error.message);
    // Don't throw - fail gracefully (fail-open pattern)
  }
}

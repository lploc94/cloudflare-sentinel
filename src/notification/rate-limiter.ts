/**
 * Simple in-memory rate limiter for notifications
 * Prevents notification spam during attack bursts
 */

export class NotificationRateLimiter {
  private counters: Map<string, { count: number; resetAt: number }> = new Map();

  constructor(
    private limit: number = 10,
    private periodSeconds: number = 300 // 5 minutes
  ) {}

  /**
   * Check if rate limit allows notification
   */
  check(key: string = 'global'): boolean {
    const now = Date.now();
    const counter = this.counters.get(key);

    // No counter or expired - allow
    if (!counter || now >= counter.resetAt) {
      this.counters.set(key, {
        count: 1,
        resetAt: now + this.periodSeconds * 1000,
      });
      return true;
    }

    // Check limit
    if (counter.count >= this.limit) {
      return false; // Rate limit exceeded
    }

    // Increment and allow
    counter.count++;
    return true;
  }

  /**
   * Get current count
   */
  getCount(key: string = 'global'): number {
    const counter = this.counters.get(key);
    if (!counter || Date.now() >= counter.resetAt) {
      return 0;
    }
    return counter.count;
  }

  /**
   * Reset counter
   */
  reset(key: string = 'global'): void {
    this.counters.delete(key);
  }

  /**
   * Clean up expired counters
   */
  cleanup(): void {
    const now = Date.now();
    for (const [key, counter] of this.counters.entries()) {
      if (now >= counter.resetAt) {
        this.counters.delete(key);
      }
    }
  }
}

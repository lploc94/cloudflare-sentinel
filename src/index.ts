/**
 * Cloudflare Sentinel
 * Attack detection and rate limiting middleware for Cloudflare Workers
 * 
 * @packageDocumentation
 */

// Export types
export * from './types';

// Export middleware
export * from './middleware';

// Export detector (base classes for custom detectors)
export * from './detector';
export { BaseDetector, type IDetector, type DetectorResult, type DetectionEvidence } from './detector/base';

// Export logger
export * from './logger';

// Export notification system
export { NotificationManager } from './notification';
export { BaseNotificationChannel } from './notification/base';
export { EmailChannel, SlackChannel } from './notification/channels';
export type {
  INotificationChannel,
  AttackNotification,
  AttackSummary,
  AttackSpikeAlert,
  MetricsSummary,
  NotificationPayload,
  EmailChannelConfig,
  SlackChannelConfig,
} from './types/notification';

// Export utilities
export * from './utils';

// Re-export main class for convenience
export { Sentinel } from './middleware';

// Helper functions
export { createRequestContext } from './types';

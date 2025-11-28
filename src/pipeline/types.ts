/**
 * Pipeline types for Cloudflare Sentinel
 */

import type { DetectorResult } from '../detector/base';

/**
 * Built-in action types
 * 
 * You can also use custom action types (any string) for extensibility:
 * ```typescript
 * // Custom action
 * { type: 'my_custom_action', data: { ... } }
 * 
 * // Register handler
 * pipeline.on('my_custom_action', myHandler);
 * ```
 */
export const ActionType = {
  // Terminal actions
  BLOCK: 'block',
  PROCEED: 'proceed',
  
  // Logging & Notification
  LOG: 'log',
  NOTIFY: 'notify',
  
  // Reputation
  UPDATE_REPUTATION: 'update_reputation',
} as const;

export type ActionTypeValue = typeof ActionType[keyof typeof ActionType];

/**
 * Helper to create custom action
 * 
 * @example
 * ```typescript
 * // In resolver
 * return [customAction('ai_analyze', { priority: 'high' })];
 * 
 * // Register handler
 * pipeline.on('ai_analyze', new AIHandler());
 * ```
 */
export function customAction(type: string, data?: Record<string, any>): Action {
  return { type, data };
}

/**
 * Threat level based on score
 */
export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Aggregated threat score
 */
export interface ThreatScore {
  /** Score 0-100 */
  score: number;
  /** Threat level */
  level: ThreatLevel;
  /** Detection results that contributed to score */
  results: DetectorResult[];
}

/**
 * Action to be executed
 */
export interface Action {
  /** Action type */
  type: ActionTypeValue | string;
  /** Action-specific data */
  data?: Record<string, any>;
}

/**
 * Pipeline context passed to detectors and handlers
 */
export interface PipelineContext {
  /** Cloudflare environment bindings */
  env: Record<string, any>;
  /** Cloudflare execution context */
  ctx: ExecutionContext;
  /** Original request */
  request?: Request;
  /** Original response (for response detection) */
  response?: Response;
}

/**
 * Handler context with additional info
 */
export interface HandlerContext extends PipelineContext {
  /** Threat score */
  score: ThreatScore;
  /** All detection results */
  results: DetectorResult[];
}

/**
 * Resolver context
 */
export interface ResolverContext {
  /** Threat score */
  score: ThreatScore;
  /** All detection results */
  results: DetectorResult[];
  /** Original request */
  request: Request;
  /** Original response (for response detection) */
  response?: Response;
}

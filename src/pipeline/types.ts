/**
 * Pipeline Types
 * 
 * Core type definitions for Cloudflare Sentinel pipeline.
 * Includes action types, contexts, and scoring interfaces.
 * 
 * @module pipeline
 */

import type { DetectorResult } from '../detector/base';

/**
 * Built-in action types
 * 
 * Use these constants instead of strings for type safety.
 * Custom action types (any string) are also supported for extensibility.
 * 
 * | Action | Value | Description |
 * |--------|-------|-------------|
 * | BLOCK | 'block' | Block the request (return 403) |
 * | PROCEED | 'proceed' | Allow the request |
 * | LOG | 'log' | Log detection details |
 * | NOTIFY | 'notify' | Send notification (Slack, etc.) |
 * | UPDATE_REPUTATION | 'update_reputation' | Update IP reputation score |
 * 
 * @example
 * ```typescript
 * import { ActionType } from 'cloudflare-sentinel';
 * 
 * // In resolver
 * actions.push({ type: ActionType.BLOCK, data: { reason: 'Attack' } });
 * 
 * // Register handler
 * pipeline.on(ActionType.LOG, new LogHandler());
 * 
 * // Custom action
 * pipeline.on('escalate', new EscalateHandler());
 * ```
 */
export const ActionType = {
  /** Block the request - typically returns 403 */
  BLOCK: 'block',
  /** Allow the request to proceed */
  PROCEED: 'proceed',
  /** Log detection details */
  LOG: 'log',
  /** Send notification via webhook */
  NOTIFY: 'notify',
  /** Update IP/user reputation score */
  UPDATE_REPUTATION: 'update_reputation',
} as const;

/** Union type of all built-in action type values */
export type ActionTypeValue = typeof ActionType[keyof typeof ActionType];

/**
 * Helper to create custom action
 * 
 * Use when creating custom action types beyond the built-in ones.
 * 
 * @param type - Custom action type string
 * @param data - Optional action data
 * @returns Action object
 * 
 * @example
 * ```typescript
 * // In custom resolver
 * return [
 *   customAction('ai_analyze', { priority: 'high' }),
 *   customAction('rate_limit', { window: 60 }),
 * ];
 * 
 * // Register handlers
 * pipeline
 *   .on('ai_analyze', new AIHandler())
 *   .on('rate_limit', new RateLimitHandler());
 * ```
 */
export function customAction(type: string, data?: Record<string, any>): Action {
  return { type, data };
}

/**
 * Threat level based on score
 * 
 * | Level | Score Range | Description |
 * |-------|-------------|-------------|
 * | none | 0-19 | No threat detected |
 * | low | 20-39 | Minor suspicious activity |
 * | medium | 40-59 | Moderate threat |
 * | high | 60-79 | Significant threat |
 * | critical | 80-100 | Critical/Active attack |
 */
export type ThreatLevel = 'none' | 'low' | 'medium' | 'high' | 'critical';

/**
 * Aggregated threat score from all detectors
 * 
 * Returned by score aggregators after combining all detection results.
 * 
 * @example
 * ```typescript
 * // Access in handler context
 * console.log(ctx.score.score);   // 85
 * console.log(ctx.score.level);   // 'critical'
 * console.log(ctx.score.results); // [DetectorResult, ...]
 * ```
 */
export interface ThreatScore {
  /** Numeric score 0-100 */
  score: number;
  /** Threat level derived from score */
  level: ThreatLevel;
  /** Detection results that contributed to this score */
  results: DetectorResult[];
}

/**
 * Action to be executed by handlers
 * 
 * Returned by resolvers and passed to registered handlers.
 * 
 * @example
 * ```typescript
 * // Block action
 * { type: ActionType.BLOCK, data: { reason: 'SQLi detected', statusCode: 403 } }
 * 
 * // Log action
 * { type: ActionType.LOG, data: { level: 'warn', message: 'Suspicious' } }
 * 
 * // Custom action
 * { type: 'escalate', data: { priority: 'high' } }
 * ```
 */
export interface Action {
  /** Action type (built-in or custom string) */
  type: ActionTypeValue | string;
  /** Action-specific data passed to handler */
  data?: Record<string, any>;
}

/**
 * Pipeline context passed to detectors and handlers
 * 
 * Contains Cloudflare Worker environment bindings and execution context.
 * 
 * @example
 * ```typescript
 * // In Worker fetch handler
 * await pipeline.process(request, {
 *   env: env,  // KV, D1, etc.
 *   ctx: ctx,  // ExecutionContext
 * });
 * ```
 */
/**
 * Pipeline context - contains all request information for detectors and handlers
 * 
 * This is the "bag of data" that flows through the pipeline.
 * Handlers and detectors can read from this context to make decisions.
 */
export interface PipelineContext {
  /** Cloudflare environment bindings (KV, D1, R2, etc.) */
  env: Record<string, any>;
  /** Cloudflare execution context for waitUntil */
  ctx: ExecutionContext;
  /** Original request */
  request?: Request;
  /** Original response (for response-phase detection) */
  response?: Response;
  
  // ─── Request Info (extracted for convenience) ───────────────────────────
  
  /** Client IP address (from CF-Connecting-IP) */
  clientIp?: string;
  /** Request path (e.g., '/api/auth/login') */
  path?: string;
  /** Request method (GET, POST, etc.) */
  method?: string;
  /** User agent */
  userAgent?: string;
  
  // ─── Extension Point ───────────────────────────────────────────────────
  
  /** 
   * Custom metadata - extend with any fields you need
   * Use this for app-specific context data (CF metadata, tenant info, etc.)
   * 
   * @example
   * ```typescript
   * const ctx = {
   *   ...baseContext,
   *   metadata: {
   *     colo: request.cf?.colo,
   *     country: request.cf?.country,
   *     tenantId: 'acme',
   *     requestId: crypto.randomUUID(),
   *   }
   * };
   * ```
   */
  metadata?: Record<string, any>;
}

/**
 * Handler context with full detection information
 * 
 * Extended context passed to action handlers with threat score
 * and all detection results.
 * 
 * @example
 * ```typescript
 * class CustomHandler implements IActionHandler {
 *   async execute(action: Action, ctx: HandlerContext) {
 *     console.log(ctx.score.score);      // 85
 *     console.log(ctx.results.length);   // 3
 *     console.log(ctx.request.url);      // 'https://...'
 *     console.log(ctx.env.MY_KV);        // KVNamespace
 *   }
 * }
 * ```
 */
export interface HandlerContext extends PipelineContext {
  /** Aggregated threat score */
  score: ThreatScore;
  /** All detection results from detectors */
  results: DetectorResult[];
}

/**
 * Resolver context for action resolution
 * 
 * Passed to resolvers to determine what actions to take.
 * 
 * @example
 * ```typescript
 * class CustomResolver extends BaseActionResolver {
 *   async resolve(ctx: ResolverContext): Promise<Action[]> {
 *     if (ctx.score.score >= 80) {
 *       return [this.block('High threat')];
 *     }
 *     return [this.proceed()];
 *   }
 * }
 * ```
 */
export interface ResolverContext {
  /** Aggregated threat score */
  score: ThreatScore;
  /** All detection results */
  results: DetectorResult[];
  /** Original request */
  request: Request;
  /** Original response (for response-phase resolution) */
  response?: Response;
}

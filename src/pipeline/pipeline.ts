/**
 * SentinelPipeline - Core Security Pipeline
 * 
 * The main entry point for Cloudflare Sentinel security processing.
 * Provides a fluent API for composing detectors, scoring, resolution, and handlers.
 * 
 * @module pipeline
 */

import type { IDetector, DetectorResult } from '../detector/base';
import type { IScoreAggregator } from '../scoring/types';
import type { IActionResolver } from '../resolver/types';
import type { IActionHandler } from '../handler/types';
import type { Action, PipelineContext, HandlerContext } from './types';
import { Decision } from './decision';

/**
 * Pipeline execution mode
 * - 'sync': Returns Decision, used for blocking pipelines
 * - 'async': Returns void, used for background monitoring
 */
type PipelineMode = 'sync' | 'async';

/**
 * SentinelPipeline - Composable security detection pipeline
 * 
 * **Architecture:**
 * ```
 * Request → Detectors → Aggregator → Resolver → Handlers → Decision
 *              ↓            ↓           ↓           ↓
 *           Results      Score       Actions    Execute
 * ```
 * 
 * **Two Modes:**
 * 
 * | Mode | Factory | Returns | Use Case |
 * |------|---------|---------|----------|
 * | sync | `SentinelPipeline.sync()` | `Decision` | Blocking (return 403) |
 * | async | `SentinelPipeline.async()` | `void` | Monitoring (log only) |
 * 
 * **Fluent API:**
 * ```typescript
 * SentinelPipeline.sync([...detectors])
 *   .score(aggregator)    // Required: How to combine scores
 *   .resolve(resolver)    // Required: Score → Actions
 *   .on(actionType, handler)  // Optional: Handle actions
 * ```
 * 
 * @example
 * ```typescript
 * import { 
 *   SentinelPipeline, 
 *   BlocklistDetector,
 *   SQLInjectionRequestDetector,
 *   MaxScoreAggregator,
 *   MultiLevelResolver,
 *   LogHandler,
 *   ActionType,
 * } from 'cloudflare-sentinel';
 * 
 * // Sync pipeline (blocking)
 * const pipeline = SentinelPipeline.sync([
 *   new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
 *   new SQLInjectionRequestDetector(),
 * ])
 *   .score(new MaxScoreAggregator())
 *   .resolve(new MultiLevelResolver({
 *     levels: [
 *       { maxScore: 50, actions: [ActionType.LOG] },
 *       { maxScore: 100, actions: [ActionType.BLOCK, ActionType.NOTIFY] },
 *     ],
 *   }))
 *   .on(ActionType.LOG, new LogHandler({ console: true }));
 * 
 * // In Worker fetch handler
 * export default {
 *   async fetch(request, env, ctx) {
 *     const decision = await pipeline.process(request, { env, ctx });
 *     
 *     if (decision.has('block')) {
 *       return new Response('Blocked', { status: 403 });
 *     }
 *     
 *     return fetch(request);
 *   }
 * };
 * ```
 * 
 * @example
 * ```typescript
 * // Async pipeline (monitoring only)
 * const monitorPipeline = SentinelPipeline.async([...detectors])
 *   .score(new WeightedAggregator())
 *   .resolve(new DefaultResolver())
 *   .on(ActionType.LOG, new AnalyticsHandler({ analytics: env.ANALYTICS }));
 * 
 * // Fire and forget - doesn't block request
 * ctx.waitUntil(monitorPipeline.process(request, { env, ctx }));
 * return fetch(request);
 * ```
 */
export class SentinelPipeline {
  private aggregator!: IScoreAggregator;
  private resolver!: IActionResolver;
  private handlers = new Map<string, IActionHandler>();

  private constructor(
    private readonly mode: PipelineMode,
    private readonly detectors: IDetector[]
  ) {}

  /**
   * Create SYNC pipeline that returns a Decision
   * 
   * Use for blocking pipelines where you need to check
   * `decision.has('block')` before proceeding.
   * 
   * @param detectors - Array of detectors to run
   * @returns New SentinelPipeline instance
   * 
   * @example
   * ```typescript
   * const pipeline = SentinelPipeline.sync([
   *   new BlocklistDetector({ kv }),
   *   new SQLInjectionRequestDetector(),
   * ]);
   * ```
   */
  static sync(detectors: IDetector[]): SentinelPipeline {
    return new SentinelPipeline('sync', detectors);
  }

  /**
   * Create ASYNC pipeline that returns void
   * 
   * Use for monitoring/logging pipelines that don't block requests.
   * Typically used with `ctx.waitUntil()` for background processing.
   * 
   * @param detectors - Array of detectors to run
   * @returns New SentinelPipeline instance
   * 
   * @example
   * ```typescript
   * const pipeline = SentinelPipeline.async([...detectors]);
   * ctx.waitUntil(pipeline.process(request, { env, ctx }));
   * ```
   */
  static async(detectors: IDetector[]): SentinelPipeline {
    return new SentinelPipeline('async', detectors);
  }

  /**
   * Set score aggregator (required)
   * 
   * Determines how multiple detection scores are combined.
   * 
   * @param aggregator - Score aggregator instance
   * @returns this for chaining
   * 
   * @example
   * ```typescript
   * pipeline.score(new MaxScoreAggregator())
   * // or
   * pipeline.score(new WeightedAggregator({ 'sql-injection': 1.5 }))
   * ```
   */
  score(aggregator: IScoreAggregator): this {
    this.aggregator = aggregator;
    return this;
  }

  /**
   * Set action resolver (required)
   * 
   * Determines what actions to take based on the threat score.
   * 
   * @param resolver - Action resolver instance
   * @returns this for chaining
   * 
   * @example
   * ```typescript
   * pipeline.resolve(new DefaultResolver({ blockThreshold: 70 }))
   * // or
   * pipeline.resolve(new MultiLevelResolver({ levels: [...] }))
   * ```
   */
  resolve(resolver: IActionResolver): this {
    this.resolver = resolver;
    return this;
  }

  /**
   * Register action handler
   * 
   * Handlers are executed when the resolver returns matching actions.
   * Multiple handlers can be registered for the same action type.
   * 
   * @param actionType - Action type to handle (e.g., ActionType.LOG)
   * @param handler - Handler instance
   * @returns this for chaining
   * 
   * @example
   * ```typescript
   * pipeline
   *   .on(ActionType.LOG, new LogHandler({ console: true }))
   *   .on(ActionType.NOTIFY, new NotifyHandler({ webhookUrl: '...' }))
   *   .on(ActionType.BLOCK, new BlocklistHandler({ kv }))
   *   .on('custom_action', new CustomHandler());
   * ```
   */
  on(actionType: string, handler: IActionHandler): this {
    this.handlers.set(actionType, handler);
    return this;
  }

  /**
   * Process request through pipeline
   * 
   * Runs all request-phase detectors, aggregates scores,
   * resolves actions, and executes handlers.
   * 
   * @param request - Incoming request to analyze
   * @param ctx - Pipeline context with env and ctx bindings
   * @returns Decision (sync mode) or void (async mode)
   * 
   * @throws Error if aggregator or resolver not configured
   * 
   * @example
   * ```typescript
   * const decision = await pipeline.process(request, { env, ctx });
   * if (decision?.has('block')) {
   *   return new Response('Blocked', { status: 403 });
   * }
   * ```
   */
  async process(request: Request, ctx: PipelineContext): Promise<Decision | void> {
    // Validate pipeline configuration
    this.validateConfig();

    // 1. Run request detectors
    const results = await this.runRequestDetectors(request, ctx);

    // 2. Aggregate scores
    const score = this.aggregator.aggregate(results);

    // 3. Resolve actions
    const actions = await this.resolver.resolve({
      score,
      results,
      request,
    });

    // 4. Execute handlers
    const handlerCtx: HandlerContext = {
      ...ctx,
      request,
      score,
      results,
    };
    await this.executeHandlers(actions, handlerCtx);

    // 5. Return based on mode
    if (this.mode === 'sync') {
      return new Decision(actions, score);
    }
    // async mode returns void
  }

  /**
   * Process response through pipeline (for response detection)
   */
  async processResponse(
    request: Request,
    response: Response,
    ctx: PipelineContext
  ): Promise<Decision> {
    // Validate pipeline configuration
    this.validateConfig();

    // 1. Run response detectors
    const results = await this.runResponseDetectors(request, response, ctx);

    // 2. Aggregate scores
    const score = this.aggregator.aggregate(results);

    // 3. Resolve actions
    const actions = await this.resolver.resolve({
      score,
      results,
      request,
      response,
    });

    // 4. Execute handlers
    const handlerCtx: HandlerContext = {
      ...ctx,
      request,
      response,
      score,
      results,
    };
    await this.executeHandlers(actions, handlerCtx);

    // Always return Decision for response detection
    return new Decision(actions, score);
  }

  /**
   * Run all request-phase detectors in parallel
   */
  private async runRequestDetectors(
    request: Request,
    ctx: PipelineContext
  ): Promise<DetectorResult[]> {
    const requestDetectors = this.detectors.filter(
      d => d.phase === 'request' || d.phase === 'both'
    );

    const promises = requestDetectors.map(async detector => {
      try {
        if (detector.detectRequest) {
          const startTime = Date.now();
          const result = await detector.detectRequest(request, ctx);
          if (result) {
            // Add phase and processingTime to metadata
            result.metadata = {
              phase: 'request' as const,
              processingTime: Date.now() - startTime,
              ...result.metadata,
            };
          }
          return result;
        }
        return null;
      } catch (error) {
        console.error(`Detector ${detector.name} error:`, error);
        return null;
      }
    });

    const results = await Promise.all(promises);
    return results.filter((r): r is DetectorResult => r !== null);
  }

  /**
   * Run all response-phase detectors in parallel
   */
  private async runResponseDetectors(
    request: Request,
    response: Response,
    ctx: PipelineContext
  ): Promise<DetectorResult[]> {
    const responseDetectors = this.detectors.filter(
      d => d.phase === 'response' || d.phase === 'both'
    );

    const promises = responseDetectors.map(async detector => {
      try {
        if (detector.detectResponse) {
          const startTime = Date.now();
          const result = await detector.detectResponse(request, response, ctx);
          if (result) {
            // Add phase and processingTime to metadata
            result.metadata = {
              phase: 'response' as const,
              processingTime: Date.now() - startTime,
              ...result.metadata,
            };
          }
          return result;
        }
        return null;
      } catch (error) {
        console.error(`Detector ${detector.name} error:`, error);
        return null;
      }
    });

    const results = await Promise.all(promises);
    return results.filter((r): r is DetectorResult => r !== null);
  }

  /**
   * Execute handlers for matching actions
   */
  private async executeHandlers(
    actions: Action[],
    ctx: HandlerContext
  ): Promise<void> {
    for (const action of actions) {
      const handler = this.handlers.get(action.type);
      if (handler) {
        try {
          await handler.execute(action, ctx);
        } catch (error) {
          console.error(`Handler ${action.type} error:`, error);
        }
      }
    }
  }

  /**
   * Validate pipeline configuration
   */
  private validateConfig(): void {
    if (!this.aggregator) {
      throw new Error('SentinelPipeline: aggregator is required. Call .score()');
    }
    if (!this.resolver) {
      throw new Error('SentinelPipeline: resolver is required. Call .resolve()');
    }
  }
}

/**
 * SentinelPipeline - Core pipeline for security detection
 */

import type { IDetector, DetectorResult } from '../detector/base';
import type { IScoreAggregator } from '../scoring/types';
import type { IActionResolver } from '../resolver/types';
import type { IActionHandler } from '../handler/types';
import type { Action, PipelineContext, HandlerContext } from './types';
import { Decision } from './decision';

type PipelineMode = 'sync' | 'async';

/**
 * SentinelPipeline - Composable security pipeline
 * 
 * @example
 * ```typescript
 * const pipeline = SentinelPipeline.sync([
 *   new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
 *   new SqlInjectionDetector(),
 * ])
 *   .score(new MaxScoreAggregator())
 *   .resolve(new DefaultResolver())
 *   .on('log', new LogHandler())
 *   .on('notify', new SlackHandler());
 * 
 * const decision = await pipeline.process(request, { env, ctx });
 * if (decision.has('block')) {
 *   return new Response('Blocked', { status: 403 });
 * }
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
   * Create SYNC pipeline - returns Decision
   */
  static sync(detectors: IDetector[]): SentinelPipeline {
    return new SentinelPipeline('sync', detectors);
  }

  /**
   * Create ASYNC pipeline - returns void, executes all handlers
   */
  static async(detectors: IDetector[]): SentinelPipeline {
    return new SentinelPipeline('async', detectors);
  }

  /**
   * Set score aggregator
   */
  score(aggregator: IScoreAggregator): this {
    this.aggregator = aggregator;
    return this;
  }

  /**
   * Set action resolver
   */
  resolve(resolver: IActionResolver): this {
    this.resolver = resolver;
    return this;
  }

  /**
   * Register action handler
   */
  on(actionType: string, handler: IActionHandler): this {
    this.handlers.set(actionType, handler);
    return this;
  }

  /**
   * Process request through pipeline
   * 
   * SYNC mode: Returns Decision
   * ASYNC mode: Returns void (executes all handlers)
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

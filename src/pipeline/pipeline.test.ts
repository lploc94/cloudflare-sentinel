/**
 * SentinelPipeline tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { SentinelPipeline } from './pipeline';
import { Decision } from './decision';
import { ActionType } from './types';
import { AttackType, SecuritySeverity } from '../types';
import type { IDetector, DetectorResult } from '../detector/base';
import type { IScoreAggregator } from '../scoring/types';
import type { IActionResolver } from '../resolver/types';
import type { IActionHandler } from '../handler/types';
import type { PipelineContext, ThreatScore, Action } from './types';

// Mock detector
function createMockDetector(result: DetectorResult | null = null): IDetector {
  return {
    name: 'mock-detector',
    phase: 'request',
    detectRequest: vi.fn().mockResolvedValue(result),
  };
}

// Mock aggregator
function createMockAggregator(score: number = 50): IScoreAggregator {
  return {
    name: 'mock-aggregator',
    aggregate: vi.fn().mockReturnValue({
      score,
      level: score >= 80 ? 'critical' : score >= 60 ? 'high' : score >= 40 ? 'medium' : 'low',
      results: [],
    }),
  };
}

// Mock resolver
function createMockResolver(actions: Action[] = []): IActionResolver {
  return {
    name: 'mock-resolver',
    resolve: vi.fn().mockResolvedValue(actions),
  };
}

// Mock handler
function createMockHandler(): IActionHandler {
  return {
    execute: vi.fn().mockResolvedValue(undefined),
  };
}

// Mock context
function createMockContext(): PipelineContext {
  return {
    env: {},
    ctx: { waitUntil: vi.fn() } as unknown as ExecutionContext,
  };
}

describe('SentinelPipeline', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe('Creation', () => {
    it('should create sync pipeline', () => {
      const pipeline = SentinelPipeline.sync([]);
      expect(pipeline).toBeInstanceOf(SentinelPipeline);
    });

    it('should create async pipeline', () => {
      const pipeline = SentinelPipeline.async([]);
      expect(pipeline).toBeInstanceOf(SentinelPipeline);
    });
  });

  describe('Configuration', () => {
    it('should chain score, resolve, on methods', () => {
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator())
        .resolve(createMockResolver())
        .on(ActionType.LOG, createMockHandler());

      expect(pipeline).toBeInstanceOf(SentinelPipeline);
    });

    it('should throw if aggregator not set', async () => {
      const pipeline = SentinelPipeline.sync([])
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      await expect(pipeline.process(request, createMockContext()))
        .rejects.toThrow('aggregator is required');
    });

    it('should throw if resolver not set', async () => {
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator());

      const request = new Request('https://example.com');
      await expect(pipeline.process(request, createMockContext()))
        .rejects.toThrow('resolver is required');
    });
  });

  describe('Sync mode', () => {
    it('should return Decision', async () => {
      const pipeline = SentinelPipeline.sync([createMockDetector()])
        .score(createMockAggregator())
        .resolve(createMockResolver([{ type: ActionType.LOG }]));

      const request = new Request('https://example.com');
      const result = await pipeline.process(request, createMockContext());

      expect(result).toBeInstanceOf(Decision);
    });

    it('should include score in Decision', async () => {
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator(75))
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      const decision = await pipeline.process(request, createMockContext());

      expect(decision).toBeInstanceOf(Decision);
      expect((decision as Decision).score.score).toBe(75);
    });

    it('should run detectors', async () => {
      const detector = createMockDetector();
      const pipeline = SentinelPipeline.sync([detector])
        .score(createMockAggregator())
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      await pipeline.process(request, createMockContext());

      expect(detector.detectRequest).toHaveBeenCalled();
    });

    it('should execute handlers', async () => {
      const handler = createMockHandler();
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator())
        .resolve(createMockResolver([{ type: ActionType.LOG }]))
        .on(ActionType.LOG, handler);

      const request = new Request('https://example.com');
      await pipeline.process(request, createMockContext());

      expect(handler.execute).toHaveBeenCalled();
    });
  });

  describe('Async mode', () => {
    it('should return void', async () => {
      const pipeline = SentinelPipeline.async([])
        .score(createMockAggregator())
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      const result = await pipeline.process(request, createMockContext());

      expect(result).toBeUndefined();
    });

    it('should still execute handlers', async () => {
      const handler = createMockHandler();
      const pipeline = SentinelPipeline.async([])
        .score(createMockAggregator())
        .resolve(createMockResolver([{ type: ActionType.LOG }]))
        .on(ActionType.LOG, handler);

      const request = new Request('https://example.com');
      await pipeline.process(request, createMockContext());

      expect(handler.execute).toHaveBeenCalled();
    });
  });

  describe('Detector filtering', () => {
    it('should only run request-phase detectors in process()', async () => {
      const requestDetector = { ...createMockDetector(), phase: 'request' as const };
      const responseDetector = { ...createMockDetector(), phase: 'response' as const };
      const bothDetector = { ...createMockDetector(), phase: 'both' as const };

      const pipeline = SentinelPipeline.sync([requestDetector, responseDetector, bothDetector])
        .score(createMockAggregator())
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      await pipeline.process(request, createMockContext());

      expect(requestDetector.detectRequest).toHaveBeenCalled();
      expect(responseDetector.detectRequest).not.toHaveBeenCalled();
      expect(bothDetector.detectRequest).toHaveBeenCalled();
    });

    it('should only run response-phase detectors in processResponse()', async () => {
      const requestDetector = { 
        ...createMockDetector(), 
        phase: 'request' as const,
        detectResponse: vi.fn(),
      };
      const responseDetector = { 
        ...createMockDetector(), 
        phase: 'response' as const,
        detectResponse: vi.fn().mockResolvedValue(null),
      };

      const pipeline = SentinelPipeline.sync([requestDetector, responseDetector])
        .score(createMockAggregator())
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      const response = new Response('OK');
      await pipeline.processResponse(request, response, createMockContext());

      expect(requestDetector.detectResponse).not.toHaveBeenCalled();
      expect(responseDetector.detectResponse).toHaveBeenCalled();
    });
  });

  describe('Detection results', () => {
    it('should aggregate detection results', async () => {
      const mockResult: DetectorResult = {
        detected: true,
        attackType: AttackType.SQL_INJECTION,
        severity: SecuritySeverity.HIGH,
        confidence: 0.9,
        detectorName: 'sql-injection',
      };

      const detector = createMockDetector(mockResult);
      const aggregator = createMockAggregator();
      
      const pipeline = SentinelPipeline.sync([detector])
        .score(aggregator)
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      await pipeline.process(request, createMockContext());

      expect(aggregator.aggregate).toHaveBeenCalledWith(
        expect.arrayContaining([
          expect.objectContaining({ attackType: AttackType.SQL_INJECTION }),
        ])
      );
    });

    it('should handle detector errors gracefully', async () => {
      const errorDetector: IDetector = {
        name: 'error-detector',
        phase: 'request',
        detectRequest: vi.fn().mockRejectedValue(new Error('Detector failed')),
      };

      const pipeline = SentinelPipeline.sync([errorDetector])
        .score(createMockAggregator())
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      // Should not throw
      const decision = await pipeline.process(request, createMockContext());
      expect(decision).toBeInstanceOf(Decision);
    });
  });

  describe('Handler execution', () => {
    it('should only execute registered handlers', async () => {
      const logHandler = createMockHandler();
      const notifyHandler = createMockHandler();

      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator())
        .resolve(createMockResolver([
          { type: ActionType.LOG },
          { type: ActionType.NOTIFY },
          { type: ActionType.BLOCK },
        ]))
        .on(ActionType.LOG, logHandler)
        .on(ActionType.NOTIFY, notifyHandler);
      // No BLOCK handler registered

      const request = new Request('https://example.com');
      await pipeline.process(request, createMockContext());

      expect(logHandler.execute).toHaveBeenCalled();
      expect(notifyHandler.execute).toHaveBeenCalled();
    });

    it('should handle handler errors gracefully', async () => {
      const errorHandler: IActionHandler = {
        execute: vi.fn().mockRejectedValue(new Error('Handler failed')),
      };

      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator())
        .resolve(createMockResolver([{ type: ActionType.LOG }]))
        .on(ActionType.LOG, errorHandler);

      const request = new Request('https://example.com');
      // Should not throw
      const decision = await pipeline.process(request, createMockContext());
      expect(decision).toBeInstanceOf(Decision);
    });

    it('should pass correct context to handlers', async () => {
      const handler = createMockHandler();
      
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator(75))
        .resolve(createMockResolver([{ type: ActionType.LOG, data: { test: true } }]))
        .on(ActionType.LOG, handler);

      const request = new Request('https://example.com');
      const ctx = createMockContext();
      await pipeline.process(request, ctx);

      expect(handler.execute).toHaveBeenCalledWith(
        expect.objectContaining({ type: ActionType.LOG, data: { test: true } }),
        expect.objectContaining({ score: expect.objectContaining({ score: 75 }) })
      );
    });
  });

  describe('processResponse', () => {
    it('should always return Decision', async () => {
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator())
        .resolve(createMockResolver());

      const request = new Request('https://example.com');
      const response = new Response('OK');
      const decision = await pipeline.processResponse(request, response, createMockContext());

      expect(decision).toBeInstanceOf(Decision);
    });

    it('should pass response to resolver', async () => {
      const resolver = createMockResolver();
      
      const pipeline = SentinelPipeline.sync([])
        .score(createMockAggregator())
        .resolve(resolver);

      const request = new Request('https://example.com');
      const response = new Response('OK');
      await pipeline.processResponse(request, response, createMockContext());

      expect(resolver.resolve).toHaveBeenCalledWith(
        expect.objectContaining({ response })
      );
    });
  });
});

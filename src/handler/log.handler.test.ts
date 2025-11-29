/**
 * Log Handler tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LogHandler } from './log.handler';
import { AttackType, SecuritySeverity } from '../types';
import type { HandlerContext, Action } from '../pipeline/types';

function createMockContext(overrides: Partial<HandlerContext> = {}): HandlerContext {
  return {
    env: {},
    ctx: { waitUntil: vi.fn() } as unknown as ExecutionContext,
    score: {
      score: 75,
      level: 'high',
      results: [],
    },
    results: [
      {
        detected: true,
        attackType: AttackType.SQL_INJECTION,
        severity: SecuritySeverity.HIGH,
        confidence: 0.95,
        detectorName: 'sql-injection',
      },
    ],
    ...overrides,
  };
}

describe('LogHandler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
  });

  describe('Console logging', () => {
    it('should log to console by default', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.log).toHaveBeenCalled();
    });

    it('should not log when console is disabled', async () => {
      const handler = new LogHandler({ console: false });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.log).not.toHaveBeenCalled();
    });

    it('should use custom prefix', async () => {
      const handler = new LogHandler({ prefix: '[WAF]' });
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.log).toHaveBeenCalledWith('[WAF]', expect.any(Object));
    });

    it('should use default prefix [Sentinel]', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.log).toHaveBeenCalledWith('[Sentinel]', expect.any(Object));
    });
  });

  describe('Log levels', () => {
    it('should use console.error for error level', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log', data: { level: 'error' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.error).toHaveBeenCalled();
    });

    it('should use console.warn for warn level', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log', data: { level: 'warn' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.warn).toHaveBeenCalled();
    });

    it('should use console.log for info level', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log', data: { level: 'info' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(console.log).toHaveBeenCalled();
    });
  });

  describe('Log entry', () => {
    it('should include score and threat level', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const logCall = (console.log as any).mock.calls[0];
      const logEntry = logCall[1];
      
      expect(logEntry.score).toBe(75);
      expect(logEntry.threatLevel).toBe('high');
      expect(logEntry.detections).toBe(1);
      expect(logEntry.timestamp).toBeDefined();
    });

    it('should include custom data from action', async () => {
      const handler = new LogHandler();
      const action: Action = { type: 'log', data: { customField: 'value' } };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const logCall = (console.log as any).mock.calls[0];
      const logEntry = logCall[1];
      
      expect(logEntry.customField).toBe('value');
    });
  });
});

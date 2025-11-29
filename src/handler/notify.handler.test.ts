/**
 * Notify Handler tests
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { NotifyHandler } from './notify.handler';
import { AttackType, SecuritySeverity } from '../types';
import type { HandlerContext, Action } from '../pipeline/types';

function createMockContext(overrides: Partial<HandlerContext> = {}): HandlerContext {
  return {
    env: { SLACK_WEBHOOK: 'https://hooks.slack.com/test' },
    ctx: { waitUntil: vi.fn() } as unknown as ExecutionContext,
    score: {
      score: 85,
      level: 'critical',
      results: [],
    },
    results: [
      {
        detected: true,
        attackType: AttackType.SQL_INJECTION,
        severity: SecuritySeverity.CRITICAL,
        confidence: 0.99,
        detectorName: 'sql-injection',
      },
    ],
    request: new Request('https://example.com/api/test', {
      headers: { 'cf-connecting-ip': '192.168.1.100' },
    }),
    ...overrides,
  };
}

describe('NotifyHandler', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(console, 'warn').mockImplementation(() => {});
    vi.spyOn(console, 'error').mockImplementation(() => {});
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: true }));
  });

  describe('Webhook URL', () => {
    it('should send to configured webhookUrl', async () => {
      const handler = new NotifyHandler({ webhookUrl: 'https://webhook.example.com' });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(fetch).toHaveBeenCalledWith(
        'https://webhook.example.com',
        expect.objectContaining({ method: 'POST' })
      );
    });

    it('should use webhookEnvKey to get URL from env', async () => {
      const handler = new NotifyHandler({ webhookEnvKey: 'SLACK_WEBHOOK' });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(fetch).toHaveBeenCalledWith(
        'https://hooks.slack.com/test',
        expect.any(Object)
      );
    });

    it('should warn when no webhook URL configured', async () => {
      const handler = new NotifyHandler({});
      const action: Action = { type: 'notify' };
      const ctx = createMockContext({ env: {} });

      await handler.execute(action, ctx);

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining('No webhook URL')
      );
      expect(fetch).not.toHaveBeenCalled();
    });
  });

  describe('Payload', () => {
    it('should include score and threat level', async () => {
      const handler = new NotifyHandler({ webhookUrl: 'https://webhook.example.com' });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const fetchCall = (fetch as any).mock.calls[0];
      const body = JSON.parse(fetchCall[1].body);
      
      expect(body.score).toBe(85);
      expect(body.threatLevel).toBe('critical');
    });

    it('should include detections', async () => {
      const handler = new NotifyHandler({ webhookUrl: 'https://webhook.example.com' });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const fetchCall = (fetch as any).mock.calls[0];
      const body = JSON.parse(fetchCall[1].body);
      
      expect(body.detections).toHaveLength(1);
      expect(body.detections[0].type).toBe(AttackType.SQL_INJECTION);
    });

    it('should include request info', async () => {
      const handler = new NotifyHandler({ webhookUrl: 'https://webhook.example.com' });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const fetchCall = (fetch as any).mock.calls[0];
      const body = JSON.parse(fetchCall[1].body);
      
      expect(body.request.url).toBe('https://example.com/api/test');
      expect(body.request.ip).toBe('192.168.1.100');
    });

    it('should include custom headers', async () => {
      const handler = new NotifyHandler({
        webhookUrl: 'https://webhook.example.com',
        headers: { 'X-Custom': 'value' },
      });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      const fetchCall = (fetch as any).mock.calls[0];
      expect(fetchCall[1].headers['X-Custom']).toBe('value');
    });
  });

  describe('Retry logic', () => {
    it('should retry on failure', async () => {
      vi.stubGlobal('fetch', vi.fn()
        .mockResolvedValueOnce({ ok: false, status: 500 })
        .mockResolvedValueOnce({ ok: true }));

      const handler = new NotifyHandler({
        webhookUrl: 'https://webhook.example.com',
        retries: 1,
      });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(fetch).toHaveBeenCalledTimes(2);
    });

    it('should not retry when retries is 0', async () => {
      vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 500 }));

      const handler = new NotifyHandler({
        webhookUrl: 'https://webhook.example.com',
        retries: 0,
      });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(fetch).toHaveBeenCalledTimes(1);
    });

    it('should retry on network error', async () => {
      vi.stubGlobal('fetch', vi.fn()
        .mockRejectedValueOnce(new Error('Network error'))
        .mockResolvedValueOnce({ ok: true }));

      const handler = new NotifyHandler({
        webhookUrl: 'https://webhook.example.com',
        retries: 1,
      });
      const action: Action = { type: 'notify' };
      const ctx = createMockContext();

      await handler.execute(action, ctx);

      expect(fetch).toHaveBeenCalledTimes(2);
    });
  });
});

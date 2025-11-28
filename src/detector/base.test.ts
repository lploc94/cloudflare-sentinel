/**
 * Unit tests for BaseDetector
 */

import { describe, it, expect } from 'vitest';
import { BaseDetector } from './base';
import { AttackType, SecuritySeverity } from '../types';
import type { DetectorResult } from './base';

class TestDetector extends BaseDetector {
  name = 'test-detector';
  priority = 100;

  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    const url = new URL(request.url);
    
    if (url.searchParams.has('malicious')) {
      return this.createResult(
        AttackType.SUSPICIOUS_PATTERN,
        SecuritySeverity.HIGH,
        0.9,
        {
          field: 'query',
          value: url.searchParams.get('malicious') || '',
          pattern: 'malicious parameter',
        }
      );
    }

    return null;
  }

  async detectResponse(
    request: Request,
    response: Response,
    context: any
  ): Promise<DetectorResult | null> {
    if (response.status === 500) {
      return this.createResult(
        AttackType.LOGIC_ABUSE,
        SecuritySeverity.MEDIUM,
        0.7,
        { field: 'status_code', value: '500' }
      );
    }

    return null;
  }
}

describe('BaseDetector', () => {
  describe('detectRequest', () => {
    it('should detect attack in request', async () => {
      const detector = new TestDetector();
      const request = new Request('https://example.com?malicious=true');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
      expect(result?.attackType).toBe(AttackType.SUSPICIOUS_PATTERN);
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
      expect(result?.confidence).toBe(0.9);
      expect(result?.evidence).toEqual({
        field: 'query',
        value: 'true',
        pattern: 'malicious parameter',
      });
    });

    it('should return null when no attack detected', async () => {
      const detector = new TestDetector();
      const request = new Request('https://example.com?safe=true');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('detectResponse', () => {
    it('should detect attack in response', async () => {
      const detector = new TestDetector();
      const request = new Request('https://example.com');
      const response = new Response('Error', { status: 500 });

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
      expect(result?.attackType).toBe(AttackType.LOGIC_ABUSE);
      expect(result?.severity).toBe(SecuritySeverity.MEDIUM);
      expect(result?.confidence).toBe(0.7);
    });

    it('should return null for normal responses', async () => {
      const detector = new TestDetector();
      const request = new Request('https://example.com');
      const response = new Response('OK', { status: 200 });

      const result = await detector.detectResponse(request, response, {});

      expect(result).toBeNull();
    });
  });

  describe('createResult', () => {
    it('should create detection result with all fields', () => {
      const detector = new TestDetector();

      const result = detector['createResult'](
        AttackType.SQL_INJECTION,
        SecuritySeverity.CRITICAL,
        1.0,
        { field: 'query', value: "'; DROP TABLE users--" },
        { dbType: 'postgres' }
      );

      expect(result.detected).toBe(true);
      expect(result.detectorName).toBe('test-detector');
      expect(result.attackType).toBe(AttackType.SQL_INJECTION);
      expect(result.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result.confidence).toBe(1.0);
      expect(result.evidence).toEqual({
        field: 'query',
        value: "'; DROP TABLE users--",
      });
      expect(result.metadata?.dbType).toBe('postgres');
      expect(result.metadata?.timestamp).toBeTypeOf('number');
    });

    it('should create result without optional fields', () => {
      const detector = new TestDetector();

      const result = detector['createResult'](
        AttackType.XSS,
        SecuritySeverity.HIGH,
        0.85
      );

      expect(result.detected).toBe(true);
      expect(result.detectorName).toBe('test-detector');
      expect(result.attackType).toBe(AttackType.XSS);
      expect(result.severity).toBe(SecuritySeverity.HIGH);
      expect(result.confidence).toBe(0.85);
      expect(result.metadata?.timestamp).toBeTypeOf('number');
    });
  });

  describe('enabled flag', () => {
    it('should be enabled by default', () => {
      const detector = new TestDetector();
      expect(detector.enabled).toBe(true);
    });

    it('should respect disabled flag', () => {
      const detector = new TestDetector();
      detector.enabled = false;
      expect(detector.enabled).toBe(false);
    });
  });

  describe('priority', () => {
    it('should have configurable priority', () => {
      const detector = new TestDetector();
      expect(detector.priority).toBe(100);
    });
  });
});

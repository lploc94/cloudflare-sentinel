/**
 * Unit tests for SQL Injection Detectors
 */

import { describe, it, expect } from 'vitest';
import { SQLInjectionRequestDetector } from './sql-injection.request.detector';
import { SQLInjectionResponseDetector } from './sql-injection.response.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('SQLInjectionRequestDetector', () => {
  const detector = new SQLInjectionRequestDetector();

  describe('detectRequest', () => {
    it('should detect classic OR 1=1 injection with quote', async () => {
      // Real SQL injection needs quote to break out of string context
      const request = new Request("https://example.com?id=' OR '1'='1");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SQL_INJECTION);
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
      expect(result?.confidence).toBeGreaterThan(0.9);
    });

    it('should detect UNION SELECT injection', async () => {
      const request = new Request('https://example.com?id=1 UNION SELECT * FROM users');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SQL_INJECTION);
      expect(result?.confidence).toBeGreaterThanOrEqual(0.95);
    });

    it('should detect DROP TABLE injection', async () => {
      const request = new Request("https://example.com?id=1; DROP TABLE users");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.confidence).toBeGreaterThan(0.95);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect URL-encoded injection', async () => {
      // URL-encoded: ' OR '1'='1
      const request = new Request("https://example.com?id=%27%20OR%20%271%27%3D%271");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SQL_INJECTION);
    });

    it('should detect SQL comments with context', async () => {
      // Comment after quote - actual injection pattern
      const request = new Request("https://example.com?id=admin'--");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SQL_INJECTION);
    });

    it('should detect time-based blind injection', async () => {
      const request = new Request('https://example.com?id=1 AND SLEEP(5)');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.confidence).toBeGreaterThan(0.85);
    });

    it('should not detect normal queries', async () => {
      const request = new Request('https://example.com?id=123&name=john');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect safe strings with OR/AND', async () => {
      const request = new Request('https://example.com?search=California');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should detect injection in POST body', async () => {
      const request = new Request('https://example.com/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: "admin' OR '1'='1" }),
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('body');
    });

    it('should sanitize sensitive data in evidence', async () => {
      // Injection pattern that contains password - will be masked in evidence
      const request = new Request("https://example.com?query=' OR '1'='1 password=secret123");
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      // Password should be masked in the evidence value
      expect(result?.evidence?.value).toContain('password=***');
    });
  });

  describe('priority and name', () => {
    it('should have correct priority', () => {
      expect(detector.priority).toBe(100);
    });

    it('should have correct name', () => {
      expect(detector.name).toBe('sql-injection-request');
    });
  });
});

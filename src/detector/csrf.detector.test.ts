/**
 * CSRF Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { CSRFDetector } from './csrf.detector';
import { AttackType, SecuritySeverity } from '../types';

// Helper to create request with headers
const createRequest = (
  url: string,
  method: string,
  headers: Record<string, string> = {}
) => new Request(url, { method, headers });

describe('CSRFDetector', () => {
  describe('Safe methods', () => {
    it('should skip GET requests', async () => {
      const detector = new CSRFDetector({ mode: 'strict' });
      const request = createRequest('https://example.com/api', 'GET');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should skip HEAD requests', async () => {
      const detector = new CSRFDetector({ mode: 'strict' });
      const request = createRequest('https://example.com/api', 'HEAD');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should skip OPTIONS requests', async () => {
      const detector = new CSRFDetector({ mode: 'strict' });
      const request = createRequest('https://example.com/api', 'OPTIONS');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Same-origin requests', () => {
    it('should allow same-origin POST', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://example.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow same-origin with port', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com:8080/api', 'POST', {
        'origin': 'https://example.com:8080',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Cross-origin detection', () => {
    it('should detect cross-origin POST', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://evil.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.CSRF);
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
      expect(result?.metadata?.reason).toBe('origin_mismatch');
    });

    it('should detect cross-origin PUT', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com/api', 'PUT', {
        'origin': 'https://attacker.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.CSRF);
    });

    it('should detect cross-origin DELETE', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com/api', 'DELETE', {
        'origin': 'https://malicious.site',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should include origins in evidence', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://api.example.com/users', 'POST', {
        'origin': 'https://phishing.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result?.evidence?.value).toBe('https://phishing.com');
      expect(result?.metadata?.sourceOrigin).toBe('https://phishing.com');
      expect(result?.metadata?.requestOrigin).toBe('https://api.example.com');
    });
  });

  describe('Referer fallback', () => {
    it('should use Referer when Origin missing', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com/api', 'POST', {
        'referer': 'https://evil.com/page',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('referer_mismatch');
    });

    it('should allow same-origin via Referer', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://example.com/api', 'POST', {
        'referer': 'https://example.com/form',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Strict mode', () => {
    it('should block missing Origin in strict mode', async () => {
      const detector = new CSRFDetector({ mode: 'strict' });
      const request = createRequest('https://example.com/api', 'POST');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.MEDIUM);
      expect(result?.metadata?.reason).toBe('missing_origin');
    });

    it('should block null Origin in strict mode', async () => {
      const detector = new CSRFDetector({ mode: 'strict' });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'null',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('null_origin');
    });
  });

  describe('Standard mode', () => {
    it('should allow missing Origin in standard mode', async () => {
      const detector = new CSRFDetector({ mode: 'standard' });
      const request = createRequest('https://example.com/api', 'POST');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow null Origin in standard mode', async () => {
      const detector = new CSRFDetector({ mode: 'standard' });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'null',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Allowed origins', () => {
    it('should allow configured origins', async () => {
      const detector = new CSRFDetector({
        allowedOrigins: ['https://trusted.com', 'https://partner.com'],
      });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://trusted.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should block non-allowed origins', async () => {
      const detector = new CSRFDetector({
        allowedOrigins: ['https://trusted.com'],
      });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://untrusted.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Same parent domain', () => {
    it('should allow subdomains by default', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://api.example.com/users', 'POST', {
        'origin': 'https://www.example.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow different subdomains', async () => {
      const detector = new CSRFDetector();
      const request = createRequest('https://api.example.com/data', 'POST', {
        'origin': 'https://admin.example.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should block when allowSameParentDomain is false', async () => {
      const detector = new CSRFDetector({ allowSameParentDomain: false });
      const request = createRequest('https://api.example.com/users', 'POST', {
        'origin': 'https://www.example.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Custom header requirement', () => {
    it('should detect missing custom header', async () => {
      const detector = new CSRFDetector({
        requireCustomHeader: true,
      });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://example.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.LOW);
      expect(result?.metadata?.reason).toBe('missing_custom_header');
    });

    it('should allow with custom header present', async () => {
      const detector = new CSRFDetector({
        requireCustomHeader: true,
      });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://example.com',
        'x-requested-with': 'XMLHttpRequest',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should use custom header name', async () => {
      const detector = new CSRFDetector({
        requireCustomHeader: true,
        customHeaderName: 'x-csrf-check',
      });
      const request = createRequest('https://example.com/api', 'POST', {
        'origin': 'https://example.com',
        'x-csrf-check': 'true',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Protected methods configuration', () => {
    it('should only protect configured methods', async () => {
      const detector = new CSRFDetector({
        protectedMethods: ['DELETE'],
        mode: 'strict',
      });

      // POST should be allowed (not in protected list)
      const postRequest = createRequest('https://example.com/api', 'POST');
      const postResult = await detector.detectRequest(postRequest, {});
      expect(postResult).toBeNull();

      // DELETE should be checked
      const deleteRequest = createRequest('https://example.com/api', 'DELETE');
      const deleteResult = await detector.detectRequest(deleteRequest, {});
      expect(deleteResult).not.toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      const detector = new CSRFDetector();

      expect(detector.name).toBe('csrf');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(90);
    });

    it('should default to standard mode', async () => {
      const detector = new CSRFDetector();
      // Missing origin should be allowed in standard mode
      const request = createRequest('https://example.com/api', 'POST');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });
});

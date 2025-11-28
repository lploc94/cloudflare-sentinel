/**
 * XSS Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { XSSRequestDetector } from './xss.request.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('XSSRequestDetector', () => {
  const detector = new XSSRequestDetector();

  describe('Script injection', () => {
    it('should detect script tags', async () => {
      const request = new Request('https://example.com?q=<script>alert(1)</script>');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.XSS);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect script tag open', async () => {
      const request = new Request('https://example.com?q=<script src="evil.js">');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.confidence).toBeGreaterThanOrEqual(0.95);
    });
  });

  describe('Event handlers', () => {
    it('should detect onload handler', async () => {
      const request = new Request('https://example.com?q=<img onload="alert(1)">');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.XSS);
    });

    it('should detect onerror handler', async () => {
      const request = new Request('https://example.com?q=<img onerror=alert(1)>');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect onclick handler', async () => {
      const request = new Request('https://example.com?q=<div onclick="evil()">');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Protocol handlers', () => {
    it('should detect javascript: protocol', async () => {
      const request = new Request('https://example.com?url=javascript:alert(1)');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect vbscript: protocol', async () => {
      const request = new Request('https://example.com?url=vbscript:msgbox(1)');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('HTML injection', () => {
    it('should detect iframe injection', async () => {
      const request = new Request('https://example.com?q=<iframe src="evil.html">');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect object tag', async () => {
      const request = new Request('https://example.com?q=<object data="evil.swf">');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('SVG-based XSS', () => {
    it('should detect SVG with event handler', async () => {
      const request = new Request('https://example.com?q=<svg onload="alert(1)">');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect SVG with script', async () => {
      const request = new Request('https://example.com?q=<svg><script>alert(1)</script></svg>');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Encoding bypasses', () => {
    it('should detect URL-encoded script tag', async () => {
      const request = new Request('https://example.com?q=%3Cscript%3Ealert(1)%3C/script%3E');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect double URL-encoded', async () => {
      const request = new Request('https://example.com?q=%253Cscript%253E');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('POST body', () => {
    it('should detect XSS in JSON body', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ comment: '<script>alert(1)</script>' }),
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('body');
    });

    it('should detect XSS in form body', async () => {
      const request = new Request('https://example.com/submit', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'comment=<script>alert(1)</script>',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Safe input', () => {
    it('should not detect normal text', async () => {
      const request = new Request('https://example.com?q=hello world');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect safe HTML entities', async () => {
      const request = new Request('https://example.com?q=1 &lt; 2');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should exclude specified fields', async () => {
      const detector = new XSSRequestDetector({ excludeFields: ['html_content'] });
      const request = new Request('https://example.com?html_content=<script>alert(1)</script>');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should have correct name and phase', () => {
      expect(detector.name).toBe('xss-request');
      expect(detector.phase).toBe('request');
    });
  });
});

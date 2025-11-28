/**
 * Open Redirect Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { OpenRedirectDetector } from './open-redirect.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('OpenRedirectDetector', () => {
  const detector = new OpenRedirectDetector();

  describe('External Redirect Detection', () => {
    it('should detect redirect to external domain', async () => {
      const request = new Request('https://example.com/login?redirect=https://evil.com/phishing');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.OPEN_REDIRECT);
      expect(result?.metadata?.reason).toBe('external_redirect');
    });

    it('should detect redirect with url parameter', async () => {
      const request = new Request('https://example.com/out?url=https://malicious.site');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect redirect with return_url parameter', async () => {
      const request = new Request('https://example.com/auth?return_url=https://attacker.com');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect redirect with next parameter', async () => {
      const request = new Request('https://example.com/login?next=https://phishing.site/fake');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Dangerous Protocol Detection', () => {
    it('should detect javascript: protocol', async () => {
      const request = new Request('https://example.com/redirect?url=javascript:alert(1)');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('dangerous_pattern');
    });

    it('should detect vbscript: protocol', async () => {
      const request = new Request('https://example.com/redirect?url=vbscript:msgbox(1)');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect data: URL', async () => {
      const request = new Request('https://example.com/redirect?url=data:text/html,<script>alert(1)</script>');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });
  });

  describe('Protocol-relative URL Detection', () => {
    it('should detect //evil.com', async () => {
      const request = new Request('https://example.com/redirect?url=//evil.com/path');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });
  });

  describe('URL Bypass Tricks', () => {
    it('should detect backslash trick', async () => {
      const request = new Request('https://example.com/redirect?url=/\\evil.com');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect @ credential trick', async () => {
      const request = new Request('https://example.com/redirect?url=https://example.com@evil.com');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect null byte injection', async () => {
      const request = new Request('https://example.com/redirect?url=https://evil.com%00.example.com');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('URL Encoding Bypass', () => {
    it('should detect URL-encoded redirect', async () => {
      const request = new Request(
        'https://example.com/redirect?url=' + encodeURIComponent('https://evil.com')
      );
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect double URL-encoded redirect', async () => {
      const request = new Request(
        'https://example.com/redirect?url=' + encodeURIComponent(encodeURIComponent('https://evil.com'))
      );
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('POST Body Detection', () => {
    it('should detect redirect in form body', async () => {
      const request = new Request('https://example.com/login', {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: 'username=test&redirect=https://evil.com',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('form.redirect');
    });

    it('should detect redirect in JSON body', async () => {
      const request = new Request('https://example.com/api/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username: 'test', return_url: 'https://evil.com' }),
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Safe Redirects', () => {
    it('should allow same-host redirect', async () => {
      const request = new Request('https://example.com/login?redirect=https://example.com/dashboard');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow relative URL by default', async () => {
      const request = new Request('https://example.com/login?redirect=/dashboard');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow ./relative URL', async () => {
      const request = new Request('https://example.com/login?redirect=./profile');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow ../relative URL', async () => {
      const request = new Request('https://example.com/auth/login?redirect=../home');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow same parent domain by default', async () => {
      const request = new Request('https://app.example.com/login?redirect=https://api.example.com/callback');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not flag non-redirect parameters', async () => {
      const request = new Request('https://example.com/search?q=https://evil.com');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Allowed Domains', () => {
    it('should allow configured domains', async () => {
      const detector = new OpenRedirectDetector({
        allowedDomains: ['trusted-partner.com', 'auth.example.org'],
      });
      const request = new Request('https://example.com/redirect?url=https://trusted-partner.com/callback');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should block non-allowed domains', async () => {
      const detector = new OpenRedirectDetector({
        allowedDomains: ['trusted-partner.com'],
      });
      const request = new Request('https://example.com/redirect?url=https://untrusted.com');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Same Parent Domain', () => {
    it('should block subdomain when disabled', async () => {
      const detector = new OpenRedirectDetector({
        allowSameParentDomain: false,
      });
      const request = new Request('https://app.example.com/redirect?url=https://api.example.com');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Strict Mode', () => {
    it('should flag all external redirects in strict mode', async () => {
      const detector = new OpenRedirectDetector({
        strictMode: true,
        allowSameParentDomain: false,
      });
      const request = new Request('https://example.com/redirect?url=https://any-external.com');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });
  });

  describe('Custom Parameter Names', () => {
    it('should check custom parameters', async () => {
      const detector = new OpenRedirectDetector({
        parameterNames: ['custom_redirect', 'my_url'],
      });
      const request = new Request('https://example.com/auth?custom_redirect=https://evil.com');

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should not check default parameters when custom provided', async () => {
      const detector = new OpenRedirectDetector({
        parameterNames: ['custom_redirect'],
      });
      const request = new Request('https://example.com/auth?redirect=https://evil.com');

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('open-redirect');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(85);
    });
  });
});

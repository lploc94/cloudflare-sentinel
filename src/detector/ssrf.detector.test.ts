/**
 * SSRF Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { SSRFDetector } from './ssrf.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('SSRFDetector', () => {
  describe('Internal IP Detection', () => {
    it('should detect localhost', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://localhost/admin', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.SSRF);
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect 127.0.0.1', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://127.0.0.1:8080', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect private IP 10.x.x.x', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://10.0.0.1/internal', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect private IP 192.168.x.x', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://192.168.1.1', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect private IP 172.16-31.x.x', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://172.16.0.1', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('Cloud Metadata Endpoints', () => {
    it('should detect AWS metadata endpoint', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://169.254.169.254/latest/meta-data/', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect GCP metadata endpoint', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://metadata.google.internal/computeMetadata/v1/', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('Dangerous URL Schemes', () => {
    it('should detect file:// scheme', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?path=file:///etc/passwd', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect gopher:// scheme', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=gopher://localhost:25/', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect dict:// scheme', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=dict://localhost:11211/', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('SSRF Bypass Techniques', () => {
    it('should detect DNS rebinding services', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http://127.0.0.1.nip.io/admin', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect URL encoded bypass', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=http:%2f%2flocalhost', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('JSON Body Detection', () => {
    it('should detect SSRF in JSON body', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com/api/webhook', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ callback_url: 'http://169.254.169.254/latest/' }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('Exclusions', () => {
    it('should allow localhost when configured', async () => {
      const detector = new SSRFDetector({ allowLocalhost: true });
      const request = new Request('https://example.com?url=http://localhost/api', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });

    it('should exclude specified paths', async () => {
      const detector = new SSRFDetector({ excludePaths: ['/webhook/*'] });
      const request = new Request('https://example.com/webhook/test?url=http://localhost', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });
  });

  describe('Safe Input', () => {
    it('should not detect public URLs', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?url=https://api.github.com/users', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });

    it('should not detect normal text', async () => {
      const detector = new SSRFDetector();
      const request = new Request('https://example.com?name=localhost_user', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });
  });
});

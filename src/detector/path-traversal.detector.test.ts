/**
 * Path Traversal Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { PathTraversalRequestDetector } from './path-traversal.request.detector';
import { PathTraversalResponseDetector } from './path-traversal.response.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('PathTraversalRequestDetector', () => {
  const detector = new PathTraversalRequestDetector();

  describe('Basic traversal patterns', () => {
    it('should detect ../ pattern', async () => {
      const request = new Request('https://example.com?file=../../../etc/passwd');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.PATH_TRAVERSAL);
    });

    it('should detect ..\\ pattern (Windows)', async () => {
      const request = new Request('https://example.com?file=..\\..\\windows\\system32');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect absolute path /etc/passwd', async () => {
      const request = new Request('https://example.com?file=/etc/passwd');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('Encoding bypasses', () => {
    it('should detect URL-encoded traversal', async () => {
      const request = new Request('https://example.com?file=%2e%2e%2f%2e%2e%2fetc/passwd');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect double URL-encoded', async () => {
      const request = new Request('https://example.com?file=%252e%252e%252f');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Sensitive files', () => {
    it('should detect /etc/shadow access', async () => {
      const request = new Request('https://example.com?file=/etc/shadow');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect Windows system files', async () => {
      const request = new Request('https://example.com?file=c:\\windows\\system.ini');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect .env file access', async () => {
      const request = new Request('https://example.com?file=../../.env');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('LFI wrappers', () => {
    it('should detect php://filter', async () => {
      const request = new Request('https://example.com?file=php://filter/convert.base64-encode/resource=index.php');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect file:// protocol', async () => {
      const request = new Request('https://example.com?file=file:///etc/passwd');
      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('POST body', () => {
    it('should detect traversal in JSON body', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ path: '../../../etc/passwd' }),
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Safe input', () => {
    it('should not detect normal file paths', async () => {
      const request = new Request('https://example.com?file=images/photo.jpg');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should not detect relative paths without traversal', async () => {
      const request = new Request('https://example.com?file=docs/readme.txt');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('path-traversal-request');
      expect(detector.phase).toBe('request');
    });
  });
});

describe('PathTraversalResponseDetector', () => {
  const detector = new PathTraversalResponseDetector();

  describe('Directory listing detection', () => {
    it('should detect Apache directory listing', async () => {
      const request = new Request('https://example.com/files/');
      const response = new Response('<title>Index of /files</title><h1>Index of /files</h1>');

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.PATH_TRAVERSAL);
    });

    it('should detect Nginx directory listing', async () => {
      const request = new Request('https://example.com/dir/');
      const response = new Response('<html><head><title>Index of /dir/</title></head>');

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Sensitive file content detection', () => {
    it('should detect /etc/passwd content', async () => {
      const request = new Request('https://example.com/file');
      const response = new Response('root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin');

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect /etc/shadow content', async () => {
      const request = new Request('https://example.com/file');
      const response = new Response('root:$6$hash:18000:0:99999:7:::');

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
    });

    it('should detect .env file content', async () => {
      const request = new Request('https://example.com/file');
      const response = new Response('DATABASE_URL=postgres://user:pass@localhost\nSECRET_KEY=abc123');

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
    });

    it('should detect SSH private key', async () => {
      const request = new Request('https://example.com/file');
      const response = new Response('-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...');

      const result = await detector.detectResponse(request, response, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('Safe responses', () => {
    it('should not detect normal HTML', async () => {
      const request = new Request('https://example.com/page');
      const response = new Response('<html><body><h1>Welcome</h1></body></html>');

      const result = await detector.detectResponse(request, response, {});

      expect(result).toBeNull();
    });

    it('should not detect normal JSON', async () => {
      const request = new Request('https://example.com/api');
      const response = new Response('{"status":"ok","data":[]}', {
        headers: { 'content-type': 'application/json' },
      });

      const result = await detector.detectResponse(request, response, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('path-traversal-response');
      expect(detector.phase).toBe('response');
    });
  });
});

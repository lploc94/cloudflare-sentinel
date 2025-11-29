import { describe, it, expect } from 'vitest';
import { MLDetector } from './ml.detector';

describe('MLDetector', () => {
  const detector = new MLDetector();

  // Helper to create mock request and context
  const createRequest = (method: string, url: string, body?: string) => {
    return {
      request: new Request(url, { method }),
      context: body ? { body } : {},
    };
  };

  describe('Safe requests', () => {
    const safeRequests = [
      { method: 'GET', url: 'https://api.example.com/users?page=1&limit=10' },
      { method: 'GET', url: 'https://api.example.com/health' },
      { method: 'GET', url: 'https://api.example.com/products/123' },
      { method: 'POST', url: 'https://api.example.com/auth/login', body: 'username=john&password=secret123' },
      { method: 'DELETE', url: 'https://api.example.com/cart/456' },
      { method: 'PUT', url: 'https://api.example.com/users/123?status=active' },
    ];

    safeRequests.forEach(({ method, url, body }) => {
      it(`should NOT detect: ${method} ${new URL(url).pathname}`, async () => {
        const { request, context } = createRequest(method, url, body);
        const result = await detector.detectRequest(request, context);
        
        // Safe requests should return null (no detection)
        expect(result).toBeNull();
      });
    });
  });

  describe('Suspicious requests - SQL Injection', () => {
    const sqliRequests = [
      { method: 'GET', url: "https://api.example.com/users?id=1' OR '1'='1" },
      { method: 'GET', url: "https://api.example.com/search?q=' UNION SELECT * FROM users--" },
      { method: 'POST', url: 'https://api.example.com/login', body: "username=admin'--&password=x" },
    ];

    sqliRequests.forEach(({ method, url, body }) => {
      it(`should detect SQLi: ${method} ${new URL(url).pathname}`, async () => {
        const { request, context } = createRequest(method, url, body);
        const result = await detector.detectRequest(request, context);
        
        expect(result).not.toBeNull();
        expect(result?.detected).toBe(true);
        expect(result?.confidence).toBeGreaterThan(0);
      });
    });
  });

  describe('Suspicious requests - XSS', () => {
    const xssRequests = [
      { method: 'GET', url: 'https://api.example.com/search?q=<script>alert(1)</script>' },
      { method: 'POST', url: 'https://api.example.com/comment', body: 'text=<img src=x onerror=alert(1)>' },
    ];

    xssRequests.forEach(({ method, url, body }) => {
      it(`should detect XSS: ${method} ${new URL(url).pathname}`, async () => {
        const { request, context } = createRequest(method, url, body);
        const result = await detector.detectRequest(request, context);
        
        expect(result).not.toBeNull();
        expect(result?.detected).toBe(true);
      });
    });
  });

  describe('Suspicious requests - Path Traversal', () => {
    const pathTraversalRequests = [
      { method: 'GET', url: 'https://api.example.com/file?path=../../../etc/passwd' },
      { method: 'GET', url: 'https://api.example.com/download?file=....//....//etc/shadow' },
    ];

    pathTraversalRequests.forEach(({ method, url }) => {
      it(`should detect Path Traversal: ${new URL(url).search}`, async () => {
        const { request, context } = createRequest(method, url);
        const result = await detector.detectRequest(request, context);
        
        expect(result).not.toBeNull();
        expect(result?.detected).toBe(true);
      });
    });
  });

  describe('Suspicious requests - Command Injection', () => {
    const cmdRequests = [
      { method: 'GET', url: 'https://api.example.com/ping?host=; cat /etc/passwd' },
      { method: 'POST', url: 'https://api.example.com/exec', body: 'cmd=$(cat /etc/passwd)' },
    ];

    cmdRequests.forEach(({ method, url, body }) => {
      it(`should detect Command Injection`, async () => {
        const { request, context } = createRequest(method, url, body);
        const result = await detector.detectRequest(request, context);
        
        expect(result).not.toBeNull();
        expect(result?.detected).toBe(true);
      });
    });
  });

  describe('Suspicious requests - SSRF', () => {
    const ssrfRequests = [
      { method: 'GET', url: 'https://api.example.com/fetch?url=http://169.254.169.254/latest/meta-data/' },
      { method: 'GET', url: 'https://api.example.com/proxy?target=http://localhost:6379/' },
    ];

    ssrfRequests.forEach(({ method, url }) => {
      it(`should detect SSRF`, async () => {
        const { request, context } = createRequest(method, url);
        const result = await detector.detectRequest(request, context);
        
        expect(result).not.toBeNull();
        expect(result?.detected).toBe(true);
      });
    });
  });

  describe('Confidence and Severity mapping', () => {
    it('should return confidence between 0 and 1', async () => {
      const { request, context } = createRequest('GET', "https://api.example.com/users?id=' OR '1'='1");
      const result = await detector.detectRequest(request, context);
      
      expect(result?.confidence).toBeGreaterThanOrEqual(0);
      expect(result?.confidence).toBeLessThanOrEqual(1);
    });

    it('should return valid severity', async () => {
      const { request, context } = createRequest('GET', "https://api.example.com/search?q=<script>alert(1)</script>");
      const result = await detector.detectRequest(request, context);
      
      expect(['low', 'medium', 'high', 'critical']).toContain(result?.severity);
    });

    it('should include ML metadata fields', async () => {
      const { request, context } = createRequest('GET', "https://api.example.com/users?id=1' OR '1'='1");
      const result = await detector.detectRequest(request, context);
      
      expect(result?.metadata).toHaveProperty('mlClass');
      expect(result?.metadata).toHaveProperty('mlConfidence');
      expect(result?.metadata).toHaveProperty('suspiciousScore');
    });
  });
});

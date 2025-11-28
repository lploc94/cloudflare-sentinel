/**
 * HTTP Smuggling Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { HTTPSmugglingDetector } from './http-smuggling.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('HTTPSmugglingDetector', () => {
  const detector = new HTTPSmugglingDetector();

  describe('Conflicting Headers (CL.TE / TE.CL)', () => {
    it('should detect Content-Length + Transfer-Encoding', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: {
          'content-length': '10',
          'transfer-encoding': 'chunked',
        },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.HTTP_SMUGGLING);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('conflicting_headers');
    });

    it('should allow Content-Length only', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-length': '10' },
        body: '0123456789',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow Transfer-Encoding only', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'transfer-encoding': 'chunked' },
        body: '0\r\n\r\n',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Header Injection (CRLF)', () => {
    // Note: Raw CRLF/null bytes are rejected by Headers API at construction
    // In real attacks, these would be in raw HTTP before parsing
    // We test URL-encoded versions which can be passed through

    it('should detect URL-encoded CRLF (%0d%0a)', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-for': '1.2.3.4%0d%0aX-Injected: evil' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('header_injection');
    });

    it('should detect URL-encoded CR (%0d)', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'referer': 'https://example.com%0dX-Evil: injected' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('header_injection');
    });

    it('should detect URL-encoded LF (%0a)', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-host': 'example.com%0aX-Injected: evil' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('header_injection');
    });

    it('should detect URL-encoded null byte (%00)', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-host': 'example.com%00.evil.com' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('null_byte_injection');
    });
  });

  describe('Invalid Content-Length', () => {
    it('should detect non-numeric Content-Length', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-length': '10abc' },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('invalid_content_length');
    });

    it('should detect multiple Content-Length values', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-length': '5, 10' },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      // Gets detected as invalid first (non-numeric due to comma)
      expect(result?.metadata?.reason).toBe('invalid_content_length');
    });

    it('should detect leading zeros in Content-Length', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-length': '0010' },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('leading_zeros_cl');
    });

    it('should allow valid Content-Length', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'content-length': '10' },
        body: '0123456789',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Obfuscated Transfer-Encoding', () => {
    it('should detect multiple Transfer-Encoding values', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'transfer-encoding': 'chunked, identity' },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('multiple_transfer_encoding');
    });

    it('should detect unknown Transfer-Encoding', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'transfer-encoding': 'chunkedd' }, // typo
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('unknown_transfer_encoding');
    });

    it('should handle whitespace (normalized by Headers API)', async () => {
      // Note: Headers API normalizes whitespace automatically
      // In raw HTTP, this could be used for obfuscation
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'transfer-encoding': ' chunked ' },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      // After normalization, this becomes valid 'chunked'
      // The test verifies the detector handles normalized input correctly
      // Real obfuscation would need to bypass Headers API (raw HTTP level)
      expect(result).toBeNull();
    });

    it('should allow valid Transfer-Encoding', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'transfer-encoding': 'chunked' },
        body: '0\r\n\r\n',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow gzip Transfer-Encoding', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'transfer-encoding': 'gzip' },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Safe Requests', () => {
    it('should allow normal GET request', async () => {
      const request = new Request('https://example.com/api');
      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow normal POST with Content-Type', async () => {
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 
          'content-type': 'application/json',
          'content-length': '13',
        },
        body: '{"test":true}',
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Host Header Abuse', () => {
    it('should detect Host override via X-Forwarded-Host', async () => {
      const request = new Request('https://example.com/api', {
        headers: {
          'host': 'example.com',
          'x-forwarded-host': 'evil.com',
        },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('host_override');
    });

    it('should detect Host override via X-Host', async () => {
      const request = new Request('https://example.com/api', {
        headers: {
          'host': 'example.com',
          'x-host': 'malicious.com',
        },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('host_override');
    });

    it('should detect @ in Host header', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'host': 'user@evil.com' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('host_authority_injection');
    });

    it('should detect path in Host header', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'host': 'example.com/admin' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('host_path_injection');
    });

    it('should allow valid Host header', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'host': 'example.com' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow Host with valid port', async () => {
      const request = new Request('https://example.com:8080/api', {
        headers: { 'host': 'example.com:8080' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('X-Forwarded Header Abuse', () => {
    it('should detect localhost in X-Forwarded-For', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-for': '127.0.0.1' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('suspicious_xff');
    });

    it('should detect 0.0.0.0 in X-Forwarded-For', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-for': '0.0.0.0' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect excessive XFF chain', async () => {
      const manyIPs = Array(15).fill('1.2.3.4').join(', ');
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-for': manyIPs },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('excessive_xff_chain');
    });

    it('should detect invalid X-Forwarded-Proto', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-proto': 'javascript' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('invalid_xfp');
    });

    it('should detect invalid X-Forwarded-Port', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-port': '99999' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('invalid_xf_port');
    });

    it('should allow valid X-Forwarded headers', async () => {
      const request = new Request('https://example.com/api', {
        headers: {
          'x-forwarded-for': '203.0.113.50',
          'x-forwarded-proto': 'https',
          'x-forwarded-port': '443',
        },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('http-smuggling');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(98);
    });

    it('should allow disabling specific checks', async () => {
      const detector = new HTTPSmugglingDetector({
        checkConflictingHeaders: false,
      });

      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: {
          'content-length': '10',
          'transfer-encoding': 'chunked',
        },
        body: 'test',
      });

      const result = await detector.detectRequest(request, {});

      // Should not detect because check is disabled
      expect(result).toBeNull();
    });

    it('should allow disabling header injection check', async () => {
      const detector = new HTTPSmugglingDetector({
        checkHeaderInjection: false,
      });

      // Use URL-encoded CRLF since raw CRLF is rejected by Headers API
      const request = new Request('https://example.com/api', {
        headers: { 'x-forwarded-for': '1.2.3.4%0d%0aX-Injected: evil' },
      });

      const result = await detector.detectRequest(request, {});

      // Should not detect because check is disabled
      expect(result).toBeNull();
    });
  });
});

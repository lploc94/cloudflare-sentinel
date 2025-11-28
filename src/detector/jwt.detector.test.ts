/**
 * JWT Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { JWTDetector } from './jwt.detector';
import { AttackType, SecuritySeverity } from '../types';

// Helper to create JWT
const createJWT = (header: object, payload: object = {}, signature = 'fake-sig'): string => {
  const encodeBase64Url = (obj: object) => {
    const json = JSON.stringify(obj);
    const base64 = btoa(json);
    return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  };
  
  return `${encodeBase64Url(header)}.${encodeBase64Url(payload)}.${signature}`;
};

// Helper to create request with Authorization header
const createRequest = (token: string) =>
  new Request('https://example.com/api', {
    headers: { 'authorization': `Bearer ${token}` },
  });

describe('JWTDetector', () => {
  const detector = new JWTDetector();

  describe('alg=none Attack', () => {
    it('should detect alg=none', async () => {
      const token = createJWT({ alg: 'none', typ: 'JWT' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.JWT_ATTACK);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('alg_none');
    });

    it('should detect alg=None (case variation)', async () => {
      const token = createJWT({ alg: 'None', typ: 'JWT' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('alg_none');
    });

    it('should detect alg=NONE', async () => {
      const token = createJWT({ alg: 'NONE', typ: 'JWT' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should allow valid algorithms', async () => {
      const token = createJWT({ alg: 'HS256', typ: 'JWT' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('kid Injection', () => {
    it('should detect path traversal in kid', async () => {
      const token = createJWT({ alg: 'HS256', kid: '../../../etc/passwd' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('kid_path_traversal');
    });

    it('should detect Windows path traversal in kid', async () => {
      const token = createJWT({ alg: 'HS256', kid: '..\\..\\windows\\system32' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('kid_path_traversal');
    });

    it('should detect SQL injection in kid', async () => {
      const token = createJWT({ alg: 'HS256', kid: "key' OR '1'='1" });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('kid_sql_injection');
    });

    it('should detect command injection in kid', async () => {
      const token = createJWT({ alg: 'HS256', kid: 'key | whoami' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('kid_command_injection');
    });

    it('should allow normal kid', async () => {
      const token = createJWT({ alg: 'HS256', kid: 'key-2024-01' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('jku/x5u SSRF', () => {
    it('should detect localhost in jku', async () => {
      const token = createJWT({ alg: 'RS256', jku: 'http://localhost/.well-known/jwks.json' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
      expect(result?.metadata?.reason).toBe('jku_ssrf');
    });

    it('should detect internal IP in jku', async () => {
      const token = createJWT({ alg: 'RS256', jku: 'http://192.168.1.1/jwks.json' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('jku_ssrf');
    });

    it('should detect 127.0.0.1 in x5u', async () => {
      const token = createJWT({ alg: 'RS256', x5u: 'http://127.0.0.1/cert.pem' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('x5u_ssrf');
    });

    it('should detect AWS metadata IP in jku', async () => {
      const token = createJWT({ alg: 'RS256', jku: 'http://169.254.169.254/keys' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should detect file:// protocol in jku', async () => {
      const token = createJWT({ alg: 'RS256', jku: 'file:///etc/passwd' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('jku_file_access');
    });

    it('should allow external jku URL', async () => {
      const token = createJWT({ alg: 'RS256', jku: 'https://auth.example.com/.well-known/jwks.json' });
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Malformed JWT', () => {
    it('should detect JWT with wrong part count', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'authorization': 'Bearer invalid.token' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('malformed_structure');
    });

    it('should detect JWT with invalid base64 header', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'authorization': 'Bearer !!!invalid!!!.payload.signature' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.metadata?.reason).toBe('invalid_header');
    });
  });

  describe('Token Extraction', () => {
    it('should extract Bearer token', async () => {
      const token = createJWT({ alg: 'none' });
      const request = new Request('https://example.com/api', {
        headers: { 'authorization': `Bearer ${token}` },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should extract raw JWT from header', async () => {
      const token = createJWT({ alg: 'none' });
      const request = new Request('https://example.com/api', {
        headers: { 'authorization': token },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });

    it('should skip non-JWT authorization', async () => {
      const request = new Request('https://example.com/api', {
        headers: { 'authorization': 'Basic dXNlcjpwYXNz' },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Query Parameter Check', () => {
    it('should check query params when enabled', async () => {
      const detector = new JWTDetector({ checkQueryParams: true });
      const token = createJWT({ alg: 'none' });
      const request = new Request(`https://example.com/api?token=${token}`);

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('query.token');
    });

    it('should not check query params by default', async () => {
      const token = createJWT({ alg: 'none' });
      const request = new Request(`https://example.com/api?token=${token}`);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Custom Header Names', () => {
    it('should check custom headers', async () => {
      const detector = new JWTDetector({
        headerNames: ['x-access-token'],
      });
      const token = createJWT({ alg: 'none' });
      const request = new Request('https://example.com/api', {
        headers: { 'x-access-token': token },
      });

      const result = await detector.detectRequest(request, {});

      expect(result).not.toBeNull();
    });
  });

  describe('Safe Tokens', () => {
    it('should allow valid JWT', async () => {
      const token = createJWT(
        { alg: 'HS256', typ: 'JWT' },
        { sub: '1234567890', name: 'John Doe', iat: 1516239022 }
      );
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });

    it('should allow RS256 with normal jku', async () => {
      const token = createJWT(
        { alg: 'RS256', jku: 'https://trusted.auth.com/jwks.json' },
        { sub: 'user123' }
      );
      const request = createRequest(token);

      const result = await detector.detectRequest(request, {});

      expect(result).toBeNull();
    });
  });

  describe('Configuration', () => {
    it('should have correct name and phase', () => {
      expect(detector.name).toBe('jwt');
      expect(detector.phase).toBe('request');
      expect(detector.priority).toBe(88);
    });
  });
});

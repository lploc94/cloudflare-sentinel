/**
 * Unit tests for EntropyDetector
 */

import { describe, it, expect } from 'vitest';
import { EntropyDetector } from './entropy.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('EntropyDetector', () => {
  describe('calculateEntropy', () => {
    it('should return low entropy for normal text', async () => {
      const detector = new EntropyDetector();
      const request = new Request('https://example.com?name=john', {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      // Normal text should not trigger detection
      expect(result).toBeNull();
    });

    it('should detect high entropy base64 encoded data', async () => {
      const detector = new EntropyDetector({ entropyThreshold: 4.5 });
      // Base64 encoded "SELECT * FROM users WHERE id = 1"
      const encoded = 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDE=';
      const request = new Request(`https://example.com?payload=${encoded}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
      expect(result?.attackType).toBe(AttackType.OBFUSCATED_PAYLOAD);
    });

    it('should detect high entropy hex encoded data', async () => {
      const detector = new EntropyDetector({ 
        entropyThreshold: 3.0, 
        minLength: 10,
        excludeFields: [], // Clear default excludes for this test
      });
      // Hex encoded string - longer to ensure enough entropy
      // Hex only uses 0-9, a-f (16 chars) so max entropy is ~4 bits
      const hexData = '53454c454354202a2046524f4d20757365727320574845524520696420';
      const request = new Request(`https://example.com?payload=${hexData}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
    });

    it('should exclude paths in excludePaths', async () => {
      const detector = new EntropyDetector({
        excludePaths: ['/api/auth/*', '/oauth/*'],
        entropyThreshold: 4.0,
      });
      
      const encoded = 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDE=';
      const request = new Request(`https://example.com/api/auth/token?payload=${encoded}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      // Should not detect because path is excluded
      expect(result).toBeNull();
    });

    it('should exclude fields in excludeFields', async () => {
      const detector = new EntropyDetector({
        excludeFields: ['token', 'jwt'],
        entropyThreshold: 4.0,
      });
      
      const encoded = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';
      const request = new Request(`https://example.com?jwt_token=${encoded}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      // Should not detect because field contains 'token'
      expect(result).toBeNull();
    });

    it('should not detect strings shorter than minLength', async () => {
      const detector = new EntropyDetector({
        minLength: 20,
        entropyThreshold: 4.0,
      });
      
      const request = new Request('https://example.com?id=abc123xyz', {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      // Short string should not be analyzed
      expect(result).toBeNull();
    });

    it('should detect high entropy in JSON body', async () => {
      const detector = new EntropyDetector({ entropyThreshold: 4.5 });
      const encoded = 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDE=';
      
      const request = new Request('https://example.com/api/data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ payload: encoded }),
      });

      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.OBFUSCATED_PAYLOAD);
    });

    it('should return severity based on entropy level', async () => {
      const detector = new EntropyDetector({ entropyThreshold: 4.0 });
      
      // Very high entropy random string with more character variety
      const highEntropy = 'aB3cD5eF7gH9iJ1kL3mN5oP7qR9sT1uV3wX5yZ!@#$%^&*()+=[]{}|;:,.<>?';
      const request = new Request(`https://example.com?random=${encodeURIComponent(highEntropy)}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      // Should detect high entropy
      expect(result?.detected).toBe(true);
      expect(result?.metadata?.entropy).toBeGreaterThan(4.0);
    });

    it('should provide entropy value in metadata', async () => {
      const detector = new EntropyDetector({ entropyThreshold: 4.0 });
      const encoded = 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDE=';
      
      const request = new Request(`https://example.com?payload=${encoded}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.metadata?.entropy).toBeGreaterThan(4.0);
      expect(result?.metadata?.threshold).toBe(4.0);
    });
  });

  describe('requireAdditionalSignals', () => {
    it('should only detect when additional signals present', async () => {
      const detector = new EntropyDetector({
        entropyThreshold: 4.0,
        requireAdditionalSignals: true,
      });
      
      // Pure base64 pattern - has additional signal
      const base64 = 'U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDE=';
      const request = new Request(`https://example.com?payload=${base64}`, {
        method: 'GET',
      });

      const result = await detector.detectRequest(request, {});
      
      // Should detect because base64 pattern is an additional signal
      expect(result).not.toBeNull();
    });
  });
});

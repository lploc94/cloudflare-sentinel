/**
 * NoSQL Injection Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { NoSQLInjectionDetector } from './nosql-injection.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('NoSQLInjectionDetector', () => {
  describe('MongoDB Operators', () => {
    it('should detect $ne operator (auth bypass)', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: { '$ne': '' } }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.NOSQL_INJECTION);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);  // Auth bypass is CRITICAL
    });

    it('should detect $gt operator', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: { '$gt': '' } }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect $regex operator', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com?search={"$regex": ".*"}', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect $where clause', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/find', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: '$where: this.password' }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });
  });

  describe('Update Operators', () => {
    it('should detect $set operator', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/update?q={"$set": {"isAdmin": true}}', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);  // Update operators are CRITICAL
    });

    it('should detect $unset operator', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com?query={"$unset": {"password": 1}}', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('JavaScript Injection', () => {
    it('should detect function definition', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: 'function() { return true; }' }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect sleep (DoS)', async () => {
      const detector = new NoSQLInjectionDetector();
      // sleep needs $ or function context to be detected
      const request = new Request('https://example.com?q=$where: sleep(5000)', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });

    it('should detect return true (auth bypass)', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com?where=return true', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('Operator in Field Name', () => {
    it('should detect $ operator as object key', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/data', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ '$or': [{ admin: true }] }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);  // Operator as key is CRITICAL
    });
  });

  describe('Query Parameter Detection', () => {
    it('should detect injection in query params', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/users?filter={"$or":[{"admin":1}]}', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('Safe Input', () => {
    it('should not detect normal JSON', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'John', email: 'john@example.com' }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });

    it('should not detect normal text with $', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com?price=$100', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });

    it('should not detect JavaScript keywords in normal context', async () => {
      const detector = new NoSQLInjectionDetector();
      const request = new Request('https://example.com?q=learn javascript function', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });
  });
});

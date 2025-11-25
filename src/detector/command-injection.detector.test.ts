/**
 * Command Injection Detector Tests
 */

import { describe, it, expect } from 'vitest';
import { CommandInjectionDetector } from './command-injection.detector';
import { AttackType, SecuritySeverity } from '../types';

describe('CommandInjectionDetector', () => {
  describe('Command Chaining', () => {
    it('should detect semicolon command chaining', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?cmd=test;ls', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.detected).toBe(true);
      expect(result?.attackType).toBe(AttackType.COMMAND_INJECTION);
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect pipe command chaining', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?input=data|cat /etc/passwd', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.attackType).toBe(AttackType.COMMAND_INJECTION);
    });

    it('should detect ampersand command chaining', async () => {
      const detector = new CommandInjectionDetector();
      // Note: & in URL is query separator, so use encoded or in body
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ cmd: 'test && whoami' }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('Command Substitution', () => {
    it('should detect backtick command substitution', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?name=`id`', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.HIGH);
    });

    it('should detect $() command substitution', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?file=$(cat /etc/passwd)', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('Dangerous Commands', () => {
    it('should detect rm -rf', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?action=;rm -rf /', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.severity).toBe(SecuritySeverity.CRITICAL);
    });

    it('should detect /etc/passwd access', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?file=;cat /etc/passwd', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
    });
  });

  describe('JSON Body Detection', () => {
    it('should detect command injection in JSON body', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command: 'test; whoami' }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('body.command');
    });

    it('should detect nested command injection', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com/api', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ data: { cmd: '$(id)' } }),
      });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).not.toBeNull();
      expect(result?.evidence?.field).toBe('body.data.cmd');
    });
  });

  describe('Exclusions', () => {
    it('should exclude specified paths', async () => {
      const detector = new CommandInjectionDetector({ excludePaths: ['/health/*'] });
      const request = new Request('https://example.com/health/check?cmd=;ls', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });

    it('should exclude specified fields', async () => {
      const detector = new CommandInjectionDetector({ excludeFields: ['script'] });
      const request = new Request('https://example.com?script=;ls', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });
  });

  describe('Safe Input', () => {
    it('should not detect normal text', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?name=John Doe', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });

    it('should not detect normal URLs', async () => {
      const detector = new CommandInjectionDetector();
      const request = new Request('https://example.com?url=https://google.com', { method: 'GET' });
      
      const result = await detector.detectRequest(request, {});
      
      expect(result).toBeNull();
    });
  });
});

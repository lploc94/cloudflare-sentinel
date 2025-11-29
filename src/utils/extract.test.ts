/**
 * Extract utilities tests
 */

import { describe, it, expect } from 'vitest';
import { extractIP, extractIPFromContext } from './extract';

describe('extractIP', () => {
  it('should extract cf-connecting-ip', () => {
    const request = new Request('https://example.com', {
      headers: { 'cf-connecting-ip': '1.2.3.4' },
    });
    expect(extractIP(request)).toBe('1.2.3.4');
  });

  it('should extract x-forwarded-for (first IP)', () => {
    const request = new Request('https://example.com', {
      headers: { 'x-forwarded-for': '1.2.3.4, 5.6.7.8, 9.10.11.12' },
    });
    expect(extractIP(request)).toBe('1.2.3.4');
  });

  it('should extract x-real-ip as fallback', () => {
    const request = new Request('https://example.com', {
      headers: { 'x-real-ip': '1.2.3.4' },
    });
    expect(extractIP(request)).toBe('1.2.3.4');
  });

  it('should prefer cf-connecting-ip over others', () => {
    const request = new Request('https://example.com', {
      headers: {
        'cf-connecting-ip': '1.1.1.1',
        'x-forwarded-for': '2.2.2.2',
        'x-real-ip': '3.3.3.3',
      },
    });
    expect(extractIP(request)).toBe('1.1.1.1');
  });

  it('should return null if no IP headers', () => {
    const request = new Request('https://example.com');
    expect(extractIP(request)).toBeNull();
  });

  it('should handle whitespace in x-forwarded-for', () => {
    const request = new Request('https://example.com', {
      headers: { 'x-forwarded-for': '  1.2.3.4  ,  5.6.7.8  ' },
    });
    expect(extractIP(request)).toBe('1.2.3.4');
  });
});

describe('extractIPFromContext', () => {
  it('should extract IP from results evidence', () => {
    const ctx = {
      results: [
        { evidence: { field: 'ip', value: '1.2.3.4' } },
      ],
    };
    expect(extractIPFromContext(ctx)).toBe('1.2.3.4');
  });

  it('should fallback to request headers', () => {
    const ctx = {
      results: [],
      request: new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '5.6.7.8' },
      }),
    };
    expect(extractIPFromContext(ctx)).toBe('5.6.7.8');
  });

  it('should prefer results over request', () => {
    const ctx = {
      results: [
        { evidence: { field: 'ip', value: '1.1.1.1' } },
      ],
      request: new Request('https://example.com', {
        headers: { 'cf-connecting-ip': '2.2.2.2' },
      }),
    };
    expect(extractIPFromContext(ctx)).toBe('1.1.1.1');
  });

  it('should return null if no IP found', () => {
    const ctx = {
      results: [],
    };
    expect(extractIPFromContext(ctx)).toBeNull();
  });

  it('should skip non-IP evidence fields', () => {
    const ctx = {
      results: [
        { evidence: { field: 'url', value: '/test' } },
        { evidence: { field: 'ip', value: '1.2.3.4' } },
      ],
    };
    expect(extractIPFromContext(ctx)).toBe('1.2.3.4');
  });
});

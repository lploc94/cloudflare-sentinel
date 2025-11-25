/**
 * Tests for unified detectors configuration
 */

import { describe, it, expect } from 'vitest';
import { Sentinel } from './index';
import { SQLInjectionRequestDetector, EntropyDetector } from '../detector';
import type { SentinelConfig } from '../types';

describe('Unified Detectors Configuration', () => {
  it('should support array format (backward compatibility)', async () => {
    const config: SentinelConfig = {
      rateLimiter: {} as any,
      detectors: [
        new SQLInjectionRequestDetector(),
      ],
    };

    const sentinel = new Sentinel(config);
    
    // Should have global detectors
    expect((sentinel as any).detectors).toHaveLength(1);
    expect((sentinel as any).endpointDetectors).toEqual({});
  });

  it('should support object format with global and endpoint-specific', async () => {
    const config: SentinelConfig = {
      rateLimiter: {} as any,
      detectors: {
        '*': [new SQLInjectionRequestDetector()],
        '/api/search/*': [new EntropyDetector({ entropyThreshold: 5.0 })],
      },
    };

    const sentinel = new Sentinel(config);
    
    // Should have global detectors
    expect((sentinel as any).detectors).toHaveLength(1);
    
    // Should have endpoint-specific detectors
    expect(Object.keys((sentinel as any).endpointDetectors)).toContain('/api/search/*');
    expect((sentinel as any).endpointDetectors['/api/search/*']).toHaveLength(1);
  });

  it('should handle object format without global detectors', async () => {
    const config: SentinelConfig = {
      rateLimiter: {} as any,
      detectors: {
        '/api/search/*': [new EntropyDetector()],
      },
    };

    const sentinel = new Sentinel(config);
    
    // Should have no global detectors
    expect((sentinel as any).detectors).toHaveLength(0);
    
    // Should have endpoint-specific detectors
    expect(Object.keys((sentinel as any).endpointDetectors)).toContain('/api/search/*');
  });

  it('should filter disabled detectors', async () => {
    const config: SentinelConfig = {
      rateLimiter: {} as any,
      detectors: [
        new SQLInjectionRequestDetector(),
        { ...new EntropyDetector(), enabled: false } as any,
      ],
    };

    const sentinel = new Sentinel(config);
    
    // Should only have enabled detectors
    expect((sentinel as any).detectors).toHaveLength(1);
  });

  it('should handle empty configuration', async () => {
    const config: SentinelConfig = {
      rateLimiter: {} as any,
    };

    const sentinel = new Sentinel(config);
    
    // Should have no detectors
    expect((sentinel as any).detectors).toHaveLength(0);
    expect((sentinel as any).endpointDetectors).toEqual({});
  });
});

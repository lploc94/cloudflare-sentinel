/**
 * Weighted Scoring Example
 * 
 * This example demonstrates how to use WeightedAggregator with detector weights
 * to prioritize certain detectors over others.
 */

import {
  SentinelPipeline,
  WeightedAggregator,
  DefaultResolver,
  BlocklistDetector,
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  RateLimitDetector,
} from '../src';

/**
 * Example 1: Basic weighted scoring (confidence only)
 */
export function createBasicWeightedPipeline() {
  return SentinelPipeline.sync([
    new BlocklistDetector({ kv: null as any }),
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
  ])
    .score(new WeightedAggregator())  // No weights = confidence only
    .resolve(new DefaultResolver());
}

/**
 * Example 2: Prioritize critical detectors
 * 
 * Use case: Admin panel where SQL injection and blocklist are more critical
 */
export function createAdminPanelPipeline() {
  return SentinelPipeline.sync([
    new BlocklistDetector({ kv: null as any }),
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new RateLimitDetector({ kv: null as any, limit: 100, windowSeconds: 60 }),
  ])
    .score(new WeightedAggregator({
      'blocklist': 2.0,           // 2x more important
      'sql-injection-request': 1.8,       // 80% more important
      'xss-request': 1.2,                 // 20% more important
      'rate_limit': 0.8,          // 20% less important
    }))
    .resolve(new DefaultResolver());
}

/**
 * Example 3: Public API with balanced scoring
 * 
 * Use case: Public API where all detectors are equally important
 */
export function createPublicApiPipeline() {
  return SentinelPipeline.sync([
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new RateLimitDetector({ kv: null as any, limit: 100, windowSeconds: 60 }),
  ])
    .score(new WeightedAggregator({
      'sql-injection-request': 1.0,
      'xss-request': 1.0,
      'rate_limit': 1.0,
    }))
    .resolve(new DefaultResolver());
}

/**
 * Example 4: E-commerce checkout with strict rate limiting
 * 
 * Use case: Checkout flow where rate limiting is most important
 */
export function createCheckoutPipeline() {
  return SentinelPipeline.sync([
    new RateLimitDetector({ kv: null as any, limit: 100, windowSeconds: 60 }),
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
  ])
    .score(new WeightedAggregator({
      'rate_limit': 2.5,          // Highest priority
      'sql-injection-request': 1.5,
      'xss-request': 1.0,
    }))
    .resolve(new DefaultResolver());
}

/**
 * How scoring works with weights:
 * 
 * Formula: score = baseScore * confidence * weight
 * 
 * Example scenario:
 * - SQL Injection detected: severity=high (80), confidence=0.9, weight=1.8
 *   → weighted score = 80 * 0.9 * 1.8 = 129.6
 * 
 * - XSS detected: severity=medium (50), confidence=0.7, weight=1.2
 *   → weighted score = 50 * 0.7 * 1.2 = 42
 * 
 * - Average: (129.6 + 42) / 2 = 85.8 → rounded to 86
 * - Threat level: critical (>80)
 */

/**
 * Usage in Cloudflare Worker:
 */
export default {
  async fetch(request: Request, env: any, ctx: any) {
    const pipeline = createAdminPanelPipeline();
    const decision = await pipeline.process(request, { env, ctx });
    
    if (decision && decision.has('block')) {
      return new Response('Blocked', { status: 403 });
    }
    
    // Continue to origin
    return fetch(request);
  },
};

/**
 * ══════════════════════════════════════════════════════════════════════════════
 * SENTINEL PROXY CONFIGURATION
 * ══════════════════════════════════════════════════════════════════════════════
 * 
 * Multi-level threat response:
 * - low:    score < 30  → log only
 * - medium: score < 60  → log + notify
 * - high:   score >= 60 → block + notify
 * 
 * Customize thresholds per route.
 */

import {
  // Security Detectors
  BlocklistDetector,
  RateLimitDetector,
  
  // Attack Detectors
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  PathTraversalRequestDetector,
  BruteForceDetector,
  CommandInjectionDetector,
  SSRFDetector,
  NoSQLInjectionDetector,
  EntropyDetector,
  
  // Response Detectors
  SQLInjectionResponseDetector,
  XSSResponseDetector,
  PathTraversalResponseDetector,
} from 'cloudflare-sentinel';

import type { Env } from './lib/types';

// ══════════════════════════════════════════════════════════════════════════════
// THRESHOLD PRESETS
// Each level inherits actions from previous levels
// ══════════════════════════════════════════════════════════════════════════════

/** Standard thresholds for most routes */
const STANDARD = [
  { maxScore: 30, actions: ['log'] },
  { maxScore: 60, actions: ['log', 'notify'] },
  { maxScore: 100, actions: ['block', 'notify'] },
];

/** Strict thresholds for sensitive routes (auth, admin) */
const STRICT = [
  { maxScore: 20, actions: ['log'] },
  { maxScore: 40, actions: ['log', 'notify'] },
  { maxScore: 100, actions: ['block', 'notify'] },
];

/** Relaxed thresholds for public routes */
const RELAXED = [
  { maxScore: 50, actions: ['log'] },
  { maxScore: 80, actions: ['log', 'notify'] },
  { maxScore: 100, actions: ['block'] },
];

/** Custom example - aggressive escalation */
const AGGRESSIVE = [
  { maxScore: 10, actions: ['log'] },
  { maxScore: 30, actions: ['log', 'notify'] },
  { maxScore: 50, actions: ['block', 'notify'] },
];

// ══════════════════════════════════════════════════════════════════════════════
// CONFIGURATION
// ══════════════════════════════════════════════════════════════════════════════

export function createConfig(env: Env) {
  // ────────────────────────────────────────────────────────────────────────────
  // REUSABLE DETECTOR SETS
  // ────────────────────────────────────────────────────────────────────────────
  
  const basic = [
    new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new PathTraversalRequestDetector(),
    new CommandInjectionDetector(),
    new SSRFDetector(),
    new NoSQLInjectionDetector(),
  ];
  
  // ────────────────────────────────────────────────────────────────────────────
  // ROUTES
  // ────────────────────────────────────────────────────────────────────────────
  
  return {
    // ══════════════════════════════════════════════════════════════════════════
    // GLOBAL - Fallback for unmatched routes
    // ══════════════════════════════════════════════════════════════════════════
    global: {
      detectors: [
        ...basic,
        new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 100, windowSeconds: 60 }),
      ],
      thresholds: STANDARD,
    },
    
    // ══════════════════════════════════════════════════════════════════════════
    // ROUTES - Full control per route
    // ══════════════════════════════════════════════════════════════════════════
    routes: {
      // ────────────────────────────────────────────────────────────────────────
      // AUTH - Strict thresholds + brute force detection
      // ────────────────────────────────────────────────────────────────────────
      '/login': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 5, windowSeconds: 60 }),
          new BruteForceDetector({ kv: env.RATE_LIMIT_KV }),
          new EntropyDetector({ entropyThreshold: 4.0 }),
        ],
        thresholds: STRICT,
      },
      
      '/auth/**': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 10, windowSeconds: 60 }),
          new BruteForceDetector({ kv: env.RATE_LIMIT_KV }),
          new EntropyDetector({ entropyThreshold: 4.5 }),
        ],
        thresholds: STRICT,
      },
      
      '/api/auth/**': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 10, windowSeconds: 60 }),
          new BruteForceDetector({ kv: env.RATE_LIMIT_KV }),
          new EntropyDetector({ entropyThreshold: 4.5 }),
        ],
        thresholds: STRICT,
      },
      
      // ────────────────────────────────────────────────────────────────────────
      // ADMIN - Strict thresholds + entropy
      // ────────────────────────────────────────────────────────────────────────
      '/admin/**': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 30, windowSeconds: 60 }),
          new EntropyDetector({ entropyThreshold: 4.0 }),
        ],
        thresholds: STRICT,
      },
      
      '/api/admin/**': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 30, windowSeconds: 60 }),
          new EntropyDetector({ entropyThreshold: 4.0 }),
        ],
        thresholds: STRICT,
      },
      
      // ────────────────────────────────────────────────────────────────────────
      // API - Standard thresholds
      // ────────────────────────────────────────────────────────────────────────
      '/api/**': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 60, windowSeconds: 60 }),
        ],
        thresholds: STANDARD,
      },
      
      // ────────────────────────────────────────────────────────────────────────
      // SEARCH - Relaxed thresholds (high false positive risk)
      // ────────────────────────────────────────────────────────────────────────
      '/search': {
        detectors: [
          ...basic,
          new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 30, windowSeconds: 60 }),
          new EntropyDetector({ entropyThreshold: 5.0 }),
        ],
        thresholds: RELAXED,
      },
      
      // ────────────────────────────────────────────────────────────────────────
      // STATIC - Skip all security
      // ────────────────────────────────────────────────────────────────────────
      '/static/**': { skip: true },
      '/assets/**': { skip: true },
      '/favicon.ico': { skip: true },
      '/robots.txt': { skip: true },
      '/health': { skip: true },
    },
    
    // ══════════════════════════════════════════════════════════════════════════
    // RESPONSE DETECTION (optional)
    // ══════════════════════════════════════════════════════════════════════════
    response: {
      enabled: false,
      detectors: [
        new SQLInjectionResponseDetector(),
        new XSSResponseDetector(),
        new PathTraversalResponseDetector(),
      ],
    },
    
    // ══════════════════════════════════════════════════════════════════════════
    // NOTIFICATIONS
    // ══════════════════════════════════════════════════════════════════════════
    notifications: {
      slack: false,
      blockedOnly: true,
      minSeverity: 'high' as const,
    },
  };
}

export type ProxyConfig = ReturnType<typeof createConfig>;

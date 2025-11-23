/**
 * Zod validation schemas for Sentinel configuration
 */

import { z } from 'zod';

/**
 * Attack limit schema
 */
export const attackLimitSchema = z.object({
  limit: z.number().int().positive().describe('Maximum number of attacks allowed'),
  period: z.number().int().positive().describe('Time window in seconds'),
  action: z.enum(['block', 'log_only']).describe('Action to take when limit exceeded'),
  logOnly: z.boolean().optional().describe('Override: only log, do not block'),
  priority: z.number().int().optional().describe('Rule priority'),
});

/**
 * Endpoint limit schema
 */
export const endpointLimitSchema = z.object({
  limit: z.number().int().positive(),
  period: z.number().int().positive(),
  keyExtractor: z.function().optional(),
});

/**
 * Sentinel configuration schema
 */
export const sentinelConfigSchema = z.object({
  // Bindings
  db: z.any().optional().describe('D1 database binding'),
  analytics: z.any().optional().describe('Analytics Engine binding'),
  kv: z.any().optional().describe('KV namespace binding'),
  rateLimiter: z.any().optional().describe('Rate Limiter binding'),
  
  // Attack limits (can be nested for endpoint-scoped)
  attackLimits: z.record(
    z.string(),
    z.union([
      attackLimitSchema,
      z.record(z.string(), attackLimitSchema)
    ])
  ).optional().describe('Attack-based rate limits'),
  
  // Endpoint limits (legacy)
  endpointLimits: z.record(z.string(), endpointLimitSchema).optional(),
  
  // Identifier extractor
  identifierExtractor: z.function().optional(),
  
  // Detectors
  detectors: z.array(z.any()).optional().describe('Array of detector instances'),
  
  // Feature flags
  enableEarlyBlockCheck: z.boolean().optional().default(true),
  enableAnalytics: z.boolean().optional().default(true),
  enableD1: z.boolean().optional().default(true),
  enableBehaviorTracking: z.boolean().optional().default(true),
  
  // Behavior tracking config
  behaviorFailureThreshold: z.number().int().positive().optional().default(5),
  behaviorTimeWindow: z.number().int().positive().optional().default(60),
  behaviorMaxPaths: z.number().int().positive().optional().default(20),
  
  // Legacy
  rules: z.array(z.any()).optional(),
  patterns: z.array(z.any()).optional(),
  
  // Logging
  debug: z.boolean().optional().default(false),
  logger: z.function().optional(),
  
  // Batching
  batchSize: z.number().int().positive().optional(),
  batchFlushInterval: z.number().int().positive().optional(),
  
  // Privacy
  excludeHeaders: z.array(z.string()).optional(),
});

/**
 * Validate Sentinel configuration
 */
export function validateSentinelConfig(config: unknown): {
  success: boolean;
  data?: any;
  errors?: string[];
} {
  try {
    const validated = sentinelConfigSchema.parse(config);
    return {
      success: true,
      data: validated,
    };
  } catch (error) {
    if (error instanceof z.ZodError) {
      return {
        success: false,
        errors: error.errors.map(e => `${e.path.join('.')}: ${e.message}`),
      };
    }
    return {
      success: false,
      errors: ['Unknown validation error'],
    };
  }
}

/**
 * Validate and return safe config with defaults
 */
export function validateAndNormalizeSentinelConfig(config: any): any {
  const result = validateSentinelConfig(config);
  
  if (!result.success) {
    const errorMsg = `Invalid Sentinel configuration:\n${result.errors?.join('\n')}`;
    throw new Error(errorMsg);
  }
  
  return result.data;
}

/**
 * Check if attack limits are properly configured
 */
export function validateAttackLimits(attackLimits: Record<string, any>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];
  
  for (const [key, value] of Object.entries(attackLimits)) {
    // Check if this is endpoint-scoped (has / or *)
    const isEndpointScoped = key.includes('/') || key.includes('*');
    
    if (isEndpointScoped) {
      // Should be Record<attackType, AttackLimit>
      if (typeof value !== 'object' || Array.isArray(value)) {
        errors.push(`${key}: Endpoint-scoped limits must be an object`);
        continue;
      }
      
      for (const [attackType, limit] of Object.entries(value)) {
        const result = attackLimitSchema.safeParse(limit);
        if (!result.success) {
          errors.push(`${key}.${attackType}: ${result.error.errors[0].message}`);
        }
      }
    } else {
      // Should be AttackLimit
      const result = attackLimitSchema.safeParse(value);
      if (!result.success) {
        errors.push(`${key}: ${result.error.errors[0].message}`);
      }
    }
  }
  
  return {
    valid: errors.length === 0,
    errors,
  };
}

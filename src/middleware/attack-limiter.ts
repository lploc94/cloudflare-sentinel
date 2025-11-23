/**
 * Attack-based rate limiter with endpoint layering
 * Supports both global and endpoint-scoped attack limits
 */

import type { SentinelConfig, Identifier, AttackType, AttackLimit, AttackTypeOrWildcard } from '../types';
import { IdentifierType } from '../types';
import { checkRateLimitsParallel, shouldUseParallel } from './parallel-limiter';
import { RateLimitCache } from './rate-limit-cache';

/**
 * Parsed attack rule
 */
interface AttackRule {
  attackType: AttackTypeOrWildcard;
  endpoint?: string;  // undefined = global
  limit: AttackLimit;
  specificity: number;  // For sorting (0 = global, higher = more specific)
}

/**
 * Check result
 */
export interface BlockCheckResult {
  blocked: boolean;
  attackType?: AttackTypeOrWildcard;
  endpoint?: string;
  reason?: string;
  retryAfter?: number;
}

/**
 * Rate limit check result
 */
export interface RateLimitCheckResult {
  allowed: boolean;
  retryAfter?: number;
  reason?: string;
  violatedRule?: AttackRule;
}

/**
 * Attack limiter with layered endpoint support
 */
export class AttackLimiter {
  private config: SentinelConfig;
  private rateLimiter?: any;
  private rules: AttackRule[];
  private cache?: RateLimitCache;

  constructor(config: SentinelConfig) {
    this.config = config;
    this.rateLimiter = config.rateLimiter;
    this.rules = this.parseAttackLimits(config.attackLimits || {});
    
    // Initialize cache if enabled
    if (config.enableRateLimitCache) {
      this.cache = new RateLimitCache(
        config.rateLimitCacheTTL || 1000,
        1000 // max 1000 entries
      );
    }
    
    if (config.debug) {
      console.log(`[Sentinel] Loaded ${this.rules.length} attack rules`);
      if (this.cache) {
        console.log(`[Sentinel] Rate limit cache enabled (TTL: ${config.rateLimitCacheTTL || 1000}ms)`);
      }
    }
  }

  /**
   * Parse attackLimits config into flat list of rules
   * Sort by specificity: global first, then by endpoint specificity
   */
  private parseAttackLimits(
    attackLimits: Record<string, AttackLimit | Record<string, AttackLimit>>
  ): AttackRule[] {
    const rules: AttackRule[] = [];

    for (const [key, value] of Object.entries(attackLimits)) {
      // Check if this is an endpoint pattern
      if (key.includes('*') || key.startsWith('/')) {
        // Endpoint-scoped limits
        const endpoint = key;
        const specificity = this.calculateSpecificity(endpoint);
        
        // value should be Record<attackType, AttackLimit>
        const limits = value as Record<string, AttackLimit>;
        for (const [attackType, limit] of Object.entries(limits)) {
          rules.push({
            attackType: attackType as AttackTypeOrWildcard,
            endpoint,
            limit,
            specificity,
          });
        }
      } else {
        // Global attack limit
        const attackType = key as AttackType;
        const limit = value as AttackLimit;
        
        rules.push({
          attackType,
          endpoint: undefined,  // Global
          limit,
          specificity: 0,  // Global = lowest specificity
        });
      }
    }

    // Sort by specificity: lower first (global → less specific → more specific)
    // Same specificity: sort by priority if defined
    return rules.sort((a, b) => {
      if (a.specificity !== b.specificity) {
        return a.specificity - b.specificity;
      }
      return (b.limit.priority || 0) - (a.limit.priority || 0);
    });
  }

  /**
   * Calculate endpoint specificity (higher = more specific)
   * Examples:
   * - wildcard = 1
   * - /api/wildcard = 2
   * - /api/user/wildcard = 3
   * - /api/user/wildcard/profile = 4
   */
  private calculateSpecificity(pattern: string): number {
    // Count path segments (not counting wildcards as extra specificity)
    const segments = pattern.split('/').filter(s => s && s !== '*');
    return segments.length;
  }

  /**
   * Check if endpoint matches pattern
   */
  private matchEndpoint(endpoint: string, pattern: string): boolean {
    // Convert glob pattern to regex
    const regexPattern = pattern
      .replace(/\*/g, '.*')
      .replace(/\?/g, '.');
    const regex = new RegExp(`^${regexPattern}$`);
    return regex.test(endpoint);
  }

  /**
   * Get all matching rules for endpoint + attack type
   * Returns rules in order: global first, then by specificity
   */
  private getMatchingRules(endpoint: string, attackType: AttackType): AttackRule[] {
    return this.rules.filter(rule => {
      // Check attack type (support wildcard)
      const attackMatches = rule.attackType === attackType || rule.attackType === '*';
      if (!attackMatches) return false;
      
      // Check endpoint (global or pattern match)
      if (rule.endpoint === undefined) return true;  // Global rule
      return this.matchEndpoint(endpoint, rule.endpoint);
    });
  }

  /**
   * Early check: Is this identifier already blocked?
   * Checks ALL possible attack types to see if any are blocked
   * Uses cache to optimize repeated checks
   */
  async isBlocked(identifier: Identifier, endpoint: string): Promise<BlockCheckResult> {
    if (!this.rateLimiter || this.rules.length === 0) {
      return { blocked: false };
    }

    // Check cache first (if enabled)
    const cacheKey = `block:${identifier.value}:${endpoint}`;
    if (this.cache) {
      const cached = this.cache.get(cacheKey);
      if (cached !== null) {
        if (this.config.debug) {
          console.log(`[Sentinel] Cache hit for ${cacheKey}: ${cached ? 'blocked' : 'allowed'}`);
        }
        return cached ? { 
          blocked: true, 
          reason: 'Cached block status',
        } : { 
          blocked: false 
        };
      }
    }

    // Get all rules that could apply to this endpoint
    const applicableRules = this.rules.filter(rule => {
      if (rule.endpoint === undefined) return true;  // Global
      return this.matchEndpoint(endpoint, rule.endpoint);
    });

    // Check each rule to see if already blocked
    for (const rule of applicableRules) {
      if (rule.limit.action !== 'block') continue;  // Skip log_only
      
      const key = this.buildKey(rule, identifier);
      
      try {
        // Check without incrementing
        const { success } = await this.rateLimiter.limit({
          key,
          limit: rule.limit.limit,
          period: rule.limit.period,
        });

        if (!success) {
          // Cache the blocked status
          if (this.cache) {
            this.cache.set(cacheKey, true);
          }
          
          return {
            blocked: true,
            attackType: rule.attackType,
            endpoint: rule.endpoint,
            reason: `Attack limit exceeded: ${rule.attackType}${rule.endpoint ? ` on ${rule.endpoint}` : ''}`,
            retryAfter: rule.limit.period,
          };
        }
      } catch (error: any) {
        if (this.config.debug) {
          console.error(`[Sentinel] Rate limit check error for ${rule.attackType}:`, error.message);
        }
        continue;  // On error, assume not blocked
      }
    }

    // Cache the allowed status (shorter TTL)
    if (this.cache) {
      this.cache.set(cacheKey, false, 500); // 500ms for allowed status
    }

    return { blocked: false };
  }

  /**
   * Check and increment rate limits for detected attack
   * Checks ALL matching rules (layered checking)
   * Returns FIRST violation
   */
  async checkAndIncrement(
    identifier: Identifier,
    attackType: AttackType,
    endpoint: string
  ): Promise<RateLimitCheckResult> {
    
    if (!this.rateLimiter) {
      return { allowed: true };
    }

    // Get all matching rules (global + endpoint-specific)
    const matchingRules = this.getMatchingRules(endpoint, attackType);
    
    if (matchingRules.length === 0) {
      // No limits configured
      return { allowed: true };
    }

    // Check each rule in order (global first, then by specificity)
    for (const rule of matchingRules) {
      const key = this.buildKey(rule, identifier);
      
      try {
        const { success } = await this.rateLimiter.limit({
          key,
          limit: rule.limit.limit,
          period: rule.limit.period,
        });

        if (!success) {
          // Rate limit exceeded for this rule
          return {
            allowed: false,
            retryAfter: rule.limit.period,
            reason: `Attack limit exceeded: ${rule.attackType}${rule.endpoint ? ` on ${rule.endpoint}` : ' (global)'}`,
            violatedRule: rule,
          };
        }
      } catch (error: any) {
        if (this.config.debug) {
          console.error(`[Sentinel] Rate limiter error for ${rule.attackType}:`, error.message);
        }
        // Continue checking other rules
      }
    }

    // All rules passed
    return { allowed: true };
  }

  /**
   * Build rate limit key
   * Format: attack:{attackType}:{endpoint}:{identifier}
   */
  private buildKey(rule: AttackRule, identifier: Identifier): string {
    const parts = ['attack', rule.attackType];
    
    if (rule.endpoint) {
      // Normalize endpoint for key (remove wildcards, etc.)
      const normalizedEndpoint = rule.endpoint.replace(/\*/g, 'wildcard');
      parts.push(normalizedEndpoint);
    } else {
      parts.push('global');
    }
    
    parts.push(identifier.value);
    
    return parts.join(':');
  }

  /**
   * Get default identifier from request
   */
  async getIdentifier(request: Request, context: any): Promise<Identifier> {
    if (this.config.identifierExtractor) {
      return await this.config.identifierExtractor(request, context);
    }

    // Default: IP address
    const ip = request.headers.get('CF-Connecting-IP') || 
               context.cf?.ip || 
               'unknown';
    
    return {
      value: ip,
      type: IdentifierType.IP,
    };
  }
}

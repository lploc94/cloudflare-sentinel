/**
 * Core types for Cloudflare Sentinel
 */

/**
 * Attack types that can be detected
 */
export enum AttackType {
  BRUTE_FORCE = 'brute_force',
  CREDENTIAL_STUFFING = 'credential_stuffing',
  SQL_INJECTION = 'sql_injection',
  XSS = 'xss',
  PATH_TRAVERSAL = 'path_traversal',
  DDOS = 'ddos',
  API_ABUSE = 'api_abuse',
  SCRAPING = 'scraping',
  RATE_LIMIT_VIOLATION = 'rate_limit_violation',
  SUSPICIOUS_PATTERN = 'suspicious_pattern',
  // Behavior-based attacks
  RESOURCE_ENUMERATION = 'resource_enumeration',
  LOGIC_ABUSE = 'logic_abuse',
  UNAUTHORIZED_ACCESS_ATTEMPT = 'unauthorized_access_attempt',
  ENDPOINT_PROBING = 'endpoint_probing',
  SEQUENTIAL_FAILURE = 'sequential_failure',
  // Entropy-based detection
  OBFUSCATED_PAYLOAD = 'obfuscated_payload',
  UNKNOWN = 'unknown',
  // Wildcard for matching all attacks
  WILDCARD = '*'
}

/**
 * Union type for attack types (includes wildcard)
 */
export type AttackTypeOrWildcard = AttackType | '*';

/**
 * Rate limit strategy
 */
export enum RateLimitStrategy {
  FIXED_WINDOW = 'fixed_window',
  SLIDING_WINDOW = 'sliding_window',
  TOKEN_BUCKET = 'token_bucket',
  ADAPTIVE = 'adaptive'
}

/**
 * Action to take when rate limit is exceeded
 */
export enum RateLimitAction {
  BLOCK = 'block',
  CHALLENGE = 'challenge',
  LOG_ONLY = 'log_only',
  THROTTLE = 'throttle'
}

/**
 * Rate limit period in seconds
 * Cloudflare Rate Limiting API only supports 10s or 60s
 */
export enum RateLimitPeriod {
  /** 10 seconds - for burst protection */
  TEN_SECONDS = 10,
  /** 60 seconds (1 minute) - for sustained rate limiting */
  ONE_MINUTE = 60
}

/**
 * Severity level of security events
 */
export enum SecuritySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

/**
 * Identifier type for rate limiting
 */
export enum IdentifierType {
  IP = 'ip',
  USER = 'user',
  IP_RANGE = 'ip_range',
  IP_ENDPOINT = 'ip_endpoint',
  CUSTOM = 'custom'
}

/**
 * Identifier for rate limiting
 */
export interface Identifier {
  value: string;
  type: IdentifierType;
}

/**
 * Attack limit configuration
 */
export interface AttackLimit {
  /** Max occurrences allowed */
  limit: number;
  /** Time period - only 10s or 60s supported by Cloudflare Rate Limiting API */
  period: RateLimitPeriod;
  /** Action: block immediately or log only */
  action: 'block' | 'log_only';
  /** Only log, don't block */
  logOnly?: boolean;
  /** Priority (higher = check first, lower = check last) */
  priority?: number;
}

/**
 * Endpoint limit configuration
 */
export interface EndpointLimit {
  /** Max requests allowed */
  limit: number;
  /** Time period - only 10s or 60s supported by Cloudflare Rate Limiting API */
  period: RateLimitPeriod;
  /** Key extractor */
  keyExtractor?: (request: Request, context?: any) => string | Promise<string>;
}

/**
 * Rate limit rule definition (legacy)
 */
export interface RateLimitRule {
  /** Rule ID */
  id: string;
  /** Rule name */
  name: string;
  /** Path pattern to match (glob format) */
  pathPattern: string;
  /** Method to match (GET, POST, etc.) */
  method?: string | string[];
  /** Maximum requests allowed in window */
  maxRequests: number;
  /** Time window in seconds */
  windowSeconds: number;
  /** Rate limiting strategy */
  strategy: RateLimitStrategy;
  /** Action to take when limit exceeded */
  action: RateLimitAction;
  /** Key to group requests by (ip, user_id, custom) */
  keyExtractor: (request: Request, context?: any) => string | Promise<string>;
  /** Custom condition to enable rule */
  condition?: (request: Request, context?: any) => boolean | Promise<boolean>;
  /** Bypass condition */
  bypass?: (request: Request, context?: any) => boolean | Promise<boolean>;
  /** Rule enabled */
  enabled: boolean;
}

/**
 * Attack pattern definition for detection
 */
export interface AttackPattern {
  /** Pattern identifier */
  id: string;
  /** Attack type this pattern detects */
  type: AttackType;
  /** Pattern name */
  name: string;
  /** Pattern description */
  description?: string;
  /** Severity if detected */
  severity: SecuritySeverity;
  /** Detection function */
  detect: (request: Request, context?: any) => boolean | Promise<boolean>;
  /** Confidence score (0-1) if detected */
  confidence?: number;
}

/**
 * Detection method
 */
export enum DetectionMethod {
  PATTERN = 'pattern',      // Pattern-based (SQL injection, XSS)
  BEHAVIOR = 'behavior',    // Behavior-based (sequential failures)
  RATE_LIMIT = 'rate_limit' // Rate limit violation
}

/**
 * Event category
 */
export enum EventCategory {
  TECHNICAL = 'technical',  // Technical attacks (SQL, XSS)
  LOGICAL = 'logical',      // Business logic attacks
  ABUSE = 'abuse'           // Rate limit, API abuse
}

/**
 * Security event to be logged
 */
export interface SecurityEvent {
  /** Event timestamp */
  timestamp: number;
  /** Event ID (UUID) */
  eventId: string;
  /** Attack type detected */
  attackType: AttackType;
  /** Detection method */
  detectionMethod: DetectionMethod;
  /** Event category */
  eventCategory: EventCategory;
  /** Severity level */
  severity: SecuritySeverity;
  /** Confidence score (0-1) */
  confidence: number;
  /** Request path */
  path: string;
  /** HTTP method */
  method: string;
  /** Response status code */
  statusCode: number;
  /** Client IP address */
  ipAddress: string;
  /** User agent */
  userAgent?: string;
  /** Country code (from CF) */
  country?: string;
  /** ASN (autonomous system number) */
  asn?: number;
  /** Request headers (filtered) */
  headers?: Record<string, string>;
  /** Request body (sanitized) */
  body?: string;
  /** Query parameters */
  queryParams?: Record<string, string>;
  /** User ID if authenticated */
  userId?: string;
  /** Rule ID that triggered */
  ruleId?: string;
  /** Action taken */
  action: RateLimitAction;
  /** Was request blocked */
  blocked: boolean;
  /** Number of violations for this key */
  violations?: number;
  /** Sequential failure count (for behavior detection) */
  sequentialFailures?: number;
  /** Response time in ms */
  responseTime?: number;
  /** Additional metadata */
  metadata?: Record<string, any>;
}

/**
 * Rate limit state for a key
 */
export interface RateLimitState {
  /** Number of requests in current window */
  count: number;
  /** Window start timestamp */
  windowStart: number;
  /** First violation timestamp */
  firstViolation?: number;
  /** Total violations */
  violations: number;
  /** Is currently blocked */
  blocked: boolean;
  /** Block expires at */
  blockExpiresAt?: number;
}

/**
 * Configuration for Sentinel
 */
export interface SentinelConfig {
  /** D1 database binding for persistent logs */
  db?: D1Database;
  /** Analytics Engine binding for real-time analytics */
  analytics?: AnalyticsEngineDataset;
  /** KV namespace for behavior tracking (not for rate limiting) */
  kv?: KVNamespace;
  /** Cloudflare Rate Limiting API binding */
  rateLimiter?: any;
  
  /** 
   * Attack limits (NEW - primary rate limiting method)
   * 
   * Supports:
   * 1. Global limits: { sql_injection: { limit, period, action } }
   * 2. Endpoint-scoped: { '/api/*': { sql_injection: {...} } }
   * 
   * Execution order: Global first, then by endpoint specificity
   */
  attackLimits?: Record<string, AttackLimit | Record<string, AttackLimit>>;
  
  /** Endpoint limits (optional, legacy) */
  endpointLimits?: Record<string, EndpointLimit>;
  /** Identifier extractor (default: IP) */
  identifierExtractor?: (request: Request, context?: any) => Identifier | Promise<Identifier>;
  
  /** Detectors (NEW - pluggable detector system) */
  detectors?: any[];  // IDetector[] - any to avoid circular dependency
  
  /**
   * Endpoint-specific detectors
   * 
   * Apply additional detectors only to specific endpoints.
   * Global detectors (above) run first, then endpoint-specific detectors.
   * 
   * Example:
   * ```typescript
   * endpointDetectors: {
   *   '/api/search/*': [new EntropyDetector({ entropyThreshold: 5.0 })],
   *   '/api/admin/*': [new EntropyDetector({ entropyThreshold: 4.5 })],
   * }
   * ```
   * 
   * Supports glob patterns: *, **, ?
   * Default: {} (no endpoint-specific detectors)
   */
  endpointDetectors?: Record<string, any[]>;  // Record<string, IDetector[]>
  
  /** Enable early block check (skip detection if already blocked) */
  enableEarlyBlockCheck?: boolean;
  
  /** Rate limit rules (legacy - for backwards compatibility) */
  rules?: RateLimitRule[];
  /** Attack patterns to detect (legacy) */
  patterns?: AttackPattern[];
  /** Enable debug logging */
  debug?: boolean;
  /** Custom logger function */
  logger?: (message: string, data?: any) => void;
  /** Max events to batch before writing to D1 */
  batchSize?: number;
  /** Batch flush interval in seconds */
  batchFlushInterval?: number;
  /** Headers to exclude from logging (for privacy) */
  excludeHeaders?: string[];
  /** Enable analytics engine logging */
  enableAnalytics?: boolean;
  /** Enable D1 logging */
  enableD1?: boolean;
  /** Enable behavior tracking for logic-based attacks */
  enableBehaviorTracking?: boolean;
  /** Failure threshold for behavior detection */
  behaviorFailureThreshold?: number;
  /** Time window for behavior detection (seconds) */
  behaviorTimeWindow?: number;
  /** Max paths to track per IP */
  behaviorMaxPaths?: number;
  
  /** Enable in-memory caching for rate limit checks */
  enableRateLimitCache?: boolean;
  /** Cache TTL in milliseconds */
  rateLimitCacheTTL?: number;
  
  /** Whitelist configuration - bypass security checks for trusted sources */
  whitelist?: {
    ips?: string[];
    ipRanges?: string[];
    userIds?: string[];
    customCheck?: (identifier: Identifier, context?: any) => boolean | Promise<boolean>;
  };
  
  /** Notification configuration */
  notification?: {
    enabled: boolean;
    manager?: any; // NotificationManager instance (avoid circular dependency)
    realtime?: {
      enabled: boolean;
      severities?: string[]; // 'critical', 'high', 'medium', 'low'
      attackTypes?: string[]; // Specific attack types or '*' for all
      blockedOnly?: boolean;
      minConfidence?: number;
      rateLimit?: {
        limit: number;
        period: number; // seconds
      };
    };
  };
}

/**
 * Result of rate limit check
 */
export interface RateLimitResult {
  /** Is request allowed */
  allowed: boolean;
  /** Rule that was triggered */
  rule?: RateLimitRule;
  /** Current state */
  state?: RateLimitState;
  /** Retry after (seconds) */
  retryAfter?: number;
  /** Reason for blocking */
  reason?: string;
}

/**
 * Attack detection result
 */
export interface AttackDetectionResult {
  /** Was attack detected */
  detected: boolean;
  /** Patterns that matched */
  patterns: AttackPattern[];
  /** Highest severity found */
  severity: SecuritySeverity;
  /** Average confidence score */
  confidence: number;
}

export type { RequestContext, CloudflareContext } from './request-context';
export { extractCloudflareContext, createRequestContext } from './request-context';

// Notification types
export type {
  NotificationChannel,
  NotificationSeverity,
  NotificationType,
  INotificationChannel,
  AttackNotification,
  AttackSummary,
  AttackSpikeAlert,
  MetricsSummary,
  NotificationPayload,
  RealtimeNotificationConfig,
  NotificationConfig,
  EmailChannelConfig,
  SlackChannelConfig,
  TelegramChannelConfig,
  WebhookChannelConfig,
} from './notification';

// Validation
export * from './validation';

/**
 * Core types for Cloudflare Sentinel
 */

/**
 * Attack types that can be detected
 */
export enum AttackType {
  BLOCKLIST = 'blocklist',
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
  RESOURCE_ENUMERATION = 'resource_enumeration',
  LOGIC_ABUSE = 'logic_abuse',
  UNAUTHORIZED_ACCESS_ATTEMPT = 'unauthorized_access_attempt',
  ENDPOINT_PROBING = 'endpoint_probing',
  SEQUENTIAL_FAILURE = 'sequential_failure',
  OBFUSCATED_PAYLOAD = 'obfuscated_payload',
  COMMAND_INJECTION = 'command_injection',
  SSRF = 'ssrf',
  NOSQL_INJECTION = 'nosql_injection',
  DATA_LEAK = 'data_leak',
  ERROR_LEAK = 'error_leak',
  // New attack types
  CSRF = 'csrf',
  XXE = 'xxe',
  OPEN_REDIRECT = 'open_redirect',
  HTTP_SMUGGLING = 'http_smuggling',
  BOT = 'bot',
  JWT_ATTACK = 'jwt_attack',
  SSTI = 'ssti',
  UNKNOWN = 'unknown',
}

/**
 * Severity level of security events
 */
export enum SecuritySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical',
}

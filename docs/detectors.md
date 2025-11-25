# Detector Configuration Guide

## Architecture

```
Request → [Request Detectors] → Handler → Response → [Response Detectors] → Client
```

## Detector Types

### Request Detectors
Scan incoming requests **before** reaching origin:
- `SQLInjectionRequestDetector` - SQL injection in query/body/headers
- `XSSRequestDetector` - XSS payloads in input
- `PathTraversalRequestDetector` - Path traversal in paths/params
- `BruteForceDetector` - Login patterns (request + response)
- `EntropyDetector` - Obfuscated/encoded payloads using Shannon entropy

### Response Detectors
Scan outgoing responses **after** from origin:
- `SQLInjectionResponseDetector` - SQL error leaks, query structures
- `XSSResponseDetector` - Reflected XSS, unsafe scripts
- `PathTraversalResponseDetector` - Directory listings, file leaks

---

## Configuration Options

### Option 1: Full Protection (Recommended)

Enable **both** request and response detection:

```typescript
import {
  Sentinel,
  // Request detectors
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  PathTraversalRequestDetector,
  BruteForceDetector,
  // Response detectors
  SQLInjectionResponseDetector,
  XSSResponseDetector,
  PathTraversalResponseDetector,
} from 'cloudflare-sentinel';

const sentinel = new Sentinel({
  rateLimiter: env.RATE_LIMITER,
  db: env.DB,
  analytics: env.ANALYTICS,
  kv: env.BEHAVIOR_KV,
  
  detectors: [
    // Request scanning
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new PathTraversalRequestDetector(),
    new BruteForceDetector(),
    
    // Response scanning
    new SQLInjectionResponseDetector(),
    new XSSResponseDetector(),
    new PathTraversalResponseDetector(),
  ],
});
```

**Coverage**: ~95% attacks

---

### Option 2: Request-Only (Performance)

Only scan requests, skip response scanning:

```typescript
const sentinel = new Sentinel({
  detectors: [
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new PathTraversalRequestDetector(),
    new BruteForceDetector(),
    // No response detectors
  ],
});
```

**Coverage**: ~60% attacks  
**Performance**: Faster (no response cloning)

---

### Option 3: Response-Only (Monitoring)

Only scan responses to detect leaks:

```typescript
const sentinel = new Sentinel({
  detectors: [
    new SQLInjectionResponseDetector(),
    new XSSResponseDetector(),
    new PathTraversalResponseDetector(),
  ],
});
```

**Coverage**: ~35% (leaks only)  
**Use case**: Monitor existing website for vulnerabilities

---

### Option 4: Selective Detection

Choose specific detectors for your use case:

```typescript
// E-commerce: Focus on SQL + brute force
const sentinel = new Sentinel({
  detectors: [
    new SQLInjectionRequestDetector(),
    new SQLInjectionResponseDetector(),
    new BruteForceDetector(),
  ],
});

// Blog/CMS: Focus on XSS
const sentinel = new Sentinel({
  detectors: [
    new XSSRequestDetector(),
    new XSSResponseDetector(),
  ],
});

// File sharing: Focus on path traversal
const sentinel = new Sentinel({
  detectors: [
    new PathTraversalRequestDetector(),
    new PathTraversalResponseDetector(),
  ],
});
```

---

## Performance Comparison

| Configuration | Detectors | Avg Latency | Coverage |
|---------------|-----------|-------------|----------|
| **Full** | 7 (4 req + 3 res) | ~15ms | 95% |
| **Request Only** | 4 | ~8ms | 60% |
| **Response Only** | 3 | ~12ms | 35% |
| **Selective** | 2-3 | ~6-10ms | 40-70% |

---

## Best Practices

### ✅ DO

1. **Enable both request + response** for full protection
2. **Test configuration** with real traffic  
3. **Monitor false positives** and tune
4. **Start with full protection** then optimize if needed

### ❌ DON'T

1. **Don't disable all response detectors** - miss critical leaks
2. **Don't enable too many** if performance is critical
3. **Don't skip testing** - verify detectors work with your app

---

## Examples

### Production Website

```typescript
const sentinel = new Sentinel({
  detectors: [
    // Critical request scanning
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new BruteForceDetector(),
    
    // Response leak detection
    new SQLInjectionResponseDetector(),
    new XSSResponseDetector(),
  ],
});
```

### High-Performance API

```typescript
const sentinel = new Sentinel({
  detectors: [
    // Request only - faster
    new SQLInjectionRequestDetector(),
    // Skip response scanning
  ],
});
```

### Security Audit

```typescript
import { RateLimitPeriod } from 'cloudflare-sentinel';

const sentinel = new Sentinel({
  detectors: [
    // Full coverage
    new SQLInjectionRequestDetector(),
    new SQLInjectionResponseDetector(),
    new XSSRequestDetector(),
    new XSSResponseDetector(),
    new PathTraversalRequestDetector(),
    new PathTraversalResponseDetector(),
    new BruteForceDetector(),
  ],
  
  // Log only - don't block (still requires valid period due to API constraints)
  attackLimits: {
    '*': { limit: 999999, period: RateLimitPeriod.TEN_SECONDS, action: 'log_only' },
  },
});
```

---

## Shannon Entropy Detector

Detects **obfuscated/encoded payloads** by analyzing the randomness (entropy) of input data.

### What is Shannon Entropy?

Shannon entropy measures the randomness of data (0-8 bits):

| Entropy | Type | Examples |
|---------|------|----------|
| 0-3 | Normal text | `hello world`, `john doe` |
| 3-5 | URL/JSON data | `id=123&name=john`, `{"user":"test"}` |
| **5-8** | **Encoded/Obfuscated** | Base64, hex, encrypted data |

### Use Cases

**✅ WHEN TO USE:**
- API endpoints that should NOT receive encoded data
- Login forms (detect encoded injection payloads)
- Query parameters that expect simple values
- Detect data exfiltration (encoded sensitive data being sent out)

**❌ WHEN NOT TO USE (or add to excludePaths):**
- JWT/OAuth token endpoints
- File upload endpoints (base64 images)
- Encryption/crypto endpoints
- Webhook endpoints receiving encoded payloads

### Configuration

```typescript
import { EntropyDetector, RateLimitPeriod } from 'cloudflare-sentinel';

const sentinel = new Sentinel({
  detectors: [
    // Pattern-based detectors first
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    
    // Entropy detector catches obfuscated attacks
    new EntropyDetector({
      // Minimum entropy to trigger (0-8, default: 5.0)
      entropyThreshold: 5.0,
      
      // Minimum string length to analyze (default: 16)
      minLength: 16,
      
      // Paths to exclude (glob patterns)
      excludePaths: [
        '/api/auth/token',
        '/api/auth/refresh',
        '/oauth/*',
        '/api/upload/*',
        '/webhook/*',
      ],
      
      // Fields to exclude
      excludeFields: [
        'token', 'jwt', 'access_token', 'refresh_token',
        'image', 'file', 'data', 'password',
      ],
      
      // What to check
      checkQuery: true,
      checkBody: true,
      checkHeaders: ['x-api-key', 'x-auth-token'],
      
      // Reduce false positives: require encoding patterns
      requireAdditionalSignals: false,
    }),
  ],
  
  attackLimits: {
    obfuscated_payload: {
      limit: 5,
      period: RateLimitPeriod.ONE_MINUTE,
      action: 'block',
    },
  },
});
```

### Threshold Guidelines

| Threshold | Sensitivity | False Positives | Use Case |
|-----------|-------------|-----------------|----------|
| **4.5** | High | More FPs | Security audit, paranoid mode |
| **5.0** | Balanced | Moderate | Default, production |
| **5.5** | Low | Few FPs | High-traffic APIs |
| **6.0** | Very Low | Minimal | Only catch highly obfuscated |

### Example Detections

```typescript
// ✅ DETECTED (high entropy)
"U0VMRUNUICogRlJPTSB1c2VycyBXSEVSRSBpZCA9IDE="  // Base64 SQL injection
"53454c454354202a2046524f4d207573657273"        // Hex encoded payload
"\\x53\\x45\\x4c\\x45\\x43\\x54"                      // Hex escape sequences

// ✅ NOT DETECTED (normal text)
"hello world"                                      // Low entropy
"john.doe@example.com"                             // Normal email
"user_id=12345"                                    // Simple parameter
```

### Combining with Pattern Detectors

Entropy detector is **complementary** to pattern-based detectors:

1. **Pattern detectors** catch known attack signatures
2. **Entropy detector** catches obfuscated/encoded versions that bypass patterns

```typescript
// Attacker's evolution:
"' OR '1'='1"                    // Caught by SQLInjectionDetector
"JyBPUiAnMSc9JzE="              // Base64 encoded - caught by EntropyDetector
"\\x27\\x20\\x4f\\x52\\x20\\x27\\x31" // Hex encoded - caught by EntropyDetector
```

### Performance

- **Overhead**: ~1-2ms per request
- **Memory**: Minimal (no state)
- **Recommended**: Enable on endpoints receiving user input

---

## Endpoint-Specific Detectors

Apply detectors **only to specific endpoints** instead of globally.

### Why Use Endpoint-Specific Detectors?

1. **Performance** - Don't run expensive detectors on all endpoints
2. **Reduce false positives** - Only check entropy on endpoints that shouldn't receive encoded data
3. **Fine-grained control** - Different detection rules for different parts of your app

### Configuration

```typescript
import { 
  Sentinel, 
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  EntropyDetector,
  RateLimitPeriod,
} from 'cloudflare-sentinel';

const sentinel = new Sentinel({
  // Unified detectors configuration (supports both formats)
  detectors: {
    // Global detectors - run on ALL endpoints (use '*' key)
    '*': [
      new SQLInjectionRequestDetector(),
      new XSSRequestDetector(),
    ],
    
    // Endpoint-specific detectors - run ONLY on matching endpoints
    '/api/search/*': [
      new EntropyDetector({ entropyThreshold: 5.0 }),
    ],
    
    // Admin endpoints - stricter entropy check
    '/api/admin/*': [
      new EntropyDetector({ 
        entropyThreshold: 4.5,  // More sensitive
        excludeFields: [],       // Check all fields
      }),
    ],
    
    // Public API - very strict
    '/api/public/**': [
      new EntropyDetector({ entropyThreshold: 4.0 }),
    ],
  },
  
  attackLimits: {
    sql_injection: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
    xss: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
    obfuscated_payload: { limit: 3, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
  },
});
```

#### Backward Compatibility (Array Format)

```typescript
// Still supported - all detectors are global
const sentinel = new Sentinel({
  detectors: [
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
  ],
});
```

### Execution Order

1. **Global detectors** run first (in priority order)
2. **Endpoint-specific detectors** run after (if endpoint matches)
3. First detection wins - stops on first attack found

### Pattern Matching

| Pattern | Matches | Doesn't Match |
|---------|---------|---------------|
| `/api/*` | `/api/users`, `/api/posts` | `/api/v1/users` |
| `/api/**` | `/api/users`, `/api/v1/users`, `/api/a/b/c` | `/other` |
| `/api/v?/users` | `/api/v1/users`, `/api/v2/users` | `/api/v10/users` |

### Examples

#### Only check entropy on form endpoints

```typescript
endpointDetectors: {
  '/api/*/submit': [
    new EntropyDetector({ entropyThreshold: 5.0 }),
  ],
  '/api/contact': [
    new EntropyDetector({ entropyThreshold: 5.0 }),
  ],
}
```

#### Different thresholds for different security levels

```typescript
endpointDetectors: {
  // Public endpoints - standard check
  '/public/*': [
    new EntropyDetector({ entropyThreshold: 5.5 }),
  ],
  
  // Internal API - stricter
  '/internal/*': [
    new EntropyDetector({ entropyThreshold: 4.5 }),
  ],
  
  // Admin - most strict
  '/admin/**': [
    new EntropyDetector({ 
      entropyThreshold: 4.0,
      requireAdditionalSignals: false,
    }),
  ],
}
```

#### Skip entropy check on certain endpoints

Don't add endpoint to `endpointDetectors` - only global detectors will run:

```typescript
// EntropyDetector NOT in global detectors
detectors: [
  new SQLInjectionRequestDetector(),
  new XSSRequestDetector(),
],

// EntropyDetector ONLY on these endpoints
endpointDetectors: {
  '/api/search/*': [new EntropyDetector()],
  '/api/form/*': [new EntropyDetector()],
}
// Other endpoints won't run EntropyDetector

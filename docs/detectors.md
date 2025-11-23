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
  
  // Log only - don't block
  attackLimits: {
    '*': { limit: 999999, period: 1, logOnly: true },
  },
});
```


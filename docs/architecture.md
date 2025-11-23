# Architecture

Internal design and component overview for contributors.

## System Overview

```
┌─────────────────────────────────────────┐
│         Sentinel Middleware              │
│                                          │
│  ┌────────────────────────────────────┐ │
│  │  Request → Detect → Limit → Log   │ │
│  └────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

## Core Components

### 1. Sentinel (Middleware)

**Location**: `src/middleware/index.ts`

Main orchestrator that coordinates all components:

```typescript
Request
  → Whitelist Check
  → Early Block Check (optimization)
  → Request Detectors
  → Rate Limiting
  → Origin Request
  → Response Detectors
  → Behavior Tracking
  → Logging
```

**Key Methods**:
- `protect()` - Main protection flow
- `runRequestDetectors()` - Execute request detectors
- `runResponseDetectors()` - Execute response detectors
- `logAttack()` - Log to Analytics + D1

### 2. Detectors

**Location**: `src/detector/`

Pluggable system for attack detection:

```typescript
interface IDetector {
  name: string;
  priority: number;
  detectRequest?(request, context): Promise<DetectorResult | null>;
  detectResponse?(request, response, context): Promise<DetectorResult | null>;
}
```

**Built-in Detectors**:
- SQL Injection (request + response)
- XSS (request + response)
- Path Traversal (request + response)
- Brute Force
- Command Injection

**Priority System**: Higher priority = checked first (0-100)

### 3. Attack Limiter

**Location**: `src/middleware/attack-limiter.ts`

Rate limiting based on attack types:

```typescript
// Layered rate limiting
Global → Endpoint-scoped → Specific

// Uses Cloudflare Rate Limiting API (free)
rateLimiter.limit({ key, limit, period })
```

**Features**:
- Attack-based (not just endpoint-based)
- Layered checking (global + endpoint)
- Early block optimization
- In-memory cache

### 4. Logger

**Location**: `src/logger/index.ts`

Smart logging to minimize costs:

```typescript
Success (< 400) → Skip logging
Error (>= 400) → Log to Analytics
Attack → Log to Analytics + D1 (if critical)
```

**Destinations**:
- **Analytics Engine**: All errors/attacks
- **D1**: Critical attacks only (high/critical severity)
- **Behavior Tracking**: Sequential failures (KV)

### 5. Behavior Tracker

**Location**: `src/logger/behavior-tracker.ts`

Detects logic-based attacks via KV:

```typescript
Track: IP + Endpoint + Failures
Detect:
- Resource enumeration (many 404s)
- Endpoint probing
- Sequential failures
```

### 6. Notification System

**Location**: `src/notification/`

Pluggable notification channels:

```typescript
NotificationManager
  ├─ EmailChannel
  ├─ SlackChannel
  └─ [Future channels]
```

## Data Flow

### Protection Flow

```
1. Request Arrives
   ↓
2. Whitelist Check → Bypass?
   ↓
3. Early Block Check → Already blocked?
   ↓
4. Request Detection → Attack found?
   ↓
5. Rate Limit Check → Limit exceeded?
   ↓
6. Fetch Origin
   ↓
7. Response Detection → Leaks found?
   ↓
8. Behavior Tracking → Pattern detected?
   ↓
9. Logging (if needed)
   ↓
10. Notification (if critical)
```

### Logging Decision Tree

```
Request/Response
   ↓
Status < 400? → Skip (success)
   ↓ No
Status >= 400?
   ↓ Yes
Log to Analytics
   ↓
Critical/High severity? → Yes → Log to D1
   ↓ No
Done
```

## Storage

### Analytics Engine
- **Purpose**: Real-time metrics
- **What**: All errors + attacks
- **Retention**: 90 days
- **Cost**: FREE (unlimited writes)

### D1 Database
- **Purpose**: Detailed attack logs
- **What**: Critical attacks only
- **Retention**: User-controlled
- **Cost**: FREE (<50M reads/month)

### KV
- **Purpose**: Behavior tracking
- **What**: Sequential failures
- **Retention**: TTL-based
- **Cost**: FREE (<10M ops/month)

## Extension Points

### 1. Custom Detector

```typescript
class MyDetector extends BaseDetector {
  name = 'my-attack';
  priority = 80;
  
  async detectRequest(request, context) {
    // Your logic
    if (suspicious) {
      return this.createResult(...);
    }
    return null;
  }
}
```

### 2. Custom Notification Channel

```typescript
class MyChannel extends BaseNotificationChannel {
  name = 'my-channel';
  priority = 50;
  
  async send(notification) {
    // Your send logic
  }
}
```

### 3. Custom Identifier

```typescript
identifierExtractor: async (request) => {
  const userId = await extractUser(request);
  return { value: userId, type: 'user' };
}
```

## Performance Considerations

### Optimizations

1. **Early Block Check**: Skip detection if IP already blocked
2. **Smart Logging**: Only log errors/attacks (95% reduction)
3. **Cache**: In-memory cache for rate limit checks
4. **Parallel**: Detectors run in parallel (when possible)

### Overhead

```
Base: ~1-2ms per request
+ Request detection: ~0.5-1ms per detector
+ Response detection: ~5-20ms (body parsing)
+ Rate limit check: ~0.5ms
+ Logging: ~1ms (async)
```

**Recommendation**: Disable response detectors if not needed

## Design Decisions

### Why Pluggable Detectors?

- Easy to extend
- Custom detection logic
- Enable/disable specific detectors
- Priority-based execution

### Why Attack-Based Rate Limiting?

Traditional WAF rate limits by endpoint:
```
/api/* → 100 req/min
```

Sentinel limits by attack type:
```
sql_injection → 10/hour (across all endpoints)
/api/admin/* → sql_injection → 1/day (specific endpoint)
```

**Benefit**: Can't bypass by switching endpoints

### Why Smart Logging?

Logging every request to D1/Analytics = expensive

Only log errors/attacks = 95% cost reduction

### Why Cloudflare Rate Limiting API?

- Native, fast, atomic
- FREE (included in Workers)
- No KV operations needed
- Cross-isolate consistency

## Testing Strategy

### Unit Tests

```bash
npm test
```

Test individual components:
- Detectors
- Rate limiter logic
- Logger decisions
- Formatters

### Integration Tests

Test full flow:
- Request → Detection → Blocking
- Logging to D1/Analytics
- Notification sending

### Manual Testing

```bash
# Deploy to staging
wrangler deploy --env staging

# Trigger attacks
curl "https://your-worker.workers.dev?id=1' OR '1'='1"

# Check results
wrangler tail --env staging
```

## Contributing

See implementation guides in each component:
- [Detector Guide](../src/detector/README.md)
- [Notification Guide](../src/notification/README.md)
- [Middleware Guide](../src/middleware/README.md)

---

For questions or discussions, open an issue on GitHub.

# Middleware

Internal guide for contributors working on core middleware.

## Architecture

```
Sentinel (main middleware)
    ├─ Whitelist
    ├─ AttackLimiter (rate limiting)
    ├─ Detectors (pluggable)
    ├─ SecurityLogger (smart logging)
    └─ BehaviorTracker (KV-based)
```

## File Structure

```
middleware/
├── index.ts           # Sentinel class (main)
├── attack-limiter.ts  # Rate limiting logic
└── whitelist.ts       # IP whitelisting
```

## Sentinel Flow

```typescript
Request → protect()
    ↓
1. Whitelist Check → Bypass?
    ↓
2. Early Block Check → Already blocked?
    ↓
3. Request Detection → Attack found?
    ├─ Yes → Rate limit → Block or log
    └─ No → Continue
    ↓
4. Fetch Origin
    ↓
5. Response Detection → Leak found?
    ├─ Yes → Log (can't block, already sent)
    └─ No → Continue
    ↓
6. Behavior Tracking → Pattern detected?
    ↓
7. Logging (if needed)
    ↓
8. Notification (if critical)
```

## Key Components

### 1. AttackLimiter

**Purpose**: Rate limit by attack type

**Features**:
- Layered checking (global + endpoint)
- Cloudflare Rate Limiting API
- In-memory cache
- Early block optimization

**Methods**:
```typescript
getIdentifier(request) → Identifier
checkAndIncrement(identifier, attackType, endpoint) → allowed?
isBlocked(identifier, endpoint) → blocked?
```

### 2. SecurityLogger

**Purpose**: Smart logging to minimize costs

**Decision Tree**:
```
Success (< 400) → Skip
Error (>= 400) → Analytics
Attack → Analytics + D1 (if critical)
```

**Methods**:
```typescript
logIfNeeded(request, response, context)
decideLogging(request, response, context) → LogDecision
```

### 3. BehaviorTracker

**Purpose**: Detect logic-based attacks

**Tracks**: Sequential failures per IP+endpoint

**Detection**:
- Resource enumeration (many 404s)
- Endpoint probing
- Brute force patterns

## Configuration

### SentinelConfig

```typescript
interface SentinelConfig {
  // Required bindings
  rateLimiter: any;
  db?: D1Database;
  analytics?: AnalyticsEngineDataset;
  kv?: KVNamespace;
  
  // Attack limits (NEW - primary method)
  attackLimits?: Record<string, AttackLimit | Record<string, AttackLimit>>;
  
  // Detectors (pluggable)
  detectors?: IDetector[];
  
  // Feature flags
  enableEarlyBlockCheck?: boolean;
  enableAnalytics?: boolean;
  enableD1?: boolean;
  enableBehaviorTracking?: boolean;
  
  // Whitelist
  whitelist?: {
    ips?: string[];
    ipRanges?: string[];
    customCheck?: (identifier, context) => boolean;
  };
  
  // Notification
  notification?: {
    enabled: boolean;
    manager: NotificationManager;
    realtime?: { ... };
  };
}
```

## Extending

### Custom Middleware Hook

Not officially supported, but you can wrap:

```typescript
const sentinel = new Sentinel(config);

// Wrap protect method
const originalProtect = sentinel.protect.bind(sentinel);
sentinel.protect = async (request, next) => {
  // Before protection
  console.log('Before protect');
  
  // Call original
  const response = await originalProtect(request, next);
  
  // After protection
  console.log('After protect');
  
  return response;
};
```

### Custom Identifier Extractor

```typescript
identifierExtractor: async (request, context) => {
  // Extract from JWT
  const token = request.headers.get('Authorization')?.replace('Bearer ', '');
  const userId = await decodeJWT(token);
  
  return {
    value: userId || request.headers.get('CF-Connecting-IP'),
    type: userId ? 'user' : 'ip',
  };
}
```

## Performance

### Optimizations

1. **Early Block Check**: Skip detection if already blocked
2. **Parallel Detection**: Request detectors run in parallel
3. **Cache**: In-memory cache for rate limit checks
4. **Smart Logging**: Only log errors/attacks

### Monitoring

```typescript
// Measure overhead
const startTime = Date.now();
await sentinel.protect(request, next);
const overhead = Date.now() - startTime;
console.log(`Sentinel overhead: ${overhead}ms`);
```

## Testing

### Unit Tests

```bash
npm test -- middleware
```

### Integration Tests

```typescript
import { Sentinel } from '../middleware';

describe('Sentinel Integration', () => {
  it('blocks SQL injection', async () => {
    const sentinel = new Sentinel(config);
    
    const maliciousRequest = new Request('https://example.com?id=1\' OR \'1\'=\'1');
    const response = await sentinel.protect(maliciousRequest, () => {
      return new Response('Should not reach here');
    });
    
    expect(response.status).toBe(403);
  });
});
```

## Contributing

### Making Changes

1. Understand the flow (see above)
2. Add tests first
3. Implement feature
4. Update types
5. Document changes

### Code Style

- Use async/await
- Prefer early returns
- Add JSDoc comments
- Handle errors gracefully (fail-open)

---

**Questions?** Open an issue or discussion.

# Handler System

Handlers execute actions determined by the Resolver.

## Architecture

```
IActionHandler (interface)
    ↓
Built-in Handlers
    ├─ LogHandler          → Console/Analytics logging
    ├─ NotifyHandler       → Slack/webhook notifications (with timeout/retry)
    ├─ IncrementHandler    → Rate limit counter
    ├─ EscalateHandler     → Track repeat offenders + auto-block
    ├─ BlocklistHandler    → Add IP to blocklist (handles 'block', 'ban')
    └─ ReputationHandler   → Update reputation scores
```

## File Structure

```
handler/
├── types.ts              # IActionHandler interface
├── index.ts              # Exports
├── log.handler.ts        # Console + Analytics Engine
├── notify.handler.ts     # Webhook with timeout/retry
├── increment.handler.ts  # Rate limit counter
├── escalate.handler.ts   # Track + auto-block repeat offenders
├── blocklist.handler.ts  # Add to blocklist (handles 'block', 'ban')
└── reputation.handler.ts # IP reputation tracking
```

## Creating Custom Handler

```typescript
// src/handler/my-custom.handler.ts
import type { Action, HandlerContext } from '../pipeline/types';
import type { IActionHandler } from './types';

export interface MyHandlerOptions {
  // Your options
}

export class MyHandler implements IActionHandler {
  type = 'my_action';  // Action type to handle

  constructor(private options: MyHandlerOptions) {}

  async execute(action: Action, ctx: HandlerContext): Promise<void> {
    // Your logic here
    const data = action.data;
    
    // Example: Send to external service
    await fetch('https://api.example.com/events', {
      method: 'POST',
      body: JSON.stringify({
        type: this.type,
        data,
        timestamp: Date.now(),
      }),
    });
  }
}
```

## Registering Handler

```typescript
const pipeline = SentinelPipeline.sync([...])
  .score(new MaxScoreAggregator())
  .resolve(new DefaultResolver())
  .on('my_action', new MyHandler({ /* options */ }));
```

## Built-in Handlers

### LogHandler
```typescript
new LogHandler({
  console: true,           // Log to console
  analytics: env.ANALYTICS // CloudFlare Analytics Engine
})
```

### NotifyHandler
```typescript
new NotifyHandler({
  webhookUrl: 'https://hooks.slack.com/...',
  timeout: 5000,    // Timeout in ms (default: 5000)
  retries: 2,       // Retry count on failure (default: 0)
})
```

### IncrementHandler
```typescript
new IncrementHandler({
  kv: env.RATE_LIMIT_KV,
  ttl: 60  // seconds
})
```

### EscalateHandler
Track repeat offenders and auto-block when threshold reached:
```typescript
new EscalateHandler({
  kv: env.ESCALATION_KV,
  threshold: 3,           // Auto-block after 3 escalations
  ttl: 3600,              // 1 hour memory
  blocklistKv: env.BLOCKLIST_KV,  // Optional: enable auto-block
  blockDuration: 3600,    // Block duration when threshold reached
})
```

### BlocklistHandler
Handles `block` and `ban` actions:
```typescript
new BlocklistHandler({
  kv: env.BLOCKLIST_KV,
  defaultDuration: 3600,  // Block duration in seconds
  keyPrefix: 'blocked:',  // Key prefix in KV
})
```

### CuckooBlocklistHandler
Cost-efficient blocking with Cache API + Cuckoo Filter:
```typescript
new CuckooBlocklistHandler({
  queue: env.BLOCKLIST_QUEUE,  // Optional: for global sync
  pendingTtl: 300,             // Pending cache TTL (default: 300s)
})
```

## BlocklistHandler vs CuckooBlocklistHandler

| Aspect | BlocklistHandler | CuckooBlocklistHandler |
|--------|------------------|------------------------|
| **Write** | KV only | Pending Cache + KV + Queue |
| **Read** | KV per request | Filter (cached) + KV verify |
| **Latency** | ~10-50ms | ~0-5ms |
| **Cost (1M req)** | ~$0.50 | ~$0.001 |
| **Complexity** | Simple | Requires Queue consumer |
| **Global sync** | Immediate (KV) | ~5s (Queue) or ~5m (Cron) |

### When to use BlocklistHandler
- ✅ Simple setup, no Queue needed
- ✅ Low traffic (<100K requests/month)
- ✅ Need immediate global consistency
- ✅ Already have KV, don't want extra infrastructure

### When to use CuckooBlocklistHandler
- ✅ High traffic (>100K requests/month)
- ✅ Cost optimization is priority
- ✅ Can tolerate ~5s global sync delay
- ✅ Already have Queue infrastructure
- ✅ Need 0ms edge-local blocking

### Hybrid Usage (Both Together)
Both handlers use the same KV format (`blocked:${key}`), so they're compatible:

```typescript
// Option 1: Use CuckooBlocklistHandler for write + both detectors for read
pipeline.on(ActionType.BLOCK, new CuckooBlocklistHandler({
  queue: env.BLOCKLIST_QUEUE,
}));

// BlocklistDetector: Fallback direct KV check
// CuckooBlocklistDetector: Fast path via Filter

// Option 2: Use BlocklistHandler for write + CuckooBlocklistDetector for read
pipeline.on(ActionType.BLOCK, new BlocklistHandler({
  kv: env.BLOCKLIST_KV,
}));

// Use scheduled cron to rebuild Cuckoo Filter from KV every 5-10 minutes
// This gives cost-efficient reads with simple writes
```

## Action Types

| Type | Handler | Description |
|------|---------|-------------|
| `log` | LogHandler | Log event to console/analytics |
| `notify` | NotifyHandler | Send webhook notification |
| `increment_counter` | IncrementHandler | Increment rate limit counter |
| `escalate` | EscalateHandler | Track repeat offender, auto-block |
| `block` | BlocklistHandler | Add to blocklist |
| `ban` | BlocklistHandler | Add to blocklist |
| `update_reputation` | ReputationHandler | Update IP reputation score |

## Best Practices

1. **Keep handlers fast** - Use `ctx.waitUntil()` for slow operations
2. **Handle errors gracefully** - Don't let handler errors block the request
3. **Use typed action data** - Define interfaces for action.data

---

**Questions?** Open an issue on GitHub.

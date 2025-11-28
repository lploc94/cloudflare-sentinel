# Pipeline System

The core orchestration layer for Cloudflare Sentinel.

## Architecture

```
SentinelPipeline
    │
    ├─ .sync(detectors)     → Returns Decision
    ├─ .async(detectors)    → Returns void (fire & forget)
    │
    ├─ .score(aggregator)   → Set score aggregator
    ├─ .resolve(resolver)   → Set action resolver
    ├─ .on(type, handler)   → Register action handler
    │
    ├─ .process(request)    → Run request detection
    └─ .processResponse()   → Run response detection
```

## File Structure

```
pipeline/
├── types.ts              # Core interfaces
├── pipeline.ts           # SentinelPipeline class
├── decision.ts           # Decision class
└── index.ts              # Exports
```

## Pipeline Modes

### SYNC Pipeline
Returns `Decision` - user decides what to do.

```typescript
const pipeline = SentinelPipeline.sync([
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new RateLimitDetector({ kv: env.RATE_KV, limit: 100 }),
  new SQLInjectionRequestDetector(),
])
  .score(new MaxScoreAggregator())
  .resolve(new DefaultResolver())
  .on('log', new LogHandler())
  .on('increment_counter', new IncrementHandler(env.RATE_KV));

// Usage
const decision = await pipeline.process(request, { env, ctx });
if (decision.has('block')) {
  return new Response('Blocked', { status: 403 });
}
```

### ASYNC Pipeline
Returns `void` - executes all handlers automatically.

```typescript
const asyncPipeline = SentinelPipeline.async([
  new BehaviorDetector(),
])
  .score(new WeightedAggregator())
  .resolve(new DefaultResolver())
  .on('update_reputation', new ReputationHandler());

// Usage (fire & forget)
ctx.waitUntil(asyncPipeline.process(request, { env, ctx }));
```

## Decision Class

```typescript
interface Decision {
  actions: Action[];
  score: ThreatScore;
  
  has(type: string): boolean;   // Check if action exists
  get(type: string): any;       // Get action data
}

// Example
const decision = await pipeline.process(request, ctx);

if (decision.has('block')) {
  const blockData = decision.get('block');
  return new Response(blockData.reason, { status: 403 });
}
```

## Request vs Response Detection

### Request Detection
Analyze incoming request before forwarding to origin.

```typescript
const decision = await pipeline.process(request, ctx);
```

### Response Detection
Analyze response from origin (data leak detection).

```typescript
const response = await fetch(request);
const respDecision = await pipeline.processResponse(request, response, ctx);
```

## Pipeline Flow

```
Request
    │
    ▼
┌─────────────────────────────────────┐
│  1. DETECTION                       │
│     Run all detectors               │
│     → DetectorResult[]              │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  2. SCORING                         │
│     Aggregate results               │
│     → ThreatScore                   │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  3. RESOLUTION                      │
│     Determine actions               │
│     → Action[]                      │
└─────────────────────────────────────┘
    │
    ▼
┌─────────────────────────────────────┐
│  4. HANDLING                        │
│     Execute handlers                │
│     → void                          │
└─────────────────────────────────────┘
    │
    ▼
Decision (sync) / void (async)
```

## Core Types

```typescript
interface Action {
  type: string;
  data?: any;
}

interface ThreatScore {
  score: number;           // 0-100
  level: ThreatLevel;      // 'none' | 'low' | 'medium' | 'high' | 'critical'
  results: DetectorResult[];
}

interface PipelineContext {
  env: any;
  ctx: ExecutionContext;
  request?: Request;
  response?: Response;
}
```

## Full Example

```typescript
import { 
  SentinelPipeline,
  BlocklistDetector,
  RateLimitDetector,
  SQLInjectionRequestDetector,
  MaxScoreAggregator,
  MultiLevelResolver,
  LogHandler,
  IncrementHandler,
  BanHandler,
} from 'cloudflare-sentinel';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Build pipeline
    const pipeline = SentinelPipeline.sync([
      new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
      new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 100, period: 60 }),
      new SQLInjectionRequestDetector(),
    ])
      .score(new MaxScoreAggregator())
      .resolve(new MultiLevelResolver({
        levels: [
          { maxScore: 30, actions: ['increment'] },
          { maxScore: 60, actions: ['log', 'escalate'] },
          { maxScore: 100, actions: ['block', 'notify', 'ban'] },
        ],
      }))
      .on('log', new LogHandler({ console: true }))
      .on('increment', new IncrementHandler({ kv: env.RATE_LIMIT_KV }))
      .on('ban', new BanHandler({ kv: env.BLOCKLIST_KV }));

    // Process request
    const decision = await pipeline.process(request, { env, ctx });
    
    if (decision.has('block')) {
      return new Response('Blocked', { status: 403 });
    }
    
    return fetch(request);
  },
};
```

---

**Questions?** Open an issue on GitHub.

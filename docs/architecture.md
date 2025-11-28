# Architecture

Cloudflare Sentinel - Pipeline-based security middleware for Cloudflare Workers.

## Design Principles

1. **Everything is a Detector**: Blocklist, Whitelist, RateLimit - all are detectors
2. **Pipeline Architecture**: SYNC and ASYNC pipelines with independent flows
3. **User Control**: SYNC returns Decision, user decides to block/proceed
4. **Fire & Forget**: ASYNC executes all handlers automatically
5. **Request & Response**: Full protection for both phases

---

## System Overview

```
                                    Request
                                       │
         ┌─────────────────────────────┴─────────────────────────────┐
         │                                                           │
         ▼                                                           ▼
┌─────────────────────────────┐                    ┌─────────────────────────────┐
│  SYNC PIPELINE              │                    │  ASYNC PIPELINE             │
│                             │                    │  (fire & forget)            │
│  Detectors:                 │                    │                             │
│  - BlocklistDetector        │                    │  Detectors:                 │
│  - WhitelistDetector        │                    │  - BehaviorDetector         │
│  - RateLimitDetector        │                    │  - DeepAIDetector           │
│  - SqlInjectionDetector     │                    │                             │
│  - XssDetector              │                    │  Handlers:                  │
│  - ...                      │                    │  - ReputationHandler        │
│                             │                    │  - BlocklistHandler         │
│  .process(request)          │                    │  - AnalyticsHandler         │
│      → Decision             │                    │                             │
└──────────────┬──────────────┘                    │  .process(request)          │
               │                                   │      → void                 │
               │                                   └──────────────┬──────────────┘
               │                                                  │
               ▼                                           ctx.waitUntil()
       decision.has('block')?                                     │
          │           │                                           ▼
          ▼           ▼                                        (end)
        403        Origin
                      │
                      ▼
                ┌──────────┐
                │ Response │
                └────┬─────┘
                     │
                     ▼
┌────────────────────────────────────────────────────────────────────────────┐
│  RESPONSE DETECTION (optional)                                             │
│                                                                            │
│  Response Detectors:                                                       │
│  - DataLeakDetector       (SSN, credit cards, API keys)                    │
│  - ErrorLeakDetector      (stack traces, debug info)                       │
│                                                                            │
│  .processResponse(response) → Decision                                     │
└───────────────────────────────────┬────────────────────────────────────────┘
                                    │
                                    ▼
                        decision.has('block')?
                           │           │
                           ▼           ▼
                      Sanitized    Original
                      Response     Response
```

---

## Core Concepts

### SYNC SentinelPipeline

Returns `Decision` - user decides what to do.

```typescript
const syncSentinelPipeline = SentinelPipeline.sync([
  // Security detectors (all are just detectors!)
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new WhitelistDetector({ ips: ['10.0.0.0/8'] }),
  new RateLimitDetector({ kv: env.RATE_KV, limit: 100, period: 60 }),
  
  // Attack detectors
  new SqlInjectionDetector(),
  new XssDetector(),
  new BruteForceDetector(),
  
  // Response detectors
  new DataLeakDetector(),
  new ErrorLeakDetector(),
])
  .score(new MaxScoreAggregator())
  .resolve(new DefaultResolver())
  .on('log', new LogHandler())
  .on('notify', new SlackHandler())
  .on('increment_counter', new IncrementHandler(env.RATE_KV));
```

### ASYNC SentinelPipeline

Returns `void` - executes all handlers automatically.

```typescript
const asyncSentinelPipeline = SentinelPipeline.async([
  new BehaviorDetector(),
  new DeepAIDetector(),
])
  .score(new WeightedAggregator())
  .resolve(new AnalyticsResolver())
  .on('log', new AnalyticsHandler())
  .on('notify', new EmailHandler())
  .on('update_reputation', new ReputationHandler())
  .on('add_blocklist', new BlocklistHandler());
```

### Decision Interface

```typescript
interface Decision {
  actions: Action[];
  score: ThreatScore;
  
  has(type: string): boolean;   // Check if action exists
  get(type: string): any;       // Get action data
}
```

---

## Full Usage Example

```typescript
import { 
  SentinelPipeline, 
  BlocklistDetector, 
  RateLimitDetector,
  SqlInjectionDetector,
  DataLeakDetector,
  MaxScoreAggregator,
  DefaultResolver,
  LogHandler,
  IncrementHandler,
} from 'cloudflare-sentinel';

// Define pipelines
const syncPipeline = SentinelPipeline.sync([
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new RateLimitDetector({ kv: env.RATE_KV, limit: 100, period: 60 }),
  new SqlInjectionDetector(),
  new DataLeakDetector(),  // Response detector
])
  .score(new MaxScoreAggregator())
  .resolve(new DefaultResolver())
  .on('log', new LogHandler())
  .on('increment_counter', new IncrementHandler(env.RATE_KV));

const asyncPipeline = SentinelPipeline.async([
  new BehaviorDetector(),
])
  .score(new WeightedAggregator())
  .resolve(new AnalyticsResolver())
  .on('update_reputation', new ReputationHandler());

// Worker
export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const pctx = { env, ctx };
    
    // ════════════════════════════════════════════════════════════════
    // REQUEST DETECTION
    // ════════════════════════════════════════════════════════════════
    const reqDecision = await syncPipeline.process(request, pctx);
    if (reqDecision.has('block')) {
      return new Response(reqDecision.get('block')?.reason, { status: 403 });
    }
    
    // ════════════════════════════════════════════════════════════════
    // ASYNC PIPELINE (fire & forget)
    // ════════════════════════════════════════════════════════════════
    ctx.waitUntil(asyncPipeline.process(request, pctx));
    
    // ════════════════════════════════════════════════════════════════
    // ORIGIN REQUEST
    // ════════════════════════════════════════════════════════════════
    const response = await fetch(request);
    
    // ════════════════════════════════════════════════════════════════
    // RESPONSE DETECTION
    // ════════════════════════════════════════════════════════════════
    const respDecision = await syncPipeline.processResponse(response, pctx);
    if (respDecision.has('block')) {
      return new Response('Response blocked', { status: 500 });
    }
    
    return response;
  },
};
```

---

## Built-in Detectors

### Security Detectors (formerly Gate)

```typescript
// Blocklist - check if IP/user is blocked
class BlocklistDetector extends BaseDetector {
  name = 'blocklist';
  phase = 'request';
  
  async detectRequest(ctx) {
    const ip = ctx.request.headers.get('cf-connecting-ip');
    const blocked = await this.kv.get(ip);
    if (blocked) return this.createResult(true, 100, { reason: 'ip_blocked' });
    return this.createResult(false, 0);
  }
}

// Whitelist - skip checks if whitelisted
class WhitelistDetector extends BaseDetector {
  name = 'whitelist';
  phase = 'request';
  
  async detectRequest(ctx) {
    const ip = ctx.request.headers.get('cf-connecting-ip');
    if (this.whitelist.includes(ip)) {
      return this.createResult(false, -100, { skip: true });  // Negative = safe
    }
    return this.createResult(false, 0);
  }
}

// Rate Limit - check and flag for increment
class RateLimitDetector extends BaseDetector {
  name = 'rate_limit';
  phase = 'request';
  
  async detectRequest(ctx) {
    const key = this.getKey(ctx.request);
    const count = await this.kv.get<number>(key, 'json') || 0;
    
    if (count >= this.limit) {
      return this.createResult(true, 100, { reason: 'rate_limit_exceeded' });
    }
    
    return this.createResult(false, 0, { 
      shouldIncrement: true, 
      key 
    });
  }
}
```

### Attack Detectors

```typescript
// SQL Injection
class SqlInjectionDetector extends BaseDetector {
  name = 'sql_injection';
  phase = 'request';
  // ...
}

// XSS
class XssDetector extends BaseDetector {
  name = 'xss';
  phase = 'request';
  // ...
}

// Brute Force
class BruteForceDetector extends BaseDetector {
  name = 'brute_force';
  phase = 'request';
  // ...
}

// Prompt Injection
class PromptInjectionDetector extends BaseDetector {
  name = 'prompt_injection';
  phase = 'request';
  // ...
}
```

### Response Detectors

```typescript
// Data Leak - detect sensitive data in response
class DataLeakDetector extends BaseDetector {
  name = 'data_leak';
  phase = 'response';
  
  async detectResponse(ctx) {
    const body = await ctx.response.text();
    const patterns = [
      /\b\d{3}-\d{2}-\d{4}\b/,           // SSN
      /\b\d{16}\b/,                       // Credit card
      /password["\s:=]+["']?[^"'\s]+/i,   // Passwords
      /api[_-]?key["\s:=]+["']?[^"'\s]+/i // API keys
    ];
    
    for (const pattern of patterns) {
      if (pattern.test(body)) {
        return this.createResult(true, 90, { reason: 'sensitive_data_leak' });
      }
    }
    return this.createResult(false, 0);
  }
}

// Error Leak - detect stack traces, debug info
class ErrorLeakDetector extends BaseDetector {
  name = 'error_leak';
  phase = 'response';
  
  async detectResponse(ctx) {
    const body = await ctx.response.text();
    const patterns = [
      /at\s+\w+\s+\([^)]+:\d+:\d+\)/,     // Stack trace
      /Error:.*\n\s+at/,                   // Error with stack
      /SQLSTATE\[/,                        // SQL errors
    ];
    
    for (const pattern of patterns) {
      if (pattern.test(body)) {
        return this.createResult(true, 70, { reason: 'error_leak' });
      }
    }
    return this.createResult(false, 0);
  }
}
```

---

## Components (All Extensible)

### Detector Interface

```typescript
interface IDetector {
  name: string;
  phase: 'request' | 'response' | 'both';
  
  detectRequest?(ctx: DetectorContext): Promise<DetectionResult>;
  detectResponse?(ctx: ResponseDetectorContext): Promise<DetectionResult>;
}

abstract class BaseDetector implements IDetector {
  abstract name: string;
  phase: 'request' | 'response' | 'both' = 'request';
  
  protected createResult(detected: boolean, score: number, evidence?: any): DetectionResult;
}
```

### Aggregator Interface

```typescript
interface IScoreAggregator {
  name: string;
  aggregate(results: DetectionResult[]): ThreatScore;
}

// Built-in: MaxScoreAggregator, WeightedAggregator
```

### Resolver Interface

```typescript
interface IActionResolver {
  name: string;
  resolve(ctx: ResolverContext): Promise<Action[]>;
}

interface ResolverContext {
  score: ThreatScore;
  results: DetectionResult[];
  request: Request;
}

// Built-in: DefaultResolver, StrictResolver, LenientResolver
```

### Handler Interface

```typescript
interface IActionHandler {
  type: string;
  execute(action: Action, ctx: HandlerContext): Promise<void>;
}

// Built-in: LogHandler, NotifyHandler, ReputationHandler, BlocklistHandler, IncrementHandler
```

---

## SentinelPipeline Implementation

```typescript
class SentinelPipeline {
  private mode: 'sync' | 'async';
  private detectors: IDetector[];
  private aggregator: IScoreAggregator;
  private resolver: IActionResolver;
  private handlers = new Map<string, IActionHandler>();

  static sync(detectors: IDetector[]): SentinelPipeline {
    return new SentinelPipeline('sync', detectors);
  }
  
  static async(detectors: IDetector[]): SentinelPipeline {
    return new SentinelPipeline('async', detectors);
  }
  
  score(aggregator: IScoreAggregator): this { ... }
  resolve(resolver: IActionResolver): this { ... }
  on(type: string, handler: IActionHandler): this { ... }
  
  // Request detection
  async process(request: Request, ctx: SentinelPipelineContext): Promise<Decision | void> {
    const results = await this.runRequestDetectors(request, ctx);
    const score = this.aggregator.aggregate(results);
    const actions = await this.resolver.resolve({ score, results, request });
    
    await this.executeHandlers(actions, ctx);
    
    if (this.mode === 'sync') {
      return new Decision(actions, score);
    }
  }
  
  // Response detection
  async processResponse(response: Response, ctx: SentinelPipelineContext): Promise<Decision> {
    const results = await this.runResponseDetectors(response, ctx);
    const score = this.aggregator.aggregate(results);
    const actions = await this.resolver.resolve({ score, results, response });
    
    await this.executeHandlers(actions, ctx);
    
    return new Decision(actions, score);
  }
}

class Decision {
  constructor(private actions: Action[], public readonly score: ThreatScore) {}
  
  has(type: string): boolean {
    return this.actions.some(a => a.type === type);
  }
  
  get(type: string): any {
    return this.actions.find(a => a.type === type)?.data;
  }
}
```

---

## Folder Structure

```
cloudflare-sentinel/
├── src/
│   ├── index.ts                          # Main exports
│   │
│   ├── pipeline/
│   │   ├── types.ts
│   │   ├── pipeline.ts                   # SentinelPipeline
│   │   └── decision.ts
│   │
│   ├── detector/
│   │   ├── base.ts                       # BaseDetector
│   │   ├── index.ts
│   │   ├── blocklist.detector.ts
│   │   ├── whitelist.detector.ts
│   │   ├── rate-limit.detector.ts
│   │   ├── sql-injection.request.detector.ts
│   │   ├── sql-injection.response.detector.ts
│   │   ├── xss.request.detector.ts
│   │   ├── xss.response.detector.ts
│   │   ├── brute-force.detector.ts
│   │   ├── entropy.detector.ts
│   │   └── _examples.ts                  # Custom detector examples
│   │
│   ├── scoring/
│   │   ├── base.ts
│   │   ├── types.ts
│   │   ├── index.ts
│   │   ├── max.aggregator.ts
│   │   ├── weighted.aggregator.ts
│   │   └── hybrid.aggregator.ts
│   │
│   ├── resolver/
│   │   ├── base.ts
│   │   ├── types.ts
│   │   ├── index.ts
│   │   ├── default.resolver.ts
│   │   ├── strict.resolver.ts
│   │   ├── lenient.resolver.ts
│   │   └── multi-level.resolver.ts       # Configurable thresholds
│   │
│   ├── handler/
│   │   ├── types.ts
│   │   ├── index.ts
│   │   ├── log.handler.ts
│   │   ├── notify.handler.ts
│   │   ├── increment.handler.ts
│   │   ├── escalate.handler.ts
│   │   └── ban.handler.ts
│   │
│   ├── types/
│   │   └── index.ts                      # AttackType, SecuritySeverity
│   │
│   └── utils/
│       └── ip-matcher.ts
│
├── examples/
│   └── sentinel-proxy/                   # Ready-to-deploy security proxy
│
└── docs/
```

---

## Summary

| Phase | Method | Returns | Description |
|-------|--------|---------|-------------|
| **Request** | `.process(request)` | `Decision` (sync) / `void` (async) | Detect attacks |
| **Response** | `.processResponse(response)` | `Decision` | Detect data leaks |

| Component | Interface | Built-in | Description |
|-----------|-----------|----------|-------------|
| **Detector** | `IDetector` | Blocklist, Whitelist, RateLimit, SQLi, XSS, DataLeak... | Analyze request/response |
| **Aggregator** | `IScoreAggregator` | Max, Weighted, Hybrid | Combine results |
| **Resolver** | `IActionResolver` | Default, Strict, Lenient | Score → Actions |
| **Handler** | `IActionHandler` | Log, Notify, Reputation, Blocklist, Increment | Execute actions |

---

## Quick Extension Guide

### Custom Detector
```typescript
class MyDetector extends BaseDetector {
  name = 'my_detector';
  phase = 'request';
  
  async detectRequest(ctx) {
    return this.createResult(true, 50, { reason: 'suspicious' });
  }
}
```

### Custom Aggregator
```typescript
class MyAggregator extends BaseScoreAggregator {
  name = 'my_aggregator';
  
  aggregate(results) {
    const max = Math.max(...results.map(r => r.score));
    return { score: max, level: this.calculateLevel(max), results };
  }
}
```

### Custom Resolver
```typescript
class MyResolver extends BaseActionResolver {
  name = 'my_resolver';
  
  async resolve(ctx) {
    const actions = [];
    
    // Rate limit increment
    const rateResult = ctx.results.find(r => r.detector === 'rate_limit');
    if (rateResult?.evidence?.shouldIncrement) {
      actions.push({ type: 'increment_counter', data: { key: rateResult.evidence.key } });
    }
    
    // Block or proceed
    if (ctx.score.score >= 70) {
      actions.push(this.block('High threat score'));
    } else {
      actions.push(this.proceed());
    }
    
    return actions;
  }
}
```

### Custom Handler
```typescript
class MyHandler implements IActionHandler {
  type = 'my_action';
  
  async execute(action, ctx) {
    await doSomething(action.data);
  }
}

pipeline.on('my_action', new MyHandler());
```

---

For questions or discussions, open an issue on GitHub.

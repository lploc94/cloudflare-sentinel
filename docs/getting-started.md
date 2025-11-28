# Getting Started

## Installation

```bash
npm install cloudflare-sentinel
```

## Prerequisites

- Cloudflare Workers account
- wrangler CLI installed
- KV namespaces for rate limiting/blocklist

## Quick Setup

### 1. Create KV Namespaces

```bash
wrangler kv:namespace create BLOCKLIST_KV
wrangler kv:namespace create RATE_LIMIT_KV
wrangler kv:namespace create ESCALATION_KV
```

### 2. Configure wrangler.toml

```toml
name = "my-protected-worker"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[[kv_namespaces]]
binding = "BLOCKLIST_KV"
id = "<your-blocklist-id>"

[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "<your-ratelimit-id>"

[[kv_namespaces]]
binding = "ESCALATION_KV"
id = "<your-escalation-id>"

# Optional
[[analytics_engine_datasets]]
binding = "ANALYTICS"
```

### 3. Create Worker

```typescript
import { 
  SentinelPipeline,
  BlocklistDetector,
  RateLimitDetector,
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  MaxScoreAggregator,
  MultiLevelResolver,
  LogHandler,
  NotifyHandler,
} from 'cloudflare-sentinel';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Build pipeline
    const pipeline = SentinelPipeline.sync([
      new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
      new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 100, windowSeconds: 60 }),
      new SQLInjectionRequestDetector(),
      new XSSRequestDetector(),
    ])
      .score(new MaxScoreAggregator())
      .resolve(new MultiLevelResolver({
        levels: [
          { maxScore: 30, actions: ['log'] },
          { maxScore: 60, actions: ['log', 'warn'] },
          { maxScore: 100, actions: ['block', 'notify'] },
        ],
      }))
      .on('log', new LogHandler({ console: true }))
      .on('notify', new NotifyHandler({ webhookUrl: env.SLACK_WEBHOOK }));

    // Process request
    const decision = await pipeline.process(request, { env, ctx });
    
    if (decision.has('block')) {
      return new Response('Blocked by Sentinel', { status: 403 });
    }
    
    // Your app logic
    return new Response('Hello World');
  },
};
```

### 4. Deploy

```bash
wrangler deploy
```

## Test Protection

```bash
# Test SQL injection
curl "https://your-worker.workers.dev/?id=1' OR '1'='1"
# → 403 Blocked

# Test XSS
curl "https://your-worker.workers.dev/?q=<script>alert(1)</script>"
# → 403 Blocked

# Normal request
curl "https://your-worker.workers.dev/"
# → 200 Hello World
```

## Using Sentinel Proxy

For protecting existing websites without code changes:

```bash
cd examples/sentinel-proxy
npm install

# Edit wrangler.toml
# - Set ORIGIN_URL to your backend
# - Add KV namespace IDs

# Edit sentinel.config.ts
# - Configure routes and thresholds

wrangler deploy
```

## Multi-Level Thresholds

Configure different actions per threat level:

```typescript
new MultiLevelResolver({
  levels: [
    { maxScore: 30, actions: ['log'] },                 // Low: log only
    { maxScore: 60, actions: ['log', 'warn'] },         // Medium: log + warn
    { maxScore: 100, actions: ['block', 'notify'] },    // High: block + alert
  ],
})

Actions cascade - level 3 executes: log + warn + block + notify.

## Route-Based Config

Different protection per endpoint:

```typescript
// In sentinel.config.ts
routes: {
  '/login': {
    detectors: [...basic, new BruteForceDetector()],
    thresholds: STRICT,
  },
  '/api/**': {
    detectors: [...basic],
    thresholds: STANDARD,
  },
  '/static/**': { skip: true },
}
```

## Next Steps

- [Architecture](architecture.md) - Understand the pipeline
- [src/detector/README.md](../src/detector/README.md) - Create custom detectors
- [src/resolver/README.md](../src/resolver/README.md) - Custom resolvers
- [examples/sentinel-proxy/](../examples/sentinel-proxy/) - Full example

---

**Ready to protect your Workers!** 🛡️

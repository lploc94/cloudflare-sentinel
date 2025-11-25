# Getting Started with Cloudflare Sentinel

Complete guide to install, configure, and deploy Sentinel.

## Installation

```bash
npm install cloudflare-sentinel
```

## Prerequisites

- Cloudflare Workers account
- Basic knowledge of TypeScript
- wrangler CLI installed

## Setup D1 Database

```bash
# Create D1 database
wrangler d1 create sentinel-db

# Create schema
wrangler d1 execute sentinel-db --file=schema.sql
```

**Schema:**
```sql
CREATE TABLE security_events (
  event_id TEXT PRIMARY KEY,
  timestamp INTEGER NOT NULL,
  attack_type TEXT NOT NULL,
  severity TEXT NOT NULL,
  confidence REAL NOT NULL,
  path TEXT NOT NULL,
  method TEXT NOT NULL,
  status_code INTEGER,
  ip_address TEXT NOT NULL,
  user_agent TEXT,
  country TEXT,
  blocked INTEGER NOT NULL,
  metadata TEXT
);

CREATE INDEX idx_timestamp ON security_events(timestamp);
CREATE INDEX idx_ip ON security_events(ip_address);
CREATE INDEX idx_attack_type ON security_events(attack_type);
```

## Setup KV & Analytics

```bash
# KV for behavior tracking
wrangler kv:namespace create BEHAVIOR_KV

# Analytics Engine (auto-available in Workers)
```

## Configuration

### wrangler.toml

```toml
name = "my-sentinel-worker"
main = "src/index.ts"
compatibility_date = "2024-01-01"

# Rate Limiter (Cloudflare Rate Limiting API)
[[unsafe.bindings]]
name = "RATE_LIMITER"
type = "ratelimit"

# D1 Database
[[d1_databases]]
binding = "DB"
database_name = "sentinel-db"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# KV Namespace
[[kv_namespaces]]
binding = "BEHAVIOR_KV"
id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# Analytics Engine
[[analytics_engine_datasets]]
binding = "ANALYTICS"
```

## Basic Usage

### Minimal Setup

```typescript
import { Sentinel } from 'cloudflare-sentinel';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    // Initialize Sentinel
    const sentinel = new Sentinel({
      rateLimiter: env.RATE_LIMITER,
      db: env.DB,
      analytics: env.ANALYTICS,
      
      // Attack limits (Cloudflare Rate Limiting API only supports 10s or 60s)
      attackLimits: {
        sql_injection: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
        xss: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
        brute_force: { limit: 3, period: RateLimitPeriod.TEN_SECONDS, action: 'block' },
      },
    });

    // Protect request
    return sentinel.protect(request, async () => {
      // Your application logic
      return new Response('Hello World');
    });
  },
};
```

### With Custom Detectors

```typescript
import {
  Sentinel,
  SQLInjectionRequestDetector,
  XSSRequestDetector,
  BruteForceDetector,
  RateLimitPeriod,
} from 'cloudflare-sentinel';

const sentinel = new Sentinel({
  rateLimiter: env.RATE_LIMITER,
  db: env.DB,
  analytics: env.ANALYTICS,
  
  // Custom detectors
  detectors: [
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new BruteForceDetector(),
  ],
  
  // Per-endpoint limits (Cloudflare Rate Limiting API only supports 10s or 60s)
  attackLimits: {
    // Global
    sql_injection: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
    
    // Endpoint-specific
    '/api/admin/*': {
      '*': { limit: 1, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
    },
    
    '/api/auth/*': {
      brute_force: { limit: 3, period: RateLimitPeriod.TEN_SECONDS, action: 'block' },
    },
  },
});
```

## Deploy

```bash
# Development
wrangler dev

# Production
wrangler deploy
```

## Test Protection

```bash
# Test SQL injection detection
curl "https://sentinel-proxy.workers.dev/api/test?id=1' OR '1'='1"
# Should return 403 Forbidden

# Test XSS detection
curl "https://sentinel-proxy.workers.dev/search?q=<script>alert(1)</script>"
# Should return 403 Forbidden

# Check logs
wrangler tail
```

## Common Patterns

### 1. Progressive Protection

Start with `log_only` mode, then enable blocking:

```typescript
import { RateLimitPeriod } from 'cloudflare-sentinel';

// Week 1: Monitor only
attackLimits: {
  sql_injection: { limit: 100, period: RateLimitPeriod.ONE_MINUTE, action: 'log_only' },
}

// Week 2: Enable blocking
attackLimits: {
  sql_injection: { limit: 10, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
}
```

### 2. Whitelist Trusted IPs

```typescript
const sentinel = new Sentinel({
  // ... config
  whitelist: {
    ips: ['1.2.3.4', '5.6.7.8'],
    ipRanges: ['10.0.0.0/8'],
  },
});
```

### 3. User-Based Rate Limiting

```typescript
const sentinel = new Sentinel({
  // ... config
  identifierExtractor: async (request) => {
    const userId = await getUserId(request);
    return {
      value: userId || request.headers.get('CF-Connecting-IP'),
      type: userId ? 'user' : 'ip',
    };
  },
});
```

## Monitoring

### View Metrics

```bash
# Query Analytics Engine
wrangler analytics --binding ANALYTICS
```

### Query D1 Logs

```bash
wrangler d1 execute sentinel-db --command \
  "SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 10"
```

## Next Steps

- [Detectors Guide](detectors.md) - Custom detectors
- [Notifications](notifications.md) - Setup alerts
- [Architecture](architecture.md) - System design
- [Examples](../examples/) - Full examples

## Troubleshooting

### No attacks being logged?

1. Check bindings in wrangler.toml
2. Verify D1 schema created
3. Check `DEBUG = "true"` in config
4. View logs: `wrangler tail`

### Too many false positives?

1. Start with `log_only` mode
2. Adjust detector confidence thresholds
3. Add whitelist rules
4. Use custom detectors

### Performance issues?

1. Disable response detectors if not needed
2. Enable early block check
3. Use endpoint-specific limits
4. Monitor with Analytics

---

**Ready to protect your Workers!** 🛡️

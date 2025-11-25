# Cloudflare Sentinel

[![npm version](https://badge.fury.io/js/cloudflare-sentinel.svg)](https://www.npmjs.com/package/cloudflare-sentinel)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Attack detection and rate limiting middleware for Cloudflare Workers**

Sentinel protects your Workers with pluggable detectors, attack-based rate limiting, and smart logging. Block SQL injection, XSS, brute force, and more - automatically.

## ✨ Features

- 🛡️ **Attack-Based Rate Limiting** - Limit by attack type, not just endpoint
- 🔌 **Pluggable Detectors** - Extend with custom detection logic
- ⚡ **Optimized** - Early block check, parallel detection, smart caching
- 📊 **Smart Logging** - Only log errors/attacks (95% cost reduction)
- 🔔 **Notifications** - Email & Slack alerts for critical attacks
- 💰 **Cost-Effective** - $0-11/month for most websites

## 🚀 Quick Start

### Installation

```bash
npm install cloudflare-sentinel
```

### Basic Usage

```typescript
import { Sentinel, RateLimitPeriod } from 'cloudflare-sentinel';

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const sentinel = new Sentinel({
      rateLimiter: env.RATE_LIMITER,
      db: env.DB,
      analytics: env.ANALYTICS,
      
      // Note: Cloudflare Rate Limiting API only supports 10s or 60s periods
      attackLimits: {
        sql_injection: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },  // 60s
        xss: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },            // 60s
      },
    });

    return sentinel.protect(request, async () => {
      // Your app logic
      return new Response('Hello World');
    });
  },
};
```

### Configuration

```toml
# wrangler.toml
[[unsafe.bindings]]
name = "RATE_LIMITER"
type = "ratelimit"

[[d1_databases]]
binding = "DB"
database_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"  # Your D1 database ID

[[analytics_engine_datasets]]
binding = "ANALYTICS"
```

## 📖 Documentation

- [Getting Started](docs/getting-started.md) - Complete setup guide
- [Detectors Guide](docs/detectors.md) - Built-in & custom detectors
- [Notifications](docs/notifications.md) - Email & Slack alerts
- [Architecture](docs/architecture.md) - System design & internals
- [API Reference](#api-reference) - Full API docs

## 🎯 Examples

### Custom Detector

```typescript
import { Sentinel, SQLInjectionRequestDetector, XSSRequestDetector } from 'cloudflare-sentinel';

const sentinel = new Sentinel({
  // ...
  detectors: [
    new SQLInjectionRequestDetector(),
    new XSSRequestDetector(),
    new MyCustomDetector(), // Your detector
  ],
});
```

Or with endpoint-specific detectors:
```typescript
const sentinel = new Sentinel({
  detectors: {
    '*': [  // Global detectors
      new SQLInjectionRequestDetector(),
      new XSSRequestDetector(),
    ],
    '/api/search/*': [  // Endpoint-specific
      new MyCustomDetector(),
    ],
  },
});
```

### Per-Endpoint Limits

```typescript
import { RateLimitPeriod } from 'cloudflare-sentinel';

attackLimits: {
  // Global - 60s window
  sql_injection: { limit: 5, period: RateLimitPeriod.ONE_MINUTE, action: 'block' },
  
  // Endpoint-specific - 10s burst protection
  '/api/admin/*': {
    '*': { limit: 1, period: RateLimitPeriod.TEN_SECONDS, action: 'block' },
  },
}
```

> **Note**: Cloudflare Rate Limiting API only supports `RateLimitPeriod.TEN_SECONDS` (10s) or `RateLimitPeriod.ONE_MINUTE` (60s).

### With Notifications

```typescript
import { NotificationManager, EmailChannel, SlackChannel } from 'cloudflare-sentinel';

const manager = new NotificationManager();
manager.addChannel(new EmailChannel({ apiKey: env.RESEND_API_KEY, to: ['admin@company.com'] }));
manager.addChannel(new SlackChannel({ webhookUrl: env.SLACK_WEBHOOK }));

const sentinel = new Sentinel({
  // ...
  notification: {
    enabled: true,
    manager,
    realtime: { enabled: true, severities: ['critical', 'high'] },
  },
});
```

See [examples/](examples/) for complete implementations.

## 🛠️ Built-in Detectors

- **SQL Injection** - Request & response detection
- **XSS** - Cross-site scripting attacks
- **Path Traversal** - Directory traversal attempts
- **Brute Force** - Failed login attempts
- **Command Injection** - OS command injection

Create your own: [Detector Guide](docs/detectors.md)

## 📊 Smart Logging

Sentinel only logs what matters:

```
✅ Success (< 400) → Skip logging
⚠️  Error (>= 400) → Log to Analytics Engine
🚨 Attack → Log to Analytics + D1 (critical only)
```

**Result**: 95% cost reduction vs. logging everything

## 🔔 Notifications

Get alerts when attacks happen:

- **Real-time**: Email & Slack on critical attacks
- **Scheduled**: Hourly/daily summaries via cron
- **Spike Detection**: Alert on unusual activity
- **Threshold-based**: Only notify when needed

Setup: [Notifications Guide](docs/notifications.md)

## 💰 Cost Estimate

| Website Size | Requests/Day | Cost/Month |
|--------------|--------------|------------|
| Small        | < 100k       | **$0**     |
| Medium       | 100k-500k    | **$5**     |
| Large        | > 1M         | **$11**    |

- Cloudflare Rate Limiting API: **FREE**
- Analytics Engine: **FREE**
- D1 Database: **FREE** (< 50M reads/month)
- Email (Resend): **FREE** (100/day) → $1/month if more
- Slack: **FREE**

## 📦 Full Example: Sentinel Proxy

Complete reverse proxy with protection:

```bash
cd examples/sentinel-proxy
npm install
npm run deploy
```

Features:
- Full attack protection
- Metrics endpoint
- Email & Slack notifications
- Automatic cleanup

See [examples/sentinel-proxy/](examples/sentinel-proxy/)

## 🤝 Contributing

We welcome contributions!

1. Fork the repo
2. Create your feature branch
3. Add tests
4. Submit a pull request

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Component Guides** (for contributors):
- [Detector System](src/detector/README.md)
- [Notification System](src/notification/README.md)
- [Middleware](src/middleware/README.md)

## 📜 License

MIT © 2025 lploc94

---

## API Reference

### Sentinel

Main middleware class.

**Constructor:**
```typescript
new Sentinel(config: SentinelConfig)
```

**Methods:**
```typescript
protect(request: Request, next: () => Promise<Response>): Promise<Response>
```

### SentinelConfig

```typescript
interface SentinelConfig {
  // Required
  rateLimiter: any;
  
  // Optional but recommended
  db?: D1Database;
  analytics?: AnalyticsEngineDataset;
  kv?: KVNamespace;
  
  // Attack limits (primary method)
  attackLimits?: Record<string, AttackLimit | Record<string, AttackLimit>>;
  
  // Detectors (pluggable) - supports both array and object formats
  detectors?: IDetector[] | Record<string, IDetector[]>;
  
  // Whitelist
  whitelist?: {
    ips?: string[];
    ipRanges?: string[];
  };
  
  // Notifications
  notification?: {
    enabled: boolean;
    manager: NotificationManager;
    realtime?: RealtimeConfig;
  };
}
```

### AttackLimit

```typescript
interface AttackLimit {
  limit: number;          // Max occurrences
  period: number;         // Time window (seconds)
  action: 'block' | 'log_only';
  logOnly?: boolean;      // Deprecated, use action
}
```

### Detectors

Create custom detectors:

```typescript
import { BaseDetector } from 'cloudflare-sentinel';

class MyDetector extends BaseDetector {
  name = 'my_attack';
  priority = 80;
  
  async detectRequest(request, context) {
    if (suspicious) {
      return this.createResult({
        attackType: 'my_attack',
        severity: 'high',
        confidence: 0.9,
      });
    }
    return null;
  }
}
```

See [Detector Guide](docs/detectors.md) for details.

---

**Made with ❤️ for Cloudflare Workers**

# Cloudflare Sentinel

[![npm version](https://badge.fury.io/js/cloudflare-sentinel.svg)](https://www.npmjs.com/package/cloudflare-sentinel)
[![License: Custom](https://img.shields.io/badge/License-Cloudflare%20Only-blue.svg)](LICENSE)

**Pipeline-based security middleware for Cloudflare Workers**

Protect your Workers with pluggable detectors, multi-level threat response, and configurable actions. Block SQL injection, XSS, brute force, and more.

## ✨ Features

- 🔄 **Pipeline Architecture** - Composable detection → scoring → resolution → handling
- 🛡️ **Multi-Level Thresholds** - Configurable actions per threat level
- 🔌 **Pluggable Everything** - Detectors, aggregators, resolvers, handlers
- ⚡ **High Performance** - Parallel detection, early exit, KV caching
- 🎯 **Route-Based Config** - Different protection per endpoint
- 💰 **Cost-Effective** - $0 for most websites

## 🚀 Quick Start

```bash
npm install cloudflare-sentinel
```

```typescript
import { 
  SentinelPipeline,
  BlocklistDetector,
  ReputationDetector,
  RateLimitDetector,
  SQLInjectionRequestDetector,
  MaxScoreAggregator,
  MultiLevelResolver,
  LogHandler,
  ActionType,
} from 'cloudflare-sentinel';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const pipeline = SentinelPipeline.sync([
      new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
      new ReputationDetector({ kv: env.REPUTATION_KV }),
      new RateLimitDetector({ kv: env.RATE_LIMIT_KV, limit: 100, windowSeconds: 60 }),
      new SQLInjectionRequestDetector(),
    ])
      .score(new MaxScoreAggregator())
      .resolve(new MultiLevelResolver({
        levels: [
          { maxScore: 30, actions: [ActionType.LOG] },
          { maxScore: 60, actions: [ActionType.LOG, ActionType.UPDATE_REPUTATION] },
          { maxScore: 100, actions: [ActionType.BLOCK, ActionType.NOTIFY] },
        ],
      }))
      .on(ActionType.LOG, new LogHandler({ console: true }));

    const decision = await pipeline.process(request, { env, ctx });
    
    if (decision.has('block')) {
      return new Response('Blocked', { status: 403 });
    }
    
    return fetch(request);
  },
};
```

## 📖 Documentation

- [Getting Started](docs/getting-started.md) - Installation & setup
- [Architecture](docs/architecture.md) - System design
- [Cuckoo Blocklist](docs/cuckoo-blocklist.md) - Cost-efficient blocklist (~99% savings)
- [Notifications](docs/notifications.md) - Slack/email alerts

### Component Guides

- [Pipeline](src/pipeline/README.md) - Core orchestration
- [Detector](src/detector/README.md) - Attack detection
- [Scoring](src/scoring/README.md) - Score aggregation
- [Resolver](src/resolver/README.md) - Action resolution
- [Handler](src/handler/README.md) - Action execution

## 🎯 Built-in Components

### Detectors
| Type | Detectors |
|------|-----------|
| Security | `BlocklistDetector`, `CuckooBlocklistDetector`, `RateLimitDetector`, `ReputationDetector` |
| Request | `SQLInjectionRequestDetector`, `XSSRequestDetector`, `PathTraversalRequestDetector`, `CommandInjectionDetector`, `SSRFDetector`, `NoSQLInjectionDetector`, `XXEDetector`, `SSTIDetector`, `JWTDetector` |
| Response | `SQLInjectionResponseDetector`, `XSSResponseDetector`, `PathTraversalResponseDetector` |
| Behavior | `BruteForceDetector`, `EntropyDetector`, `FailureThresholdDetector` |
| ML | `MLDetector` - Lightweight ML classifier for request pre-filtering |

### Aggregators
- `MaxScoreAggregator` - Use highest score (any high-severity = block)
- `WeightedAggregator` - Weighted average with detector weights

### Resolvers
- `DefaultResolver` - Standard thresholds
- `StrictResolver` - Aggressive blocking
- `LenientResolver` - Permissive
- `MultiLevelResolver` - Configurable cascading actions

### Handlers
- `LogHandler` - Console logging
- `NotifyHandler` - Webhook notifications (Slack, Discord, etc.)
- `BlocklistHandler` - Add to KV blocklist
- `CuckooBlocklistHandler` - Add to Cache API blocklist + Queue sync
- `ReputationHandler` - Update IP reputation score
- `AnalyticsHandler` - Cloudflare Analytics Engine logging

## 🤖 ML Detector

Lightweight binary classifier for suspicious request detection:

```typescript
import { MLDetector } from 'cloudflare-sentinel';

const pipeline = SentinelPipeline.async([
  new MLDetector(),  // Uses bundled model (~224KB)
  // ... other detectors
]);
```

### Custom Model Training

```bash
cd scripts/training

# 1. Download attack payloads
python3 download_datasets.py

# 2. Generate safe requests
python3 generate_safe_requests.py --count 50000

# 3. Prepare & train
python3 prepare_dataset.py
python3 train_classifier.py --data data/dataset.jsonl --output ../../models/classifier.json
```

See [scripts/training/README.md](scripts/training/README.md) for details.

## 📦 Sentinel Proxy Example

Ready-to-deploy security proxy for legacy websites:

```bash
cd examples/sentinel-proxy
npm install

# Create KV namespaces
wrangler kv:namespace create BLOCKLIST_KV
wrangler kv:namespace create RATE_LIMIT_KV
wrangler kv:namespace create REPUTATION_KV

# Configure wrangler.toml + sentinel.config.ts
# Deploy
wrangler deploy
```

See [examples/sentinel-proxy/](examples/sentinel-proxy/)

## 🤝 Contributing

1. Fork the repo
2. Create feature branch
3. Add tests
4. Submit PR

See [CONTRIBUTING.md](CONTRIBUTING.md)

## 📜 License

Cloudflare Only License © 2025 lploc94

See [LICENSE](LICENSE) for details.

---

**Made with ❤️ for Cloudflare Workers**

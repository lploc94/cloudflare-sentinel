# Sentinel Proxy

Security reverse proxy for protecting legacy websites without modifying backend code.

## Overview

Sentinel Proxy sits between users and your origin server, inspecting all traffic for attacks and blocking malicious requests before they reach your backend.

```
User → Sentinel Proxy → Origin Website
           │
           ├─ Blocklist Check
           ├─ Rate Limit Check
           ├─ SQL Injection Detection
           ├─ XSS Detection
           ├─ Path Traversal Detection
           └─ Response Leak Detection
```

## Quick Start

### 1. Install

```bash
cd examples/sentinel-proxy
npm install
```

### 2. Create KV Namespaces

```bash
wrangler kv:namespace create BLOCKLIST_KV
wrangler kv:namespace create RATE_LIMIT_KV
wrangler kv:namespace create REPUTATION_KV
wrangler kv:namespace create ESCALATION_KV
```

### 3. Configure

Edit `wrangler.toml`:

```toml
[vars]
ORIGIN_URL = "https://your-backend.com"

[[kv_namespaces]]
binding = "BLOCKLIST_KV"
id = "<id-from-step-2>"

[[kv_namespaces]]
binding = "RATE_LIMIT_KV"
id = "<id-from-step-2>"

[[kv_namespaces]]
binding = "REPUTATION_KV"
id = "<id-from-step-2>"

[[kv_namespaces]]
binding = "ESCALATION_KV"
id = "<id-from-step-2>"
```

### 4. Deploy

```bash
wrangler deploy
```

### 5. Point Domain

```toml
routes = [
  { pattern = "your-domain.com/*", zone_name = "your-domain.com" }
]
```

## Architecture

```
User → Sentinel Proxy → Origin
           │
           ├─ Route Matching (sentinel.config.ts)
           ├─ Detector Pipeline
           ├─ Multi-Level Thresholds
           └─ Action Handlers
```

## Files

| File | Purpose |
|------|---------|
| `wrangler.toml` | KV bindings, origin URL |
| `sentinel.config.ts` | Routes, detectors, thresholds |
| `src/index.ts` | Entry point (no changes needed) |
| `src/lib/*` | Internal pipeline logic |

## Route-Based Protection

Configure in `sentinel.config.ts`:

| Route | Thresholds | Detectors |
|-------|------------|-----------|
| `/login` | STRICT | basic + BruteForce + Entropy |
| `/admin/**` | STRICT | basic + Entropy |
| `/api/**` | STANDARD | basic + RateLimit |
| `/search` | RELAXED | basic + Entropy |
| `/static/**` | skip | none |

## Customization

Edit `src/sentinel.config.ts` to customize:

```typescript
// Define reusable detector sets
const basic = [
  new BlocklistDetector({ kv: env.BLOCKLIST_KV }),
  new SQLInjectionRequestDetector(),
  new XSSRequestDetector(),
];

// Configure thresholds with cascading actions
const STRICT = [
  { maxScore: 20, actions: ['increment'] },
  { maxScore: 40, actions: ['log', 'escalate'] },
  { maxScore: 100, actions: ['block', 'notify'] },
];

return {
  global: {
    detectors: [...basic, new RateLimitDetector(...)],
    thresholds: STANDARD,
  },
  routes: {
    '/login': {
      detectors: [...basic, new BruteForceDetector()],
      thresholds: STRICT,
    },
  },
};
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ORIGIN_URL` | | - | Backend URL |
| `DEBUG` | | `false` | Debug logging |
| `ORIGIN_TIMEOUT` | | `30` | Timeout in seconds |
| `ENABLE_RESPONSE_DETECTION` | | `false` | Check responses for leaks |
| `ENABLE_ASYNC_PIPELINE` | | `false` | Background processing |
| `SLACK_WEBHOOK` | | - | Notifications |

## Endpoints

| Path | Description |
|------|-------------|
| `/__sentinel/health` | Health check |

## How It Works

```
Request
    │
    ▼
┌─────────────────────────────────────────────────────────────┐
│                      SENTINEL PROXY                         │
│                                                             │
│  1. Route Matching → Select Pipeline                        │
│     /api/auth/* → authSync (strict)                         │
│     /admin/* → adminSync (very strict)                      │
│     * → globalSync (default)                                │
│                                                             │
│  2. Request Detection                                       │
│     BlocklistDetector → RateLimitDetector → AttackDetectors │
│                                                             │
│  3. Decision                                                │
│     Block? → 403 Response                                   │
│     Allow? → Continue to origin                             │
│                                                             │
│  4. Proxy to Origin                                         │
│     Add X-Forwarded-* headers                               │
│     Handle timeouts                                         │
│                                                             │
│  5. Response Detection (optional)                           │
│     Check for data leaks                                    │
│                                                             │
│  6. Return secured response                                 │
└─────────────────────────────────────────────────────────────┘
```

## Security Features

- **Blocklist**: Auto-block repeat offenders
- **Rate Limiting**: Per-IP request limits
- **SQL Injection**: Pattern-based detection
- **XSS**: Cross-site scripting detection
- **Path Traversal**: Directory traversal detection
- **SSRF**: Server-side request forgery detection
- **NoSQL Injection**: MongoDB injection detection
- **Command Injection**: Shell command detection
- **Entropy Analysis**: Obfuscated payload detection
- **Response Leak Detection**: Prevent data exposure

## License

MIT

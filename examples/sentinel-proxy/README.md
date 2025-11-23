# Sentinel Proxy

Reverse proxy example with full Sentinel protection for existing websites.

Protects legacy PHP sites, WordPress, or any website without code changes.

## Quick Start

### 1. Install
```bash
npm install
```

### 2. Setup D1
```bash
wrangler d1 create sentinel
# Copy database_id to wrangler.toml

wrangler d1 execute sentinel --file=schema.sql
```

### 3. Setup KV
```bash
wrangler kv:namespace create BEHAVIOR_KV
# Copy id to wrangler.toml
```

### 4. Setup R2 (Optional - for log archiving)
```bash
wrangler r2 bucket create sentinel-archives
```

### 5. Config

Edit `wrangler.toml`:
```toml
[vars]
ORIGIN_URL = "https://example.com"  # Website to protect

# Optional - Performance & Reliability
ORIGIN_TIMEOUT = "30"           # Timeout in seconds (default: 30)
MAX_REQUEST_SIZE = "10485760"   # Max size in bytes (default: 10MB)
ENABLE_STATIC_CACHE = "true"    # Cache static assets

# Optional - Attack Notifications (NEW!)
EMAIL_ENABLED = "true"
RESEND_API_KEY = "re_xxxxx"     # Get from https://resend.com
EMAIL_TO = "admin@company.com"
SLACK_ENABLED = "true"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/xxx"
```

**📢 Attack Notifications Setup (Optional):**

See [../../docs/notifications.md](../../docs/notifications.md) for complete guide.

Quick setup:
1. Get Resend API key: https://resend.com/api-keys
2. Get Slack webhook: https://api.slack.com/messaging/webhooks
3. Add config to wrangler.toml (see above)
4. Add cron triggers for scheduled reports

### 6. Deploy
```bash
npm run deploy
```

### 7. Connect Domain to Worker (REQUIRED!)

**Option A: Custom Domain** (Recommended)

Cloudflare Dashboard:
1. Workers & Pages > sentinel-proxy
2. Settings > Triggers > Custom Domains
3. Click "Add Custom Domain"
4. Enter: `yourdomain.com`
5. Click "Add domain"

✅ Done! Traffic automatically routes through worker.

**Option B: Routes** (Alternative)

Uncomment in `wrangler.toml` BEFORE deploy:
```toml
routes = [
  { pattern = "yourdomain.com/*", zone_name = "yourdomain.com" }
]
```

**⚠️ Important**: 
- Without this step → traffic does NOT go through worker → website is NOT protected!
- `yourdomain.com` must already be in Cloudflare
- DNS settings don't need changes (Cloudflare auto-routes)

## How It Works

```
User Request
    ↓
Cloudflare Worker (Sentinel Proxy)
    ↓
├─ Attack Detection (SQL, XSS, Path Traversal, Brute Force)
├─ Rate Limiting  
├─ Behavior Tracking
├─ Logging (D1 + Analytics)
│
├─ If Attack → Block (403)
│
└─ If Clean → Proxy to Origin
         ↓
    Your Website (protected!)
```

## Features

✅ **Flexible Detection** (Request + Response scanning):
   - SQL injection (requests + error leaks in responses)
   - XSS (requests + reflected XSS in responses)
   - Path traversal (requests + file/directory leaks)
   - Brute force (login patterns)
   - **Configurable**: Enable/disable specific detectors
   
✅ Rate limiting (global + endpoint-specific)  
✅ Behavior tracking (detect attack patterns)  
✅ Auto-logging to D1 + Analytics  
✅ Auto-cleanup (weekly cron with R2 backup)  
✅ **Metrics endpoint** (`/__sentinel/metrics`) - real-time monitoring  
✅ **Production-ready**:
   - Origin timeout protection (configurable)
   - Request size limits (prevent memory exhaustion)
   - Error handling (502/504 responses)
   - Static asset caching (optional)
✅ Zero config - just deploy  
✅ No code changes needed on origin site

## Detector Configuration

This worker uses **separate request/response detectors** for flexibility:

```typescript
detectors: [
  // Request scanning (before origin)
  new SQLInjectionRequestDetector(),
  new XSSRequestDetector(),
  new PathTraversalRequestDetector(),
  new BruteForceDetector(),
  
  // Response scanning (after origin)
  new SQLInjectionResponseDetector(),
  new XSSResponseDetector(),
  new PathTraversalResponseDetector(),
]
```

**Can customize**:
- Remove response detectors → faster, but misses leaks
- Remove request detectors → monitoring only
- Add custom detectors → extend protection

See [Detector Guide](../../docs/detectors.md) for more about custom detectors.

---

## 🎯 Use Cases


## �� Monitoring

### Metrics Endpoint

```bash
curl https://yourdomain.com/__sentinel/metrics
```

Returns JSON with attacks, performance, cache stats.

**Protect with Cloudflare Zero Trust** - Don't expose publicly!

---

## 🎛️ Configuration Reference

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `ORIGIN_URL` | Required | Website to protect |
| `ORIGIN_TIMEOUT` | 30 | Origin timeout (seconds) |
| `MAX_REQUEST_SIZE` | 10485760 | Max request size (bytes) |
| `ENABLE_STATIC_CACHE` | false | Cache static assets |
| `DEBUG` | false | Enable debug logging |

### Notifications

See [../../docs/notifications.md](../../docs/notifications.md)

### Custom Detectors

See [../../docs/detectors.md](../../docs/detectors.md)

---

## 💰 Cost

Same as core package: **$0-11/month**

See main [README](../../README.md#cost-estimate)

---

## 📚 Documentation

- [Getting Started](../../docs/getting-started.md)
- [Detector Guide](../../docs/detectors.md)
- [Notifications Setup](../../docs/notifications.md)
- [Architecture](../../docs/architecture.md)

---

## 🤝 Contributing

Issues & PRs welcome! See [CONTRIBUTING.md](../../CONTRIBUTING.md)

---

**Protect your legacy sites with zero code changes!** 🛡️

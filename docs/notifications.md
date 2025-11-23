# Notification Configuration Guide

## 📢 Attack Notification System

Sentinel Proxy supports automatic notifications via Email and Slack when attacks are detected.

---

## 🎛️ Environment Variables

### Email Channel (Resend/SendGrid)

```toml
# wrangler.toml
[vars]
# Email channel
EMAIL_ENABLED = "true"
RESEND_API_KEY = "re_xxxxx"          # Get from https://resend.com/api-keys
EMAIL_FROM = "sentinel@yourdomain.com"
EMAIL_TO = "admin@company.com,security@company.com"  # Comma-separated
EMAIL_PROVIDER = "resend"             # "resend" or "sendgrid"
```

### Slack Channel

```toml
# Slack channel
SLACK_ENABLED = "true"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/xxx/yyy/zzz"
SLACK_CHANNEL = "#security-alerts"   # Optional
SLACK_USERNAME = "Sentinel"          # Optional
SLACK_ICON_EMOJI = ":shield:"        # Optional
```

### Notification Rate Limiting

```toml
# Rate limiting (prevent spam)
NOTIFICATION_RATE_LIMIT = "10"       # Max 10 notifications
NOTIFICATION_RATE_PERIOD = "300"     # per 5 minutes (seconds)
```

---

## 🔔 Cron Handlers

### 1. Attack Notifier

Aggregate attacks and notify if thresholds are exceeded.

**Configuration:**
```toml
# Cron schedule (user controls frequency)
[[ triggers.crons]]
schedule = "*/5 * * * *"              # Every 5 minutes (customize as needed)

# Handler config
CRON_ATTACK_NOTIFIER = "*/5 * * * *" # Must match schedule above
ATTACK_NOTIFIER_PERIOD = "5m"         # Period to aggregate (5m, 1h, 24h, etc.)
ATTACK_NOTIFIER_MIN_ATTACKS = "5"     # Minimum attacks to trigger notification
ATTACK_NOTIFIER_MIN_BLOCKED = "2"     # Minimum blocked to trigger
ATTACK_NOTIFIER_MIN_CRITICAL = "1"    # Minimum critical attacks
ATTACK_NOTIFIER_SEVERITIES = "critical,high"  # Which severities to include
```

**Examples:**
```toml
# Aggressive monitoring (every 5 min)
"*/5 * * * *"
ATTACK_NOTIFIER_PERIOD = "5m"
ATTACK_NOTIFIER_MIN_ATTACKS = "1"  # Notify on any attack

# Balanced (every hour)
"0 * * * *"
ATTACK_NOTIFIER_PERIOD = "1h"
ATTACK_NOTIFIER_MIN_ATTACKS = "10"

# Relaxed (daily)
"0 8 * * *"
ATTACK_NOTIFIER_PERIOD = "24h"
ATTACK_NOTIFIER_MIN_ATTACKS = "50"
```

### 2. Report Notifier

Send detailed report (always send, no threshold check).

**Configuration:**
```toml
[[triggers.crons]]
schedule = "0 8 * * *"                # Daily at 8am

CRON_REPORT_NOTIFIER = "0 8 * * *"
REPORT_NOTIFIER_PERIOD = "24h"
REPORT_NOTIFIER_INCLUDE_ALL = "false" # false = filter by severities
REPORT_NOTIFIER_SEVERITIES = "critical,high,medium"
```

**Examples:**
```toml
# Daily report
"0 8 * * *"
REPORT_NOTIFIER_PERIOD = "24h"

# Weekly report (Monday 8am)
"0 8 * * 1"
REPORT_NOTIFIER_PERIOD = "7d"

# Monthly report (1st of month)
"0 8 1 * *"
REPORT_NOTIFIER_PERIOD = "30d"
```

### 3. Spike Detector

Detect spike (anomaly) compared to baseline.

**Configuration:**
```toml
[[triggers.crons]]
schedule = "*/15 * * * *"             # Every 15 minutes

CRON_SPIKE_DETECTOR = "*/15 * * * *"
SPIKE_DETECTOR_BASELINE_PERIOD = "1h"   # Compare with 1h average
SPIKE_DETECTOR_CHECK_PERIOD = "15m"     # Check last 15 minutes
SPIKE_DETECTOR_THRESHOLD = "3"          # Spike = 3x baseline
SPIKE_DETECTOR_MIN_ATTACKS = "10"       # Minimum attacks to consider spike
```

**Examples:**
```toml
# Frequent check (every 5 min)
"*/5 * * * *"
SPIKE_DETECTOR_CHECK_PERIOD = "5m"
SPIKE_DETECTOR_THRESHOLD = "2"  # More sensitive

# Relaxed (every 30 min)
"*/30 * * * *"
SPIKE_DETECTOR_CHECK_PERIOD = "30m"
SPIKE_DETECTOR_THRESHOLD = "5"  # Less sensitive
```

### 4. Metrics Aggregator

Aggregate general metrics (lightweight).

**Configuration:**
```toml
[[triggers.crons]]
schedule = "0 * * * *"                # Every hour

CRON_METRICS_AGGREGATOR = "0 * * * *"
METRICS_AGGREGATOR_PERIOD = "1h"
METRICS_AGGREGATOR_MIN_REQUESTS = "100"  # Minimum requests to notify
```

---

## 📋 Complete Example

```toml
# wrangler.toml
name = "sentinel-proxy"
main = "src/index.ts"
compatibility_date = "2024-01-01"

[vars]
# ==========================================
# Email Notification
# ==========================================
EMAIL_ENABLED = "true"
RESEND_API_KEY = "re_xxxxx"
EMAIL_FROM = "sentinel@mywebsite.com"
EMAIL_TO = "admin@mywebsite.com,security@mywebsite.com"

# ==========================================
# Slack Notification
# ==========================================
SLACK_ENABLED = "true"
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/xxx"
SLACK_CHANNEL = "#security"
SLACK_USERNAME = "Sentinel"
SLACK_ICON_EMOJI = ":shield:"

# ==========================================
# Rate Limiting
# ==========================================
NOTIFICATION_RATE_LIMIT = "10"
NOTIFICATION_RATE_PERIOD = "300"

# ==========================================
# Cron Handlers
# ==========================================

# Attack Notifier - Every 15 minutes
CRON_ATTACK_NOTIFIER = "*/15 * * * *"
ATTACK_NOTIFIER_PERIOD = "15m"
ATTACK_NOTIFIER_MIN_ATTACKS = "5"
ATTACK_NOTIFIER_MIN_BLOCKED = "2"
ATTACK_NOTIFIER_MIN_CRITICAL = "1"
ATTACK_NOTIFIER_SEVERITIES = "critical,high"

# Report Notifier - Daily at 8am
CRON_REPORT_NOTIFIER = "0 8 * * *"
REPORT_NOTIFIER_PERIOD = "24h"
REPORT_NOTIFIER_INCLUDE_ALL = "false"
REPORT_NOTIFIER_SEVERITIES = "critical,high,medium"

# Spike Detector - Every 15 minutes
CRON_SPIKE_DETECTOR = "*/15 * * * *"
SPIKE_DETECTOR_BASELINE_PERIOD = "1h"
SPIKE_DETECTOR_CHECK_PERIOD = "15m"
SPIKE_DETECTOR_THRESHOLD = "3"
SPIKE_DETECTOR_MIN_ATTACKS = "10"

# Metrics Aggregator - Every hour
CRON_METRICS_AGGREGATOR = "0 * * * *"
METRICS_AGGREGATOR_PERIOD = "1h"
METRICS_AGGREGATOR_MIN_REQUESTS = "100"

# ==========================================
# Cron Triggers
# ==========================================
[[triggers.crons]]
schedule = "*/15 * * * *"  # Attack notifier & Spike detector

[[triggers.crons]]
schedule = "0 * * * *"     # Metrics aggregator

[[triggers.crons]]
schedule = "0 8 * * *"     # Report notifier

# ... (other bindings: DB, ANALYTICS, etc.)
```

---

## 🚀 Quick Start

### 1. Setup Email (Resend)

1. Sign up at https://resend.com
2. Get API key
3. Add to wrangler.toml:
   ```toml
   EMAIL_ENABLED = "true"
   RESEND_API_KEY = "re_xxxxx"
   EMAIL_FROM = "sentinel@yourdomain.com"
   EMAIL_TO = "admin@yourdomain.com"
   ```

### 2. Setup Slack

1. Create Incoming Webhook: https://api.slack.com/messaging/webhooks
2. Add to wrangler.toml:
   ```toml
   SLACK_ENABLED = "true"
   SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/xxx"
   ```

### 3. Configure Cron

Choose your monitoring frequency:

**Light (for small sites):**
```toml
# Check hourly
CRON_ATTACK_NOTIFIER = "0 * * * *"
ATTACK_NOTIFIER_PERIOD = "1h"

# Daily report
CRON_REPORT_NOTIFIER = "0 8 * * *"
```

**Medium (balanced):**
```toml
# Check every 15 min
CRON_ATTACK_NOTIFIER = "*/15 * * * *"
ATTACK_NOTIFIER_PERIOD = "15m"

# Daily report + spike detection
CRON_SPIKE_DETECTOR = "*/15 * * * *"
CRON_REPORT_NOTIFIER = "0 8 * * *"
```

**Heavy (for critical sites):**
```toml
# Check every 5 min
CRON_ATTACK_NOTIFIER = "*/5 * * * *"
ATTACK_NOTIFIER_PERIOD = "5m"
ATTACK_NOTIFIER_MIN_ATTACKS = "1"  # Notify on any attack

# Frequent spike detection
CRON_SPIKE_DETECTOR = "*/5 * * * *"

# Daily + Weekly reports
CRON_REPORT_NOTIFIER = "0 8 * * *"   # Daily
# Add another trigger for weekly if needed
```

### 4. Deploy

```bash
npm run deploy
```

### 5. Test

Trigger a test attack to verify notifications:
```bash
curl "https://yoursite.com/api/test?id=1' OR '1'='1"
```

Check logs:
```bash
wrangler tail
```

---

## 📊 Notification Examples

### Attack Notification (Email)

```
Subject: 🚨 Critical Attack - SQL Injection

Attack Details:
- Type: SQL Injection
- Severity: CRITICAL
- Status: BLOCKED ✅
- Confidence: 95%

Attacker:
- IP: 192.0.2.123 (Russia)
- User-Agent: curl/7.68.0

Target:
- Endpoint: /api/users
- Method: POST

Evidence:
- Field: username
- Value: admin' OR '1'='1
- Pattern: Classic SQL injection

Timestamp: 2024-01-15 10:30:45 UTC
```

### Attack Summary (Slack)

```
📊 Attack Summary

Period: 1h
From: 2024-01-15 10:00:00
To: 2024-01-15 11:00:00

Total Attacks: 25
Blocked: 23 (92%)
Unique IPs: 5
Affected Endpoints: 3

Top Attackers:
1. 192.0.2.123 - 10 attacks
2. 198.51.100.45 - 8 attacks
3. 203.0.113.78 - 7 attacks
```

---

## ⚠️ Important Notes

1. **Secrets Management**
   - Never commit API keys to git
   - Use `wrangler secret put` for production:
     ```bash
     wrangler secret put RESEND_API_KEY
     wrangler secret put SLACK_WEBHOOK_URL
     ```

2. **Rate Limiting**
   - Always enable rate limiting to prevent spam
   - Adjust `NOTIFICATION_RATE_LIMIT` based on your needs

3. **Testing**
   - Start with high thresholds
   - Monitor for false positives
   - Adjust thresholds gradually

4. **Cost**
   - Email (Resend): 100 free/day → 3k/month
   - Slack: Unlimited (webhook free)
   - Cron: Free (Cloudflare Workers)

---

**Happy monitoring!** 🛡️

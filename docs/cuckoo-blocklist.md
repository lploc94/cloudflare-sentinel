# Cuckoo Blocklist - Cost-Efficient Blocklist for Cloudflare Workers

High-performance blocklist implementation using **Cuckoo Filter** and **Cache API** for near-zero cost operation.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Components](#components)
- [Usage Guide](#usage-guide)
- [Use Cases](#use-cases)
- [Configuration](#configuration)
- [Cost Analysis](#cost-analysis)

---

## Overview

Traditional blocklist implementations using KV reads per request can be expensive at scale:

| Traffic | KV Reads | Monthly Cost |
|---------|----------|--------------|
| 1M req/month | 1M | ~$0.50 |
| 10M req/month | 10M | ~$5.00 |
| 100M req/month | 100M | ~$50.00 |

**Cuckoo Blocklist** reduces this to near-zero by:
- Using **Cache API** for edge-local storage (FREE)
- Using **Cuckoo Filter** for O(1) probabilistic lookup
- Only reading KV on cold starts (~0.1% of requests)

**Result: ~99.8% cost reduction**

### Trade-offs

| Aspect | Traditional KV | Cuckoo Blocklist |
|--------|---------------|------------------|
| **Cost** | $0.50/1M req | ~$0.001/1M req |
| **Latency** | 5-50ms | 1-5ms |
| **Consistency** | Strong | Eventual (~5 min) |
| **Immediate block** | No | Yes (pending cache) |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         REQUEST FLOW                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │   Request    │────▶│   Pending    │────▶│   Cuckoo     │        │
│  │   Arrives    │     │   Cache      │     │   Filter     │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│                              │                    │                  │
│                              ▼                    ▼                  │
│                        ┌──────────┐        ┌──────────┐             │
│                        │  BLOCK   │        │  BLOCK   │             │
│                        │ (0ms)    │        │ (1-5ms)  │             │
│                        └──────────┘        └──────────┘             │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                         BLOCK FLOW                                   │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │   Attack     │────▶│   Pending    │────▶│   Queue      │        │
│  │   Detected   │     │   Cache      │     │   Message    │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│         │                    │                    │                  │
│         │              Immediate              Global                 │
│         │              block at               sync via               │
│         │              this edge              Queue                  │
│         ▼                                        ▼                   │
│  ┌──────────────┐                        ┌──────────────┐           │
│  │   KV Write   │                        │   Queue      │           │
│  │   (TTL)      │                        │   Consumer   │           │
│  └──────────────┘                        └──────────────┘           │
│                                                 │                    │
│                                                 ▼                    │
│                                          ┌──────────────┐           │
│                                          │   Update     │           │
│                                          │   Filter     │           │
│                                          └──────────────┘           │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                         CRON REBUILD                                 │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐        │
│  │   Scheduled  │────▶│   List KV    │────▶│   Build      │        │
│  │   Trigger    │     │   Entries    │     │   New Filter │        │
│  └──────────────┘     └──────────────┘     └──────────────┘        │
│                                                   │                  │
│                                                   ▼                  │
│                                          ┌──────────────┐           │
│                                          │   Save to KV │           │
│                                          └──────────────┘           │
│                                                   │                  │
│                                    Each edge gets new filter         │
│                                    when local cache TTL expires      │
│                                          (~5 min max)                │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

### Data Storage

| Storage | Purpose | TTL | Cost |
|---------|---------|-----|------|
| **Pending Cache** | Immediate blocks | 5 min | FREE |
| **Filter Cache** | Cuckoo Filter snapshot | 5 min | FREE |
| **KV: blocked:*** | Source of truth | Variable | Per write |
| **KV: filter_snapshot** | Filter binary | Permanent | Per read |
| **KV: filter_version** | Version tracking | Permanent | Per read |

---

## Components

### 1. BlocklistDetector (mode: 'cuckoo')

Checks if IP/token is blocked using Cache API + Cuckoo Filter.

```typescript
import { BlocklistDetector } from 'cloudflare-sentinel';

// Cuckoo mode - fast + cost-efficient
const detector = new BlocklistDetector({
  kv: env.BLOCKLIST_KV,
  mode: 'cuckoo',
  verifyWithKV: true, // Eliminate false positives
});

// Custom key extractor (e.g., for token-based blocking)
const tokenDetector = new BlocklistDetector({
  kv: env.BLOCKLIST_KV,
  mode: 'cuckoo',
  keyExtractor: (req) => req.headers.get('authorization')?.replace('Bearer ', ''),
});

// Add to pipeline
pipeline.addDetector(detector);
```

#### Static Methods

```typescript
// Immediate block (add to pending cache)
await BlocklistDetector.addToPending(ip, 300); // 5 min TTL

// Remove from pending (local only!)
await BlocklistDetector.removeFromPending(ip);

// Check if in pending
const isPending = await BlocklistDetector.isInPending(ip);

// Force reload filter from KV
await BlocklistDetector.invalidateFilterCache();
```

### 2. BlocklistHandler (mode: 'cuckoo')

Handles blocking via Cache API + KV + Queue sync.

```typescript
import { BlocklistHandler } from 'cloudflare-sentinel';

// Cuckoo mode with Queue for global sync
pipeline.on(ActionType.BLOCK, new BlocklistHandler({
  kv: env.BLOCKLIST_KV,
  mode: 'cuckoo',
  queue: env.BLOCKLIST_QUEUE,
  pendingTtl: 300, // 5 minutes
}));
```

### 3. Queue Helpers

Send block/unblock requests to queue from anywhere.

```typescript
import { sendBlockToQueue, sendUnblockToQueue } from 'cloudflare-sentinel';

// Block IP globally
await BlocklistDetector.addToPending(ip);  // Immediate
await sendBlockToQueue(env.BLOCKLIST_QUEUE, ip, 'Spam detected', {
  expiresAt: Date.now() + 3600000, // 1 hour
  score: 0.95,
  attackTypes: ['RATE_LIMIT', 'BRUTE_FORCE'],
});

// Unblock IP globally
// ⚠️ Note: removeFromPending() only works on current edge (local cache)
// Global unblock relies on:
// 1. sendUnblockToQueue() → KV.delete() + Filter.remove()
// 2. Pending cache expires naturally (5 min TTL)
await sendUnblockToQueue(env.BLOCKLIST_QUEUE, ip);

// Optional: Also delete directly from KV for immediate effect
await env.BLOCKLIST_KV.delete(`blocked:${ip}`);
```

#### ⚠️ Unblock Limitation

**Pending cache cannot be globally invalidated** (Cache API is edge-local).

When unblocking:
- ✅ KV entry deleted immediately (global)
- ✅ Filter updated via queue (global)
- ⏳ Pending cache expires naturally (~5 min max)

**Impact:** User may still be blocked for up to 5 minutes at the edge where they were originally blocked.

### 4. Queue Consumer

Process queue messages and update Cuckoo Filter.

```typescript
import { processBlocklistQueue } from 'cloudflare-sentinel';

export default {
  async queue(batch: MessageBatch<BlockQueueMessage>, env: Env) {
    await processBlocklistQueue(batch, env.BLOCKLIST_KV, {
      filterCapacity: 100000,
      blocklistKeyPrefix: 'blocked:',    // KV key prefix for verification
      defaultBlockDuration: 3600,        // Default block TTL (1 hour)
    });
  }
};
```

**What it does:**
1. Updates Cuckoo Filter (add/remove)
2. Syncs with KV (source of truth for `verifyWithKV`)
3. Handles TTL from `expiresAt` or uses default

### 5. Cron Rebuild

Periodically rebuild filter from source of truth.

> **Note:** Cache invalidation is edge-local only. After rebuild, each edge will 
> automatically get the new filter when its local cache expires (default 5 min TTL).
> This is acceptable eventual consistency.

```typescript
import { rebuildBlocklistFilter } from 'cloudflare-sentinel';

export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(rebuildBlocklistFilter(env.BLOCKLIST_KV, {
      blocklistPrefix: 'blocked:',
      filterCapacity: 100000,
    }));
  }
};
```

### 6. Stats Helper

Get blocklist statistics for monitoring.

```typescript
import { getBlocklistStats } from 'cloudflare-sentinel';

const stats = await getBlocklistStats(env.BLOCKLIST_KV);
// {
//   totalBlocked: 1234,
//   filterSize: 51200,        // bytes
//   filterVersion: 'rebuild-1701532800000',
//   filterCapacity: 100000,
//   filterUtilization: 0.05   // 5% full
// }
```

---

## Usage Guide

### Complete Setup

#### 1. Environment Types

```typescript
// src/types/env.ts
interface Env {
  BLOCKLIST_KV: KVNamespace;
  BLOCKLIST_QUEUE: Queue;
}
```

#### 2. Wrangler Configuration

```toml
# wrangler.toml
name = "my-worker"

[[kv_namespaces]]
binding = "BLOCKLIST_KV"
id = "xxx"

[[queues.producers]]
queue = "blocklist-queue"
binding = "BLOCKLIST_QUEUE"

[[queues.consumers]]
queue = "blocklist-queue"
max_batch_size = 100
max_batch_timeout = 30

[triggers]
crons = ["0 */6 * * *"]  # Rebuild every 6 hours
```

#### 3. Main Worker

```typescript
// src/index.ts
import { 
  RequestPipeline,
  CuckooBlocklistDetector,
  CuckooBlocklistHandler,
  RateLimitDetector,
  ActionType,
} from 'cloudflare-sentinel';

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    // Create pipeline
    const pipeline = new RequestPipeline();
    
    // Add detectors
    pipeline.addDetector(new CuckooBlocklistDetector({
      kv: env.BLOCKLIST_KV,
    }));
    
    pipeline.addDetector(new RateLimitDetector({
      rateLimiter: env.RL_MODERATE,
    }));
    
    // Add handlers
    pipeline.on(ActionType.BLOCK, new CuckooBlocklistHandler({
      queue: env.BLOCKLIST_QUEUE,
    }));
    
    // Process
    const decision = await pipeline.process(request, {});
    
    if (decision.action === ActionType.BLOCK) {
      return new Response('Blocked', { status: 403 });
    }
    
    // Continue to application...
  },
  
  // Queue consumer
  async queue(batch: MessageBatch, env: Env) {
    const { processBlocklistQueue } = await import('cloudflare-sentinel');
    await processBlocklistQueue(batch, env.BLOCKLIST_KV);
  },
  
  // Cron rebuild
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    const { rebuildBlocklistFilter } = await import('cloudflare-sentinel');
    ctx.waitUntil(rebuildBlocklistFilter(env.BLOCKLIST_KV));
  },
};
```

---

## Use Cases

### Consistency Model

Before choosing a use case, understand the consistency guarantees:

#### 🟢 Strong Consistency: IP-based Blocking

IP addresses achieve **near-strong consistency** because:
- Cloudflare routes requests from an IP to the **nearest edge cluster**
- Same IP → Same cluster (unless network issues)
- Pending cache at that cluster blocks **immediately** (0ms)
- The attacker cannot easily switch to another edge

```
User IP: 203.0.113.45 (Vietnam)
  ↓
Always routed to Singapore cluster
  ↓
Pending cache block = Immediate + Consistent
```

#### 🟡 Eventual Consistency: Token/Key-based Blocking

Tokens/API keys may be used from **multiple locations**:
- User A in Vietnam, User B in US share same API key
- Different edges, different caches
- ~5 min eventual consistency via Queue + Filter

**Solution for Strong Consistency:** Restrict token usage by `colo` (colocation):

```typescript
// Token contains colo claim (e.g., JWT with colo field)
const tokenPayload = decodeToken(token); // { sub: 'user123', colo: 'SIN', ... }
const requestColo = request.cf?.colo;    // e.g., "LAX"

// If token's colo claim doesn't match request colo → block
if (tokenPayload.colo && tokenPayload.colo !== requestColo) {
  // Token issued for SIN but used from LAX → suspicious
  await CuckooBlocklistDetector.addToPending(token);
  return new Response('Token location mismatch', { status: 403 });
}
```

**Alternative:** Bind token to colo on first use:

```typescript
// First request with token → store colo binding in KV
const bindingKey = `token_colo:${token}`;
const boundColo = await env.KV.get(bindingKey);

if (!boundColo) {
  // First use - bind to current colo
  await env.KV.put(bindingKey, requestColo, { expirationTtl: 3600 });
} else if (boundColo !== requestColo) {
  // Used from different colo → block
  await CuckooBlocklistDetector.addToPending(token);
  return new Response('Token location changed', { status: 403 });
}
```

---

### ✅ Recommended Use Cases

#### 1. IP-based Blocking (Strong Consistency) ✅

```typescript
// Block IPs that exceed rate limits
const detector = new CuckooBlocklistDetector({
  kv: env.BLOCKLIST_KV,
  // Default: uses cf-connecting-ip
});
```

**Why it's strong consistency:**
- Cloudflare routes same IP → same edge cluster (nearest)
- Pending cache at that cluster = immediate block
- Attacker cannot easily switch edges

#### 2. Token/API Key Blocking (Eventual Consistency)

```typescript
// Block compromised or abused API keys
const detector = new CuckooBlocklistDetector({
  kv: env.BLOCKLIST_KV,
  keyExtractor: (req) => {
    const auth = req.headers.get('authorization');
    return auth?.replace('Bearer ', '') ?? null;
  },
});
```

**Eventual consistency (~5 min):**
- Token can be used from multiple locations
- Block at detecting edge is immediate
- Other edges wait for global sync

**Acceptable for:** Abuse detection, rate limit violations, spam prevention

#### 3. Token with Colo Binding (Strong Consistency) ✅

To achieve strong consistency for tokens, **bind token to colo** and reject mismatches:

```typescript
// Middleware: Validate token colo before detector runs
async function validateTokenColo(request: Request, env: Env): Promise<Response | null> {
  const token = request.headers.get('authorization')?.replace('Bearer ', '');
  if (!token) return null;
  
  const requestColo = (request as any).cf?.colo;
  const bindingKey = `token_colo:${token}`;
  const boundColo = await env.BLOCKLIST_KV.get(bindingKey);
  
  if (!boundColo) {
    // First use - bind to current colo (1 hour TTL)
    await env.BLOCKLIST_KV.put(bindingKey, requestColo, { expirationTtl: 3600 });
    return null; // Allow
  }
  
  if (boundColo !== requestColo) {
    // Colo changed - suspicious, block token
    await CuckooBlocklistDetector.addToPending(token);
    await sendBlockToQueue(env.BLOCKLIST_QUEUE, token, `Colo mismatch: ${boundColo} → ${requestColo}`);
    return new Response('Token location changed', { status: 403 });
  }
  
  return null; // Allow
}
```

**Why it's strong consistency:**
- Token bound to first-use colo
- Same token + same colo → same edge → immediate pending block
- Colo change = immediate rejection (no cache needed)

#### 4. User ID Blocking

```typescript
// Block abusive users
const detector = new CuckooBlocklistDetector({
  kv: env.BLOCKLIST_KV,
  keyExtractor: (req) => req.headers.get('x-user-id'),
});
```

#### 5. Fingerprint Blocking

```typescript
// Block by browser fingerprint
const detector = new CuckooBlocklistDetector({
  kv: env.BLOCKLIST_KV,
  keyExtractor: (req) => req.headers.get('x-fingerprint'),
});
```

### ⚠️ Consider Carefully

These scenarios may need additional measures:

#### High-Value Transactions

For financial or critical operations, consider hybrid approach:

```typescript
// Cuckoo for general blocking
const cuckooDetector = new CuckooBlocklistDetector({
  kv: env.BLOCKLIST_KV,
});

// KV for critical real-time check
const kvDetector = new BlocklistDetector({
  kv: env.CRITICAL_BLOCKLIST_KV,
  keyExtractor: (req) => req.headers.get('x-user-id'),
});

// Use both
pipeline.addDetector(cuckooDetector);
pipeline.addDetector(kvDetector); // For critical paths only
```

### ❌ Not Recommended

These scenarios need strong consistency:

- **Session invalidation** - Use KV directly or Durable Objects
- **Permission revocation** - Need immediate global effect
- **Two-factor bypass** - Security-critical, no delay acceptable

---

## Configuration

### Detector Options

```typescript
interface CuckooBlocklistDetectorOptions {
  /** KV namespace containing filter snapshot */
  kv: KVNamespace;
  
  /** Key extractor (default: IP address) */
  keyExtractor?: (request: Request) => string | null;
  
  /** 
   * Verify with KV when filter reports blocked (default: true)
   * - true: Check KV to eliminate false positives (~1% filter FP rate)
   * - false: Trust filter result (zero KV reads, but ~1% false positive blocks)
   */
  verifyWithKV?: boolean;
  
  /** Key prefix for blocklist entries in KV (default: 'blocked:') */
  blocklistKeyPrefix?: string;
  
  /** Filter snapshot key in KV (default: 'filter_snapshot') */
  filterSnapshotKey?: string;
  
  /** Filter version key in KV (default: 'filter_version') */
  filterVersionKey?: string;
  
  /** Filter cache TTL in seconds (default: 300) */
  filterCacheTtl?: number;
  
  /** Pending cache TTL in seconds (default: 300) */
  pendingCacheTtl?: number;
  
  /** Filter capacity (default: 100000) */
  filterCapacity?: number;
}
```

### Handler Options

```typescript
interface CuckooBlocklistHandlerOptions {
  /** Queue for global filter sync (optional) */
  queue?: Queue;
  
  /** Pending cache TTL in seconds (default: 300) */
  pendingTtl?: number;
  
  /** Custom key extractor */
  keyExtractor?: (action: Action, ctx: HandlerContext) => string | null;
}
```

### Cuckoo Filter Options

```typescript
interface CuckooFilterOptions {
  /** Maximum number of items (default: 100000) */
  capacity?: number;
  
  /** Fingerprint bits - higher = lower false positive (default: 8) */
  fingerprintBits?: number;
  
  /** Entries per bucket (default: 4) */
  bucketSize?: number;
}
```

### Capacity Planning

| Blocked Items | Filter Size | Memory |
|---------------|-------------|--------|
| 10,000 | ~10 KB | Minimal |
| 100,000 | ~100 KB | Low |
| 1,000,000 | ~1 MB | Moderate |

**Recommendation:** Start with 100K capacity, monitor utilization via `getBlocklistStats()`.

---

## Cost Analysis

### Comparison (1M requests/month, 1% blocked)

| Component | KV Blocklist | Cuckoo (verify=true) | Cuckoo (verify=false) |
|-----------|--------------|----------------------|----------------------|
| Check blocked | 1M reads ($0.50) | ~10K reads* ($0.005) | ~0 (cache) |
| Cold start filter load | N/A | ~2K reads ($0.001) | ~2K reads ($0.001) |
| Block write | ~1K writes (~$0) | ~1K writes (~$0) | ~1K writes (~$0) |
| False positive blocks | 0% | 0% | ~1% |
| **Total** | **~$0.50** | **~$0.006** | **~$0.001** |

*With `verifyWithKV: true`, KV reads only occur when filter reports blocked (~1% of requests due to actual blocks + ~1% false positives = ~2% total). These reads are cached at edge for 1 hour.

### At Scale (100M requests/month)

| Component | KV Blocklist | Cuckoo (verify=true) | Cuckoo (verify=false) |
|-----------|--------------|----------------------|----------------------|
| Monthly cost | ~$50.00 | ~$0.60 | ~$0.10 |
| False positive blocks | 0 | 0 | ~1M |
| **Savings** | - | **98.8%** | **99.8%** |

### Recommendation

- **`verifyWithKV: true` (default)**: Best for most use cases. Eliminates false positives with minimal cost increase.
- **`verifyWithKV: false`**: Only for high-volume, low-stakes blocking (e.g., aggressive rate limiting where 1% false positives are acceptable).

---

## Troubleshooting

### Filter not blocking

1. Check if filter is loaded:
```typescript
const stats = await getBlocklistStats(env.BLOCKLIST_KV);
console.log('Filter version:', stats.filterVersion);
console.log('Items:', stats.totalBlocked);
```

2. Force rebuild:
```typescript
await rebuildBlocklistFilter(env.BLOCKLIST_KV);
```

3. Check pending cache:
```typescript
const isPending = await CuckooBlocklistDetector.isInPending(ip);
```

### High false positive rate

Cuckoo Filter has ~1% false positive rate. If seeing higher:

1. Check filter utilization:
```typescript
const stats = await getBlocklistStats(env.BLOCKLIST_KV);
if (stats.filterUtilization > 0.9) {
  console.warn('Filter near capacity, increase filterCapacity');
}
```

2. Increase capacity and rebuild:
```typescript
await rebuildBlocklistFilter(env.BLOCKLIST_KV, {
  filterCapacity: 200000, // Double capacity
});
```

### Queue messages not processing

1. Check queue binding in wrangler.toml
2. Verify consumer is exported correctly
3. Check queue dead letter queue for failed messages

---

## Best Practices

1. **Set appropriate TTLs**
   - Pending: 5-10 minutes (covers sync delay)
   - Filter cache: 5 minutes (balance freshness vs. KV reads)

2. **Schedule regular rebuilds**
   - Every 6-24 hours depending on block/unblock frequency
   - Cleans up filter fragmentation

3. **Monitor utilization**
   - Alert when filter > 80% full
   - Plan capacity for 2x expected blocks

4. **Use pending cache for immediate effect**
   - Always write to pending cache first
   - Queue sync is for global consistency

5. **Combine with KV for critical cases**
   - Use Cuckoo for general blocking
   - Use KV directly for security-critical immediate revocation

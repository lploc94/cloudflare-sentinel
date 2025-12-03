# Detector System

Guide for contributors working on detectors.

## Architecture

```
BaseDetector (abstract)
    ↓
Built-in Detectors (23 detectors)
    ├─ Access Control: BlocklistDetector, CuckooBlocklistDetector, RateLimitDetector, ReputationDetector
    ├─ Injection: SQLInjection, XSS, NoSQL, CommandInjection, SSTI
    ├─ Protocol: CSRF, XXE, HTTPSmuggling, JWT
    ├─ Redirect: OpenRedirect, SSRF
    ├─ Path: PathTraversal
    ├─ Response: SQLInjection, XSS, PathTraversal (leak detection)
    ├─ Behavior: BruteForce, FailureThreshold, Entropy
    └─ ML: MLDetector (lightweight classifier)
```

## File Structure

```
detector/
├── base.ts                           # Base class & interfaces
├── index.ts                          # Exports
│
│ # Access Control
├── blocklist.detector.ts             # IP/key blocklist (KV-based)
├── cuckoo-blocklist.detector.ts      # Cost-efficient blocklist (Cache API + Cuckoo Filter)
├── rate-limit.detector.ts            # Rate limiting (CF API or KV)
│
│ # Injection Attacks
├── sql-injection.request.detector.ts # SQL injection (request)
├── sql-injection.response.detector.ts# SQL injection (response leak)
├── xss.request.detector.ts           # XSS (request)
├── xss.response.detector.ts          # XSS (response)
├── nosql-injection.detector.ts       # NoSQL injection (MongoDB, etc.)
├── command-injection.detector.ts     # OS command injection
├── ssti.detector.ts                  # Server-Side Template Injection (RCE)
│
│ # Protocol Attacks
├── csrf.detector.ts                  # Cross-Site Request Forgery
├── xxe.detector.ts                   # XML External Entity
├── http-smuggling.detector.ts        # HTTP Request Smuggling
├── jwt.detector.ts                   # JWT attacks (alg=none, kid injection)
│
│ # Redirect Attacks
├── open-redirect.detector.ts         # Open redirect vulnerabilities
├── ssrf.detector.ts                  # Server-Side Request Forgery
│
│ # Path Attacks
├── path-traversal.request.detector.ts
├── path-traversal.response.detector.ts
│
│ # Behavior Analysis
├── brute-force.detector.ts           # Auth brute force (extends FailureThreshold)
├── failure-threshold.detector.ts     # Generic failure counting
├── entropy.detector.ts               # High entropy detection (encoded payloads)
│
│ # ML-based
├── ml.detector.ts                    # Lightweight ML classifier
│
└── _examples.ts                      # Example custom detectors
```

## Adding New Detector

### 1. Create Detector Class

```typescript
// src/detector/my-attack.detector.ts
import { BaseDetector, type DetectorResult } from './base';
import { AttackType, SecuritySeverity } from '../types';

export class MyAttackDetector extends BaseDetector {
  name = 'my_attack';
  priority = 70; // 0-100, higher = checked first
  
  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    // Your detection logic
    const suspicious = await this.checkRequest(request);
    
    if (suspicious) {
      return this.createResult(
        AttackType.SUSPICIOUS_PATTERN,
        SecuritySeverity.HIGH,
        0.9,
        { field: 'query', value: 'suspicious value' }
      );
    }
    
    return null; // No attack detected
  }
  
  private async checkRequest(request: Request): Promise<boolean> {
    // Implementation
    return false;
  }
}
```

### 2. Export Detector

```typescript
// src/detector/index.ts
export { MyAttackDetector } from './my-attack.detector';
```

### 3. Add Tests

```typescript
// src/detector/my-attack.detector.test.ts
import { MyAttackDetector } from './my-attack.detector';

describe('MyAttackDetector', () => {
  it('detects my attack', async () => {
    const detector = new MyAttackDetector();
    const result = await detector.detectRequest(maliciousRequest, {});
    
    expect(result).not.toBeNull();
    expect(result?.attackType).toBe('my_attack');
  });
});
```

## Detection Methods

### Request Detection

Analyze request before forwarding:
- Query parameters
- Headers
- Body
- Path

**Use case**: Block before origin access

### Response Detection

Analyze response from origin:
- Response body
- Headers

**Use case**: Detect data leaks, SQL errors

## Best Practices

### 1. Performance

- Keep detection fast (<5ms)
- Use regex efficiently
- Cache compiled patterns
- Return early on no match

### 2. False Positives

- Start with high confidence threshold (>0.8)
- Test with real traffic
- Provide evidence for debugging
- Use `log_only` mode first

### 3. Evidence

Always provide clear evidence:

```typescript
evidence: {
  field: 'query.id',           // Where found
  value: "1' OR '1'='1",       // What found
  pattern: 'SQL_UNION',        // Which pattern (optional)
}
```

### 4. Severity Levels

```typescript
'low'      // Minor issue, monitor
'medium'   // Suspicious, alert
'high'     // Clear attack, block recommended
'critical' // Severe attack, immediate block
```

## Testing

```bash
# Run tests
npm test

# Test specific detector
npm test -- sql-injection

# Watch mode
npm test -- --watch
```

## Integration

Detector is auto-registered when added to Sentinel config:

```typescript
const sentinel = new Sentinel({
  detectors: [
    new MyAttackDetector(),
  ],
});

// Or with endpoint-specific detectors:
const sentinel = new Sentinel({
  detectors: {
    '*': [new MyAttackDetector()],  // Global
    '/api/sensitive/*': [new MyAttackDetector()],  // Endpoint-specific
  },
});
```

Execution order: Priority DESC (100 → 0)

## Examples

See existing detectors:

**Injection Detection:**
- `sql-injection.request.detector.ts` - Pattern-based SQL injection
- `xss.request.detector.ts` - XSS with HTML entity decoding
- `ssti.detector.ts` - Template injection (Jinja2, Twig, ERB, etc.)
- `command-injection.detector.ts` - Shell metacharacter detection

**Protocol Detection:**
- `csrf.detector.ts` - Origin/Referer validation
- `jwt.detector.ts` - alg=none, kid injection, jku SSRF
- `http-smuggling.detector.ts` - CL.TE, header injection

**Behavior Detection:**
- `brute-force.detector.ts` - KV-based failure counting
- `rate-limit.detector.ts` - CF API or KV rate limiting

**Blocklist Detector:**
- `blocklist.detector.ts` - Unified blocklist with two modes

### BlocklistDetector Modes

| Aspect | mode: 'direct' | mode: 'cuckoo' |
|--------|----------------|----------------|
| **Storage** | KV only | Cache API + Cuckoo Filter + KV |
| **Read cost** | ~$0.50/1M reads | ~$0.001/1M reads |
| **Latency** | ~10-50ms | ~0-5ms |
| **False positives** | None | ~1% (eliminated with verifyWithKV) |
| **Complexity** | Simple | Requires Queue/Cron for sync |

**When to use mode: 'direct':**
- ✅ Simple setup, low traffic (<100K req/month)
- ✅ Don't want Queue/Cron infrastructure

**When to use mode: 'cuckoo':**
- ✅ High traffic (>100K req/month)
- ✅ Cost optimization is priority
- ✅ Need fastest possible blocking (~0ms)

```typescript
// Simple mode
new BlocklistDetector({ kv, mode: 'direct' })

// Cuckoo mode (fast + cost-efficient)
new BlocklistDetector({ kv, mode: 'cuckoo', verifyWithKV: true })

// Hybrid: direct write + cuckoo read (with cron rebuild)
new BlocklistHandler({ kv, mode: 'direct' });
new BlocklistDetector({ kv, mode: 'cuckoo' });
```

See [Cuckoo Blocklist Guide](../../docs/cuckoo-blocklist.md) for details.

**Custom Examples:**
- `_examples.ts` - Custom detector examples

---

**Questions?** Open an issue or discussion.

# Detector System

Internal guide for contributors working on detectors.

## Architecture

```
BaseDetector (abstract)
    ↓
Built-in Detectors
    ├─ SQLInjectionRequestDetector
    ├─ XSSRequestDetector
    ├─ PathTraversalRequestDetector
    └─ BruteForceDetector
```

## File Structure

```
detector/
├── base.ts                      # Base classes & interfaces
├── sql-injection/
│   ├── request-detector.ts      # Request detection
│   ├── response-detector.ts     # Response detection  
│   └── patterns.ts              # SQL patterns
├── xss/
│   ├── request-detector.ts
│   ├── response-detector.ts
│   └── patterns.ts
├── path-traversal/
│   └── ...
├── brute-force/
│   └── detector.ts
└── index.ts                     # Exports
```

## Adding New Detector

### 1. Create Detector Class

```typescript
// src/detector/my-attack/detector.ts
import { BaseDetector } from '../base';
import type { DetectorResult } from '../base';

export class MyAttackDetector extends BaseDetector {
  name = 'my_attack';
  priority = 70; // 0-100, higher = checked first
  
  async detectRequest(request: Request, context: any): Promise<DetectorResult | null> {
    // Your detection logic
    const suspicious = await this.checkRequest(request);
    
    if (suspicious) {
      return this.createResult({
        attackType: 'my_attack',
        severity: 'high',
        confidence: 0.9,
        evidence: {
          field: 'query',
          value: 'suspicious value',
        },
      });
    }
    
    return null; // No attack detected
  }
  
  private async checkRequest(request: Request): Promise<boolean> {
    // Implementation
    return false;
  }
}
```

### 2. Add Patterns (if pattern-based)

```typescript
// src/detector/my-attack/patterns.ts
export const MY_ATTACK_PATTERNS = [
  /pattern1/i,
  /pattern2/i,
];
```

### 3. Export Detector

```typescript
// src/detector/index.ts
export { MyAttackDetector } from './my-attack/detector';
```

### 4. Add Tests

```typescript
// src/detector/my-attack/__tests__/detector.test.ts
import { MyAttackDetector } from '../detector';

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
- `sql-injection/` - Pattern-based detection
- `xss/` - Regex + context analysis
- `brute-force/` - Rate-based detection

---

**Questions?** Open an issue or discussion.

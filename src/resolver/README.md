# Resolver System

Resolvers convert threat scores into actions.

## Architecture

```
IActionResolver (interface)
    ↓
BaseActionResolver (abstract)
    ↓
Built-in Resolvers
    ├─ DefaultResolver      → Standard thresholds
    ├─ StrictResolver       → Lower thresholds, aggressive
    ├─ LenientResolver      → Higher thresholds, permissive
    └─ MultiLevelResolver   → Configurable cascading actions
```

## File Structure

```
resolver/
├── types.ts                  # IActionResolver interface
├── base.ts                   # BaseActionResolver
├── index.ts                  # Exports
├── default.resolver.ts
├── strict.resolver.ts
├── lenient.resolver.ts
└── multi-level.resolver.ts
```

## Creating Custom Resolver

```typescript
// src/resolver/my-custom.resolver.ts
import type { Action, ResolverContext } from '../pipeline/types';
import { BaseActionResolver } from './base';

export class MyResolver extends BaseActionResolver {
  name = 'my-resolver';

  async resolve(ctx: ResolverContext): Promise<Action[]> {
    const actions: Action[] = [];
    const { score, results } = ctx;

    // Always log
    actions.push(this.log('info', { score: score.score }));

    // Custom logic
    if (score.score >= 80) {
      actions.push(this.block('Critical threat detected'));
      actions.push(this.notify('security', 'Attack blocked'));
    } else if (score.score >= 50) {
      actions.push({ type: 'escalate', data: {} });
      actions.push(this.proceed());
    } else {
      actions.push(this.proceed());
    }

    return actions;
  }
}
```

## Built-in Resolvers

### DefaultResolver
Standard threshold-based resolution.

```typescript
new DefaultResolver({
  blockThreshold: 70,   // Block if score >= 70
  warnThreshold: 40,    // Log warning if score >= 40
  alwaysLog: false,     // Log all requests
})
```

### StrictResolver
Aggressive blocking for sensitive endpoints.

```typescript
new StrictResolver({
  blockThreshold: 40,   // Lower threshold
})
```

### LenientResolver
Permissive for public/search endpoints.

```typescript
new LenientResolver({
  blockThreshold: 90,   // Higher threshold
})
```

### MultiLevelResolver ⭐
Configurable multi-level thresholds with cascading actions.

```typescript
new MultiLevelResolver({
  levels: [
    { maxScore: 30, actions: ['increment'] },
    { maxScore: 60, actions: ['log', 'escalate'] },
    { maxScore: 100, actions: ['block', 'notify'] },
  ]
})
```

**How it works:**
- Score 25 → Level 1 → `increment`
- Score 45 → Level 2 → `increment` + `log` + `escalate`
- Score 75 → Level 3 → `increment` + `log` + `escalate` + `block` + `notify`

Each level inherits actions from previous levels (cascading).

## BaseActionResolver Helpers

```typescript
// Block request
this.block(reason: string): Action

// Allow request
this.proceed(): Action

// Log event
this.log(level: string, data: any): Action

// Send notification
this.notify(channel: string, message: string): Action
```

## ResolverContext

```typescript
interface ResolverContext {
  score: ThreatScore;        // Aggregated score
  results: DetectorResult[]; // All detector results
  request?: Request;         // Original request
  response?: Response;       // Response (if response detection)
}
```

## Best Practices

1. **Always return actions** - At least `proceed()` or `block()`
2. **Check detector results** - Access specific detector data via `results`
3. **Consider false positives** - Higher thresholds for search/public APIs
4. **Use MultiLevelResolver** - For fine-grained control

---

**Questions?** Open an issue on GitHub.

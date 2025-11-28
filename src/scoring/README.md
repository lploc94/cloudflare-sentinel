# Scoring System

Aggregators combine multiple detector results into a single threat score.

## Architecture

```
IScoreAggregator (interface)
    ↓
BaseScoreAggregator (abstract)
    ↓
Built-in Aggregators
    ├─ MaxScoreAggregator     → Use highest score
    └─ WeightedAggregator     → Weighted average with detector weights
```

## File Structure

```
scoring/
├── types.ts              # IScoreAggregator interface
├── base.ts               # BaseScoreAggregator
├── index.ts              # Exports
├── max.aggregator.ts
└── weighted.aggregator.ts
```

## Creating Custom Aggregator

```typescript
// src/scoring/my-custom.aggregator.ts
import type { DetectorResult } from '../detector/base';
import type { ThreatScore } from '../pipeline/types';
import { BaseScoreAggregator } from './base';

export class MyAggregator extends BaseScoreAggregator {
  name = 'my-aggregator';

  aggregate(results: DetectorResult[]): ThreatScore {
    // Filter only detected results
    const detected = results.filter(r => r.detected);
    
    if (detected.length === 0) {
      return { score: 0, level: 'none', results };
    }

    // Custom scoring logic
    let score = 0;
    for (const result of detected) {
      const baseScore = this.severityToScore(result.severity);
      score += baseScore * result.confidence;
    }

    // Normalize to 0-100
    score = Math.min(100, score);

    return {
      score,
      level: this.calculateLevel(score),
      results,
    };
  }
}
```

## Built-in Aggregators

### MaxScoreAggregator
Uses the highest score from all detectors.

```typescript
new MaxScoreAggregator()
```

**Use case:** When any single high-severity detection should trigger action.

### WeightedAggregator
Calculates weighted average based on severity and confidence, with optional detector weights.

```typescript
// Without detector weights (confidence only)
new WeightedAggregator()

// With detector weights (prioritize certain detectors)
new WeightedAggregator({
  'sql-injection': 1.5,        // 50% more important
  'blocklist': 2.0,             // 2x more important
  'xss': 1.0,                   // Normal weight (default)
})
```

**Formula:** `score = baseScore * confidence * weight`

**Use case:** When you want balanced scoring across multiple detections, or need to prioritize certain detector types.

## ThreatScore Interface

```typescript
interface ThreatScore {
  score: number;           // 0-100
  level: ThreatLevel;      // 'none' | 'low' | 'medium' | 'high' | 'critical'
  results: DetectorResult[];
}
```

## BaseScoreAggregator Helpers

```typescript
// Convert severity to numeric score
this.severityToScore(severity: SecuritySeverity): number
// low: 25, medium: 50, high: 75, critical: 100

// Calculate threat level from score
this.calculateLevel(score: number): ThreatLevel
// 0-20: none, 21-40: low, 41-60: medium, 61-80: high, 81-100: critical
```

## Choosing an Aggregator

| Aggregator | Best For | Example |
|------------|----------|---------|
| **MaxScoreAggregator** | Critical endpoints (auth, admin) | Block on any high-severity |
| **WeightedAggregator** | General APIs, with detector weights | Balanced scoring with priorities |

## Usage

```typescript
const pipeline = SentinelPipeline.sync([...])
  .score(new MaxScoreAggregator())  // <-- Choose aggregator
  .resolve(new DefaultResolver())
  .on('log', new LogHandler());
```

---

**Questions?** Open an issue on GitHub.

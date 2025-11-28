# ML Training Scripts

Train lightweight binary classifier for request pre-filtering.

**Goal**: Filter safe requests → Skip LLM. Flag suspicious → Send to LLM for analysis.

## Setup

```bash
cd scripts/training
pip install -r requirements.txt
```

## Quick Start

### 1. Download attack payloads

```bash
python3 download_datasets.py
```

Downloads from PayloadsAllTheThings + SecLists → `data/samples/suspicious.txt`

### 2. Generate safe requests

```bash
python3 generate_safe_requests.py --count 50000
```

Generates synthetic safe API requests → `data/samples/safe.txt`

### 3. Prepare dataset

```bash
python3 prepare_dataset.py
```

Combines samples → `data/dataset.jsonl`

### 4. Train model

```bash
python3 train_classifier.py --data data/dataset.jsonl --output ../../models/classifier.json
```

Options:
- `--test-size 0.2` - Test set ratio (default: 20%)
- `--model logistic` - Model type: `logistic` or `sgd`

### 5. Use in Worker

```typescript
import { LinearClassifier } from 'cloudflare-sentinel/ml';
import modelJson from './models/classifier.json';

const classifier = new LinearClassifier(modelJson);
const result = classifier.predictText(requestText);

if (result.class === 'suspicious' && result.confidence > 0.7) {
  // Send to LLM for analysis
}
```

## Data Structure

```
data/
├── samples/
│   ├── safe.txt        # Safe requests → Skip LLM
│   └── suspicious.txt  # Attack payloads → Send to LLM
└── dataset.jsonl       # Combined (generated)
```

## Scripts

| Script | Purpose |
|--------|---------|
| `download_datasets.py` | Download attack payloads from GitHub |
| `generate_safe_requests.py` | Generate synthetic safe requests |
| `prepare_dataset.py` | Combine samples into dataset.jsonl |
| `train_classifier.py` | Train the classifier model |
| `verify_hash.py` | Verify MurmurHash3 compatibility |

## Model Size

| n_features | Size |
|------------|------|
| 4096 | ~35 KB |
| 8192 | ~70 KB |

## Using in Worker

The trained model is bundled with `MLDetector`:

```typescript
import { MLDetector } from 'cloudflare-sentinel';

// Use default bundled model
const detector = new MLDetector();

// Or custom model
import customModel from './my-model.json';
const detector = new MLDetector({ model: customModel });
```

See [src/detector/ml.detector.ts](../../src/detector/ml.detector.ts)

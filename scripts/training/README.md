# Custom ML Model Training Guide

Train a custom ML model tailored to your service's traffic patterns for better detection accuracy.

## Why Train Custom Model?

The bundled model works for general APIs, but training your own model provides:

| Benefit | Description |
|---------|-------------|
| **Lower false positives** | Model learns YOUR app's legitimate patterns |
| **Better detection** | Trained on attacks relevant to YOUR stack |
| **Domain awareness** | Understands your specific URL structures, params |

**Example:** An e-commerce API has different "safe" patterns than a banking API.

---

## Quick Start (5 minutes)

```bash
cd scripts/training
pip install -r requirements.txt

# 1. Get attack payloads
python3 download_datasets.py

# 2. Generate DIVERSE safe data (recommended - prevents overfitting!)
python3 download_safe_data.py

# Or: Generate basic safe requests (customize later)
# python3 generate_safe_requests.py --count 50000

# 3. Prepare dataset
python3 prepare_dataset.py

# 4. Train model
python3 train_classifier.py --data data/dataset.jsonl --output ../../models/classifier.json
```

> ⚠️ **Avoiding Overfitting:** Use `download_safe_data.py` to generate diverse safe data including real dictionary words, names, cities, and realistic patterns. This prevents the model from overfitting on limited safe examples.

---

## Attack Payload Sources

The `download_datasets.py` script downloads attack payloads from trusted security research repositories:

### Primary Sources

| Source | Description | Payloads |
|--------|-------------|----------|
| [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) | Modern attack payloads from security researchers | ~15,000+ |
| [SecLists](https://github.com/danielmiessler/SecLists) | Comprehensive fuzzing wordlists | ~10,000+ |

### Attack Categories Included

```
PayloadsAllTheThings/
├── SQL Injection/          # SQLi payloads
├── XSS Injection/          # Cross-site scripting
├── Command Injection/      # OS command injection
├── Directory Traversal/    # Path traversal (../)
├── Server Side Request Forgery/  # SSRF
├── XXE Injection/          # XML external entity
├── Server Side Template Injection/  # SSTI
└── NoSQL Injection/        # MongoDB, etc.
```

### How It Works

```bash
python3 download_datasets.py
```

1. **Clones** PayloadsAllTheThings & SecLists (shallow clone)
2. **Extracts** payloads from `.txt` files in attack directories
3. **Deduplicates** and writes to `data/samples/suspicious.txt`
4. **Cleans up** temporary repos

### Output

```
📥 Downloading PayloadsAllTheThings...
   ✅ Extracted 15234 payloads
📥 Downloading SecLists (Fuzzing only)...
   ✅ Extracted 8567 payloads
✅ Written 21453 payloads to data/samples/suspicious.txt
```

### Adding More Sources (Optional)

For specialized attacks, manually download from:

| Dataset | Link | Use Case |
|---------|------|----------|
| Kaggle SQLi | [sql-injection-dataset](https://www.kaggle.com/datasets/ayahkhaldi/sql-injection-dataset) | More SQLi variants |
| CSIC 2010 | [http-dataset-csic-2010](https://www.kaggle.com/datasets/ispabornikovic/http-dataset-csic-2010) | HTTP attack samples |

Append to `data/samples/suspicious.txt`:
```bash
cat kaggle_sqli.txt >> data/samples/suspicious.txt
```

---

## Customizing for Your Service

### Step 1: Define YOUR Safe Patterns

Edit `generate_safe_requests.py` to match YOUR API:

```python
# Replace with YOUR endpoints
API_PATHS = [
    # Your auth endpoints
    '/api/v1/auth/login',
    '/api/v1/auth/register',
    '/api/v1/auth/verify-otp',
    
    # Your business endpoints
    '/api/v1/wallets',
    '/api/v1/wallets/{id}/transfer',
    '/api/v1/transactions',
    '/api/v1/users/profile',
    
    # Your specific patterns
    '/webhook/stripe',
    '/webhook/paypal',
]

# Your query params
QUERY_PARAMS = {
    'wallet_id': lambda: f"wal_{random.randint(10000, 99999)}",
    'currency': lambda: random.choice(['USD', 'VND', 'BTC', 'ETH']),
    'amount': lambda: random.uniform(0.01, 10000),
    'network': lambda: random.choice(['ethereum', 'polygon', 'bsc']),
}

# Your request bodies (login, transfer, etc.)
BODY_TEMPLATES = [
    'email={email}&password=***&otp={otp}',
    'wallet_id={wallet_id}&amount={amount}&currency={currency}',
    'address={address}&network={network}',
]
```

### Step 2: Add Service-Specific Attack Patterns (Optional)

If your service has unique attack vectors, add them to `data/samples/suspicious.txt`:

```text
# Crypto/Wallet specific attacks
/api/wallets?id=wal_1' UNION SELECT private_key FROM wallets--
/api/transfer?to=attacker&amount=999999999
/webhook/stripe?signature=forged_signature

# Your app-specific injection patterns
/api/users?filter[$gt]=&role=admin
/api/search?q={{constructor.constructor('return process')()}}
```

### Step 3: Balance Your Dataset

Good ratio: **60% safe : 40% suspicious**

```bash
# Check current counts
wc -l data/samples/safe.txt
wc -l data/samples/suspicious.txt

# Generate more safe if needed
python3 generate_safe_requests.py --count 100000
```

---

## Training Options

```bash
python3 train_classifier.py \
  --data data/dataset.jsonl \
  --output my-model.json \
  --model logistic \
  --test-size 0.2
```

| Option | Values | Description |
|--------|--------|-------------|
| `--model` | `logistic` (default), `sgd` | Model algorithm |
| `--test-size` | `0.1` - `0.3` | Test set ratio |

### Expected Output

```
Loaded 75000 samples
Labels: {'safe', 'suspicious'}

Vectorizing texts...
Feature matrix shape: (75000, 4096)
Train: 60000, Test: 15000

Training logistic classifier...

=== Classification Report ===
              precision    recall  f1-score
        safe       0.97      0.98      0.97
  suspicious       0.96      0.94      0.95
    accuracy                           0.96

Model saved to my-model.json (35.2 KB)
```

**Target metrics:**
- Precision ≥ 0.95 (low false positives)
- Recall ≥ 0.90 (catch most attacks)

---

## Using Your Custom Model

### Option 1: Bundle with Your Worker

```typescript
// worker/src/sentinel/models/classifier.json
import customModel from './models/classifier.json';

import { MLDetector } from 'cloudflare-sentinel';

const detector = new MLDetector({ model: customModel as any });
```

### Option 2: Use in Pipeline

```typescript
import customModel from './models/classifier.json';
import { SentinelPipeline, MLDetector, MultiLevelResolver, ActionType } from 'cloudflare-sentinel';

const pipeline = SentinelPipeline.async([
  new MLDetector({ model: customModel as any }),
])
.score(new MaxScoreAggregator())
.resolve(new MultiLevelResolver({
  // MLDetector: severity=HIGH(80) × confidence(0-1) = finalScore
  // 50% conf → 40, 70% → 56, 90% → 72, 100% → 80
  levels: [
    { maxScore: 40, actions: [ActionType.LOG] },                                        // ≤50% - just log
    { maxScore: 56, actions: [ActionType.LOG, ActionType.UPDATE_REPUTATION] },          // ≤70% - track reputation
    { maxScore: 72, actions: [ActionType.LOG, ActionType.UPDATE_REPUTATION, ActionType.NOTIFY] }, // ≤90% - notify admin
    { maxScore: 80, actions: [ActionType.LOG, ActionType.UPDATE_REPUTATION, ActionType.NOTIFY] }, // >90% - high confidence
  ],
}));

// Fire & forget for async monitoring
ctx.waitUntil(pipeline.process(request, pctx));
```

---

## Best Practices

### 1. Collect Real Traffic

Best training data = real requests from YOUR service:

```typescript
// Log requests for training (sanitize sensitive data!)
const logEntry = `${request.method} ${url.pathname}${url.search}`;
await env.TRAINING_KV.put(`req:${Date.now()}`, logEntry);
```

Then export and label:
- Legitimate requests → `safe.txt`
- Known attacks (from WAF logs) → `suspicious.txt`

### 2. Retrain Periodically

- New endpoints? Retrain.
- New attack patterns discovered? Add to suspicious.txt & retrain.
- High false positive rate? Add more safe examples & retrain.

### 3. Test Before Deploy

```typescript
// Test with known patterns
const testCases = [
  { input: "GET /api/users?id=123", expected: "safe" },
  { input: "GET /api/users?id=1' OR '1'='1", expected: "suspicious" },
  { input: "POST /api/login email=user@example.com", expected: "safe" },
];

for (const tc of testCases) {
  const result = classifier.predictText(tc.input);
  console.assert(result.class === tc.expected, `Failed: ${tc.input}`);
}
```

---

## Directory Structure

```
scripts/training/
├── data/
│   ├── samples/
│   │   ├── safe.txt           # YOUR safe patterns
│   │   ├── safe_diverse.txt   # Diverse safe data (from download_safe_data.py)
│   │   └── suspicious.txt     # Attack payloads
│   └── dataset.jsonl          # Combined (auto-generated)
├── download_datasets.py       # Download PayloadsAllTheThings
├── download_safe_data.py      # Download diverse safe data (NEW - recommended!)
├── generate_safe_requests.py  # Generate basic safe requests
├── prepare_dataset.py         # Combine → dataset.jsonl
├── train_classifier.py        # Train model
├── verify_hash.py             # Verify hash compatibility
└── requirements.txt
```

---

## Diverse Safe Data (Recommended)

The `download_safe_data.py` script generates diverse, realistic safe data to prevent ML overfitting:

### Data Sources

| Source | Count | Description |
|--------|-------|-------------|
| English dictionary | ~10,000 | Common words |
| Names (First/Last) | ~5,000 | Real names from multiple cultures |
| Cities | ~3,000 | World cities |
| Emails | 5,000 | Realistic email formats |
| Phone numbers | 3,000 | Various formats |
| Addresses | 3,000 | Street addresses |
| Sentences | 10,000 | Lorem ipsum + realistic |
| File paths | 3,000 | Common file paths |
| URLs | 3,000 | Safe URLs |
| JSON objects | 2,000 | API responses |
| Messages | 5,000 | User messages |
| Product names | 2,000 | E-commerce products |

### Usage

```bash
python3 download_safe_data.py
# Output: data/samples/safe_diverse.txt (~47,000 samples)
```

### Why This Matters

Without diverse safe data, ML models overfit:

```
❌ Limited safe data:
   "Hello World", "Test User", "user@test.com"
   → Model thinks ANY real text is suspicious!

✅ Diverse safe data:
   Dictionary words, real names, cities, realistic messages
   → Model learns what NORMAL data looks like
```

---

## Troubleshooting

### High False Positives

Model flags safe requests as suspicious.

**Fix:**
1. Add more examples of your safe patterns
2. Check if safe patterns look too similar to attacks
3. Increase safe:suspicious ratio to 70:30

### Low Detection Rate

Model misses attacks.

**Fix:**
1. Add more attack patterns for your stack
2. Check if attacks are too different from training data
3. Try `--model sgd` for different decision boundary

### Model Too Large

Bundled model affects Worker size.

**Fix:**
```python
# In train_classifier.py, reduce n_features:
VECTORIZER_CONFIG = {
    "n_features": 2048,  # Smaller: ~18 KB
    ...
}
```

| n_features | Size | Accuracy |
|------------|------|----------|
| 2048 | ~18 KB | ~94% |
| 4096 | ~35 KB | ~96% |
| 8192 | ~70 KB | ~97% |

---

## Model Compatibility

The trained model uses:
- **Algorithm:** Logistic Regression (sklearn)
- **Vectorizer:** HashingVectorizer (char n-grams 3-5)
- **Hash:** MurmurHash3 (JS implementation matches sklearn)

Output JSON format:
```json
{
  "type": "logistic_regression",
  "classes": ["safe", "suspicious"],
  "weights": [[...], [...]],
  "bias": [-0.5, 0.5],
  "vectorizer": {
    "nFeatures": 4096,
    "ngramRange": [3, 5],
    "analyzer": "char_wb"
  }
}
```

See [src/ml/classifier.ts](../../src/ml/classifier.ts) for inference implementation.

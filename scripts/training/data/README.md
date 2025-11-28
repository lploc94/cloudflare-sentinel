# Training Data

Binary classification: **safe** vs **suspicious** (needs LLM review)

## Structure

```
data/
├── samples/
│   ├── safe.txt        # Safe requests → Skip LLM
│   └── suspicious.txt  # Suspicious → Send to LLM
└── dataset.jsonl       # Generated
```

## Goal

- **High recall**: Catch all potential attacks (some false positives OK)
- **Filter**: Skip obviously safe requests from expensive LLM calls

## Data Sources & Attribution

### Suspicious (attack payloads)

| Source | License | URL |
|--------|---------|-----|
| **PayloadsAllTheThings** | MIT | https://github.com/swisskyrepo/PayloadsAllTheThings |
| **SecLists** | MIT | https://github.com/danielmiessler/SecLists |

These projects are maintained by the security community. Thanks to all contributors!

### Safe (legitimate requests)
- Synthetic generated requests (see `generate_safe_requests.py`)

## Generate

```bash
python prepare_dataset.py
```

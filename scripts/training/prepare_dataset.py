#!/usr/bin/env python3
"""
Prepare training dataset from sample files.

Two modes:
1. Raw mode: Use samples as-is (for full request samples)
2. Inject mode: Inject payloads into request templates (default for attacks)

Usage:
    python prepare_dataset.py
    python prepare_dataset.py --raw  # Don't inject, use samples as-is
"""

import argparse
import json
import random
from pathlib import Path


# Request templates for injecting attack payloads
REQUEST_TEMPLATES = [
    "GET /api/users?id={payload}",
    "GET /api/search?q={payload}",
    "GET /api/products?filter={payload}",
    "POST /api/login username={payload}&password=test",
    "POST /api/data query={payload}",
    "GET /page?file={payload}",
    "GET /api/fetch?url={payload}",
    "GET /api/items?sort={payload}",
    "POST /api/comment body={payload}",
    "GET /download?path={payload}",
]


def load_samples(file_path: Path) -> list[str]:
    """Load samples from a text file, ignoring comments and empty lines."""
    samples = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            # Skip empty lines and comments
            if line and not line.startswith('#'):
                samples.append(line)
    return samples


def inject_into_template(payload: str) -> str:
    """Inject payload into a random request template."""
    template = random.choice(REQUEST_TEMPLATES)
    return template.format(payload=payload)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--raw', action='store_true', 
                        help='Use samples as-is, do not inject into templates')
    args = parser.parse_args()
    
    samples_dir = Path(__file__).parent / 'data' / 'samples'
    output_file = Path(__file__).parent / 'data' / 'dataset.jsonl'
    
    all_samples = []
    
    # Process each .txt file
    for txt_file in samples_dir.glob('*.txt'):
        label = txt_file.stem  # filename without extension
        samples = load_samples(txt_file)
        
        for sample in samples:
            # Safe samples are already full requests, use as-is
            # Attack samples are payloads, inject into templates
            if label == 'safe' or args.raw:
                text = sample
            else:
                text = inject_into_template(sample)
            
            all_samples.append({
                'text': text,
                'label': label
            })
        
        print(f"  {label}: {len(samples)} samples")
    
    # Shuffle
    random.shuffle(all_samples)
    
    # Write dataset
    with open(output_file, 'w', encoding='utf-8') as f:
        for sample in all_samples:
            f.write(json.dumps(sample, ensure_ascii=False) + '\n')
    
    print(f"\n✅ Created {output_file}")
    print(f"   Total: {len(all_samples)} samples")
    
    # Show examples
    print("\nExamples:")
    for sample in all_samples[:5]:
        print(f"  [{sample['label']}] {sample['text'][:60]}...")


if __name__ == '__main__':
    print("Preparing dataset...\n")
    main()

#!/usr/bin/env python3
"""
Download and combine multiple datasets for training.

Sources:
1. PayloadsAllTheThings (GitHub) - Modern attack payloads
2. SecLists (GitHub) - Comprehensive fuzzing lists  
3. Kaggle datasets (manual download required)

Usage:
    python download_datasets.py
"""

import os
import subprocess
from pathlib import Path

DATA_DIR = Path(__file__).parent / 'data'
SAMPLES_DIR = DATA_DIR / 'samples'


def download_payloads_all_the_things():
    """Download PayloadsAllTheThings attack payloads."""
    print("\n📥 Downloading PayloadsAllTheThings...")
    
    repo_dir = DATA_DIR / 'PayloadsAllTheThings'
    
    if repo_dir.exists():
        print("   Already exists, pulling latest...")
        subprocess.run(['git', 'pull'], cwd=repo_dir, capture_output=True)
    else:
        subprocess.run([
            'git', 'clone', '--depth=1',
            'https://github.com/swisskyrepo/PayloadsAllTheThings.git',
            str(repo_dir)
        ], capture_output=True)
    
    return repo_dir


def download_seclists():
    """Download SecLists fuzzing payloads."""
    print("\n📥 Downloading SecLists (Fuzzing only)...")
    
    repo_dir = DATA_DIR / 'SecLists'
    
    if repo_dir.exists():
        print("   Already exists, skipping...")
        return repo_dir
    
    # Sparse checkout - only Fuzzing folder
    subprocess.run(['git', 'clone', '--depth=1', '--filter=blob:none', '--sparse',
                    'https://github.com/danielmiessler/SecLists.git',
                    str(repo_dir)], capture_output=True)
    subprocess.run(['git', 'sparse-checkout', 'set', 'Fuzzing'], 
                   cwd=repo_dir, capture_output=True)
    
    return repo_dir


def extract_payloads(payloads_dir: Path) -> list[str]:
    """Extract attack payloads from PayloadsAllTheThings."""
    payloads = []
    
    # Key directories with attack payloads
    attack_dirs = [
        'SQL Injection',
        'XSS Injection', 
        'Command Injection',
        'Directory Traversal',
        'Server Side Request Forgery',
        'XXE Injection',
        'Server Side Template Injection',
        'NoSQL Injection',
    ]
    
    for attack_dir in attack_dirs:
        dir_path = payloads_dir / attack_dir
        if not dir_path.exists():
            continue
            
        # Find payload files
        for txt_file in dir_path.rglob('*.txt'):
            try:
                with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and len(line) > 3:
                            payloads.append(line)
            except Exception:
                pass
    
    return payloads


def extract_seclists(seclists_dir: Path) -> list[str]:
    """Extract payloads from SecLists Fuzzing."""
    payloads = []
    fuzzing_dir = seclists_dir / 'Fuzzing'
    
    if not fuzzing_dir.exists():
        return payloads
    
    # Key files
    key_files = [
        'SQLi',
        'XSS', 
        'command-injection',
        'LFI',
        'SSRF',
    ]
    
    for txt_file in fuzzing_dir.rglob('*.txt'):
        if any(k.lower() in txt_file.name.lower() for k in key_files):
            try:
                with open(txt_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and len(line) > 3:
                            payloads.append(line)
            except Exception:
                pass
    
    return payloads


def main():
    print("=" * 50)
    print("Dataset Downloader for Web Attack Detection")
    print("=" * 50)
    
    # Create directories
    DATA_DIR.mkdir(exist_ok=True)
    SAMPLES_DIR.mkdir(exist_ok=True)
    
    all_suspicious = []
    
    # 1. PayloadsAllTheThings
    try:
        payloads_dir = download_payloads_all_the_things()
        payloads = extract_payloads(payloads_dir)
        all_suspicious.extend(payloads)
        print(f"   ✅ Extracted {len(payloads)} payloads")
    except Exception as e:
        print(f"   ❌ Failed: {e}")
    
    # 2. SecLists
    try:
        seclists_dir = download_seclists()
        payloads = extract_seclists(seclists_dir)
        all_suspicious.extend(payloads)
        print(f"   ✅ Extracted {len(payloads)} payloads")
    except Exception as e:
        print(f"   ❌ Failed: {e}")
    
    # Deduplicate
    all_suspicious = list(set(all_suspicious))
    
    # Write to suspicious.txt
    output_file = SAMPLES_DIR / 'suspicious.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Auto-generated from PayloadsAllTheThings + SecLists\n")
        f.write(f"# Total: {len(all_suspicious)} unique payloads\n\n")
        for payload in all_suspicious:
            f.write(payload + '\n')
    
    print(f"\n✅ Written {len(all_suspicious)} payloads to {output_file}")
    
    # Cleanup temp repos
    print("\n🧹 Cleaning up temp repos...")
    import shutil
    for temp_dir in ['PayloadsAllTheThings', 'SecLists']:
        temp_path = DATA_DIR / temp_dir
        if temp_path.exists():
            shutil.rmtree(temp_path)
            print(f"   Deleted {temp_dir}/")
    print("   ✅ Cleanup done")
    
    print("\n" + "=" * 50)
    print("MANUAL STEPS REQUIRED:")
    print("=" * 50)
    print("""
1. Download Kaggle SQLi dataset:
   https://www.kaggle.com/datasets/ayahkhaldi/sql-injection-dataset
   
2. Download CSIC 2010 (optional, for safe requests):
   https://www.kaggle.com/datasets/ispabornikovic/http-dataset-csic-2010

3. Add to data/samples/safe.txt:
   - Your application access logs
   - Normal API requests from documentation
""")


if __name__ == '__main__':
    main()

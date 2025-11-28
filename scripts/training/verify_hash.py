#!/usr/bin/env python3
"""
Verify MurmurHash3 implementation matches between Python and TypeScript.

Run this script and compare output with TypeScript test results.

Usage:
    python verify_hash.py
"""

try:
    import mmh3
except ImportError:
    print("Installing mmh3...")
    import subprocess
    subprocess.run(['pip', 'install', 'mmh3'], check=True)
    import mmh3


def main():
    print("=== MurmurHash3 Verification ===\n")
    
    test_cases = [
        "",           # Empty string
        "hello",
        "test",
        "sql",
        " sq",        # Padded n-gram
        "sql",
        "ql ",        # Padded n-gram
        "SELECT",
        "你好",       # UTF-8 multibyte
        "SELECT * FROM users WHERE id=1",
    ]
    
    print("Copy these values to verify in TypeScript:\n")
    print("```typescript")
    print("const encoder = new TextEncoder();")
    print("const testCases = [")
    
    for text in test_cases:
        # mmh3.hash with signed=False returns unsigned 32-bit
        hash_value = mmh3.hash(text, 0, signed=False)
        print(f"  {{ text: {repr(text)}, expected: {hash_value} }},")
    
    print("];")
    print("")
    print("for (const tc of testCases) {")
    print("  const hash = murmurhash3_32(encoder.encode(tc.text), 0);")
    print("  console.log(`${tc.text}: ${hash} === ${tc.expected} ? ${hash === tc.expected}`);")
    print("}")
    print("```")
    
    print("\n\n=== Raw Values ===\n")
    for text in test_cases:
        hash_value = mmh3.hash(text, 0, signed=False)
        bytes_repr = list(text.encode('utf-8'))
        print(f"Text: {repr(text)}")
        print(f"  UTF-8 bytes: {bytes_repr}")
        print(f"  Hash: {hash_value}")
        print()


if __name__ == '__main__':
    main()

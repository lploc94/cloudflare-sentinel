/**
 * MurmurHash3 (x86_32) - Pure TypeScript implementation
 * 
 * Matches scikit-learn's HashingVectorizer exactly.
 * Reference: https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp
 */

/**
 * MurmurHash3 32-bit hash function
 * 
 * @param key - UTF-8 encoded bytes (Uint8Array)
 * @param seed - Hash seed (default: 0, matches sklearn)
 * @returns Unsigned 32-bit hash value
 */
export function murmurhash3_32(key: Uint8Array, seed: number = 0): number {
  const remainder = key.length & 3;
  const bytes = key.length - remainder;
  let h1 = seed;
  const c1 = 0xcc9e2d51;
  const c2 = 0x1b873593;
  let i = 0;
  let k1: number;

  // Process 4-byte chunks
  while (i < bytes) {
    k1 = 
      ((key[i] & 0xff)) |
      ((key[i + 1] & 0xff) << 8) |
      ((key[i + 2] & 0xff) << 16) |
      ((key[i + 3] & 0xff) << 24);
    i += 4;

    k1 = imul32(k1, c1);
    k1 = rotl32(k1, 15);
    k1 = imul32(k1, c2);

    h1 ^= k1;
    h1 = rotl32(h1, 13);
    h1 = imul32(h1, 5) + 0xe6546b64;
  }

  // Process remaining bytes
  k1 = 0;
  switch (remainder) {
    case 3:
      k1 ^= (key[i + 2] & 0xff) << 16;
    // falls through
    case 2:
      k1 ^= (key[i + 1] & 0xff) << 8;
    // falls through
    case 1:
      k1 ^= (key[i] & 0xff);
      k1 = imul32(k1, c1);
      k1 = rotl32(k1, 15);
      k1 = imul32(k1, c2);
      h1 ^= k1;
  }

  // Finalization
  h1 ^= key.length;
  h1 = fmix32(h1);

  // Return as unsigned 32-bit integer
  return h1 >>> 0;
}

/**
 * 32-bit multiplication (handles overflow correctly)
 */
function imul32(a: number, b: number): number {
  const aLo = a & 0xffff;
  const aHi = a >>> 16;
  const bLo = b & 0xffff;
  const bHi = b >>> 16;
  
  const lo = aLo * bLo;
  const mid = (aLo * bHi + aHi * bLo) & 0xffff;
  
  return ((lo + (mid << 16)) & 0xffffffff) >>> 0;
}

/**
 * 32-bit left rotation
 */
function rotl32(x: number, r: number): number {
  return ((x << r) | (x >>> (32 - r))) >>> 0;
}

/**
 * Final mix function
 */
function fmix32(h: number): number {
  h ^= h >>> 16;
  h = imul32(h, 0x85ebca6b);
  h ^= h >>> 13;
  h = imul32(h, 0xc2b2ae35);
  h ^= h >>> 16;
  return h >>> 0;
}

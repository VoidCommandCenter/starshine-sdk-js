/** `original / compressed` (e.g. 2.5 means the file shrank to ~40% before HPKE). */
export function compressionRatio(original: number, compressed: number): number {
  if (compressed <= 0) return 1;
  return original / compressed;
}

/** Aggregate stored bytes across all shards vs original plaintext size. */
export function storageMultiplier(original: number, stored: number): number {
  if (original <= 0) return Number.POSITIVE_INFINITY;
  return stored / original;
}

export function formatCompressionRatio(ratio: number): string {
  return `${ratio.toFixed(2)}×`;
}

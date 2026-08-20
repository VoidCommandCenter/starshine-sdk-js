import { bao } from "blake3-bao";

export function outboard(data: Uint8Array): {
  outboard: Uint8Array;
  topRoot: Uint8Array;
} {
  const { encoded, hash } = bao.baoEncode(data, true);
  return {
    outboard: new Uint8Array(encoded),
    topRoot: new Uint8Array(hash),
  };
}

/** BAO-commit concatenated sealed shards (index order) → global top_root + outboard. */
export function commitBlob(
  sealedShards: Uint8Array[],
  sealedShardSize: number,
): { outboard: Uint8Array; topRoot: Uint8Array } {
  const total = sealedShards.length * sealedShardSize;
  const concat = new Uint8Array(total);
  for (let i = 0; i < sealedShards.length; i++) {
    const shard = sealedShards[i]!;
    if (shard.length !== sealedShardSize) {
      throw new Error(
        `shard ${i} length ${shard.length} != expected ${sealedShardSize}`,
      );
    }
    concat.set(shard, i * sealedShardSize);
  }
  return outboard(concat);
}

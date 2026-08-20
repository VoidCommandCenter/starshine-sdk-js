import { COMPRESSION_CODEC_ZSTD, HPKE_INFO } from "./constants.js";
import { zstdCompress } from "./compress.js";
import { clientSeal } from "./hpke.js";
import { encodeRsShards } from "./reed-solomon.js";
import { sealingPct } from "./progress.js";
import {
  compressionRatio,
  formatCompressionRatio,
  storageMultiplier,
} from "./stats.js";
import type {
  BlobMeta,
  ProviderShard,
  ShardedBlob,
  StoredBlob,
  UploadProgressEvent,
} from "./types.js";
import type { ClientKeys } from "./keys.js";
import { encodeShard } from "./porepv2.js";
import { commitBlob } from "./bao.js";
import { sealedShardByteLen } from "./constants.js";
import { ciphertextDigest } from "./recovery.js";

export function makeProviderIds(n: number): Uint8Array[] {
  return Array.from({ length: n }, (_, i) =>
    new TextEncoder().encode(`starshine-api:node-${String(i).padStart(2, "0")}`),
  );
}

export async function uploadWithProgress(
  keys: ClientKeys,
  plaintext: Uint8Array,
  dataShards: number,
  parityShards: number,
  onProgress?: (event: UploadProgressEvent) => void,
): Promise<StoredBlob> {
  const totalShards = dataShards + parityShards;
  const report = (event: UploadProgressEvent) => onProgress?.(event);

  const providerIds = makeProviderIds(totalShards);
  const originalLen = plaintext.length;
  const compressed = await zstdCompress(plaintext);
  const ratio = compressionRatio(originalLen, compressed.length);
  report({
    phase: "zstd",
    pct: sealingPct("zstd", 0, totalShards),
    shards: totalShards,
    message: `zstd ${formatCompressionRatio(ratio)}${ratio > 1.01 ? ` (${originalLen} B → ${compressed.length} B)` : ""}`,
    original_bytes: originalLen,
    compressed_bytes: compressed.length,
    compression_ratio: ratio,
  });
  report({
    phase: "hpke",
    pct: sealingPct("hpke", 0, totalShards),
    shards: totalShards,
    message: "HPKE encrypting",
    original_bytes: originalLen,
    compressed_bytes: compressed.length,
    compression_ratio: ratio,
  });
  const payload = await clientSeal(compressed, keys.hpkePublicKey, HPKE_INFO);

  report({
    phase: "reed_solomon",
    pct: sealingPct("reed_solomon", 0, totalShards),
    shards: totalShards,
    message: "Reed–Solomon encoding",
  });

  const { shards: rsShards, rawShardSize } = encodeRsShards(
    payload.ciphertext,
    dataShards,
    parityShards,
  );

  const fileId = ciphertextDigest(payload.ciphertext);
  const sealedShardSize = sealedShardByteLen(rawShardSize);
  const sealedShards: Uint8Array[] = [];

  for (let i = 0; i < rsShards.length; i++) {
    report({
      phase: "porep_seal",
      pct: sealingPct("porep_seal", i, totalShards),
      shard: i,
      shards: totalShards,
      message: `PoRep sealing shard ${i + 1}/${totalShards}`,
    });
    sealedShards.push(
      encodeShard(
        rsShards[i]!,
        keys.porep.asBytes(),
        providerIds[i]!,
        fileId,
      ),
    );
    if (sealedShards[i]!.length !== sealedShardSize) {
      throw new Error(
        `sealed shard ${i} length ${sealedShards[i]!.length} != ${sealedShardSize}`,
      );
    }
  }

  const { outboard: globalOutboard, topRoot } = commitBlob(
    sealedShards,
    sealedShardSize,
  );

  const perShard = sealedShardSize + globalOutboard.length;
  const aggregate = perShard * totalShards;
  const mult = storageMultiplier(originalLen, aggregate);
  report({
    phase: "bao",
    pct: sealingPct("bao", 0, totalShards),
    shards: totalShards,
    message: `BAO complete: ${aggregate} B aggregate across ${totalShards} shards (${mult.toFixed(2)}× original plaintext; zstd ${formatCompressionRatio(ratio)})`,
    original_bytes: originalLen,
    compressed_bytes: compressed.length,
    compression_ratio: ratio,
    storage_multiplier: mult,
  });

  const providerShards: ProviderShard[] = sealedShards.map((sealed, i) => ({
    index: i,
    outboard: globalOutboard,
    data: sealed,
  }));

  const digest = ciphertextDigest(
    reconstructCiphertextFromRs(rsShards, dataShards, parityShards, payload.ciphertext.length),
  );

  const blob: ShardedBlob = {
    topRoot,
    shards: providerShards,
    encKey: payload.encKey,
    plaintextLen: originalLen,
    hpkePlaintextLen: payload.plaintextLen,
    compressionCodec: COMPRESSION_CODEC_ZSTD,
    ciphertextLen: payload.ciphertext.length,
    dataShards,
    parityShards,
    sealedShardSize,
    rawShardSize,
    fileId: digest,
    providerIds,
  };

  const meta: BlobMeta = {
    topRoot,
    encKey: payload.encKey,
    plaintextLen: originalLen,
    hpkePlaintextLen: payload.plaintextLen,
    compressionCodec: COMPRESSION_CODEC_ZSTD,
    ciphertextLen: payload.ciphertext.length,
    dataShards,
    parityShards,
    sealedShardSize,
    rawShardSize,
    providerIds,
    ciphertextDigest: digest,
  };

  report({
    phase: "done",
    pct: 100,
    shards: totalShards,
    message: `Sealed: ${aggregate} B aggregate (${mult.toFixed(2)}× original; zstd ${formatCompressionRatio(ratio)})`,
    original_bytes: originalLen,
    compressed_bytes: compressed.length,
    compression_ratio: ratio,
    storage_multiplier: mult,
  });

  return { meta, blob };
}

function reconstructCiphertextFromRs(
  rawShards: Uint8Array[],
  dataShards: number,
  _parityShards: number,
  ciphertextLen: number,
): Uint8Array {
  const out = new Uint8Array(dataShards * rawShards[0]!.length);
  for (let i = 0; i < dataShards; i++) {
    out.set(rawShards[i]!, i * rawShards[0]!.length);
  }
  return out.subarray(0, ciphertextLen);
}

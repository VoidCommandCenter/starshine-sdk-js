import { blake3 } from "blake3-bao";

import { COMPRESSION_CODEC_ZSTD, HPKE_INFO } from "./constants.js";
import { zstdDecompress } from "./compress.js";
import { clientOpenFull } from "./hpke.js";
import { downloadDecodePct } from "./progress.js";
import { compressionRatio, storageMultiplier } from "./stats.js";
import { reconstructCiphertext } from "./reed-solomon.js";
import type {
  DownloadProgressEvent,
  StoredBlob,
} from "./types.js";
import type { ClientKeys } from "./keys.js";
import { decodeShard } from "./porepv2.js";

/** In-memory recovery guard. Raise deliberately for trusted, very large workloads. */
export const DEFAULT_MAX_RECOVERED_BYTES = 1024 ** 3;

export function ciphertextDigest(ciphertext: Uint8Array): Uint8Array {
  return new Uint8Array(blake3.hash(ciphertext));
}

export async function recoverWithProgress(
  keys: ClientKeys,
  stored: StoredBlob,
  onProgress?: (event: DownloadProgressEvent) => void,
): Promise<Uint8Array> {
  const report = (event: DownloadProgressEvent) => onProgress?.(event);

  const maxRecoveredBytes = Number(
    process.env.STARSHINE_MAX_RECOVERED_BYTES ?? DEFAULT_MAX_RECOVERED_BYTES,
  );
  if (!Number.isSafeInteger(maxRecoveredBytes) || maxRecoveredBytes <= 0) {
    throw new Error("STARSHINE_MAX_RECOVERED_BYTES must be a positive integer");
  }
  if (stored.meta.plaintextLen > maxRecoveredBytes) {
    throw new Error(
      `declared plaintext length ${stored.meta.plaintextLen} exceeds recovery limit ${maxRecoveredBytes}`,
    );
  }
  if (
    stored.meta.hpkePlaintextLen != null &&
    stored.meta.hpkePlaintextLen > maxRecoveredBytes
  ) {
    throw new Error(
      `declared HPKE plaintext length ${stored.meta.hpkePlaintextLen} exceeds recovery limit ${maxRecoveredBytes}`,
    );
  }

  const total = stored.blob.shards.length;
  const slots: (Uint8Array | null)[] = Array.from(
    { length: stored.meta.dataShards + stored.meta.parityShards },
    () => null,
  );

  for (let seq = 0; seq < stored.blob.shards.length; seq++) {
    const shard = stored.blob.shards[seq]!;
    if (shard.index >= slots.length) {
      throw new Error(`shard index ${shard.index} out of range`);
    }
    const providerId = stored.meta.providerIds[shard.index];
    if (!providerId) {
      throw new Error(`missing provider_id for shard ${shard.index}`);
    }
    if (slots[shard.index] != null) {
      throw new Error(`duplicate shard index ${shard.index}`);
    }
    slots[shard.index] = decodeShard(
      shard.data,
      keys.porep.asBytes(),
      providerId,
      stored.meta.ciphertextDigest,
      stored.meta.rawShardSize,
    );
    report({
      phase: "porep_decode",
      pct: downloadDecodePct(seq + 1, total),
      shard: seq,
      shards: total,
      message: `Decoded shard ${seq + 1}/${total} (index ${shard.index})`,
    });
  }

  const k = stored.meta.dataShards;
  report({
    phase: "rs_reconstruct",
    pct: 88,
    shards: k,
    message: `Reconstructing Reed–Solomon ciphertext from ${k} data shards`,
  });

  const ciphertext = reconstructCiphertext(
    slots,
    stored.meta.dataShards,
    stored.meta.parityShards,
    stored.meta.ciphertextLen,
  );

  const zeroDigest = new Uint8Array(32);
  if (
    !buffersEqual(stored.meta.ciphertextDigest, zeroDigest) &&
    !buffersEqual(ciphertextDigest(ciphertext), stored.meta.ciphertextDigest)
  ) {
    throw new Error("reconstructed ciphertext digest mismatch");
  }

  const ratio =
    stored.meta.hpkePlaintextLen && stored.meta.hpkePlaintextLen > 0
      ? compressionRatio(stored.meta.plaintextLen, stored.meta.hpkePlaintextLen)
      : undefined;

  report({
    phase: "hpke_decrypt",
    pct: 92,
    message: "HPKE decrypting locally",
    original_bytes: stored.meta.plaintextLen,
    compressed_bytes: stored.meta.hpkePlaintextLen,
    compression_ratio: ratio,
  });

  const hpkeLen = stored.meta.hpkePlaintextLen ?? stored.meta.plaintextLen;
  const hpkeOut = await clientOpenFull(
    keys.hpkePrivateKey,
    stored.meta.encKey,
    ciphertext,
    HPKE_INFO,
    hpkeLen,
  );

  let plaintext: Uint8Array;
  if (stored.meta.compressionCodec === COMPRESSION_CODEC_ZSTD) {
    report({
      phase: "zstd_decompress",
      pct: 96,
      message: `zstd decompressing to ${stored.meta.plaintextLen} plaintext bytes${ratio != null ? ` (${ratio.toFixed(2)}×)` : ""}`,
      original_bytes: stored.meta.plaintextLen,
      compressed_bytes: stored.meta.hpkePlaintextLen,
      compression_ratio: ratio,
    });
    plaintext = await zstdDecompress(hpkeOut);
    if (plaintext.length !== stored.meta.plaintextLen) {
      throw new Error(
        `decompressed plaintext length ${plaintext.length} does not match declared length ${stored.meta.plaintextLen}`,
      );
    }
  } else {
    plaintext = hpkeOut;
    if (plaintext.length !== stored.meta.plaintextLen) {
      throw new Error(
        `plaintext length ${plaintext.length} does not match declared length ${stored.meta.plaintextLen}`,
      );
    }
  }

  const served = aggregateStoredServedBytes(stored);
  const storageMult = storageMultiplier(plaintext.length, served);
  report({
    phase: "done",
    pct: 100,
    message: `Recovered ${plaintext.length} plaintext bytes (served ${served} B aggregate shards, ${storageMult.toFixed(2)}× original${ratio != null ? `; zstd ${ratio.toFixed(2)}×` : ""})`,
    served_bytes: served,
    plaintext_len: plaintext.length,
    original_bytes: stored.meta.plaintextLen,
    compressed_bytes: stored.meta.hpkePlaintextLen,
    compression_ratio: ratio,
    storage_multiplier: storageMult,
  });

  return plaintext;
}

export function aggregateStoredServedBytes(stored: StoredBlob): number {
  return stored.blob.shards.reduce(
    (total, shard) => total + shard.data.length + shard.outboard.length,
    0,
  );
}

function buffersEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

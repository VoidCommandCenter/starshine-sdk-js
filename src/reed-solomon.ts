import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { ReedSolomonErasure } from "@digitaldefiance/reed-solomon-erasure.wasm";

/** Fresh WASM instance per call — the library singleton corrupts after reconstruct. */
function createReedSolomon(): ReedSolomonErasure {
  const here = dirname(fileURLToPath(import.meta.url));
  const wasmPath = join(
    here,
    "../node_modules/@digitaldefiance/reed-solomon-erasure.wasm/dist/reed_solomon_erasure_bg.wasm",
  );
  return ReedSolomonErasure.fromBytes(readFileSync(wasmPath));
}

export function encodeRsShards(
  ciphertext: Uint8Array,
  dataShards: number,
  parityShards: number,
): { shards: Uint8Array[]; rawShardSize: number } {
  if (dataShards === 0) {
    throw new Error("data_shards must be at least 1");
  }

  const k = dataShards;
  const m = parityShards;
  const rawShardSize = Math.ceil(ciphertext.length / k);
  const padded = new Uint8Array(rawShardSize * k);
  padded.set(ciphertext);

  const total = k + m;
  const flat = new Uint8Array(total * rawShardSize);
  for (let i = 0; i < k; i++) {
    flat.set(padded.subarray(i * rawShardSize, (i + 1) * rawShardSize), i * rawShardSize);
  }

  const rs = createReedSolomon();
  const code = rs.encode(flat, k, m);
  if (code !== ReedSolomonErasure.RESULT_OK) {
    throw new Error(
      `Reed–Solomon encode failed: ${ReedSolomonErasure.getResultMessage(code)}`,
    );
  }

  const shards: Uint8Array[] = [];
  for (let i = 0; i < total; i++) {
    shards.push(flat.subarray(i * rawShardSize, (i + 1) * rawShardSize));
  }
  return { shards, rawShardSize };
}

export function reconstructCiphertext(
  available: (Uint8Array | null)[],
  dataShards: number,
  parityShards: number,
  ciphertextLen: number,
): Uint8Array {
  if (dataShards === 0) {
    throw new Error("data_shards must be at least 1");
  }

  const expected = dataShards + parityShards;
  if (available.length !== expected) {
    throw new Error(
      `raw shards has ${available.length} entries, expected ${expected}`,
    );
  }

  const rawShardSize = available.find((s) => s !== null)?.length;
  if (!rawShardSize) {
    throw new Error("no shards available for reconstruction");
  }

  const flat = new Uint8Array(expected * rawShardSize);
  const flags: boolean[] = [];

  for (let i = 0; i < expected; i++) {
    const shard = available[i];
    if (shard) {
      if (shard.length !== rawShardSize) {
        throw new Error(`shard ${i} length ${shard.length} != ${rawShardSize}`);
      }
      flat.set(shard, i * rawShardSize);
      flags.push(true);
    } else {
      flags.push(false);
    }
  }

  const rs = createReedSolomon();
  const code = rs.reconstruct(flat, dataShards, parityShards, flags);
  if (code !== ReedSolomonErasure.RESULT_OK) {
    throw new Error(
      `Reed–Solomon reconstruct failed: ${ReedSolomonErasure.getResultMessage(code)}`,
    );
  }

  const out = new Uint8Array(dataShards * rawShardSize);
  for (let i = 0; i < dataShards; i++) {
    out.set(
      flat.subarray(i * rawShardSize, (i + 1) * rawShardSize),
      i * rawShardSize,
    );
  }
  return out.subarray(0, ciphertextLen);
}

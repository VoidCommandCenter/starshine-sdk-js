import { timingSafeEqual } from "node:crypto";

import { bao, blake3 } from "blake3-bao";

import { POREP_BLOCK_SIZE } from "./constants.js";
import type {
  PosChallengeResponse,
  PosProofWire,
  PublicBlobMetaWire,
} from "./grpc.js";

export interface PublicBlobMeta {
  topRoot: Uint8Array;
  plaintextLen: number;
  ciphertextLen: number;
  dataShards: number;
  parityShards: number;
  sealedShardSize: number;
  rawShardSize: number;
  providerIds: Uint8Array[];
  ciphertextDigest: Uint8Array;
}

export interface StorageAuditChallenge {
  topRoot: Uint8Array;
  shardIndex: number;
  totalShards: number;
  epoch: bigint;
  randomness: Uint8Array;
  blockIndices: number[];
  fileId: Uint8Array;
  providerId: Uint8Array;
}

export interface StorageAuditResponse {
  index: number;
  replicaBlock: Uint8Array;
  baoSlice: Uint8Array;
}

export interface StorageProof {
  challenge: StorageAuditChallenge;
  responses: StorageAuditResponse[];
}

function exactBytes(name: string, value: Uint8Array, length: number): Uint8Array {
  if (value.length !== length) {
    throw new Error(`${name} must be ${length} bytes, got ${value.length}`);
  }
  return new Uint8Array(value);
}

function safeInteger(name: string, value: number | string): number {
  const parsed = typeof value === "number" ? value : Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return parsed;
}

function positiveInteger(name: string, value: number | string): number {
  const parsed = safeInteger(name, value);
  if (parsed === 0) throw new Error(`${name} must be positive`);
  return parsed;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(Buffer.from(a), Buffer.from(b));
}

export function publicBlobMetaFromWire(meta: PublicBlobMetaWire): PublicBlobMeta {
  const dataShards = positiveInteger("data_shards", meta.data_shards);
  const parityShards = positiveInteger("parity_shards", meta.parity_shards);
  const totalShards = dataShards + parityShards;
  if (meta.provider_ids.length !== totalShards) {
    throw new Error(
      `provider_ids count ${meta.provider_ids.length} does not match total shards ${totalShards}`,
    );
  }
  const sealedShardSize = positiveInteger(
    "sealed_shard_size",
    meta.sealed_shard_size,
  );
  if (sealedShardSize % POREP_BLOCK_SIZE !== 0) {
    throw new Error(
      `sealed_shard_size must be a multiple of ${POREP_BLOCK_SIZE}`,
    );
  }
  return {
    topRoot: exactBytes("top_root", meta.top_root, 32),
    plaintextLen: safeInteger("plaintext_len", meta.plaintext_len),
    ciphertextLen: positiveInteger("ciphertext_len", meta.ciphertext_len),
    dataShards,
    parityShards,
    sealedShardSize,
    rawShardSize: positiveInteger("raw_shard_size", meta.raw_shard_size),
    providerIds: meta.provider_ids.map((id, index) => {
      if (id.length === 0) throw new Error(`provider_ids[${index}] is empty`);
      return new Uint8Array(id);
    }),
    ciphertextDigest: exactBytes(
      "ciphertext_digest",
      meta.ciphertext_digest,
      32,
    ),
  };
}

function proofFromWire(wire: PosProofWire): StorageProof {
  const challenge = wire.challenge;
  if (!challenge) throw new Error("PoS proof challenge is required");
  const epoch = BigInt(challenge.epoch);
  if (epoch < 0n || epoch > 0xffff_ffff_ffff_ffffn) {
    throw new Error("PoS epoch must fit uint64");
  }
  const blockIndices = challenge.block_indices.map((value, index) =>
    safeInteger(`block_indices[${index}]`, value),
  );
  if (blockIndices.length === 0) throw new Error("PoS challenge has no block indices");
  if (new Set(blockIndices).size !== blockIndices.length) {
    throw new Error("PoS challenge contains duplicate block indices");
  }
  return {
    challenge: {
      topRoot: exactBytes("challenge.top_root", challenge.top_root, 32),
      shardIndex: safeInteger("challenge.shard_index", challenge.shard_index),
      totalShards: positiveInteger(
        "challenge.total_shards",
        challenge.total_shards,
      ),
      epoch,
      randomness: exactBytes("challenge.randomness", challenge.randomness, 32),
      blockIndices,
      fileId: exactBytes("challenge.file_id", challenge.file_id, 32),
      providerId: (() => {
        if (challenge.provider_id.length === 0) {
          throw new Error("challenge.provider_id is empty");
        }
        return new Uint8Array(challenge.provider_id);
      })(),
    },
    responses: (wire.responses ?? []).map((response, index) => ({
      index: safeInteger(`responses[${index}].index`, response.index),
      replicaBlock: new Uint8Array(response.replica_block),
      baoSlice: new Uint8Array(response.bao_slice),
    })),
  };
}

export function storageProofFromWire(response: PosChallengeResponse): StorageProof {
  if (!response.proof) throw new Error("PosChallengeResponse.proof is required");
  return proofFromWire(response.proof);
}

function u64le(value: bigint): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, value, true);
  return out;
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function digestModulo(digest: Uint8Array, modulus: number): number {
  let value = 0n;
  for (const byte of digest) value = (value << 8n) | BigInt(byte);
  return Number(value % BigInt(modulus));
}

export function deriveChallengeIndices(
  meta: PublicBlobMeta,
  shardIndex: number,
  epoch: bigint,
  randomness: Uint8Array,
  count: number,
): number[] {
  const totalShards = meta.dataShards + meta.parityShards;
  if (!Number.isInteger(shardIndex) || shardIndex < 0 || shardIndex >= totalShards) {
    throw new Error(`shard index ${shardIndex} is out of range`);
  }
  exactBytes("randomness", randomness, 32);
  const numBlocks = meta.sealedShardSize / POREP_BLOCK_SIZE;
  if (!Number.isInteger(count) || count <= 0) {
    throw new Error("challenge count must be positive");
  }
  const target = Math.min(count, numBlocks);
  const providerId = meta.providerIds[shardIndex]!;
  const prefix = new TextEncoder().encode("PoRepV2:challenge:v1:");
  const indices = new Set<number>();

  for (let counter = 0n; indices.size < target; counter++) {
    if (counter > 1_000_000n) {
      throw new Error("could not sample enough unique challenge indices");
    }
    const digest = new Uint8Array(
      blake3.hash(
        concatBytes(
          prefix,
          meta.topRoot,
          meta.ciphertextDigest,
          providerId,
          u64le(BigInt(shardIndex)),
          u64le(epoch),
          randomness,
          u64le(counter),
        ),
      ),
    );
    indices.add(digestModulo(digest, numBlocks));
  }
  return [...indices].sort((a, b) => a - b);
}

export function verifyStorageProof(
  meta: PublicBlobMeta,
  proof: StorageProof,
): void {
  const challenge = proof.challenge;
  const totalShards = meta.dataShards + meta.parityShards;
  if (!bytesEqual(challenge.topRoot, meta.topRoot)) {
    throw new Error("PoS challenge top_root does not match public metadata");
  }
  if (!bytesEqual(challenge.fileId, meta.ciphertextDigest)) {
    throw new Error("PoS challenge file_id does not match public metadata");
  }
  if (challenge.totalShards !== totalShards) {
    throw new Error("PoS challenge total_shards does not match public metadata");
  }
  if (challenge.shardIndex >= totalShards) {
    throw new Error("PoS challenge shard_index is out of range");
  }
  if (!bytesEqual(challenge.providerId, meta.providerIds[challenge.shardIndex]!)) {
    throw new Error("PoS challenge provider_id does not match public metadata");
  }

  const expectedIndices = deriveChallengeIndices(
    meta,
    challenge.shardIndex,
    challenge.epoch,
    challenge.randomness,
    challenge.blockIndices.length,
  );
  const receivedIndices = [...challenge.blockIndices].sort((a, b) => a - b);
  if (expectedIndices.join(",") !== receivedIndices.join(",")) {
    throw new Error("PoS challenge indices do not match public derivation");
  }

  const responseIndices = proof.responses.map((response) => response.index).sort((a, b) => a - b);
  if (responseIndices.join(",") !== expectedIndices.join(",")) {
    throw new Error("PoS responses do not match challenged indices");
  }

  for (const response of proof.responses) {
    if (response.replicaBlock.length !== POREP_BLOCK_SIZE) {
      throw new Error(
        `PoS block ${response.index} has ${response.replicaBlock.length} bytes; expected ${POREP_BLOCK_SIZE}`,
      );
    }
    const globalOffset =
      challenge.shardIndex * meta.sealedShardSize +
      response.index * POREP_BLOCK_SIZE;
    let decoded: Uint8Array;
    try {
      decoded = new Uint8Array(
        bao.baoDecodeSlice(
          response.baoSlice,
          meta.topRoot,
          globalOffset,
          POREP_BLOCK_SIZE,
        ),
      );
    } catch {
      throw new Error(`PoS block ${response.index} has an invalid BAO proof`);
    }
    if (!bytesEqual(decoded, response.replicaBlock)) {
      throw new Error(`PoS block ${response.index} does not match its BAO proof`);
    }
  }
}

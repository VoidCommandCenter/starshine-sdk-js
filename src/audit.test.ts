import assert from "node:assert/strict";
import { test } from "node:test";

import { bao, blake3 } from "blake3-bao";

import {
  deriveChallengeIndices,
  verifyStorageProof,
  type PublicBlobMeta,
  type StorageProof,
} from "./audit.js";
import { commitBlob } from "./bao.js";
import { POREP_BLOCK_SIZE } from "./constants.js";

function fixture(): { meta: PublicBlobMeta; proof: StorageProof } {
  const sealedShardSize = POREP_BLOCK_SIZE * 4;
  const shards = [0x11, 0x22, 0x33].map(
    (byte) => new Uint8Array(sealedShardSize).fill(byte),
  );
  const { outboard, topRoot } = commitBlob(shards, sealedShardSize);
  const fullData = new Uint8Array(sealedShardSize * shards.length);
  shards.forEach((shard, index) => fullData.set(shard, index * sealedShardSize));
  const fileId = new Uint8Array(blake3.hash(new TextEncoder().encode("file-id")));
  const providerIds = ["alpha", "beta", "gamma"].map((id) =>
    new TextEncoder().encode(id),
  );
  const meta: PublicBlobMeta = {
    topRoot,
    plaintextLen: 2048,
    ciphertextLen: 3072,
    dataShards: 2,
    parityShards: 1,
    sealedShardSize,
    rawShardSize: 2048,
    providerIds,
    ciphertextDigest: fileId,
  };
  const shardIndex = 1;
  const epoch = 42n;
  const randomness = new Uint8Array(32).fill(0x44);
  const blockIndices = deriveChallengeIndices(
    meta,
    shardIndex,
    epoch,
    randomness,
    3,
  );
  const responses = blockIndices.map((index) => {
    const globalOffset = shardIndex * sealedShardSize + index * POREP_BLOCK_SIZE;
    return {
      index,
      replicaBlock: fullData.slice(globalOffset, globalOffset + POREP_BLOCK_SIZE),
      baoSlice: new Uint8Array(
        bao.baoSlice(outboard, globalOffset, POREP_BLOCK_SIZE, fullData),
      ),
    };
  });
  return {
    meta,
    proof: {
      challenge: {
        topRoot,
        shardIndex,
        totalShards: shards.length,
        epoch,
        randomness,
        blockIndices,
        fileId,
        providerId: providerIds[shardIndex]!,
      },
      responses,
    },
  };
}

test("public storage proof verifies without a client secret", () => {
  const { meta, proof } = fixture();
  assert.doesNotThrow(() => verifyStorageProof(meta, proof));
});

test("tampered storage proof is rejected", () => {
  const { meta, proof } = fixture();
  proof.responses[0]!.replicaBlock[0] ^= 0xff;
  assert.throws(() => verifyStorageProof(meta, proof), /does not match|invalid BAO/);
});

test("proof for another artifact is rejected", () => {
  const { meta, proof } = fixture();
  proof.challenge.topRoot = new Uint8Array(32).fill(0xff);
  assert.throws(() => verifyStorageProof(meta, proof), /top_root/);
});

import assert from "node:assert/strict";
import { test } from "node:test";

import type { GetResponse, ProviderShardWire } from "./grpc.js";
import { storedBlobFromGetResponse } from "./wire.js";

function shard(index: number): ProviderShardWire {
  return {
    index,
    outboard: Buffer.alloc(0),
    sealed_data: Buffer.alloc(1024, index),
  };
}

function response(shards: ProviderShardWire[]): GetResponse {
  return {
    meta: {
      top_root: Buffer.alloc(32, 1),
      enc_key: Buffer.alloc(32, 2),
      plaintext_len: 400,
      ciphertext_len: 500,
      data_shards: 1,
      parity_shards: 1,
      sealed_shard_size: 1024,
      raw_shard_size: 1024,
      provider_ids: [Buffer.from("provider-a"), Buffer.from("provider-b")],
      ciphertext_digest: Buffer.alloc(32, 3),
    },
    shards,
  };
}

test("valid metadata and a minimum shard set are accepted", () => {
  const stored = storedBlobFromGetResponse(response([shard(1)]));
  assert.equal(stored.blob.shards.length, 1);
});

test("duplicate shard indices are rejected", () => {
  assert.throws(
    () => storedBlobFromGetResponse(response([shard(0), shard(0)])),
    /duplicate shard index/,
  );
});

test("insufficient shards and unsafe numeric metadata are rejected", () => {
  assert.throws(
    () => storedBlobFromGetResponse(response([])),
    /required/,
  );
  const unsafe = response([shard(0)]);
  unsafe.meta!.plaintext_len = "9007199254740992";
  assert.throws(
    () => storedBlobFromGetResponse(unsafe),
    /safe integer/,
  );
});

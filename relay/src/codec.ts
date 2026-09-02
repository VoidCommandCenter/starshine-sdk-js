import type { StoredBlob } from "starshine-sdk-js";

export interface SerializedStoredBlob {
  meta: {
    topRoot: string;
    encKey: string;
    plaintextLen: number;
    hpkePlaintextLen?: number;
    compressionCodec?: string;
    ciphertextLen: number;
    dataShards: number;
    parityShards: number;
    sealedShardSize: number;
    rawShardSize: number;
    providerIds: string[];
    ciphertextDigest: string;
  };
  blob: {
    topRoot: string;
    shards: Array<{ index: number; outboard: string; data: string }>;
    encKey: string;
    plaintextLen: number;
    hpkePlaintextLen?: number;
    compressionCodec?: string;
    ciphertextLen: number;
    dataShards: number;
    parityShards: number;
    sealedShardSize: number;
    rawShardSize: number;
    fileId: string;
    providerIds: string[];
  };
}

export function serializeStoredBlob(stored: StoredBlob): SerializedStoredBlob {
  return {
    meta: {
      ...stored.meta,
      topRoot: encode(stored.meta.topRoot),
      encKey: encode(stored.meta.encKey),
      providerIds: stored.meta.providerIds.map(encode),
      ciphertextDigest: encode(stored.meta.ciphertextDigest),
    },
    blob: {
      ...stored.blob,
      topRoot: encode(stored.blob.topRoot),
      encKey: encode(stored.blob.encKey),
      fileId: encode(stored.blob.fileId),
      providerIds: stored.blob.providerIds.map(encode),
      shards: stored.blob.shards.map((shard) => ({
        index: shard.index,
        outboard: encode(shard.outboard),
        data: encode(shard.data),
      })),
    },
  };
}

export function deserializeStoredBlob(stored: SerializedStoredBlob): StoredBlob {
  return {
    meta: {
      ...stored.meta,
      topRoot: decode(stored.meta.topRoot),
      encKey: decode(stored.meta.encKey),
      providerIds: stored.meta.providerIds.map(decode),
      ciphertextDigest: decode(stored.meta.ciphertextDigest),
    },
    blob: {
      ...stored.blob,
      topRoot: decode(stored.blob.topRoot),
      encKey: decode(stored.blob.encKey),
      fileId: decode(stored.blob.fileId),
      providerIds: stored.blob.providerIds.map(decode),
      shards: stored.blob.shards.map((shard) => ({
        index: shard.index,
        outboard: decode(shard.outboard),
        data: decode(shard.data),
      })),
    },
  };
}

export function jsonForStorage(value: unknown): string {
  return JSON.stringify(value, (_key, entry: unknown) => {
    if (typeof entry === "bigint") return entry.toString();
    if (entry instanceof Uint8Array) return { base64url: encode(entry) };
    return entry;
  });
}

function encode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function decode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

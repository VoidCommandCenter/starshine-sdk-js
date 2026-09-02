import type { StoredBlob } from "./types.js";

export const SERIALIZED_STORED_BLOB_VERSION = "starshine.stored-blob.v1";

export interface SerializedStoredBlob {
  version: typeof SERIALIZED_STORED_BLOB_VERSION;
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

export interface DeserializeStoredBlobOptions {
  maxDecodedBytes?: number;
  allowedShardPolicies?: ReadonlySet<string>;
}

export function serializeStoredBlob(stored: StoredBlob): SerializedStoredBlob {
  return {
    version: SERIALIZED_STORED_BLOB_VERSION,
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

export function deserializeStoredBlob(
  value: SerializedStoredBlob,
  options: DeserializeStoredBlobOptions = {},
): StoredBlob {
  if (value.version !== SERIALIZED_STORED_BLOB_VERSION) {
    throw new Error(`stored blob version must be ${SERIALIZED_STORED_BLOB_VERSION}`);
  }
  const dataShards = positive("dataShards", value.meta.dataShards);
  const parityShards = positive("parityShards", value.meta.parityShards);
  const totalShards = dataShards + parityShards;
  if (totalShards > 255) throw new Error("total shard count exceeds 255");
  const policy = `${dataShards}+${parityShards}`;
  if (options.allowedShardPolicies && !options.allowedShardPolicies.has(policy)) {
    throw new Error(`shard policy ${policy} is not allowed`);
  }
  if (
    value.blob.dataShards !== dataShards ||
    value.blob.parityShards !== parityShards
  ) {
    throw new Error("blob shard policy does not match metadata");
  }
  if (value.meta.providerIds.length !== totalShards) {
    throw new Error("metadata provider count does not match total shards");
  }
  if (value.blob.providerIds.length !== totalShards) {
    throw new Error("blob provider count does not match total shards");
  }
  if (value.blob.shards.length < dataShards || value.blob.shards.length > totalShards) {
    throw new Error("serialized blob contains an invalid shard count");
  }

  const topRoot = fixed("meta.topRoot", value.meta.topRoot, 32);
  const blobRoot = fixed("blob.topRoot", value.blob.topRoot, 32);
  if (!equal(topRoot, blobRoot)) throw new Error("blob top root does not match metadata");
  const encKey = bounded("meta.encKey", value.meta.encKey, 1, 16 * 1024);
  const blobEncKey = bounded("blob.encKey", value.blob.encKey, 1, 16 * 1024);
  if (!equal(encKey, blobEncKey)) throw new Error("blob encapsulation does not match metadata");
  const ciphertextDigest = fixed("meta.ciphertextDigest", value.meta.ciphertextDigest, 32);
  const fileId = fixed("blob.fileId", value.blob.fileId, 32);
  if (!equal(ciphertextDigest, fileId)) throw new Error("file ID does not match ciphertext digest");

  const plaintextLen = nonnegative("plaintextLen", value.meta.plaintextLen);
  const ciphertextLen = positive("ciphertextLen", value.meta.ciphertextLen);
  const sealedShardSize = positive("sealedShardSize", value.meta.sealedShardSize);
  const rawShardSize = positive("rawShardSize", value.meta.rawShardSize);
  if (rawShardSize > sealedShardSize) throw new Error("raw shard size exceeds sealed shard size");
  if (ciphertextLen > dataShards * rawShardSize) {
    throw new Error("ciphertext length exceeds Reed-Solomon data capacity");
  }
  for (const field of [
    "plaintextLen",
    "hpkePlaintextLen",
    "ciphertextLen",
    "sealedShardSize",
    "rawShardSize",
  ] as const) {
    if (value.blob[field] !== value.meta[field]) {
      throw new Error(`blob ${field} does not match metadata`);
    }
  }
  if (value.blob.compressionCodec !== value.meta.compressionCodec) {
    throw new Error("blob compression codec does not match metadata");
  }
  if (
    value.meta.compressionCodec !== undefined &&
    (typeof value.meta.compressionCodec !== "string" || value.meta.compressionCodec.length > 64)
  ) {
    throw new Error("metadata compression codec is invalid");
  }

  const metaProviderIds = value.meta.providerIds.map((entry, index) =>
    bounded(`meta.providerIds[${index}]`, entry, 1, 1024)
  );
  const blobProviderIds = value.blob.providerIds.map((entry, index) =>
    bounded(`blob.providerIds[${index}]`, entry, 1, 1024)
  );
  metaProviderIds.forEach((entry, index) => {
    if (!equal(entry, blobProviderIds[index]!)) {
      throw new Error(`provider ID ${index} does not match metadata`);
    }
  });

  let decodedBytes = topRoot.length + blobRoot.length + encKey.length + blobEncKey.length;
  const seen = new Set<number>();
  const shards = value.blob.shards.map((shard, sequence) => {
    if (!Number.isInteger(shard.index) || shard.index < 0 || shard.index >= totalShards) {
      throw new Error(`shard index ${shard.index} is out of range`);
    }
    if (seen.has(shard.index)) throw new Error(`duplicate shard index ${shard.index}`);
    seen.add(shard.index);
    const outboard = bounded(`shards[${sequence}].outboard`, shard.outboard, 1, 64 * 1024 * 1024);
    const data = fixed(`shards[${sequence}].data`, shard.data, sealedShardSize);
    decodedBytes += outboard.length + data.length;
    return { index: shard.index, outboard, data };
  });
  if (
    options.maxDecodedBytes !== undefined &&
    decodedBytes > options.maxDecodedBytes
  ) {
    throw new Error(`decoded stored blob exceeds ${options.maxDecodedBytes} bytes`);
  }

  return {
    meta: {
      topRoot,
      encKey,
      plaintextLen,
      hpkePlaintextLen: optionalPositive("hpkePlaintextLen", value.meta.hpkePlaintextLen),
      compressionCodec: value.meta.compressionCodec,
      ciphertextLen,
      dataShards,
      parityShards,
      sealedShardSize,
      rawShardSize,
      providerIds: metaProviderIds,
      ciphertextDigest,
    },
    blob: {
      topRoot: blobRoot,
      shards,
      encKey: blobEncKey,
      plaintextLen,
      hpkePlaintextLen: optionalPositive("hpkePlaintextLen", value.blob.hpkePlaintextLen),
      compressionCodec: value.blob.compressionCodec,
      ciphertextLen,
      dataShards,
      parityShards,
      sealedShardSize,
      rawShardSize,
      fileId,
      providerIds: blobProviderIds,
    },
  };
}

function encode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function bounded(name: string, value: string, minimum: number, maximum: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${name} must be unpadded base64url`);
  }
  const decoded = new Uint8Array(Buffer.from(value, "base64url"));
  if (encode(decoded) !== value) throw new Error(`${name} is not canonical base64url`);
  if (decoded.length < minimum || decoded.length > maximum) {
    throw new Error(`${name} decoded length is invalid`);
  }
  return decoded;
}

function fixed(name: string, value: string, length: number): Uint8Array {
  return bounded(name, value, length, length);
}

function nonnegative(name: string, value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${name} must be a non-negative safe integer`);
  }
  return value;
}

function positive(name: string, value: number): number {
  const parsed = nonnegative(name, value);
  if (parsed === 0) throw new Error(`${name} must be positive`);
  return parsed;
}

function optionalPositive(name: string, value: number | undefined): number | undefined {
  return value === undefined ? undefined : positive(name, value);
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((byte, index) => byte === right[index]);
}

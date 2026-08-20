import type {
  BlobMetaWire,
  GetResponse,
  ProviderShardWire,
  PutRequest,
} from "./grpc.js";
import type { ProviderShard, StoredBlob } from "./types.js";

export function putRequestFromStored(stored: StoredBlob): PutRequest {
  return {
    meta: blobMetaToWire(stored.meta),
    shards: stored.blob.shards.map(providerShardToWire),
  };
}

export function storedBlobFromGetResponse(res: GetResponse): StoredBlob {
  if (!res.meta) {
    throw new Error("GetResponse.meta is required");
  }
  const meta = blobMetaFromWire(res.meta);
  const total = meta.dataShards + meta.parityShards;
  const shards = (res.shards ?? []).map(providerShardFromWire);
  shards.sort((a, b) => a.index - b.index);

  if (shards.length < meta.dataShards) {
    throw new Error(
      `response contains ${shards.length} shards; ${meta.dataShards} are required`,
    );
  }
  if (shards.length > total) {
    throw new Error(`response contains more shards than declared (${shards.length} > ${total})`);
  }

  const seen = new Set<number>();
  for (const shard of shards) {
    if (shard.index >= total) {
      throw new Error(`shard index ${shard.index} out of range (total ${total})`);
    }
    if (seen.has(shard.index)) {
      throw new Error(`duplicate shard index ${shard.index}`);
    }
    seen.add(shard.index);
    if (shard.data.length !== meta.sealedShardSize) {
      throw new Error(
        `shard ${shard.index} sealed length ${shard.data.length} != sealed_shard_size ${meta.sealedShardSize}`,
      );
    }
  }

  return {
    meta,
    blob: {
      topRoot: meta.topRoot,
      shards,
      encKey: meta.encKey,
      plaintextLen: meta.plaintextLen,
      hpkePlaintextLen: meta.hpkePlaintextLen,
      compressionCodec: meta.compressionCodec,
      ciphertextLen: meta.ciphertextLen,
      dataShards: meta.dataShards,
      parityShards: meta.parityShards,
      sealedShardSize: meta.sealedShardSize,
      rawShardSize: meta.rawShardSize,
      fileId: meta.ciphertextDigest,
      providerIds: meta.providerIds,
    },
  };
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

function blobMetaFromWire(m: BlobMetaWire) {
  if (m.top_root.length !== 32) {
    throw new Error(`top_root must be 32 bytes, got ${m.top_root.length}`);
  }
  const ciphertextDigest =
    m.ciphertext_digest.length === 0
      ? new Uint8Array(32)
      : parse32("ciphertext_digest", m.ciphertext_digest);

  if (m.enc_key.length === 0 || m.enc_key.length > 16 * 1024) {
    throw new Error(`enc_key length ${m.enc_key.length} is invalid`);
  }
  const plaintextLen = safeInteger("plaintext_len", m.plaintext_len);
  const ciphertextLen = positiveInteger("ciphertext_len", m.ciphertext_len);
  const dataShards = positiveInteger("data_shards", m.data_shards);
  const parityShards = positiveInteger("parity_shards", m.parity_shards);
  const totalShards = dataShards + parityShards;
  if (totalShards > 255) throw new Error("total shard count exceeds 255");
  const sealedShardSize = positiveInteger(
    "sealed_shard_size",
    m.sealed_shard_size,
  );
  const rawShardSize = positiveInteger("raw_shard_size", m.raw_shard_size);
  if (rawShardSize > sealedShardSize) {
    throw new Error("raw_shard_size exceeds sealed_shard_size");
  }
  if (ciphertextLen > dataShards * rawShardSize) {
    throw new Error("ciphertext_len exceeds the Reed-Solomon data capacity");
  }
  if (m.provider_ids.length !== totalShards) {
    throw new Error(
      `provider_ids count ${m.provider_ids.length} does not match total shards ${totalShards}`,
    );
  }
  for (const [index, id] of m.provider_ids.entries()) {
    if (id.length === 0 || id.length > 1024) {
      throw new Error(`provider_ids[${index}] length ${id.length} is invalid`);
    }
  }

  return {
    topRoot: new Uint8Array(m.top_root),
    encKey: new Uint8Array(m.enc_key),
    plaintextLen,
    ciphertextLen,
    dataShards,
    parityShards,
    sealedShardSize,
    rawShardSize,
    providerIds: m.provider_ids.map((id) => new Uint8Array(id)),
    ciphertextDigest,
    hpkePlaintextLen:
      m.hpke_plaintext_len && Number(m.hpke_plaintext_len) > 0
        ? positiveInteger("hpke_plaintext_len", m.hpke_plaintext_len)
        : undefined,
    compressionCodec: m.compression_codec || undefined,
  };
}

function blobMetaToWire(m: StoredBlob["meta"]): BlobMetaWire {
  return {
    top_root: Buffer.from(m.topRoot),
    enc_key: Buffer.from(m.encKey),
    plaintext_len: m.plaintextLen,
    ciphertext_len: m.ciphertextLen,
    data_shards: m.dataShards,
    parity_shards: m.parityShards,
    sealed_shard_size: m.sealedShardSize,
    raw_shard_size: m.rawShardSize,
    provider_ids: m.providerIds.map((id) => Buffer.from(id)),
    ciphertext_digest: Buffer.from(m.ciphertextDigest),
    hpke_plaintext_len: m.hpkePlaintextLen ?? 0,
    compression_codec: m.compressionCodec ?? "",
  };
}

function providerShardFromWire(s: ProviderShardWire): ProviderShard {
  return {
    index: Number(s.index),
    outboard: new Uint8Array(s.outboard),
    data: new Uint8Array(s.sealed_data),
  };
}

function providerShardToWire(s: ProviderShard): ProviderShardWire {
  return {
    index: s.index,
    outboard: Buffer.from(s.outboard),
    sealed_data: Buffer.from(s.data),
  };
}

function parse32(field: string, bytes: Buffer | Uint8Array): Uint8Array {
  if (bytes.length !== 32) {
    throw new Error(`${field} must be 32 bytes, got ${bytes.length}`);
  }
  return new Uint8Array(bytes);
}

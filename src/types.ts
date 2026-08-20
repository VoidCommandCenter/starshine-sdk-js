export interface ProviderShard {
  index: number;
  outboard: Uint8Array;
  data: Uint8Array;
}

export interface ShardedBlob {
  topRoot: Uint8Array;
  shards: ProviderShard[];
  encKey: Uint8Array;
  plaintextLen: number;
  hpkePlaintextLen?: number;
  compressionCodec?: string;
  ciphertextLen: number;
  dataShards: number;
  parityShards: number;
  sealedShardSize: number;
  rawShardSize: number;
  fileId: Uint8Array;
  providerIds: Uint8Array[];
}

export interface BlobMeta {
  topRoot: Uint8Array;
  encKey: Uint8Array;
  /** Original decompressed file size (user-facing). */
  plaintextLen: number;
  /** HPKE plaintext length when compression is enabled. */
  hpkePlaintextLen?: number;
  /** Compression codec applied before HPKE seal (e.g. `"zstd"`). */
  compressionCodec?: string;
  ciphertextLen: number;
  dataShards: number;
  parityShards: number;
  sealedShardSize: number;
  rawShardSize: number;
  providerIds: Uint8Array[];
  ciphertextDigest: Uint8Array;
}

export interface StoredBlob {
  meta: BlobMeta;
  blob: ShardedBlob;
}

export interface EncryptedPayload {
  encKey: Uint8Array;
  ciphertext: Uint8Array;
  plaintextLen: number;
}

export type UploadPhase =
  | "zstd"
  | "hpke"
  | "reed_solomon"
  | "porep_seal"
  | "bao"
  | "grpc_put"
  | "done";

export type DownloadPhase =
  | "grpc_get"
  | "shard_download"
  | "porep_decode"
  | "rs_reconstruct"
  | "hpke_decrypt"
  | "zstd_decompress"
  | "done";

export interface UploadProgressEvent {
  phase: UploadPhase;
  pct: number;
  shard?: number;
  shards?: number;
  message?: string;
  original_bytes?: number;
  compressed_bytes?: number;
  compression_ratio?: number;
  storage_multiplier?: number;
}

export interface DownloadProgressEvent {
  phase: DownloadPhase;
  pct: number;
  shard?: number;
  shards?: number;
  message?: string;
  served_bytes?: number;
  plaintext_len?: number;
  original_bytes?: number;
  compressed_bytes?: number;
  compression_ratio?: number;
  storage_multiplier?: number;
}

/** Plaintext bytes per encryption chunk. */
export const CHUNK_PT = 1024;

/** Ciphertext bytes per chunk: plaintext + 16-byte GCM tag. */
export const CHUNK_CT = CHUNK_PT + 16;

/** BAO chunk size (bytes) — PoRep-v2 blocks use the same size. */
export const BAO_CHUNK = 1024;

/** PoRep-v2 block size (matches [`BAO_CHUNK`]). */
export const POREP_BLOCK_SIZE = BAO_CHUNK;

/** HPKE `info` — binds the KDF/AEAD context to protocol v4. */
export const HPKE_INFO = new TextEncoder().encode("por-v4-starshine");

/** Codec stored in blob metadata when plaintext is zstd-compressed before HPKE seal. */
export const COMPRESSION_CODEC_ZSTD = "zstd";

/** Default zstd compression level. */
export const ZSTD_LEVEL = 3;

export const DEFAULT_KEYS_PATH = "keys.json";
/** Public Railway gRPC endpoint (plain HTTP/2, no TLS). Override with STARSHINE_SERVER. */
export const DEFAULT_SERVER = "http://maglev.proxy.rlwy.net:27561";
export const DEFAULT_DATA_SHARDS = 4;
export const DEFAULT_PARITY_SHARDS = 2;

/** Faucet credit per successful Void.Faucet claim. */
export const FAUCET_VOID_AMOUNT = 100_000_000;

/** Prefix for one JSON progress object per line on stderr. */
export const PROGRESS_LINE_PREFIX = "@starshine/progress\t";

export function replicaShardByteLen(rawShardSize: number): number {
  return Math.ceil(rawShardSize / POREP_BLOCK_SIZE) * POREP_BLOCK_SIZE;
}

/** Alias retained for blob metadata field naming. */
export function sealedShardByteLen(rawShardSize: number): number {
  return replicaShardByteLen(rawShardSize);
}

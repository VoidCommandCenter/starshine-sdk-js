import {
  deleteRequest,
  getPublicMetaRequest,
  getRequest,
  getStorageClient,
  posChallengeRequest,
  putRequest,
  putRequestWireBytes,
  type UnaryRequestOptions,
  type VoidEnvelopeWire,
  type VoidReceiptWire,
} from "./grpc.js";
import {
  publicBlobMetaFromWire,
  storageProofFromWire,
  type PublicBlobMeta,
  type StorageProof,
} from "./audit.js";
import type { TransportOptions } from "./transport.js";
import { putRequestFromStored, storedBlobFromGetResponse } from "./wire.js";
import type { StoredBlob } from "./types.js";

export interface BlobLedgerOptions {
  envelope?: VoidEnvelopeWire;
  fileName?: string;
  expectedVoid?: number;
  transport?: TransportOptions;
  rpc?: UnaryRequestOptions;
}

export interface PutBlobResult {
  contentHash: Uint8Array;
  ledger?: VoidReceiptWire;
}

function grpcMessageLimit(): number {
  const raw = process.env.STARSHINE_MAX_PUT_BYTES?.trim() || "1GiB";
  const parsed = parseByteSize(raw);
  return parsed ?? 100 * 1024 * 1024;
}

function parseByteSize(input: string): number | null {
  const compact = input.replace(/\s+/g, "");
  const match = /^([\d._]+)(.*)$/i.exec(compact);
  if (!match) return null;
  const value = Number.parseFloat(match[1]!.replace(/_/g, ""));
  if (!Number.isFinite(value) || value < 0) return null;
  const suffix = match[2]!.toLowerCase();
  const kib = 1024;
  const mult: Record<string, number> = {
    "": 1,
    b: 1,
    k: kib,
    kb: kib,
    kib: kib,
    m: kib ** 2,
    mb: kib ** 2,
    mib: kib ** 2,
    g: kib ** 3,
    gb: kib ** 3,
    gib: kib ** 3,
  };
  const multiplier = mult[suffix];
  if (multiplier == null) return null;
  return Math.round(value * multiplier);
}

export async function putBlob(
  endpoint: string,
  stored: StoredBlob,
  options: BlobLedgerOptions = {},
): Promise<Uint8Array> {
  const result = await putBlobResult(endpoint, stored, options);
  return result.contentHash;
}

export async function putBlobResult(
  endpoint: string,
  stored: StoredBlob,
  options: BlobLedgerOptions = {},
): Promise<PutBlobResult> {
  const req = {
    ...putRequestFromStored(stored),
    envelope: options.envelope,
    file_name: options.fileName ?? "",
    expected_void: options.expectedVoid ?? 0,
  };
  const wireBytes = putRequestWireBytes(req);
  const limit = grpcMessageLimit();
  if (wireBytes > limit) {
    throw new Error(
      `payload too large: ${wireBytes} bytes exceeds limit ${limit}`,
    );
  }

  const client = getStorageClient(endpoint, options.transport);
  const response = await putRequest(client, req, options.rpc);
  if (response.content_hash.length !== 32) {
    throw new Error(
      `server returned content_hash len ${response.content_hash.length}, expected 32`,
    );
  }
  return {
    contentHash: new Uint8Array(response.content_hash),
    ledger: response.ledger,
  };
}

export interface GetBlobResult {
  stored: StoredBlob;
  ledger?: VoidReceiptWire;
}

export async function getBlob(
  endpoint: string,
  contentHash: Uint8Array,
  options: BlobLedgerOptions = {},
): Promise<StoredBlob> {
  const result = await getBlobResult(endpoint, contentHash, options);
  return result.stored;
}

export async function getBlobMinimumShards(
  endpoint: string,
  contentHash: Uint8Array,
  options: BlobLedgerOptions = {},
): Promise<StoredBlob> {
  const result = await getBlobResult(endpoint, contentHash, {
    ...options,
    minimumShards: true,
  });
  return result.stored;
}

export async function getBlobResult(
  endpoint: string,
  contentHash: Uint8Array,
  options: BlobLedgerOptions & { minimumShards?: boolean } = {},
): Promise<GetBlobResult> {
  return getBlobWithOptions(
    endpoint,
    contentHash,
    0,
    options.minimumShards ?? false,
    options,
  );
}

export async function deleteBlob(
  endpoint: string,
  contentHash: Uint8Array,
  options: BlobLedgerOptions = {},
): Promise<{ ledger?: VoidReceiptWire }> {
  const client = getStorageClient(endpoint, options.transport);
  const response = await deleteRequest(client, Buffer.from(contentHash), {
    envelope: options.envelope,
    fileName: options.fileName,
    ...options.rpc,
  });
  if (!response.deleted) {
    throw new Error("server did not confirm deletion");
  }
  if (!Buffer.from(response.content_hash).equals(Buffer.from(contentHash))) {
    throw new Error("server returned mismatched deleted content hash");
  }
  return { ledger: response.ledger };
}

async function getBlobWithOptions(
  endpoint: string,
  contentHash: Uint8Array,
  shardCount: number,
  minimumShards: boolean,
  options: BlobLedgerOptions = {},
): Promise<GetBlobResult> {
  const client = getStorageClient(endpoint, options.transport);
  const response = await getRequest(client, Buffer.from(contentHash), {
    shardCount,
    minimumShards,
    envelope: options.envelope,
    fileName: options.fileName,
    ...options.rpc,
  });
  if (!response.meta) throw new Error("GetResponse.meta is required");
  if (!Buffer.from(response.meta.top_root).equals(Buffer.from(contentHash))) {
    throw new Error("server returned metadata for a different content hash");
  }
  return {
    stored: storedBlobFromGetResponse(response),
    ledger: response.ledger,
  };
}

export async function getPublicBlobMeta(
  endpoint: string,
  contentHash: Uint8Array,
  options: Pick<BlobLedgerOptions, "transport" | "rpc"> = {},
): Promise<PublicBlobMeta> {
  const client = getStorageClient(endpoint, options.transport);
  const response = await getPublicMetaRequest(
    client,
    Buffer.from(contentHash),
    options.rpc,
  );
  if (!response.meta) throw new Error("GetPublicMetaResponse.meta is required");
  const meta = publicBlobMetaFromWire(response.meta);
  if (!Buffer.from(meta.topRoot).equals(Buffer.from(contentHash))) {
    throw new Error("server returned public metadata for a different content hash");
  }
  return meta;
}

export async function requestStorageProof(
  endpoint: string,
  contentHash: Uint8Array,
  shardIndex: number,
  epoch: bigint,
  randomness: Uint8Array,
  options: Pick<BlobLedgerOptions, "transport" | "rpc"> = {},
): Promise<StorageProof> {
  if (!Number.isInteger(shardIndex) || shardIndex < 0) {
    throw new Error("shardIndex must be a non-negative integer");
  }
  if (epoch < 0n || epoch > 0xffff_ffff_ffff_ffffn) {
    throw new Error("epoch must fit uint64");
  }
  if (randomness.length !== 32) {
    throw new Error(`randomness must be 32 bytes, got ${randomness.length}`);
  }
  const client = getStorageClient(endpoint, options.transport);
  const response = await posChallengeRequest(
    client,
    {
      content_hash: Buffer.from(contentHash),
      shard_index: shardIndex,
      epoch: epoch.toString(),
      randomness: Buffer.from(randomness),
    },
    options.rpc,
  );
  const proof = storageProofFromWire(response);
  if (!Buffer.from(proof.challenge.topRoot).equals(Buffer.from(contentHash))) {
    throw new Error("server returned a PoS proof for a different content hash");
  }
  return proof;
}

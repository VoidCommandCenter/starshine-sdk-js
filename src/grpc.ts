import path from "node:path";
import { fileURLToPath } from "node:url";

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

import {
  createChannelCredentials,
  parseEndpoint as parseTransportEndpoint,
  transportCacheKey,
  type TransportOptions,
} from "./transport.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

export const DEFAULT_MAX_PUT_BYTES = "1GiB";
export const DEFAULT_RPC_TIMEOUT_MS = 30_000;

export interface UnaryRequestOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
}

export interface StorageClient {
  put(
    request: PutRequest,
    options: grpc.CallOptions,
    callback: (error: grpc.ServiceError | null, response: PutResponse) => void,
  ): grpc.ClientUnaryCall;
  get(
    request: GetRequest,
    options: grpc.CallOptions,
    callback: (error: grpc.ServiceError | null, response: GetResponse) => void,
  ): grpc.ClientUnaryCall;
  delete(
    request: DeleteRequest,
    options: grpc.CallOptions,
    callback: (
      error: grpc.ServiceError | null,
      response: DeleteResponse,
    ) => void,
  ): grpc.ClientUnaryCall;
  getPublicMeta(
    request: GetPublicMetaRequest,
    options: grpc.CallOptions,
    callback: (
      error: grpc.ServiceError | null,
      response: GetPublicMetaResponse,
    ) => void,
  ): grpc.ClientUnaryCall;
  posChallenge(
    request: PosChallengeRequest,
    options: grpc.CallOptions,
    callback: (
      error: grpc.ServiceError | null,
      response: PosChallengeResponse,
    ) => void,
  ): grpc.ClientUnaryCall;
}

export interface PutRequest {
  meta?: BlobMetaWire;
  shards?: ProviderShardWire[];
  envelope?: VoidEnvelopeWire;
  file_name?: string;
  expected_void?: number;
}

export interface PutResponse {
  content_hash: Buffer;
  ledger?: VoidReceiptWire;
}

export interface GetRequest {
  content_hash: Buffer;
  shard_count?: number;
  minimum_shards?: boolean;
  envelope?: VoidEnvelopeWire;
  file_name?: string;
}

export interface GetResponse {
  meta?: BlobMetaWire;
  shards?: ProviderShardWire[];
  ledger?: VoidReceiptWire;
}

export interface DeleteRequest {
  content_hash: Buffer;
  envelope?: VoidEnvelopeWire;
  file_name?: string;
}

export interface DeleteResponse {
  content_hash: Buffer;
  deleted: boolean;
  ledger?: VoidReceiptWire;
}

export interface PublicBlobMetaWire {
  top_root: Buffer;
  plaintext_len: number | string;
  ciphertext_len: number;
  data_shards: number;
  parity_shards: number;
  sealed_shard_size: number;
  raw_shard_size: number;
  provider_ids: Buffer[];
  ciphertext_digest: Buffer;
}

export interface GetPublicMetaRequest {
  content_hash: Buffer;
}

export interface GetPublicMetaResponse {
  meta?: PublicBlobMetaWire;
}

export interface PosChallengeRequest {
  content_hash: Buffer;
  shard_index: number;
  epoch: number | string;
  randomness: Buffer;
}

export interface PosChallengeWire {
  top_root: Buffer;
  shard_index: number;
  total_shards: number;
  epoch: number | string;
  randomness: Buffer;
  block_indices: number[];
  file_id: Buffer;
  provider_id: Buffer;
}

export interface PosAuditResponseWire {
  index: number;
  replica_block: Buffer;
  bao_slice: Buffer;
}

export interface PosProofWire {
  challenge?: PosChallengeWire;
  responses: PosAuditResponseWire[];
}

export interface PosChallengeResponse {
  proof?: PosProofWire;
}

export interface VoidEnvelopeWire {
  v: number;
  kind: string;
  from_hpke: string;
  to_hpke: string;
  amount: number;
  content_hash: string;
  nonce: string;
  issued_at: string;
  mldsa_public_key_hex: string;
  signature_hex: string;
}

export interface VoidClient {
  getAccount(
    request: { hpke_public_key: string },
    options: grpc.CallOptions,
    callback: (error: grpc.ServiceError | null, response: VoidAccountWire) => void,
  ): grpc.ClientUnaryCall;
  listTransactions(
    request: { limit: number },
    options: grpc.CallOptions,
    callback: (
      error: grpc.ServiceError | null,
      response: { transactions: VoidTransactionWire[] },
    ) => void,
  ): grpc.ClientUnaryCall;
  faucet(
    request: VoidEnvelopeWire,
    options: grpc.CallOptions,
    callback: (error: grpc.ServiceError | null, response: VoidAccountWire) => void,
  ): grpc.ClientUnaryCall;
  transfer(
    request: VoidEnvelopeWire,
    options: grpc.CallOptions,
    callback: (error: grpc.ServiceError | null, response: VoidAccountWire) => void,
  ): grpc.ClientUnaryCall;
}

export interface VoidReceiptWire {
  balance: number | string;
  tx_id: string;
  amount: number | string;
}

export interface VoidTransactionWire {
  id: string;
  kind: string;
  status: string;
  from_public_key: string;
  to_public_key: string;
  amount: number | string;
  shard_bytes: number | string;
  content_hash: string;
  file_name: string;
  plaintext_bytes: number | string;
  message: string;
  created_at: string;
  signature: string;
  mldsa_public_key: string;
  nonce: string;
  payload_hash: string;
}

export interface VoidAccountWire {
  public_key: string;
  balance: number | string;
  created_at: string;
  faucet_amount: number | string;
  transactions: VoidTransactionWire[];
}

export interface BlobMetaWire {
  top_root: Buffer;
  enc_key: Buffer;
  plaintext_len: number | string;
  ciphertext_len: number;
  data_shards: number;
  parity_shards: number;
  sealed_shard_size: number;
  raw_shard_size: number;
  provider_ids: Buffer[];
  ciphertext_digest: Buffer;
  hpke_plaintext_len?: number | string;
  compression_codec?: string;
}

export interface ProviderShardWire {
  index: number;
  outboard: Buffer;
  sealed_data: Buffer;
}

interface LoadedClients {
  storage: StorageClient;
  void: VoidClient;
}

const clientCache = new Map<string, LoadedClients>();

function grpcMessageLimit(): number {
  const raw =
    process.env.STARSHINE_MAX_PUT_BYTES?.trim() || DEFAULT_MAX_PUT_BYTES;
  const parsed = parseByteSize(raw);
  return parsed ?? parseByteSize(DEFAULT_MAX_PUT_BYTES)!;
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
    byte: 1,
    bytes: 1,
    k: kib,
    kb: kib,
    kib: kib,
    m: kib ** 2,
    mb: kib ** 2,
    mib: kib ** 2,
    g: kib ** 3,
    gb: kib ** 3,
    gib: kib ** 3,
    t: kib ** 4,
    tb: kib ** 4,
    tib: kib ** 4,
  };
  const multiplier = mult[suffix];
  if (multiplier == null) return null;
  const bytes = Math.round(value * multiplier);
  return bytes >= 1 ? bytes : null;
}

const PROTO_PATH = path.resolve(
  __dirname,
  "../proto/starshine/v1/storage.proto",
);

function loadPackage(
  endpoint: string,
  transport: TransportOptions = {},
): LoadedClients {
  const packageDefinition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: String,
    defaults: true,
    oneofs: true,
  });
  const proto = grpc.loadPackageDefinition(packageDefinition) as unknown as {
    starshine: {
      v1: {
        Storage: new (
          addr: string,
          creds: grpc.ChannelCredentials,
          options?: Record<string, number>,
        ) => StorageClient;
        Void: new (
          addr: string,
          creds: grpc.ChannelCredentials,
          options?: Record<string, number>,
        ) => VoidClient;
      };
    };
  };
  const parsed = parseTransportEndpoint(endpoint, transport);
  const limit = grpcMessageLimit();
  const creds = createChannelCredentials(parsed, transport);
  const options = {
    "grpc.max_receive_message_length": limit,
    "grpc.max_send_message_length": limit,
  };
  return {
    storage: new proto.starshine.v1.Storage(parsed.address, creds, options),
    void: new proto.starshine.v1.Void(parsed.address, creds, options),
  };
}

function getClients(endpoint: string, transport: TransportOptions = {}): LoadedClients {
  const key = transportCacheKey(endpoint, transport);
  const cached = clientCache.get(key);
  if (cached) return cached;
  const loaded = loadPackage(endpoint, transport);
  clientCache.set(key, loaded);
  return loaded;
}

export function getStorageClient(
  endpoint: string,
  transport: TransportOptions = {},
): StorageClient {
  return getClients(endpoint, transport).storage;
}

export function getVoidClient(
  endpoint: string,
  transport: TransportOptions = {},
): VoidClient {
  return getClients(endpoint, transport).void;
}

export { parseTransportEndpoint as parseEndpoint };

function grpcCallOptions(options: UnaryRequestOptions = {}): grpc.CallOptions {
  const timeoutMs = options.timeoutMs ?? DEFAULT_RPC_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) {
    throw new Error("RPC timeoutMs must be a positive number");
  }
  return { deadline: Date.now() + timeoutMs };
}

export function unaryRequest<T>(
  start: (
    options: grpc.CallOptions,
    callback: (error: grpc.ServiceError | null, response: T) => void,
  ) => grpc.ClientUnaryCall,
  options: UnaryRequestOptions = {},
): Promise<T> {
  return new Promise((resolve, reject) => {
    if (options.signal?.aborted) {
      reject(options.signal.reason ?? new Error("request aborted"));
      return;
    }
    let settled = false;
    const call = start(grpcCallOptions(options), (error, response) => {
      if (settled) return;
      settled = true;
      options.signal?.removeEventListener("abort", onAbort);
      if (error) reject(error);
      else resolve(response);
    });
    const onAbort = () => {
      if (settled) return;
      settled = true;
      call.cancel();
      reject(options.signal?.reason ?? new Error("request aborted"));
    };
    options.signal?.addEventListener("abort", onAbort, { once: true });
  });
}

export function putRequest(
  client: StorageClient,
  request: PutRequest,
  options: UnaryRequestOptions = {},
): Promise<PutResponse> {
  return unaryRequest((callOptions, callback) =>
    client.put(request, callOptions, callback), options);
}

export function getRequest(
  client: StorageClient,
  contentHash: Buffer,
  options: {
    shardCount?: number;
    minimumShards?: boolean;
    envelope?: VoidEnvelopeWire;
    fileName?: string;
  } & UnaryRequestOptions = {},
): Promise<GetResponse> {
  return unaryRequest((callOptions, callback) =>
    client.get(
      {
        content_hash: contentHash,
        shard_count: options.shardCount ?? 0,
        minimum_shards: options.minimumShards ?? false,
        envelope: options.envelope,
        file_name: options.fileName,
      },
      callOptions,
      callback,
    ), options);
}

export function deleteRequest(
  client: StorageClient,
  contentHash: Buffer,
  options: {
    envelope?: VoidEnvelopeWire;
    fileName?: string;
  } & UnaryRequestOptions = {},
): Promise<DeleteResponse> {
  return unaryRequest((callOptions, callback) =>
    client.delete(
      {
        content_hash: contentHash,
        envelope: options.envelope,
        file_name: options.fileName,
      },
      callOptions,
      callback,
    ), options);
}

export function getPublicMetaRequest(
  client: StorageClient,
  contentHash: Buffer,
  options: UnaryRequestOptions = {},
): Promise<GetPublicMetaResponse> {
  return unaryRequest((callOptions, callback) =>
    client.getPublicMeta(
      { content_hash: contentHash },
      callOptions,
      callback,
    ), options);
}

export function posChallengeRequest(
  client: StorageClient,
  request: PosChallengeRequest,
  options: UnaryRequestOptions = {},
): Promise<PosChallengeResponse> {
  return unaryRequest((callOptions, callback) =>
    client.posChallenge(request, callOptions, callback), options);
}

export function putRequestWireBytes(req: PutRequest): number {
  let n = 0;
  if (req.meta) {
    n += req.meta.top_root.length;
    n += req.meta.enc_key.length;
    n += req.meta.ciphertext_digest.length;
    for (const id of req.meta.provider_ids) n += id.length;
  }
  for (const shard of req.shards ?? []) {
    n += shard.outboard.length;
    n += shard.sealed_data.length;
  }
  return n;
}

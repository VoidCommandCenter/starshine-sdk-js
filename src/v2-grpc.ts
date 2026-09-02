import path from "node:path";
import { fileURLToPath } from "node:url";

import * as grpc from "@grpc/grpc-js";
import * as protoLoader from "@grpc/proto-loader";

import {
  createChannelCredentials,
  parseEndpoint,
  transportCacheKey,
  type TransportOptions,
} from "./transport.js";
import {
  DEFAULT_MAX_PUT_BYTES,
  unaryRequest,
  type UnaryRequestOptions,
} from "./grpc.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PROTO_PATH = path.resolve(
  __dirname,
  "../proto/starshine/v2/starshine.proto",
);

type Callback<T> = (error: grpc.ServiceError | null, response: T) => void;
type Unary<TRequest, TResponse> = (
  request: TRequest,
  options: grpc.CallOptions,
  callback: Callback<TResponse>,
) => grpc.ClientUnaryCall;

export interface V2SystemClient {
  getCapabilities: Unary<Record<string, never>, V2CapabilitiesWire>;
}

export interface V2StorageClient {
  append: Unary<V2AppendRequestWire, V2AppendResponseWire>;
  retrieve: Unary<V2RetrieveRequestWire, V2RetrieveResponseWire>;
  release: Unary<V2ReleaseRequestWire, V2ReleaseResponseWire>;
  getPublicArtifact: Unary<
    { artifact_root: Buffer },
    { artifact?: V2PublicArtifactWire }
  >;
  challengeStorage: Unary<
    V2ChallengeStorageRequestWire,
    { proof?: V2StorageProofWire }
  >;
}

export interface V2LedgerClient {
  getEvent: Unary<
    { authorization?: V2AuthorizationWire; event_id: string },
    { receipt?: V2EventReceiptWire }
  >;
  listAccountEvents: Unary<
    {
      authorization?: V2AuthorizationWire;
      limit: number;
      cursor: string;
    },
    { receipts: V2EventReceiptWire[]; next_cursor: string }
  >;
  listLedgerEvents: Unary<
    {
      authorization?: V2AuthorizationWire;
      limit: number;
      cursor: string;
    },
    { receipts: V2EventReceiptWire[]; next_cursor: string }
  >;
  getInclusionProof: Unary<
    { authorization?: V2AuthorizationWire; event_id: string },
    { proof?: V2InclusionProofWire }
  >;
}

export interface V2LedgerAdminClient {
  createLedger: Unary<{ authorization?: V2LedgerAdminAuthorizationWire }, V2LedgerDescriptorResponseWire>;
  grantSigner: Unary<{ authorization?: V2LedgerAdminAuthorizationWire }, V2LedgerDescriptorResponseWire>;
  revokeSigner: Unary<{ authorization?: V2LedgerAdminAuthorizationWire }, V2LedgerDescriptorResponseWire>;
  setLedgerActive: Unary<{ authorization?: V2LedgerAdminAuthorizationWire }, V2LedgerDescriptorResponseWire>;
  getLedger: Unary<{ authorization?: V2LedgerAdminAuthorizationWire }, V2LedgerDescriptorResponseWire>;
}

export interface V2AuthorizationWire {
  version: number;
  operation: number;
  actor_id: Buffer;
  request_id: string;
  event_id: string;
  artifact_root: Buffer;
  logical_content_id: string;
  request_digest: Buffer;
  max_void: string;
  issued_at_unix_ms: string;
  nonce: Buffer;
  mldsa_public_key: Buffer;
  mldsa_signature: Buffer;
  ledger_id: string;
}

export interface V2SealedShardWire {
  index: number;
  global_bao_outboard: Buffer;
  sealed_data: Buffer;
}

export interface V2SealedArtifactWire {
  artifact_root: Buffer;
  hpke_encapsulation: Buffer;
  plaintext_len: string;
  hpke_plaintext_len: string;
  ciphertext_len: string;
  data_shards: number;
  parity_shards: number;
  sealed_shard_size: string;
  raw_shard_size: string;
  provider_ids: Buffer[];
  ciphertext_digest: Buffer;
  compression_codec: string;
  shards: V2SealedShardWire[];
}

export interface V2AppendRequestWire {
  authorization?: V2AuthorizationWire;
  artifact?: V2SealedArtifactWire;
  file_name: string;
}

export interface V2AppendResponseWire {
  receipt?: V2EventReceiptWire;
}

export interface V2RetrieveRequestWire {
  authorization?: V2AuthorizationWire;
  artifact_root: Buffer;
  minimum_shards: boolean;
}

export interface V2RetrieveResponseWire {
  artifact?: V2SealedArtifactWire;
  receipt?: V2EventReceiptWire;
}

export interface V2ReleaseRequestWire {
  authorization?: V2AuthorizationWire;
  artifact_root: Buffer;
  reason: string;
}

export interface V2ReleaseResponseWire {
  receipt?: V2EventReceiptWire;
  physical_bytes_released: boolean;
}

export interface V2NodeAttestationWire {
  node_id: Buffer;
  mldsa_public_key: Buffer;
  mldsa_signature: Buffer;
}

export interface V2InclusionProofWire {
  checkpoint_root: Buffer;
  checkpoint_height: string;
  merkle_path: Buffer[];
  checkpoint_certificate?: V2CheckpointCertificateWire;
  finality: number;
  ledger_id: string;
  event_hash: Buffer;
  ledger_sequence: string;
  ledger_root: Buffer;
  ledger_event_count: string;
  ledger_path: V2MerkleSiblingWire[];
  ledger_commitment: Buffer;
  event_index: string;
  ledger_count: string;
  global_path: V2MerkleSiblingWire[];
  event_id: string;
  ledger_index: string;
}

export interface V2MerkleSiblingWire {
  hash: Buffer;
  sibling_on_left: boolean;
}

export interface V2CheckpointCertificateWire {
  version: number;
  checkpoint_height: string;
  created_at_unix_ms: string;
  global_root: Buffer;
  previous_checkpoint_hash: Buffer;
  checkpoint_hash: Buffer;
  node_id: Buffer;
  node_mldsa_public_key: Buffer;
  node_mldsa_signature: Buffer;
}

export interface V2EventReceiptWire {
  event_id: string;
  request_id: string;
  request_digest: Buffer;
  operation: number;
  actor_id: Buffer;
  artifact_root: Buffer;
  logical_content_id: string;
  account_sequence: string;
  previous_event_hash: Buffer;
  event_hash: Buffer;
  accepted_at_unix_ms: string;
  void_amount: string;
  void_balance: string;
  disposition: number;
  finality: number;
  node_attestation?: V2NodeAttestationWire;
  inclusion_proof?: V2InclusionProofWire;
  ledger_id: string;
  ledger_sequence: string;
  previous_ledger_event_hash: Buffer;
}

export interface V2CapabilitiesWire {
  protocol_version: string;
  pq_kem_suites: string[];
  pq_signature_suites: string[];
  authenticated_operations_required: boolean;
  idempotent_append: boolean;
  public_storage_proofs: boolean;
  owner_authorized_release: boolean;
  supported_finality: number[];
  node_id: Buffer;
  node_mldsa_public_key: Buffer;
  application_ledgers: boolean;
  checkpoint_inclusion_proofs: boolean;
  ledger_admin_mldsa_public_key: Buffer;
}

export interface V2LedgerAdminAuthorizationWire {
  version: number;
  operation: number;
  request_id: string;
  ledger_id: string;
  signer_actor_id: Buffer;
  display_name: string;
  environment: string;
  active: boolean;
  issued_at_unix_ms: string;
  nonce: Buffer;
  mldsa_public_key: Buffer;
  mldsa_signature: Buffer;
}

export interface V2LedgerDescriptorWire {
  ledger_id: string;
  display_name: string;
  environment: string;
  active: boolean;
  created_at_unix_ms: string;
  authorized_signer_actor_ids: Buffer[];
}

export interface V2LedgerDescriptorResponseWire {
  ledger?: V2LedgerDescriptorWire;
}

export interface V2PublicArtifactWire {
  artifact_root: Buffer;
  plaintext_len: string;
  ciphertext_len: string;
  data_shards: number;
  parity_shards: number;
  sealed_shard_size: string;
  raw_shard_size: string;
  provider_ids: Buffer[];
  ciphertext_digest: Buffer;
  released: boolean;
}

export interface V2ChallengeStorageRequestWire {
  artifact_root: Buffer;
  shard_index: number;
  epoch: string;
  randomness: Buffer;
}

export interface V2StorageProofWire {
  challenge?: {
    artifact_root: Buffer;
    shard_index: number;
    total_shards: number;
    epoch: string;
    randomness: Buffer;
    block_indices: number[];
    file_id: Buffer;
    provider_id: Buffer;
  };
  responses: Array<{
    index: number;
    replica_block: Buffer;
    bao_slice: Buffer;
  }>;
}

interface V2Clients {
  system: V2SystemClient;
  storage: V2StorageClient;
  ledger: V2LedgerClient;
  ledgerAdmin: V2LedgerAdminClient;
}

const cache = new Map<string, V2Clients>();

function grpcMessageLimit(): number {
  const raw = process.env.STARSHINE_MAX_PUT_BYTES?.trim() || DEFAULT_MAX_PUT_BYTES;
  const match = /^(\d+(?:\.\d+)?)\s*(b|kib|kb|mib|mb|gib|gb)?$/i.exec(raw);
  if (!match) return 1024 ** 3;
  const amount = Number(match[1]);
  const unit = (match[2] ?? "b").toLowerCase();
  const multiplier = unit === "kib" || unit === "kb"
    ? 1024
    : unit === "mib" || unit === "mb"
      ? 1024 ** 2
      : unit === "gib" || unit === "gb"
        ? 1024 ** 3
        : 1;
  return Math.round(amount * multiplier);
}

function load(endpoint: string, transport: TransportOptions): V2Clients {
  const definition = protoLoader.loadSync(PROTO_PATH, {
    keepCase: true,
    longs: String,
    enums: Number,
    defaults: true,
    oneofs: true,
  });
  const loaded = grpc.loadPackageDefinition(definition) as unknown as {
    starshine: {
      v2: {
        System: new (address: string, credentials: grpc.ChannelCredentials, options: object) => V2SystemClient;
        Storage: new (address: string, credentials: grpc.ChannelCredentials, options: object) => V2StorageClient;
        Ledger: new (address: string, credentials: grpc.ChannelCredentials, options: object) => V2LedgerClient;
        LedgerAdmin: new (address: string, credentials: grpc.ChannelCredentials, options: object) => V2LedgerAdminClient;
      };
    };
  };
  const parsed = parseEndpoint(endpoint, transport);
  const credentials = createChannelCredentials(parsed, transport);
  const limit = grpcMessageLimit();
  const options = {
    "grpc.max_receive_message_length": limit,
    "grpc.max_send_message_length": limit,
  };
  const pkg = loaded.starshine.v2;
  return {
    system: new pkg.System(parsed.address, credentials, options),
    storage: new pkg.Storage(parsed.address, credentials, options),
    ledger: new pkg.Ledger(parsed.address, credentials, options),
    ledgerAdmin: new pkg.LedgerAdmin(parsed.address, credentials, options),
  };
}

export function getV2Clients(
  endpoint: string,
  transport: TransportOptions = {},
): V2Clients {
  const key = transportCacheKey(endpoint, transport);
  const existing = cache.get(key);
  if (existing) return existing;
  const clients = load(endpoint, transport);
  cache.set(key, clients);
  return clients;
}

export function callV2<TRequest, TResponse>(
  method: Unary<TRequest, TResponse>,
  request: TRequest,
  options: UnaryRequestOptions = {},
): Promise<TResponse> {
  return unaryRequest(
    (callOptions, callback) => method(request, callOptions, callback),
    options,
  );
}

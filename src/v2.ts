import { randomBytes } from "node:crypto";

import { hash as blake3 } from "blake3-bao";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import type { PublicBlobMeta, StorageProof } from "./audit.js";
import type { UnaryRequestOptions } from "./grpc.js";
import type { StoredBlob } from "./types.js";
import type { TransportOptions } from "./transport.js";
import { hexToBytes } from "./void-sign.js";
import type { WalletFile } from "./wallet.js";
import {
  callV2,
  getV2Clients,
  type V2AuthorizationWire,
  type V2CapabilitiesWire,
  type V2CheckpointCertificateWire,
  type V2EventReceiptWire,
  type V2InclusionProofWire,
  type V2LedgerAdminAuthorizationWire,
  type V2LedgerDescriptorWire,
  type V2MerkleSiblingWire,
  type V2PublicArtifactWire,
  type V2SealedArtifactWire,
  type V2StorageProofWire,
} from "./v2-grpc.js";

const encoder = new TextEncoder();
const OPERATION_SIGN_DOMAIN = encoder.encode("starshine:operation:v2\0");
const OPERATION_SIGN_CONTEXT = encoder.encode("starshine-operation-v2");
const ACTOR_ID_DOMAIN = encoder.encode("starshine:actor-id:v2\0");
const APPEND_DIGEST_DOMAIN = encoder.encode("starshine:append-request:v2\0");
const RETRIEVE_DIGEST_DOMAIN = encoder.encode("starshine:retrieve-request:v2\0");
const RELEASE_DIGEST_DOMAIN = encoder.encode("starshine:release-request:v2\0");
const READ_EVENT_DIGEST_DOMAIN = encoder.encode("starshine:read-event-request:v2\0");
const LIST_EVENTS_DIGEST_DOMAIN = encoder.encode("starshine:list-events-request:v2\0");
const LIST_LEDGER_EVENTS_DIGEST_DOMAIN = encoder.encode("starshine:list-ledger-events-request:v2\0");
const INCLUSION_DIGEST_DOMAIN = encoder.encode("starshine:inclusion-request:v2\0");
const NODE_ID_DOMAIN = encoder.encode("starshine:node-id:v2\0");
const RECEIPT_HASH_DOMAIN = encoder.encode("starshine:event-receipt-hash:v2\0");
const RECEIPT_SIGN_DOMAIN = encoder.encode("starshine:event-receipt-signature:v2\0");
const RECEIPT_SIGN_CONTEXT = encoder.encode("starshine-event-receipt-v2");
const EVENT_LEAF_DOMAIN = encoder.encode("starshine:event-leaf:v2\0");
const MERKLE_PARENT_DOMAIN = encoder.encode("starshine:merkle-parent:v2\0");
const LEDGER_COMMITMENT_DOMAIN = encoder.encode("starshine:ledger-commitment:v2\0");
const CHECKPOINT_HASH_DOMAIN = encoder.encode("starshine:checkpoint-hash:v2\0");
const CHECKPOINT_SIGN_DOMAIN = encoder.encode("starshine:checkpoint-signature:v2\0");
const CHECKPOINT_SIGN_CONTEXT = encoder.encode("starshine-checkpoint-v2");
const LEDGER_ADMIN_SIGN_DOMAIN = encoder.encode("starshine:ledger-admin:v2\0");
const LEDGER_ADMIN_SIGN_CONTEXT = encoder.encode("starshine-ledger-admin-v2");

export const OPERATION_VERSION = 3;
export const LEDGER_ADMIN_VERSION = 1;

export enum StarshineOperation {
  Append = 1,
  Retrieve = 2,
  Release = 3,
  Transfer = 4,
  Faucet = 5,
  ReadEvent = 6,
  ListEvents = 7,
  GetInclusionProof = 8,
  ListLedgerEvents = 9,
}

export enum LedgerAdminOperation {
  Create = 1,
  GrantSigner = 2,
  RevokeSigner = 3,
  SetActive = 4,
  Get = 5,
}

export enum StarshineFinality {
  Unspecified = 0,
  NodeAttested = 1,
  LedgerCheckpointed = 2,
  NetworkFinalized = 3,
}

export interface V2CallOptions {
  /** Opaque application-ledger UUID provisioned by the VOID operator. */
  ledgerId?: string;
  transport?: TransportOptions;
  rpc?: UnaryRequestOptions;
  /** Persist this UUID and reuse it for safe retries. */
  requestId?: string;
  /** Normally generated. Exposed for deterministic recovery tooling. */
  eventId?: string;
  /** Stable plaintext identity. Required for append, optional for other events. */
  logicalContentId?: string;
  maxVoid?: bigint;
  /** Expected node identity learned over an authenticated channel. */
  expectedNode?: { nodeId?: Uint8Array; publicKey?: Uint8Array };
}

export interface EventReceipt {
  ledgerId: string;
  eventId: string;
  requestId: string;
  requestDigest: Uint8Array;
  operation: StarshineOperation;
  actorId: Uint8Array;
  artifactRoot: Uint8Array;
  logicalContentId: string;
  accountSequence: bigint;
  previousEventHash: Uint8Array;
  ledgerSequence: bigint;
  previousLedgerEventHash: Uint8Array;
  eventHash: Uint8Array;
  acceptedAtUnixMs: bigint;
  voidAmount: bigint;
  voidBalance: bigint;
  disposition: number;
  finality: StarshineFinality;
  nodeId: Uint8Array;
  nodeMlDsaPublicKey: Uint8Array;
  nodeMlDsaSignature: Uint8Array;
}

export interface StarshineCapabilities {
  protocolVersion: string;
  pqKemSuites: string[];
  pqSignatureSuites: string[];
  authenticatedOperationsRequired: boolean;
  idempotentAppend: boolean;
  publicStorageProofs: boolean;
  ownerAuthorizedRelease: boolean;
  supportedFinality: StarshineFinality[];
  nodeId: Uint8Array;
  nodeMlDsaPublicKey: Uint8Array;
  applicationLedgers: boolean;
  checkpointInclusionProofs: boolean;
  ledgerAdminMlDsaPublicKey: Uint8Array;
}

export interface V2AppendResult {
  artifactRoot: Uint8Array;
  receipt: EventReceipt;
}

export interface V2RetrieveResult {
  stored: StoredBlob;
  receipt: EventReceipt;
}

export interface V2ReleaseResult {
  receipt: EventReceipt;
  physicalBytesReleased: boolean;
}

export interface InclusionProof {
  eventId: string;
  eventHash: Uint8Array;
  ledgerId: string;
  ledgerSequence: bigint;
  ledgerRoot: Uint8Array;
  ledgerEventCount: bigint;
  ledgerPath: MerkleSibling[];
  ledgerCommitment: Uint8Array;
  eventIndex: bigint;
  ledgerIndex: bigint;
  ledgerCount: bigint;
  globalPath: MerkleSibling[];
  checkpointRoot: Uint8Array;
  checkpointHeight: bigint;
  merklePath: Uint8Array[];
  checkpointCertificate: CheckpointCertificate;
  finality: StarshineFinality;
}

export interface MerkleSibling {
  hash: Uint8Array;
  siblingOnLeft: boolean;
}

export interface CheckpointCertificate {
  version: number;
  checkpointHeight: bigint;
  createdAtUnixMs: bigint;
  globalRoot: Uint8Array;
  previousCheckpointHash: Uint8Array;
  checkpointHash: Uint8Array;
  nodeId: Uint8Array;
  nodeMlDsaPublicKey: Uint8Array;
  nodeMlDsaSignature: Uint8Array;
}

export interface LedgerDescriptor {
  ledgerId: string;
  displayName: string;
  environment: string;
  active: boolean;
  createdAtUnixMs: bigint;
  authorizedSignerActorIds: Uint8Array[];
}

export interface LedgerAdminCallOptions {
  transport?: TransportOptions;
  rpc?: UnaryRequestOptions;
  requestId?: string;
  nonce?: Uint8Array;
  issuedAtUnixMs?: bigint;
}

export function deriveActorId(mldsaPublicKey: Uint8Array): Uint8Array {
  return digestRaw(ACTOR_ID_DOMAIN, mldsaPublicKey);
}

export function operationSigningBytes(
  authorization: Omit<V2AuthorizationWire, "mldsa_signature"> & {
    mldsa_signature?: Buffer;
  },
): Uint8Array {
  const canonical = JSON.stringify({
    actor_id: base64url(authorization.actor_id),
    artifact_root: base64url(authorization.artifact_root),
    event_id: authorization.event_id,
    issued_at_unix_ms: authorization.issued_at_unix_ms,
    ledger_id: authorization.ledger_id,
    logical_content_id: authorization.logical_content_id,
    max_void: authorization.max_void,
    nonce: base64url(authorization.nonce),
    operation: authorization.operation,
    request_digest: base64url(authorization.request_digest),
    request_id: authorization.request_id,
    version: authorization.version,
  });
  return concat(OPERATION_SIGN_DOMAIN, encoder.encode(canonical));
}

export function buildOperationAuthorization(input: {
  wallet: WalletFile;
  ledgerId: string;
  operation: StarshineOperation;
  artifactRoot: Uint8Array;
  logicalContentId?: string;
  requestDigest: Uint8Array;
  requestId?: string;
  eventId?: string;
  nonce?: Uint8Array;
  issuedAtUnixMs?: bigint;
  maxVoid?: bigint;
}): V2AuthorizationWire {
  assertUuid("ledgerId", input.ledgerId);
  assertLength("artifactRoot", input.artifactRoot, 32);
  assertLength("requestDigest", input.requestDigest, 32);
  const publicKey = hexToBytes(input.wallet.mldsa_public_key_hex);
  const privateKey = hexToBytes(input.wallet.mldsa_private_key_hex);
  const derivedPublic = ml_dsa65.getPublicKey(privateKey);
  if (!equalBytes(publicKey, derivedPublic)) {
    throw new Error("wallet ML-DSA public/private keys do not match");
  }
  const authorization: V2AuthorizationWire = {
    version: OPERATION_VERSION,
    operation: input.operation,
    actor_id: Buffer.from(deriveActorId(publicKey)),
    request_id: input.requestId ?? crypto.randomUUID(),
    event_id: input.eventId ?? crypto.randomUUID(),
    artifact_root: Buffer.from(input.artifactRoot),
    logical_content_id: input.logicalContentId ?? "",
    request_digest: Buffer.from(input.requestDigest),
    max_void: (input.maxVoid ?? 0n).toString(),
    issued_at_unix_ms: (input.issuedAtUnixMs ?? BigInt(Date.now())).toString(),
    nonce: Buffer.from(input.nonce ?? randomBytes(32)),
    mldsa_public_key: Buffer.from(publicKey),
    mldsa_signature: Buffer.alloc(0),
    ledger_id: input.ledgerId,
  };
  authorization.mldsa_signature = Buffer.from(
    ml_dsa65.sign(operationSigningBytes(authorization), privateKey, {
      context: OPERATION_SIGN_CONTEXT,
    }),
  );
  return authorization;
}

export async function getCapabilitiesV2(
  endpoint: string,
  options: Pick<V2CallOptions, "transport" | "rpc"> = {},
): Promise<StarshineCapabilities> {
  const clients = getV2Clients(endpoint, options.transport);
  const wire = await callV2(
    clients.system.getCapabilities.bind(clients.system),
    {},
    options.rpc,
  );
  validateCapabilities(wire);
  return {
    protocolVersion: wire.protocol_version,
    pqKemSuites: wire.pq_kem_suites,
    pqSignatureSuites: wire.pq_signature_suites,
    authenticatedOperationsRequired: wire.authenticated_operations_required,
    idempotentAppend: wire.idempotent_append,
    publicStorageProofs: wire.public_storage_proofs,
    ownerAuthorizedRelease: wire.owner_authorized_release,
    supportedFinality: wire.supported_finality as StarshineFinality[],
    nodeId: bytes(wire.node_id),
    nodeMlDsaPublicKey: bytes(wire.node_mldsa_public_key),
    applicationLedgers: wire.application_ledgers,
    checkpointInclusionProofs: wire.checkpoint_inclusion_proofs,
    ledgerAdminMlDsaPublicKey: bytes(wire.ledger_admin_mldsa_public_key),
  };
}

export function ledgerAdminSigningBytes(
  authorization: Omit<V2LedgerAdminAuthorizationWire, "mldsa_signature"> & {
    mldsa_signature?: Buffer;
  },
): Uint8Array {
  const canonical = JSON.stringify({
    active: authorization.active,
    display_name: authorization.display_name,
    environment: authorization.environment,
    issued_at_unix_ms: authorization.issued_at_unix_ms,
    ledger_id: authorization.ledger_id,
    nonce: base64url(authorization.nonce),
    operation: authorization.operation,
    request_id: authorization.request_id,
    signer_actor_id: base64url(authorization.signer_actor_id),
    version: authorization.version,
  });
  return concat(LEDGER_ADMIN_SIGN_DOMAIN, encoder.encode(canonical));
}

export function buildLedgerAdminAuthorization(input: {
  wallet: WalletFile;
  operation: LedgerAdminOperation;
  ledgerId: string;
  signerActorId?: Uint8Array;
  displayName?: string;
  environment?: string;
  active?: boolean;
  requestId?: string;
  nonce?: Uint8Array;
  issuedAtUnixMs?: bigint;
}): V2LedgerAdminAuthorizationWire {
  assertUuid("ledgerId", input.ledgerId);
  const signerRequired =
    input.operation === LedgerAdminOperation.Create ||
    input.operation === LedgerAdminOperation.GrantSigner ||
    input.operation === LedgerAdminOperation.RevokeSigner;
  if (signerRequired) {
    if (!input.signerActorId) throw new Error("signerActorId is required");
    assertLength("signerActorId", input.signerActorId, 32);
  } else if (input.signerActorId?.length) {
    throw new Error("signerActorId must be omitted for this admin operation");
  }
  const publicKey = hexToBytes(input.wallet.mldsa_public_key_hex);
  const privateKey = hexToBytes(input.wallet.mldsa_private_key_hex);
  if (!equalBytes(publicKey, ml_dsa65.getPublicKey(privateKey))) {
    throw new Error("admin wallet ML-DSA public/private keys do not match");
  }
  const authorization: V2LedgerAdminAuthorizationWire = {
    version: LEDGER_ADMIN_VERSION,
    operation: input.operation,
    request_id: input.requestId ?? crypto.randomUUID(),
    ledger_id: input.ledgerId,
    signer_actor_id: Buffer.from(input.signerActorId ?? new Uint8Array()),
    display_name: input.displayName ?? "",
    environment: input.environment ?? "",
    active: input.active ?? false,
    issued_at_unix_ms: (input.issuedAtUnixMs ?? BigInt(Date.now())).toString(),
    nonce: Buffer.from(input.nonce ?? randomBytes(32)),
    mldsa_public_key: Buffer.from(publicKey),
    mldsa_signature: Buffer.alloc(0),
  };
  authorization.mldsa_signature = Buffer.from(
    ml_dsa65.sign(ledgerAdminSigningBytes(authorization), privateKey, {
      context: LEDGER_ADMIN_SIGN_CONTEXT,
    }),
  );
  return authorization;
}

export async function createLedgerV2(
  endpoint: string,
  adminWallet: WalletFile,
  input: {
    ledgerId: string;
    signerActorId: Uint8Array;
    displayName: string;
    environment: string;
    active?: boolean;
  },
  options: LedgerAdminCallOptions = {},
): Promise<LedgerDescriptor> {
  return callLedgerAdminV2(
    endpoint,
    adminWallet,
    LedgerAdminOperation.Create,
    { ...input, active: input.active ?? true },
    options,
  );
}

export async function grantLedgerSignerV2(
  endpoint: string,
  adminWallet: WalletFile,
  ledgerId: string,
  signerActorId: Uint8Array,
  options: LedgerAdminCallOptions = {},
): Promise<LedgerDescriptor> {
  return callLedgerAdminV2(
    endpoint,
    adminWallet,
    LedgerAdminOperation.GrantSigner,
    { ledgerId, signerActorId },
    options,
  );
}

export async function revokeLedgerSignerV2(
  endpoint: string,
  adminWallet: WalletFile,
  ledgerId: string,
  signerActorId: Uint8Array,
  options: LedgerAdminCallOptions = {},
): Promise<LedgerDescriptor> {
  return callLedgerAdminV2(
    endpoint,
    adminWallet,
    LedgerAdminOperation.RevokeSigner,
    { ledgerId, signerActorId },
    options,
  );
}

export async function setLedgerActiveV2(
  endpoint: string,
  adminWallet: WalletFile,
  ledgerId: string,
  active: boolean,
  options: LedgerAdminCallOptions = {},
): Promise<LedgerDescriptor> {
  return callLedgerAdminV2(
    endpoint,
    adminWallet,
    LedgerAdminOperation.SetActive,
    { ledgerId, active },
    options,
  );
}

export async function getLedgerV2(
  endpoint: string,
  adminWallet: WalletFile,
  ledgerId: string,
  options: LedgerAdminCallOptions = {},
): Promise<LedgerDescriptor> {
  return callLedgerAdminV2(
    endpoint,
    adminWallet,
    LedgerAdminOperation.Get,
    { ledgerId },
    options,
  );
}

async function callLedgerAdminV2(
  endpoint: string,
  adminWallet: WalletFile,
  operation: LedgerAdminOperation,
  input: {
    ledgerId: string;
    signerActorId?: Uint8Array;
    displayName?: string;
    environment?: string;
    active?: boolean;
  },
  options: LedgerAdminCallOptions,
): Promise<LedgerDescriptor> {
  const clients = getV2Clients(endpoint, options.transport);
  const authorization = buildLedgerAdminAuthorization({
    wallet: adminWallet,
    operation,
    ...input,
    requestId: options.requestId,
    nonce: options.nonce,
    issuedAtUnixMs: options.issuedAtUnixMs,
  });
  const method = operation === LedgerAdminOperation.Create
    ? clients.ledgerAdmin.createLedger
    : operation === LedgerAdminOperation.GrantSigner
      ? clients.ledgerAdmin.grantSigner
      : operation === LedgerAdminOperation.RevokeSigner
        ? clients.ledgerAdmin.revokeSigner
        : operation === LedgerAdminOperation.SetActive
          ? clients.ledgerAdmin.setLedgerActive
          : clients.ledgerAdmin.getLedger;
  const response = await callV2(
    method.bind(clients.ledgerAdmin),
    { authorization },
    options.rpc,
  );
  if (!response.ledger) throw new Error("LedgerDescriptorResponse.ledger is required");
  return ledgerDescriptorFromWire(response.ledger);
}

export async function appendV2(
  endpoint: string,
  wallet: WalletFile,
  stored: StoredBlob,
  fileName: string,
  logicalContentId: string,
  options: V2CallOptions = {},
): Promise<V2AppendResult> {
  if (!logicalContentId.trim()) {
    throw new Error("logicalContentId is required for appendV2");
  }
  const clients = getV2Clients(endpoint, options.transport);
  const artifact = sealedArtifactFromStored(stored);
  const requestDigest = appendRequestDigest(artifact, fileName);
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.Append,
    artifactRoot: stored.meta.topRoot,
    logicalContentId,
    requestDigest,
    requestId: options.requestId,
    eventId: options.eventId,
    maxVoid: options.maxVoid,
  });
  const response = await callV2(
    clients.storage.append.bind(clients.storage),
    { authorization, artifact, file_name: fileName },
    options.rpc,
  );
  const receipt = requireReceipt(response.receipt, options.expectedNode);
  assertReceiptRequest(receipt, authorization);
  return { artifactRoot: bytes(receipt.artifact_root), receipt: receiptFromWire(receipt) };
}

export async function retrieveV2(
  endpoint: string,
  wallet: WalletFile,
  artifactRoot: Uint8Array,
  minimumShards = true,
  options: V2CallOptions = {},
): Promise<V2RetrieveResult> {
  assertLength("artifactRoot", artifactRoot, 32);
  const clients = getV2Clients(endpoint, options.transport);
  const requestDigest = digestParts(
    RETRIEVE_DIGEST_DOMAIN,
    artifactRoot,
    new Uint8Array([minimumShards ? 1 : 0]),
  );
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.Retrieve,
    artifactRoot,
    logicalContentId: options.logicalContentId,
    requestDigest,
    requestId: options.requestId,
    eventId: options.eventId,
    maxVoid: options.maxVoid,
  });
  const response = await callV2(
    clients.storage.retrieve.bind(clients.storage),
    { authorization, artifact_root: Buffer.from(artifactRoot), minimum_shards: minimumShards },
    options.rpc,
  );
  if (!response.artifact) throw new Error("RetrieveResponse.artifact is required");
  const receipt = requireReceipt(response.receipt, options.expectedNode);
  assertReceiptRequest(receipt, authorization);
  return {
    stored: storedFromSealedArtifact(response.artifact),
    receipt: receiptFromWire(receipt),
  };
}

export async function releaseV2(
  endpoint: string,
  wallet: WalletFile,
  artifactRoot: Uint8Array,
  reason: string,
  options: V2CallOptions = {},
): Promise<V2ReleaseResult> {
  assertLength("artifactRoot", artifactRoot, 32);
  const clients = getV2Clients(endpoint, options.transport);
  const requestDigest = digestParts(
    RELEASE_DIGEST_DOMAIN,
    artifactRoot,
    encoder.encode(reason),
  );
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.Release,
    artifactRoot,
    logicalContentId: options.logicalContentId,
    requestDigest,
    requestId: options.requestId,
    eventId: options.eventId,
    maxVoid: options.maxVoid,
  });
  const response = await callV2(
    clients.storage.release.bind(clients.storage),
    { authorization, artifact_root: Buffer.from(artifactRoot), reason },
    options.rpc,
  );
  const receipt = requireReceipt(response.receipt, options.expectedNode);
  assertReceiptRequest(receipt, authorization);
  return {
    receipt: receiptFromWire(receipt),
    physicalBytesReleased: response.physical_bytes_released,
  };
}

export async function listAccountEventsV2(
  endpoint: string,
  wallet: WalletFile,
  limit = 100,
  cursor = "",
  options: V2CallOptions = {},
): Promise<{ receipts: EventReceipt[]; nextCursor: string }> {
  const clients = getV2Clients(endpoint, options.transport);
  const root = new Uint8Array(32);
  const requestDigest = digestParts(
    LIST_EVENTS_DIGEST_DOMAIN,
    u32be(limit),
    encoder.encode(cursor),
  );
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.ListEvents,
    artifactRoot: root,
    requestDigest,
    requestId: options.requestId,
    eventId: options.eventId,
  });
  const response = await callV2(
    clients.ledger.listAccountEvents.bind(clients.ledger),
    { authorization, limit, cursor },
    options.rpc,
  );
  return {
    receipts: response.receipts.map((receipt) => {
      verifyEventReceipt(receipt, options.expectedNode);
      return receiptFromWire(receipt);
    }),
    nextCursor: response.next_cursor,
  };
}

export async function listLedgerEventsV2(
  endpoint: string,
  wallet: WalletFile,
  limit = 100,
  cursor = "",
  options: V2CallOptions = {},
): Promise<{ receipts: EventReceipt[]; nextCursor: string }> {
  const clients = getV2Clients(endpoint, options.transport);
  const requestDigest = digestParts(
    LIST_LEDGER_EVENTS_DIGEST_DOMAIN,
    u32be(limit),
    encoder.encode(cursor),
  );
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.ListLedgerEvents,
    artifactRoot: new Uint8Array(32),
    requestDigest,
    requestId: options.requestId,
    eventId: options.eventId,
  });
  const response = await callV2(
    clients.ledger.listLedgerEvents.bind(clients.ledger),
    { authorization, limit, cursor },
    options.rpc,
  );
  return {
    receipts: response.receipts.map((receipt) => {
      verifyEventReceipt(receipt, options.expectedNode);
      return receiptFromWire(receipt);
    }),
    nextCursor: response.next_cursor,
  };
}

export async function getEventV2(
  endpoint: string,
  wallet: WalletFile,
  eventId: string,
  options: V2CallOptions = {},
): Promise<EventReceipt> {
  const clients = getV2Clients(endpoint, options.transport);
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.ReadEvent,
    artifactRoot: new Uint8Array(32),
    requestDigest: digestParts(READ_EVENT_DIGEST_DOMAIN, encoder.encode(eventId)),
    requestId: options.requestId,
    eventId: options.eventId,
  });
  const response = await callV2(
    clients.ledger.getEvent.bind(clients.ledger),
    { authorization, event_id: eventId },
    options.rpc,
  );
  const receipt = requireReceipt(response.receipt, options.expectedNode);
  return receiptFromWire(receipt);
}

export async function getInclusionProofV2(
  endpoint: string,
  wallet: WalletFile,
  eventId: string,
  options: V2CallOptions = {},
): Promise<InclusionProof> {
  const clients = getV2Clients(endpoint, options.transport);
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: requireLedgerId(options.ledgerId),
    operation: StarshineOperation.GetInclusionProof,
    artifactRoot: new Uint8Array(32),
    requestDigest: digestParts(INCLUSION_DIGEST_DOMAIN, encoder.encode(eventId)),
    requestId: options.requestId,
    eventId: options.eventId,
  });
  const response = await callV2(
    clients.ledger.getInclusionProof.bind(clients.ledger),
    { authorization, event_id: eventId },
    options.rpc,
  );
  if (!response.proof) throw new Error("GetInclusionProofResponse.proof is required");
  if (response.proof.event_id !== eventId) {
    throw new Error("server returned an inclusion proof for a different event_id");
  }
  if (response.proof.ledger_id !== authorization.ledger_id) {
    throw new Error("server returned an inclusion proof for a different ledger_id");
  }
  const proof = inclusionProofFromWire(response.proof);
  verifyInclusionProof(proof, options.expectedNode);
  return proof;
}

export async function getPublicArtifactV2(
  endpoint: string,
  artifactRoot: Uint8Array,
  options: Pick<V2CallOptions, "transport" | "rpc"> = {},
): Promise<PublicBlobMeta & { released: boolean }> {
  assertLength("artifactRoot", artifactRoot, 32);
  const clients = getV2Clients(endpoint, options.transport);
  const response = await callV2(
    clients.storage.getPublicArtifact.bind(clients.storage),
    { artifact_root: Buffer.from(artifactRoot) },
    options.rpc,
  );
  if (!response.artifact) throw new Error("GetPublicArtifactResponse.artifact is required");
  return publicArtifactFromWire(response.artifact);
}

export async function requestStorageProofV2(
  endpoint: string,
  artifactRoot: Uint8Array,
  shardIndex: number,
  epoch: bigint,
  randomness: Uint8Array,
  options: Pick<V2CallOptions, "transport" | "rpc"> = {},
): Promise<StorageProof> {
  assertLength("artifactRoot", artifactRoot, 32);
  assertLength("randomness", randomness, 32);
  const clients = getV2Clients(endpoint, options.transport);
  const response = await callV2(
    clients.storage.challengeStorage.bind(clients.storage),
    {
      artifact_root: Buffer.from(artifactRoot),
      shard_index: shardIndex,
      epoch: epoch.toString(),
      randomness: Buffer.from(randomness),
    },
    options.rpc,
  );
  if (!response.proof) throw new Error("ChallengeStorageResponse.proof is required");
  return storageProofFromV2Wire(response.proof);
}

export function verifyEventReceipt(
  receipt: V2EventReceiptWire,
  expectedNode?: { nodeId?: Uint8Array; publicKey?: Uint8Array },
): void {
  const attestation = receipt.node_attestation;
  if (!attestation) throw new Error("receipt has no node attestation");
  assertUuid("receipt.ledger_id", receipt.ledger_id);
  validateChainLink(
    "receipt account",
    BigInt(receipt.account_sequence),
    receipt.previous_event_hash,
  );
  validateChainLink(
    "receipt ledger",
    BigInt(receipt.ledger_sequence),
    receipt.previous_ledger_event_hash,
  );
  assertLength("receipt.event_hash", receipt.event_hash, 32);
  const expectedHash = digestRaw(
    RECEIPT_HASH_DOMAIN,
    receiptCanonicalBytes(receipt, false),
  );
  if (!equalBytes(expectedHash, receipt.event_hash)) {
    throw new Error("receipt event hash is invalid");
  }
  const publicKey = bytes(attestation.mldsa_public_key);
  const expectedNodeId = digestRaw(NODE_ID_DOMAIN, publicKey);
  if (!equalBytes(expectedNodeId, attestation.node_id)) {
    throw new Error("receipt node_id does not match its ML-DSA key");
  }
  if (expectedNode?.nodeId && !equalBytes(expectedNode.nodeId, attestation.node_id)) {
    throw new Error("receipt is attested by an unexpected node_id");
  }
  if (expectedNode?.publicKey && !equalBytes(expectedNode.publicKey, publicKey)) {
    throw new Error("receipt is attested by an unexpected node ML-DSA key");
  }
  const signedBytes = concat(
    RECEIPT_SIGN_DOMAIN,
    receiptCanonicalBytes(receipt, true),
  );
  const valid = ml_dsa65.verify(
    bytes(attestation.mldsa_signature),
    signedBytes,
    publicKey,
    { context: RECEIPT_SIGN_CONTEXT },
  );
  if (!valid) throw new Error("invalid receipt ML-DSA-65 signature");
}

export function verifyCheckpointCertificate(
  certificate: CheckpointCertificate,
  expectedNode?: { nodeId?: Uint8Array; publicKey?: Uint8Array },
): void {
  if (certificate.version !== 1) {
    throw new Error(`unsupported checkpoint certificate version ${certificate.version}`);
  }
  assertLength("checkpoint.globalRoot", certificate.globalRoot, 32);
  assertLength("checkpoint.checkpointHash", certificate.checkpointHash, 32);
  const expectedHash = digestRaw(
    CHECKPOINT_HASH_DOMAIN,
    checkpointCanonicalBytes(certificate, false),
  );
  if (!equalBytes(expectedHash, certificate.checkpointHash)) {
    throw new Error("checkpoint certificate hash is invalid");
  }
  const expectedNodeId = digestRaw(NODE_ID_DOMAIN, certificate.nodeMlDsaPublicKey);
  if (!equalBytes(expectedNodeId, certificate.nodeId)) {
    throw new Error("checkpoint node_id does not match its ML-DSA key");
  }
  if (expectedNode?.nodeId && !equalBytes(expectedNode.nodeId, certificate.nodeId)) {
    throw new Error("checkpoint is attested by an unexpected node_id");
  }
  if (
    expectedNode?.publicKey &&
    !equalBytes(expectedNode.publicKey, certificate.nodeMlDsaPublicKey)
  ) {
    throw new Error("checkpoint is attested by an unexpected node ML-DSA key");
  }
  const valid = ml_dsa65.verify(
    certificate.nodeMlDsaSignature,
    concat(
      CHECKPOINT_SIGN_DOMAIN,
      checkpointCanonicalBytes(certificate, true),
    ),
    certificate.nodeMlDsaPublicKey,
    { context: CHECKPOINT_SIGN_CONTEXT },
  );
  if (!valid) throw new Error("invalid checkpoint ML-DSA-65 signature");
}

export function verifyInclusionProof(
  proof: InclusionProof,
  expectedNode?: { nodeId?: Uint8Array; publicKey?: Uint8Array },
): void {
  assertLength("proof.eventHash", proof.eventHash, 32);
  assertLength("proof.ledgerRoot", proof.ledgerRoot, 32);
  assertLength("proof.ledgerCommitment", proof.ledgerCommitment, 32);
  assertLength("proof.checkpointRoot", proof.checkpointRoot, 32);
  if (proof.finality !== StarshineFinality.LedgerCheckpointed) {
    throw new Error("inclusion proof is not ledger-checkpointed");
  }
  assertUuid("proof.ledgerId", proof.ledgerId);
  if (
    proof.ledgerEventCount <= 0n ||
    proof.eventIndex < 0n ||
    proof.eventIndex >= proof.ledgerEventCount ||
    proof.ledgerSequence !== proof.eventIndex + 1n
  ) {
    throw new Error("event index is inconsistent with the ledger sequence");
  }
  if (
    proof.ledgerCount <= 0n ||
    proof.ledgerIndex < 0n ||
    proof.ledgerIndex >= proof.ledgerCount
  ) {
    throw new Error("ledger index is outside the checkpoint ledger set");
  }
  const ledgerRoot = applyMerklePath(
    digestParts(EVENT_LEAF_DOMAIN, proof.eventHash),
    proof.ledgerPath,
    proof.eventIndex,
    proof.ledgerEventCount,
  );
  if (!equalBytes(ledgerRoot, proof.ledgerRoot)) {
    throw new Error("event-to-ledger Merkle path is invalid");
  }
  const expectedCommitment = digestParts(
    LEDGER_COMMITMENT_DOMAIN,
    encoder.encode(proof.ledgerId),
    proof.ledgerRoot,
    u64be(proof.ledgerEventCount),
  );
  if (!equalBytes(expectedCommitment, proof.ledgerCommitment)) {
    throw new Error("application-ledger commitment is invalid");
  }
  const globalRoot = applyMerklePath(
    proof.ledgerCommitment,
    proof.globalPath,
    proof.ledgerIndex,
    proof.ledgerCount,
  );
  if (!equalBytes(globalRoot, proof.checkpointRoot)) {
    throw new Error("ledger-to-global Merkle path is invalid");
  }
  if (!equalBytes(proof.checkpointCertificate.globalRoot, proof.checkpointRoot)) {
    throw new Error("checkpoint certificate does not bind the proof root");
  }
  if (proof.checkpointCertificate.checkpointHeight !== proof.checkpointHeight) {
    throw new Error("checkpoint certificate height does not match the proof");
  }
  verifyCheckpointCertificate(proof.checkpointCertificate, expectedNode);
}

function applyMerklePath(
  leaf: Uint8Array,
  path: MerkleSibling[],
  originalIndex: bigint,
  originalCount: bigint,
): Uint8Array {
  if (originalCount <= 0n || originalIndex < 0n || originalIndex >= originalCount) {
    throw new Error("Merkle position is outside the tree");
  }
  let current = bytes(leaf);
  let index = originalIndex;
  let count = originalCount;
  let level = 0;
  for (const sibling of path) {
    if (count <= 1n) throw new Error("Merkle path has too many levels");
    assertLength("Merkle sibling", sibling.hash, 32);
    const expectedOnLeft = index % 2n === 1n;
    if (sibling.siblingOnLeft !== expectedOnLeft) {
      throw new Error("Merkle sibling direction is inconsistent with its index");
    }
    if (!expectedOnLeft && index + 1n >= count && !equalBytes(sibling.hash, current)) {
      throw new Error("odd Merkle level must duplicate its final leaf");
    }
    current = sibling.siblingOnLeft
      ? digestParts(MERKLE_PARENT_DOMAIN, sibling.hash, current)
      : digestParts(MERKLE_PARENT_DOMAIN, current, sibling.hash);
    index /= 2n;
    count = (count + 1n) / 2n;
    level += 1;
  }
  if (count !== 1n) {
    throw new Error(`Merkle path is missing levels after level ${level}`);
  }
  return current;
}

function checkpointCanonicalBytes(
  certificate: CheckpointCertificate,
  includeCheckpointHash: boolean,
): Uint8Array {
  const body: Record<string, string | number> = {};
  if (includeCheckpointHash) {
    body.checkpoint_hash = base64url(certificate.checkpointHash);
  }
  body.checkpoint_height = certificate.checkpointHeight.toString();
  body.created_at_unix_ms = certificate.createdAtUnixMs.toString();
  body.global_root = base64url(certificate.globalRoot);
  body.node_id = base64url(certificate.nodeId);
  body.node_mldsa_public_key = base64url(certificate.nodeMlDsaPublicKey);
  body.previous_checkpoint_hash = base64url(certificate.previousCheckpointHash);
  body.version = certificate.version;
  return encoder.encode(JSON.stringify(body));
}

function requireReceipt(
  receipt: V2EventReceiptWire | undefined,
  expectedNode?: V2CallOptions["expectedNode"],
): V2EventReceiptWire {
  if (!receipt) throw new Error("EventReceipt is required");
  verifyEventReceipt(receipt, expectedNode);
  return receipt;
}

function assertReceiptRequest(
  receipt: V2EventReceiptWire,
  authorization: V2AuthorizationWire,
): void {
  if (receipt.request_id !== authorization.request_id) {
    throw new Error("server returned a receipt for a different request_id");
  }
  if (!equalBytes(receipt.request_digest, authorization.request_digest)) {
    throw new Error("server returned a receipt for a different request digest");
  }
  if (!equalBytes(receipt.actor_id, authorization.actor_id)) {
    throw new Error("server returned a receipt for a different actor");
  }
  if (receipt.ledger_id !== authorization.ledger_id) {
    throw new Error("server returned a receipt for a different application ledger");
  }
}

function receiptCanonicalBytes(
  receipt: V2EventReceiptWire,
  includeEventHash: boolean,
): Uint8Array {
  const body: Record<string, string | number> = {
    accepted_at_unix_ms: receipt.accepted_at_unix_ms,
    account_sequence: receipt.account_sequence,
    actor_id: base64url(receipt.actor_id),
    artifact_root: base64url(receipt.artifact_root),
    disposition: receipt.disposition,
  };
  if (includeEventHash) body.event_hash = base64url(receipt.event_hash);
  body.event_id = receipt.event_id;
  body.finality = receipt.finality;
  body.ledger_id = receipt.ledger_id;
  body.ledger_sequence = receipt.ledger_sequence;
  body.logical_content_id = receipt.logical_content_id;
  body.operation = receipt.operation;
  body.previous_event_hash = base64url(receipt.previous_event_hash);
  body.previous_ledger_event_hash = base64url(receipt.previous_ledger_event_hash);
  body.request_digest = base64url(receipt.request_digest);
  body.request_id = receipt.request_id;
  body.void_amount = receipt.void_amount;
  body.void_balance = receipt.void_balance;
  return encoder.encode(JSON.stringify(body));
}

function receiptFromWire(receipt: V2EventReceiptWire): EventReceipt {
  const attestation = receipt.node_attestation!;
  return {
    ledgerId: receipt.ledger_id,
    eventId: receipt.event_id,
    requestId: receipt.request_id,
    requestDigest: bytes(receipt.request_digest),
    operation: receipt.operation as StarshineOperation,
    actorId: bytes(receipt.actor_id),
    artifactRoot: bytes(receipt.artifact_root),
    logicalContentId: receipt.logical_content_id,
    accountSequence: BigInt(receipt.account_sequence),
    previousEventHash: bytes(receipt.previous_event_hash),
    ledgerSequence: BigInt(receipt.ledger_sequence),
    previousLedgerEventHash: bytes(receipt.previous_ledger_event_hash),
    eventHash: bytes(receipt.event_hash),
    acceptedAtUnixMs: BigInt(receipt.accepted_at_unix_ms),
    voidAmount: BigInt(receipt.void_amount),
    voidBalance: BigInt(receipt.void_balance),
    disposition: receipt.disposition,
    finality: receipt.finality as StarshineFinality,
    nodeId: bytes(attestation.node_id),
    nodeMlDsaPublicKey: bytes(attestation.mldsa_public_key),
    nodeMlDsaSignature: bytes(attestation.mldsa_signature),
  };
}

function inclusionProofFromWire(proof: V2InclusionProofWire): InclusionProof {
  if (!proof.checkpoint_certificate) {
    throw new Error("InclusionProof.checkpoint_certificate is required");
  }
  return {
    eventId: proof.event_id,
    eventHash: bytes(proof.event_hash),
    ledgerId: proof.ledger_id,
    ledgerSequence: BigInt(proof.ledger_sequence),
    ledgerRoot: bytes(proof.ledger_root),
    ledgerEventCount: BigInt(proof.ledger_event_count),
    ledgerPath: proof.ledger_path.map(merkleSiblingFromWire),
    ledgerCommitment: bytes(proof.ledger_commitment),
    eventIndex: BigInt(proof.event_index),
    ledgerIndex: BigInt(proof.ledger_index),
    ledgerCount: BigInt(proof.ledger_count),
    globalPath: proof.global_path.map(merkleSiblingFromWire),
    checkpointRoot: bytes(proof.checkpoint_root),
    checkpointHeight: BigInt(proof.checkpoint_height),
    merklePath: proof.merkle_path.map(bytes),
    checkpointCertificate: checkpointCertificateFromWire(
      proof.checkpoint_certificate,
    ),
    finality: proof.finality as StarshineFinality,
  };
}

function merkleSiblingFromWire(sibling: V2MerkleSiblingWire): MerkleSibling {
  return {
    hash: bytes(sibling.hash),
    siblingOnLeft: sibling.sibling_on_left,
  };
}

function checkpointCertificateFromWire(
  certificate: V2CheckpointCertificateWire,
): CheckpointCertificate {
  return {
    version: certificate.version,
    checkpointHeight: BigInt(certificate.checkpoint_height),
    createdAtUnixMs: BigInt(certificate.created_at_unix_ms),
    globalRoot: bytes(certificate.global_root),
    previousCheckpointHash: bytes(certificate.previous_checkpoint_hash),
    checkpointHash: bytes(certificate.checkpoint_hash),
    nodeId: bytes(certificate.node_id),
    nodeMlDsaPublicKey: bytes(certificate.node_mldsa_public_key),
    nodeMlDsaSignature: bytes(certificate.node_mldsa_signature),
  };
}

function ledgerDescriptorFromWire(ledger: V2LedgerDescriptorWire): LedgerDescriptor {
  return {
    ledgerId: ledger.ledger_id,
    displayName: ledger.display_name,
    environment: ledger.environment,
    active: ledger.active,
    createdAtUnixMs: BigInt(ledger.created_at_unix_ms),
    authorizedSignerActorIds: ledger.authorized_signer_actor_ids.map(bytes),
  };
}

function sealedArtifactFromStored(stored: StoredBlob): V2SealedArtifactWire {
  return {
    artifact_root: Buffer.from(stored.meta.topRoot),
    hpke_encapsulation: Buffer.from(stored.meta.encKey),
    plaintext_len: stored.meta.plaintextLen.toString(),
    hpke_plaintext_len: (stored.meta.hpkePlaintextLen ?? stored.meta.plaintextLen).toString(),
    ciphertext_len: stored.meta.ciphertextLen.toString(),
    data_shards: stored.meta.dataShards,
    parity_shards: stored.meta.parityShards,
    sealed_shard_size: stored.meta.sealedShardSize.toString(),
    raw_shard_size: stored.meta.rawShardSize.toString(),
    provider_ids: stored.meta.providerIds.map(Buffer.from),
    ciphertext_digest: Buffer.from(stored.meta.ciphertextDigest),
    compression_codec: stored.meta.compressionCodec ?? "",
    shards: stored.blob.shards.map((shard) => ({
      index: shard.index,
      global_bao_outboard: Buffer.from(shard.outboard),
      sealed_data: Buffer.from(shard.data),
    })),
  };
}

function storedFromSealedArtifact(artifact: V2SealedArtifactWire): StoredBlob {
  const topRoot = bytes(artifact.artifact_root);
  const encKey = bytes(artifact.hpke_encapsulation);
  const ciphertextDigest = bytes(artifact.ciphertext_digest);
  const plaintextLen = safeNumber(artifact.plaintext_len, "plaintext_len");
  const hpkePlaintextLen = safeNumber(artifact.hpke_plaintext_len, "hpke_plaintext_len");
  const ciphertextLen = safeNumber(artifact.ciphertext_len, "ciphertext_len");
  const sealedShardSize = safeNumber(artifact.sealed_shard_size, "sealed_shard_size");
  const rawShardSize = safeNumber(artifact.raw_shard_size, "raw_shard_size");
  const providerIds = artifact.provider_ids.map(bytes);
  const shards = artifact.shards.map((shard) => ({
    index: shard.index,
    outboard: bytes(shard.global_bao_outboard),
    data: bytes(shard.sealed_data),
  }));
  return {
    meta: {
      topRoot,
      encKey,
      plaintextLen,
      hpkePlaintextLen,
      compressionCodec: artifact.compression_codec || undefined,
      ciphertextLen,
      dataShards: artifact.data_shards,
      parityShards: artifact.parity_shards,
      sealedShardSize,
      rawShardSize,
      providerIds,
      ciphertextDigest,
    },
    blob: {
      topRoot,
      shards,
      encKey,
      plaintextLen,
      hpkePlaintextLen,
      compressionCodec: artifact.compression_codec || undefined,
      ciphertextLen,
      dataShards: artifact.data_shards,
      parityShards: artifact.parity_shards,
      sealedShardSize,
      rawShardSize,
      fileId: ciphertextDigest,
      providerIds,
    },
  };
}

function publicArtifactFromWire(
  artifact: V2PublicArtifactWire,
): PublicBlobMeta & { released: boolean } {
  return {
    topRoot: bytes(artifact.artifact_root),
    plaintextLen: safeNumber(artifact.plaintext_len, "plaintext_len"),
    ciphertextLen: safeNumber(artifact.ciphertext_len, "ciphertext_len"),
    dataShards: artifact.data_shards,
    parityShards: artifact.parity_shards,
    sealedShardSize: safeNumber(artifact.sealed_shard_size, "sealed_shard_size"),
    rawShardSize: safeNumber(artifact.raw_shard_size, "raw_shard_size"),
    providerIds: artifact.provider_ids.map(bytes),
    ciphertextDigest: bytes(artifact.ciphertext_digest),
    released: artifact.released,
  };
}

function storageProofFromV2Wire(proof: V2StorageProofWire): StorageProof {
  if (!proof.challenge) throw new Error("StorageProof.challenge is required");
  return {
    challenge: {
      topRoot: bytes(proof.challenge.artifact_root),
      shardIndex: proof.challenge.shard_index,
      totalShards: proof.challenge.total_shards,
      epoch: BigInt(proof.challenge.epoch),
      randomness: bytes(proof.challenge.randomness),
      blockIndices: proof.challenge.block_indices,
      fileId: bytes(proof.challenge.file_id),
      providerId: bytes(proof.challenge.provider_id),
    },
    responses: proof.responses.map((response) => ({
      index: response.index,
      replicaBlock: bytes(response.replica_block),
      baoSlice: bytes(response.bao_slice),
    })),
  };
}

function validateCapabilities(capabilities: V2CapabilitiesWire): void {
  assertLength("capabilities.node_id", capabilities.node_id, 32);
  const publicKey = bytes(capabilities.node_mldsa_public_key);
  assertLength(
    "capabilities.node_mldsa_public_key",
    publicKey,
    ml_dsa65.lengths.publicKey!,
  );
  const expectedNodeId = digestRaw(NODE_ID_DOMAIN, publicKey);
  if (!equalBytes(expectedNodeId, capabilities.node_id)) {
    throw new Error("capabilities.node_id does not match the node ML-DSA key");
  }
  if (!capabilities.authenticated_operations_required) {
    throw new Error("node does not require authenticated v2 operations");
  }
  if (!capabilities.idempotent_append || !capabilities.owner_authorized_release) {
    throw new Error("node does not advertise required Starshine v2 guarantees");
  }
  if (!capabilities.application_ledgers || !capabilities.checkpoint_inclusion_proofs) {
    throw new Error("node does not advertise application-ledger checkpoint guarantees");
  }
}


function digestParts(domain: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  const framed: Uint8Array[] = [domain];
  for (const part of parts) framed.push(u64be(BigInt(part.length)), part);
  return blake3(concat(...framed));
}

function appendRequestDigest(
  artifact: V2SealedArtifactWire,
  fileName: string,
): Uint8Array {
  return digestParts(
    APPEND_DIGEST_DOMAIN,
    artifact.artifact_root,
    artifact.hpke_encapsulation,
    u64be(BigInt(artifact.plaintext_len)),
    u64be(BigInt(artifact.hpke_plaintext_len)),
    u64be(BigInt(artifact.ciphertext_len)),
    u32be(artifact.data_shards),
    u32be(artifact.parity_shards),
    u64be(BigInt(artifact.sealed_shard_size)),
    u64be(BigInt(artifact.raw_shard_size)),
    u32be(artifact.provider_ids.length),
    ...artifact.provider_ids,
    artifact.ciphertext_digest,
    encoder.encode(artifact.compression_codec),
    u32be(artifact.shards.length),
    ...artifact.shards.flatMap((shard) => [
      u32be(shard.index),
      shard.global_bao_outboard,
      shard.sealed_data,
    ]),
    encoder.encode(fileName),
  );
}

function digestRaw(domain: Uint8Array, body: Uint8Array): Uint8Array {
  return blake3(concat(domain, body));
}

function concat(...parts: Uint8Array[]): Uint8Array {
  const output = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    output.set(part, offset);
    offset += part.length;
  }
  return output;
}

function u32be(value: number): Uint8Array {
  const output = new Uint8Array(4);
  new DataView(output.buffer).setUint32(0, value, false);
  return output;
}

function u64be(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, value, false);
  return output;
}

function base64url(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

function bytes(value: Uint8Array): Uint8Array {
  return new Uint8Array(value);
}

function assertLength(name: string, value: Uint8Array, length: number): void {
  if (value.length !== length) {
    throw new Error(`${name} must be ${length} bytes, got ${value.length}`);
  }
}

function requireLedgerId(ledgerId: string | undefined): string {
  if (!ledgerId) {
    throw new Error(
      "ledgerId is required for authenticated Starshine operations",
    );
  }
  assertUuid("ledgerId", ledgerId);
  return ledgerId;
}

function validateChainLink(name: string, sequence: bigint, previousHash: Uint8Array): void {
  if (sequence <= 0n) throw new Error(`${name} sequence must be positive`);
  const expectedLength = sequence === 1n ? 0 : 32;
  if (previousHash.length !== expectedLength) {
    throw new Error(
      `${name} previous hash must be ${expectedLength} bytes at sequence ${sequence}`,
    );
  }
}

function assertUuid(name: string, value: string): void {
  if (
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
      value,
    )
  ) {
    throw new Error(`${name} must be a UUID`);
  }
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && Buffer.from(left).equals(Buffer.from(right));
}

function safeNumber(value: string | number, name: string): number {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${name} exceeds JavaScript's safe integer range`);
  }
  return parsed;
}

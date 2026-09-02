import { createHash, randomUUID } from "node:crypto";

import {
  appendV2,
  deserializeStoredBlob,
  isLogicalContentId,
  logicalContentId,
  recoverWithProgress,
  retrieveV2,
  serializeStoredBlob,
  uploadWithProgress,
  type ClientKeys,
  type EventReceipt,
  type SerializedStoredBlob,
  type WalletFile,
} from "starshine-sdk-js";

import type { RelayConfig } from "./config.js";
import {
  FILE_MANIFEST_VERSION,
  FILE_UPLOAD_VERSION,
  type FileChunkRecord,
  type FileLedgerResult,
  type FileManifestRecord,
  type FileSealingMode,
  type FileShardPolicy,
  type FileUploadRecord,
  FileCatalog,
} from "./file_catalog.js";
import type { DurableOutbox, LocatedRecord } from "./outbox.js";
import { parseRelayEvent, type JsonValue, type RelayPrivateReference } from "./schema.js";

export const CLIENT_SEALED_CHUNK_VERSION = "void.client-sealed-chunk.v1";

export const FILE_AUDIT_EVENTS = new Set([
  "file.created", "file.uploaded", "file.viewed", "file.previewed",
  "file.downloaded", "file.exported", "file.updated", "file.version-created",
  "file.renamed", "file.moved", "file.shared", "file.unshared",
  "file.deleted", "file.released", "access.requested", "access.granted",
  "access.denied", "access.revoked", "permission.changed", "record.approved",
  "record.rejected", "record.status-changed",
]);

export interface FilePrincipal {
  service: boolean;
  subject: string;
  tenantId: string;
}

export interface GatewayRoute {
  id: string;
  server: string;
  ledgerId: string;
  wallet: WalletFile;
  keys: ClientKeys;
  expectedNode: { nodeId: Uint8Array; publicKey: Uint8Array };
  transport?: { rootCertificates: Uint8Array };
  failureDomains: number;
}

export interface CreateUploadInput {
  version: typeof FILE_UPLOAD_VERSION;
  uploadId?: string;
  tenantId?: string;
  actorId?: string;
  sourceSystem: string;
  mode: FileSealingMode;
  fileName: string;
  contentType: string;
  byteLength: number;
  chunkSize?: number;
  privateReference: RelayPrivateReference;
  shardPolicy?: FileShardPolicy;
  routeId?: string;
}

export interface ClientSealedChunkInput {
  version: typeof CLIENT_SEALED_CHUNK_VERSION;
  plaintextBytes: number;
  logicalContentId: string;
  storedBlob: SerializedStoredBlob;
}

export interface FileGatewayOptions {
  maxChunkBytes: number;
  maxFileBytes: number;
  maxChunks: number;
  allowedShardPolicies: ReadonlySet<string>;
  defaultRouteId: string;
  scanEnabled: boolean;
}

export interface FileGatewayOperations {
  seal(
    route: GatewayRoute,
    plaintext: Uint8Array,
    policy: FileShardPolicy,
  ): Promise<SerializedStoredBlob>;
  append(
    route: GatewayRoute,
    prepared: SerializedStoredBlob,
    fileName: string,
    logicalId: string,
    requestId: string,
  ): Promise<FileLedgerResult>;
  retrieve(
    route: GatewayRoute,
    artifactRoot: Uint8Array,
    logicalId: string,
    requestId: string,
  ): Promise<{ stored: SerializedStoredBlob; receipt: FileLedgerResult }>;
  recover(route: GatewayRoute, stored: SerializedStoredBlob): Promise<Uint8Array>;
}

export class FileConflictError extends Error {}
export class FileNotFoundError extends Error {}
export class FileAuthorizationError extends Error {}

export class FileGateway {
  private readonly locks = new Map<string, Promise<void>>();

  constructor(
    private readonly options: FileGatewayOptions,
    private readonly catalog: FileCatalog,
    private readonly outbox: DurableOutbox,
    private readonly routes: ReadonlyMap<string, GatewayRoute>,
    private readonly operations: FileGatewayOperations = defaultOperations,
  ) {
    if (!routes.has(options.defaultRouteId)) {
      throw new Error(`default gateway route ${options.defaultRouteId} is not configured`);
    }
  }

  async create(value: unknown, principal: FilePrincipal): Promise<unknown> {
    const input = parseCreateUpload(value, this.options, this.routes);
    const tenantId = principal.service
      ? bounded(input.tenantId, "tenantId", 128)
      : principal.tenantId;
    const actorId = principal.service
      ? bounded(input.actorId, "actorId", 256)
      : principal.subject;
    const uploadId = input.uploadId ?? randomUUID();
    const route = this.routes.get(input.routeId ?? this.options.defaultRouteId)!;
    const shardPolicy = input.shardPolicy ?? policyFromKey(first(this.options.allowedShardPolicies));
    const chunkSize = input.chunkSize ?? Math.min(this.options.maxChunkBytes, Math.max(input.byteLength, 1));
    const chunkCount = input.byteLength === 0 ? 0 : Math.ceil(input.byteLength / chunkSize);
    if (chunkCount > this.options.maxChunks) {
      throw new Error(`upload requires ${chunkCount} chunks; maximum is ${this.options.maxChunks}`);
    }
    const now = new Date().toISOString();
    const candidate: FileUploadRecord = {
      version: FILE_UPLOAD_VERSION,
      uploadId,
      status: "uploading",
      createdAt: now,
      updatedAt: now,
      tenantId,
      actorId,
      sourceSystem: input.sourceSystem,
      mode: input.mode,
      fileName: input.fileName,
      contentType: input.contentType,
      byteLength: input.byteLength,
      chunkSize,
      chunkCount,
      privateReference: input.privateReference,
      shardPolicy,
      routeId: route.id,
      failureDomains: route.failureDomains,
      chunks: {},
    };
    const record = await this.catalog.create(candidate);
    if (uploadDescriptor(record) !== uploadDescriptor(candidate)) {
      throw new FileConflictError("uploadId is already bound to a different upload descriptor");
    }
    this.authorize(record, principal);
    return this.view(record);
  }

  async putChunk(
    uploadId: string,
    index: number,
    body: Uint8Array | unknown,
    principal: FilePrincipal,
  ): Promise<unknown> {
    return this.withLock(uploadId, async () => {
      const record = this.requireUpload(uploadId, principal);
      if (record.status === "complete") throw new FileConflictError("upload is already complete");
      assertChunkIndex(record, index);
      const route = this.routes.get(record.routeId)!;
      let byteLength: number;
      let fingerprint: string;
      let logicalId: string;
      let prepared: SerializedStoredBlob;
      if (record.mode === "gateway-sealed") {
        if (!(body instanceof Uint8Array)) throw new Error("gateway-sealed chunks require a binary body");
        byteLength = body.length;
        assertChunkLength(record, index, byteLength);
        fingerprint = digest(body);
        logicalId = logicalContentId(body, `void-file-chunk:${record.tenantId}`);
        const existing = record.chunks[String(index)];
        if (existing) return this.resumeChunk(record, existing, route, fingerprint);
        prepared = await this.operations.seal(route, body, record.shardPolicy);
      } else {
        const input = parseClientChunk(body);
        byteLength = input.plaintextBytes;
        assertChunkLength(record, index, byteLength);
        if (!isLogicalContentId(input.logicalContentId)) {
          throw new Error("logicalContentId must be a Starshine logical content ID");
        }
        logicalId = input.logicalContentId;
        const parsed = deserializeStoredBlob(input.storedBlob, {
          allowedShardPolicies: this.options.allowedShardPolicies,
          maxDecodedBytes: this.options.maxChunkBytes * 8 + 64 * 1024 * 1024,
        });
        if (
          parsed.meta.dataShards !== record.shardPolicy.dataShards ||
          parsed.meta.parityShards !== record.shardPolicy.parityShards
        ) throw new Error("client chunk shard policy does not match upload policy");
        if (parsed.meta.plaintextLen !== byteLength) {
          throw new Error("client chunk plaintext length does not match its sealed metadata");
        }
        prepared = serializeStoredBlob(parsed);
        fingerprint = digest(new TextEncoder().encode(JSON.stringify({
          version: CLIENT_SEALED_CHUNK_VERSION,
          plaintextBytes: byteLength,
          logicalContentId: logicalId,
          storedBlob: prepared,
        })));
        const existing = record.chunks[String(index)];
        if (existing) return this.resumeChunk(record, existing, route, fingerprint);
      }
      const chunk: FileChunkRecord = {
        index,
        byteLength,
        fingerprint,
        logicalContentId: logicalId,
        requestId: deterministicUuid("void:file-chunk:v1", uploadId, String(index)),
        prepared,
      };
      record.chunks[String(index)] = chunk;
      record.updatedAt = new Date().toISOString();
      await this.catalog.save(record);
      return this.resumeChunk(record, chunk, route, fingerprint);
    });
  }

  async complete(uploadId: string, principal: FilePrincipal): Promise<unknown> {
    return this.withLock(uploadId, async () => {
      const record = this.requireUpload(uploadId, principal);
      const route = this.routes.get(record.routeId)!;
      for (let index = 0; index < record.chunkCount; index += 1) {
        const chunk = record.chunks[String(index)];
        if (!chunk?.result) throw new FileConflictError(`chunk ${index} is not ledgered`);
      }
      const total = Object.values(record.chunks).reduce((sum, chunk) => sum + chunk.byteLength, 0);
      if (total !== record.byteLength) throw new FileConflictError("uploaded byte total does not match file size");
      if (!record.manifest) {
        const manifestBytes = manifestPayload(record);
        const manifest: FileManifestRecord = {
          requestId: deterministicUuid("void:file-manifest:v1", uploadId),
          logicalContentId: logicalContentId(manifestBytes, `void-file-manifest:${record.tenantId}`),
          prepared: await this.operations.seal(route, manifestBytes, record.shardPolicy),
        };
        record.manifest = manifest;
        record.updatedAt = new Date().toISOString();
        await this.catalog.save(record);
      }
      if (!record.manifest.result) {
        if (!record.manifest.prepared) throw new Error("prepared file manifest is missing");
        record.manifest.result = await this.operations.append(
          route,
          record.manifest.prepared,
          `${safeFilePart(record.fileName)}.void-manifest.json`,
          record.manifest.logicalContentId,
          record.manifest.requestId,
        );
      }
      delete record.manifest.prepared;
      record.completedAt ??= record.manifest.result.acceptedAt;
      await this.enqueueCompletionAudit(record);
      record.status = "complete";
      record.updatedAt = record.completedAt;
      await this.catalog.save(record);
      return this.view(record);
    });
  }

  detail(uploadId: string, principal: FilePrincipal): unknown {
    return this.view(this.requireUpload(uploadId, principal));
  }

  search(query: string, limit: number, principal: FilePrincipal): unknown {
    const tenant = principal.service ? undefined : principal.tenantId;
    return {
      version: FILE_UPLOAD_VERSION,
      query,
      uploads: this.catalog.list(query, limit, tenant).map((record) => this.view(record)),
    };
  }

  async retrieveChunk(uploadId: string, index: number, principal: FilePrincipal): Promise<
    | { mode: "gateway-sealed"; body: Uint8Array; contentType: string; receipt: FileLedgerResult }
    | { mode: "client-sealed"; body: SerializedStoredBlob; receipt: FileLedgerResult }
  > {
    return this.withLock(uploadId, async () => {
      const record = this.requireUpload(uploadId, principal);
      assertChunkIndex(record, index);
      const chunk = record.chunks[String(index)];
      if (!chunk?.result) throw new FileNotFoundError("file chunk is not ledgered");
      const route = this.routes.get(record.routeId)!;
      const artifactRoot = decodeRoot(chunk.result.artifactRoot);
      const requestId = randomUUID();
      const fetched = await this.operations.retrieve(
        route,
        artifactRoot,
        chunk.logicalContentId,
        requestId,
      );
      const receipt = fetched.receipt;
      if (record.mode === "client-sealed") {
        return { mode: record.mode, body: fetched.stored, receipt };
      }
      const plaintext = await this.operations.recover(route, fetched.stored);
      if (plaintext.length !== chunk.byteLength) throw new Error("retrieved chunk length mismatch");
      return { mode: record.mode, body: plaintext, contentType: record.contentType, receipt };
    });
  }

  async action(uploadId: string, value: unknown, principal: FilePrincipal): Promise<unknown> {
    const record = this.requireUpload(uploadId, principal);
    const input = parseAction(value);
    const envelope = parseRelayEvent({
      version: "void.relay.event.v1",
      sourceSystem: record.sourceSystem,
      sourceEventId: input.sourceEventId,
      eventType: input.eventType,
      occurredAt: input.occurredAt,
      subject: { type: "file", id: uploadId },
      privateReference: record.privateReference,
      data: {
        ...(input.data ?? {}),
        uploadId,
        actorId: principal.service ? (input.actorId ?? record.actorId) : principal.subject,
        tenantId: record.tenantId,
      },
      metadata: {
        fileGatewayVersion: FILE_UPLOAD_VERSION,
        routeId: record.routeId,
      },
    });
    const located = await this.outbox.enqueue(envelope);
    return actionView(envelope.sourceEventId, located);
  }

  private async resumeChunk(
    record: FileUploadRecord,
    chunk: FileChunkRecord,
    route: GatewayRoute,
    fingerprint: string,
  ): Promise<unknown> {
    if (chunk.fingerprint !== fingerprint) {
      throw new FileConflictError(`chunk ${chunk.index} is already bound to different bytes`);
    }
    if (!chunk.result) {
      if (!chunk.prepared) throw new Error(`prepared chunk ${chunk.index} is missing`);
      chunk.result = await this.operations.append(
        route,
        chunk.prepared,
        `${safeFilePart(record.fileName)}.part-${String(chunk.index).padStart(6, "0")}`,
        chunk.logicalContentId,
        chunk.requestId,
      );
      delete chunk.prepared;
      record.updatedAt = new Date().toISOString();
      await this.catalog.save(record);
    }
    return { version: FILE_UPLOAD_VERSION, uploadId: record.uploadId, chunk: chunkView(chunk) };
  }

  private async enqueueCompletionAudit(record: FileUploadRecord): Promise<void> {
    const sourceEventId = deterministicUuid("void:file-audit:uploaded:v1", record.uploadId);
    await this.outbox.enqueue(parseRelayEvent({
      version: "void.relay.event.v1",
      sourceSystem: record.sourceSystem,
      sourceEventId,
      eventType: "file.uploaded",
      occurredAt: record.completedAt ?? record.manifest?.result?.acceptedAt ?? record.createdAt,
      subject: { type: "file", id: record.uploadId },
      privateReference: record.privateReference,
      data: {
        uploadId: record.uploadId,
        actorId: record.actorId,
        tenantId: record.tenantId,
        mode: record.mode,
        byteLength: record.byteLength,
        chunkCount: record.chunkCount,
        manifestArtifactRoot: record.manifest?.result?.artifactRoot ?? "",
      },
      metadata: {
        fileGatewayVersion: FILE_UPLOAD_VERSION,
        routeId: record.routeId,
      },
    }));
  }

  private requireUpload(uploadId: string, principal: FilePrincipal): FileUploadRecord {
    if (!UUID.test(uploadId)) throw new Error("uploadId must be a UUID");
    const record = this.catalog.get(uploadId);
    if (!record) throw new FileNotFoundError("file upload not found");
    this.authorize(record, principal);
    return record;
  }

  private authorize(record: FileUploadRecord, principal: FilePrincipal): void {
    if (!principal.service && record.tenantId !== principal.tenantId) {
      throw new FileAuthorizationError("file capability belongs to another tenant");
    }
  }

  private view(record: FileUploadRecord): unknown {
    return {
      version: record.version,
      uploadId: record.uploadId,
      status: record.status,
      createdAt: record.createdAt,
      updatedAt: record.updatedAt,
      completedAt: record.completedAt,
      tenantId: record.tenantId,
      sourceSystem: record.sourceSystem,
      mode: record.mode,
      fileName: record.fileName,
      contentType: record.contentType,
      byteLength: record.byteLength,
      chunkSize: record.chunkSize,
      chunkCount: record.chunkCount,
      privateReference: record.privateReference,
      shardPolicy: record.shardPolicy,
      route: { id: record.routeId, failureDomains: record.failureDomains },
      chunks: Object.values(record.chunks).sort((a, b) => a.index - b.index).map(chunkView),
      manifest: record.manifest?.result ? {
        ...record.manifest.result,
        publicProofPath: this.options.scanEnabled
          ? `/scan?event=${encodeURIComponent(record.manifest.result.eventId)}`
          : undefined,
      } : undefined,
    };
  }

  private async withLock<T>(uploadId: string, work: () => Promise<T>): Promise<T> {
    const previous = this.locks.get(uploadId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => { release = resolve; });
    const tail = previous.then(() => current);
    this.locks.set(uploadId, tail);
    await previous;
    try {
      return await work();
    } finally {
      release();
      if (this.locks.get(uploadId) === tail) this.locks.delete(uploadId);
    }
  }
}

export function gatewayOptions(config: RelayConfig): FileGatewayOptions {
  return {
    maxChunkBytes: config.gatewayMaxChunkBytes,
    maxFileBytes: config.gatewayMaxFileBytes,
    maxChunks: config.gatewayMaxChunks,
    allowedShardPolicies: config.gatewayAllowedShardPolicies,
    defaultRouteId: config.gatewayDefaultRouteId,
    scanEnabled: config.scanEnabled,
  };
}

async function appendPrepared(
  route: GatewayRoute,
  prepared: SerializedStoredBlob,
  fileName: string,
  logicalId: string,
  requestId: string,
): Promise<FileLedgerResult> {
  const result = await appendV2(
    route.server,
    route.wallet,
    deserializeStoredBlob(prepared),
    fileName,
    logicalId,
    {
      ledgerId: route.ledgerId,
      requestId,
      expectedNode: route.expectedNode,
      transport: route.transport,
    },
  );
  return ledgerResult(result.receipt, result.artifactRoot);
}

const defaultOperations: FileGatewayOperations = {
  seal: async (route, plaintext, policy) => serializeStoredBlob(await uploadWithProgress(
    route.keys,
    plaintext,
    policy.dataShards,
    policy.parityShards,
  )),
  append: appendPrepared,
  retrieve: async (route, artifactRoot, logicalId, requestId) => {
    const fetched = await retrieveV2(route.server, route.wallet, artifactRoot, true, {
      ledgerId: route.ledgerId,
      requestId,
      logicalContentId: logicalId,
      expectedNode: route.expectedNode,
      transport: route.transport,
    });
    return {
      stored: serializeStoredBlob(fetched.stored),
      receipt: ledgerResult(fetched.receipt, artifactRoot),
    };
  },
  recover: async (route, stored) => recoverWithProgress(
    route.keys,
    deserializeStoredBlob(stored),
  ),
};

function ledgerResult(receipt: EventReceipt, artifactRoot: Uint8Array): FileLedgerResult {
  return {
    artifactRoot: Buffer.from(artifactRoot).toString("base64url"),
    eventId: receipt.eventId,
    ledgerId: receipt.ledgerId,
    requestId: receipt.requestId,
    acceptedAt: new Date(Number(receipt.acceptedAtUnixMs)).toISOString(),
  };
}

function manifestPayload(record: FileUploadRecord): Uint8Array {
  return new TextEncoder().encode(JSON.stringify({
    version: FILE_MANIFEST_VERSION,
    uploadId: record.uploadId,
    tenantId: record.tenantId,
    sourceSystem: record.sourceSystem,
    mode: record.mode,
    fileName: record.fileName,
    contentType: record.contentType,
    byteLength: record.byteLength,
    chunkSize: record.chunkSize,
    chunkCount: record.chunkCount,
    privateReference: record.privateReference,
    shardPolicy: record.shardPolicy,
    storageRoute: { id: record.routeId, failureDomains: record.failureDomains },
    chunks: Object.values(record.chunks)
      .sort((a, b) => a.index - b.index)
      .map((chunk) => ({
        index: chunk.index,
        byteLength: chunk.byteLength,
        logicalContentId: chunk.logicalContentId,
        artifactRoot: chunk.result?.artifactRoot,
        eventId: chunk.result?.eventId,
      })),
  }));
}

function parseCreateUpload(
  value: unknown,
  options: FileGatewayOptions,
  routes: ReadonlyMap<string, GatewayRoute>,
): CreateUploadInput {
  if (!isRecord(value) || value.version !== FILE_UPLOAD_VERSION) {
    throw new Error(`upload version must be ${FILE_UPLOAD_VERSION}`);
  }
  const mode = value.mode;
  if (mode !== "gateway-sealed" && mode !== "client-sealed") {
    throw new Error("mode must be gateway-sealed or client-sealed");
  }
  const byteLength = nonnegative(value.byteLength, "byteLength", options.maxFileBytes);
  const chunkSize = value.chunkSize === undefined
    ? undefined
    : positive(value.chunkSize, "chunkSize", options.maxChunkBytes);
  const routeId = value.routeId === undefined ? undefined : bounded(value.routeId, "routeId", 64);
  if (routeId && !routes.has(routeId)) throw new Error(`storage route ${routeId} is not allowed`);
  const shardPolicy = value.shardPolicy === undefined ? undefined : parsePolicy(value.shardPolicy);
  if (shardPolicy && !options.allowedShardPolicies.has(policyKey(shardPolicy))) {
    throw new Error(`shard policy ${policyKey(shardPolicy)} is not allowed`);
  }
  const input: CreateUploadInput = {
    version: FILE_UPLOAD_VERSION,
    uploadId: value.uploadId === undefined ? undefined : bounded(value.uploadId, "uploadId", 64),
    tenantId: value.tenantId === undefined ? undefined : bounded(value.tenantId, "tenantId", 128),
    actorId: value.actorId === undefined ? undefined : bounded(value.actorId, "actorId", 256),
    sourceSystem: bounded(value.sourceSystem, "sourceSystem", 128),
    mode,
    fileName: bounded(value.fileName, "fileName", 512),
    contentType: mediaType(value.contentType),
    byteLength,
    chunkSize,
    privateReference: parseReference(value.privateReference),
    shardPolicy,
    routeId,
  };
  if (input.uploadId && !UUID.test(input.uploadId)) throw new Error("uploadId must be a UUID");
  return input;
}

function parseClientChunk(value: unknown): ClientSealedChunkInput {
  if (!isRecord(value) || value.version !== CLIENT_SEALED_CHUNK_VERSION || !isRecord(value.storedBlob)) {
    throw new Error(`client-sealed chunk version must be ${CLIENT_SEALED_CHUNK_VERSION}`);
  }
  return {
    version: CLIENT_SEALED_CHUNK_VERSION,
    plaintextBytes: nonnegative(value.plaintextBytes, "plaintextBytes", Number.MAX_SAFE_INTEGER),
    logicalContentId: bounded(value.logicalContentId, "logicalContentId", 256),
    storedBlob: value.storedBlob as unknown as SerializedStoredBlob,
  };
}

function parseAction(value: unknown): {
  sourceEventId: string;
  eventType: string;
  occurredAt: string;
  actorId?: string;
  data?: Record<string, JsonValue>;
} {
  if (!isRecord(value)) throw new Error("file action must be a JSON object");
  const sourceEventId = bounded(value.sourceEventId, "sourceEventId", 64);
  if (!UUID.test(sourceEventId)) throw new Error("sourceEventId must be a UUID");
  const eventType = bounded(value.eventType, "eventType", 128);
  if (!FILE_AUDIT_EVENTS.has(eventType)) throw new Error(`unsupported file audit event ${eventType}`);
  const occurredAt = bounded(value.occurredAt, "occurredAt", 64);
  if (!Number.isFinite(Date.parse(occurredAt))) throw new Error("occurredAt must be an ISO-8601 timestamp");
  const data = value.data === undefined ? undefined : jsonRecord(value.data, "data");
  return {
    sourceEventId,
    eventType,
    occurredAt: new Date(occurredAt).toISOString(),
    actorId: value.actorId === undefined ? undefined : bounded(value.actorId, "actorId", 256),
    data,
  };
}

function parseReference(value: unknown): RelayPrivateReference {
  if (!isRecord(value)) throw new Error("privateReference must be an object");
  if (!Array.isArray(value.aliases) || value.aliases.length > 16) {
    throw new Error("privateReference.aliases must contain at most 16 strings");
  }
  const aliases = value.aliases.map((entry, index) => bounded(entry, `aliases[${index}]`, 256));
  if (new Set(aliases.map((entry) => entry.normalize("NFKC").toLowerCase())).size !== aliases.length) {
    throw new Error("privateReference.aliases must be unique");
  }
  return {
    kind: bounded(value.kind, "privateReference.kind", 64),
    externalId: bounded(value.externalId, "privateReference.externalId", 256),
    label: bounded(value.label, "privateReference.label", 256),
    aliases,
  };
}

function parsePolicy(value: unknown): FileShardPolicy {
  if (!isRecord(value)) throw new Error("shardPolicy must be an object");
  const dataShards = positive(value.dataShards, "shardPolicy.dataShards", 254);
  const parityShards = positive(value.parityShards, "shardPolicy.parityShards", 254);
  if (dataShards + parityShards > 255) throw new Error("total shard count exceeds 255");
  return { dataShards, parityShards };
}

function assertChunkIndex(record: FileUploadRecord, index: number): void {
  if (!Number.isInteger(index) || index < 0 || index >= record.chunkCount) {
    throw new Error(`chunk index must be between 0 and ${Math.max(0, record.chunkCount - 1)}`);
  }
}

function assertChunkLength(record: FileUploadRecord, index: number, length: number): void {
  const expected = index === record.chunkCount - 1
    ? record.byteLength - index * record.chunkSize
    : record.chunkSize;
  if (length !== expected) throw new Error(`chunk ${index} must contain exactly ${expected} plaintext bytes`);
}

function uploadDescriptor(record: FileUploadRecord): string {
  return JSON.stringify({
    tenantId: record.tenantId,
    actorId: record.actorId,
    sourceSystem: record.sourceSystem,
    mode: record.mode,
    fileName: record.fileName,
    contentType: record.contentType,
    byteLength: record.byteLength,
    chunkSize: record.chunkSize,
    chunkCount: record.chunkCount,
    privateReference: record.privateReference,
    shardPolicy: record.shardPolicy,
    routeId: record.routeId,
  });
}

function chunkView(chunk: FileChunkRecord): unknown {
  return {
    index: chunk.index,
    byteLength: chunk.byteLength,
    status: chunk.result ? "ledgered" : "prepared",
    logicalContentId: chunk.logicalContentId,
    artifactRoot: chunk.result?.artifactRoot,
    eventId: chunk.result?.eventId,
    ledgerId: chunk.result?.ledgerId,
  };
}

function actionView(sourceEventId: string, located: LocatedRecord): unknown {
  return { sourceEventId, status: located.status, record: located.value };
}

function deterministicUuid(domain: string, ...values: string[]): string {
  const bytes = createHash("sha256").update(domain).update("\0").update(values.join("\0")).digest().subarray(0, 16);
  bytes[6] = (bytes[6]! & 0x0f) | 0x50;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString("hex");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function digest(value: Uint8Array): string {
  return createHash("sha256").update(value).digest("base64url");
}

function decodeRoot(value: string): Uint8Array {
  const bytes = new Uint8Array(Buffer.from(value, "base64url"));
  if (bytes.length !== 32) throw new Error("stored artifact root is invalid");
  return bytes;
}

function policyKey(policy: FileShardPolicy): string {
  return `${policy.dataShards}+${policy.parityShards}`;
}

function policyFromKey(value: string): FileShardPolicy {
  const [dataShards, parityShards] = value.split("+").map(Number);
  return { dataShards: dataShards!, parityShards: parityShards! };
}

function first<T>(values: ReadonlySet<T>): T {
  const value = values.values().next().value as T | undefined;
  if (value === undefined) throw new Error("at least one gateway shard policy is required");
  return value;
}

function bounded(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new Error(`${name} must be a non-empty string of at most ${maximum} characters`);
  }
  return value.trim();
}

function mediaType(value: unknown): string {
  const parsed = bounded(value, "contentType", 256).toLowerCase();
  if (!/^[a-z0-9!#$&^_.+-]+\/[a-z0-9!#$&^_.+-]+$/.test(parsed)) {
    throw new Error("contentType must be a media type without parameters");
  }
  return parsed;
}

function nonnegative(value: unknown, name: string, maximum: number): number {
  if (!Number.isSafeInteger(value) || (value as number) < 0 || (value as number) > maximum) {
    throw new Error(`${name} must be an integer between 0 and ${maximum}`);
  }
  return value as number;
}

function positive(value: unknown, name: string, maximum: number): number {
  const parsed = nonnegative(value, name, maximum);
  if (parsed < 1) throw new Error(`${name} must be positive`);
  return parsed;
}

function jsonRecord(value: unknown, name: string): Record<string, JsonValue> {
  JSON.stringify(value, (_key, entry: unknown) => {
    if (typeof entry === "number" && !Number.isFinite(entry)) throw new Error(`${name} must contain JSON values`);
    if (typeof entry === "bigint" || typeof entry === "undefined" || typeof entry === "function") {
      throw new Error(`${name} must contain JSON values`);
    }
    return entry;
  });
  if (!isRecord(value)) throw new Error(`${name} must be an object`);
  return value as Record<string, JsonValue>;
}

function safeFilePart(value: string): string {
  return value.replace(/[^a-z0-9._-]+/gi, "-").slice(0, 96) || "file";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

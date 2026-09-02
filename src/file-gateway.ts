import { createRequestId, logicalContentId } from "./identity.js";
import type { ClientKeys } from "./keys.js";
import { recoverWithProgress } from "./recovery.js";
import {
  deserializeStoredBlob,
  serializeStoredBlob,
  type SerializedStoredBlob,
} from "./serialized.js";
import { uploadWithProgress } from "./upload.js";

export const FILE_UPLOAD_VERSION = "void.file-upload.v1";
export const CLIENT_SEALED_CHUNK_VERSION = "void.client-sealed-chunk.v1";

export const FILE_AUDIT_EVENT_TYPES = [
  "file.created", "file.uploaded", "file.viewed", "file.previewed",
  "file.downloaded", "file.exported", "file.updated", "file.version-created",
  "file.renamed", "file.moved", "file.shared", "file.unshared",
  "file.deleted", "file.released", "access.requested", "access.granted",
  "access.denied", "access.revoked", "permission.changed", "record.approved",
  "record.rejected", "record.status-changed",
] as const;

export type FileAuditEventType = typeof FILE_AUDIT_EVENT_TYPES[number];
export type FileSealingMode = "gateway-sealed" | "client-sealed";

export interface FilePrivateReference {
  kind: string;
  externalId: string;
  label: string;
  aliases: string[];
}

export interface FileShardPolicy {
  dataShards: number;
  parityShards: number;
}

export interface CreateFileUpload {
  version?: typeof FILE_UPLOAD_VERSION;
  uploadId?: string;
  tenantId?: string;
  actorId?: string;
  sourceSystem: string;
  mode: FileSealingMode;
  fileName: string;
  contentType: string;
  byteLength: number;
  chunkSize?: number;
  privateReference: FilePrivateReference;
  shardPolicy?: FileShardPolicy;
  routeId?: string;
}

export interface FileUploadView {
  version: typeof FILE_UPLOAD_VERSION;
  uploadId: string;
  status: "uploading" | "complete";
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  tenantId: string;
  sourceSystem: string;
  mode: FileSealingMode;
  fileName: string;
  contentType: string;
  byteLength: number;
  chunkSize: number;
  chunkCount: number;
  privateReference: FilePrivateReference;
  shardPolicy: FileShardPolicy;
  route: { id: string; failureDomains: number };
  chunks: Array<{
    index: number;
    byteLength: number;
    status: "prepared" | "ledgered";
    logicalContentId: string;
    artifactRoot?: string;
    eventId?: string;
    ledgerId?: string;
  }>;
  manifest?: {
    artifactRoot: string;
    eventId: string;
    ledgerId: string;
    requestId: string;
    acceptedAt: string;
    publicProofPath?: string;
  };
}

export interface FileGatewayClientOptions {
  baseUrl: string;
  /** Complete Authorization value: `Bearer …` or `VoidCapability …`. */
  authorization: string | (() => string | Promise<string>);
  fetch?: typeof fetch;
}

export class FileGatewayClient {
  private readonly baseUrl: URL;
  private readonly request: typeof fetch;

  constructor(private readonly options: FileGatewayClientOptions) {
    this.baseUrl = gatewayUrl(options.baseUrl);
    this.request = options.fetch ?? fetch;
  }

  async createUpload(input: CreateFileUpload): Promise<FileUploadView> {
    return this.json<FileUploadView>("/v1/files/uploads", {
      method: "POST",
      body: JSON.stringify({ ...input, version: FILE_UPLOAD_VERSION }),
      headers: { "content-type": "application/json" },
    });
  }

  async uploadGatewayChunk(
    uploadId: string,
    index: number,
    plaintext: Uint8Array,
  ): Promise<unknown> {
    return this.json(`/v1/files/uploads/${encodeURIComponent(uploadId)}/chunks/${index}`, {
      method: "PUT",
      body: Buffer.from(plaintext),
      headers: { "content-type": "application/octet-stream" },
    });
  }

  async uploadClientSealedChunk(
    uploadId: string,
    index: number,
    plaintext: Uint8Array,
    keys: ClientKeys,
    policy: FileShardPolicy,
    logicalNamespace = "void-file-client-chunk",
  ): Promise<unknown> {
    const stored = await uploadWithProgress(
      keys,
      plaintext,
      policy.dataShards,
      policy.parityShards,
    );
    return this.json(`/v1/files/uploads/${encodeURIComponent(uploadId)}/chunks/${index}`, {
      method: "PUT",
      body: JSON.stringify({
        version: CLIENT_SEALED_CHUNK_VERSION,
        plaintextBytes: plaintext.length,
        logicalContentId: logicalContentId(plaintext, logicalNamespace),
        storedBlob: serializeStoredBlob(stored),
      }),
      headers: { "content-type": "application/json" },
    });
  }

  async completeUpload(uploadId: string): Promise<FileUploadView> {
    return this.json<FileUploadView>(
      `/v1/files/uploads/${encodeURIComponent(uploadId)}/complete`,
      { method: "POST" },
    );
  }

  async upload(uploadId: string): Promise<FileUploadView> {
    return this.json(`/v1/files/uploads/${encodeURIComponent(uploadId)}`);
  }

  async search(query: string, limit = 25): Promise<{ uploads: FileUploadView[] }> {
    return this.json(`/v1/files?query=${encodeURIComponent(query)}&limit=${limit}`);
  }

  async retrieveGatewayChunk(uploadId: string, index: number): Promise<Uint8Array> {
    const response = await this.fetch(
      `/v1/files/uploads/${encodeURIComponent(uploadId)}/chunks/${index}`,
    );
    return new Uint8Array(await response.arrayBuffer());
  }

  async retrieveClientSealedChunk(
    uploadId: string,
    index: number,
  ): Promise<SerializedStoredBlob> {
    const response = await this.fetch(
      `/v1/files/uploads/${encodeURIComponent(uploadId)}/chunks/${index}`,
    );
    const value = await response.json() as { version?: string; storedBlob?: SerializedStoredBlob };
    if (value.version !== CLIENT_SEALED_CHUNK_VERSION || !value.storedBlob) {
      throw new Error("gateway returned an invalid client-sealed chunk");
    }
    deserializeStoredBlob(value.storedBlob);
    return value.storedBlob;
  }

  async recoverClientSealedChunk(
    uploadId: string,
    index: number,
    keys: ClientKeys,
  ): Promise<Uint8Array> {
    const stored = await this.retrieveClientSealedChunk(uploadId, index);
    return recoverWithProgress(keys, deserializeStoredBlob(stored));
  }

  async recordAction(
    uploadId: string,
    eventType: FileAuditEventType,
    options: {
      sourceEventId?: string;
      occurredAt?: string;
      actorId?: string;
      data?: Record<string, unknown>;
    } = {},
  ): Promise<unknown> {
    return this.json(`/v1/files/uploads/${encodeURIComponent(uploadId)}/actions`, {
      method: "POST",
      body: JSON.stringify({
        sourceEventId: options.sourceEventId ?? createRequestId(),
        eventType,
        occurredAt: options.occurredAt ?? new Date().toISOString(),
        actorId: options.actorId,
        data: options.data,
      }),
      headers: { "content-type": "application/json" },
    });
  }

  async mintCapability(input: {
    subject: string;
    tenantId: string;
    scopes: string[];
    uploadId?: string;
    ttlSeconds?: number;
  }): Promise<{ token: string; capability: unknown }> {
    return this.json("/v1/capabilities", {
      method: "POST",
      body: JSON.stringify(input),
      headers: { "content-type": "application/json" },
    });
  }

  private async json<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
    const response = await this.fetch(path, init);
    return response.json() as Promise<T>;
  }

  private async fetch(path: string, init: RequestInit = {}): Promise<Response> {
    const authorization = typeof this.options.authorization === "function"
      ? await this.options.authorization()
      : this.options.authorization;
    if (!authorization.trim()) throw new Error("file gateway authorization is required");
    const headers = new Headers(init.headers);
    headers.set("authorization", authorization);
    headers.set("accept", "application/json, application/octet-stream");
    const response = await this.request(new URL(path, this.baseUrl), { ...init, headers });
    if (!response.ok) {
      let message = `${response.status} ${response.statusText}`;
      try {
        const value = await response.json() as { error?: unknown };
        if (typeof value.error === "string") message = value.error;
      } catch {
        // Keep the status message when the server did not return JSON.
      }
      throw new Error(`file gateway request failed: ${message}`);
    }
    return response;
  }
}

function gatewayUrl(value: string): URL {
  const parsed = new URL(value);
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("file gateway URL must not include credentials, query, or fragment");
  }
  const loopback = parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
  if (parsed.protocol !== "https:" && !(loopback && parsed.protocol === "http:")) {
    throw new Error("file gateway requires HTTPS except on loopback");
  }
  if (!parsed.pathname.endsWith("/")) parsed.pathname += "/";
  return parsed;
}

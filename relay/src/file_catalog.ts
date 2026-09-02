import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { mkdir, open, readFile, readdir, rename, stat } from "node:fs/promises";
import path from "node:path";

import type { SerializedStoredBlob } from "starshine-sdk-js";
import type { RelayPrivateReference } from "./schema.js";

export const FILE_UPLOAD_VERSION = "void.file-upload.v1";
export const FILE_MANIFEST_VERSION = "void.file-manifest.v1";

export type FileSealingMode = "gateway-sealed" | "client-sealed";
export type FileUploadStatus = "uploading" | "complete";

export interface FileShardPolicy {
  dataShards: number;
  parityShards: number;
}

export interface FileLedgerResult {
  artifactRoot: string;
  eventId: string;
  ledgerId: string;
  requestId: string;
  acceptedAt: string;
}

export interface FileChunkRecord {
  index: number;
  byteLength: number;
  fingerprint: string;
  logicalContentId: string;
  requestId: string;
  prepared?: SerializedStoredBlob;
  result?: FileLedgerResult;
}

export interface FileManifestRecord {
  requestId: string;
  logicalContentId: string;
  prepared?: SerializedStoredBlob;
  result?: FileLedgerResult;
}

export interface FileUploadRecord {
  version: typeof FILE_UPLOAD_VERSION;
  uploadId: string;
  status: FileUploadStatus;
  createdAt: string;
  updatedAt: string;
  completedAt?: string;
  tenantId: string;
  actorId: string;
  sourceSystem: string;
  mode: FileSealingMode;
  fileName: string;
  contentType: string;
  byteLength: number;
  chunkSize: number;
  chunkCount: number;
  privateReference: RelayPrivateReference;
  shardPolicy: FileShardPolicy;
  routeId: string;
  failureDomains: number;
  chunks: Record<string, FileChunkRecord>;
  manifest?: FileManifestRecord;
}

export class FileCatalog {
  private readonly directory: string;
  private readonly encryptionKey: Buffer;
  private readonly records = new Map<string, FileUploadRecord>();

  constructor(root: string, rootKey: Uint8Array) {
    if (rootKey.length !== 32) throw new Error("file catalog root key must be 32 bytes");
    this.directory = path.join(path.resolve(root), "files");
    this.encryptionKey = Buffer.from(hkdfSync(
      "sha256",
      rootKey,
      Buffer.alloc(0),
      "void:file-catalog:v1",
      32,
    ));
  }

  async initialize(): Promise<void> {
    await mkdir(this.directory, { recursive: true, mode: 0o700 });
    this.records.clear();
    for (const file of await readdir(this.directory)) {
      if (!file.endsWith(".json")) continue;
      const id = file.slice(0, -5);
      const record = this.decrypt(await readFile(path.join(this.directory, file)), id);
      this.records.set(id, record);
    }
  }

  get(uploadId: string): FileUploadRecord | undefined {
    const value = this.records.get(uploadId);
    return value ? structuredClone(value) : undefined;
  }

  list(query: string, limit: number, tenantId?: string): FileUploadRecord[] {
    const needle = searchable(query);
    return [...this.records.values()]
      .filter((record) => !tenantId || record.tenantId === tenantId)
      .map((record) => ({ record, score: fileScore(needle, record) }))
      .filter((entry): entry is { record: FileUploadRecord; score: number } => entry.score !== undefined)
      .sort((left, right) =>
        left.score - right.score ||
        right.record.updatedAt.localeCompare(left.record.updatedAt) ||
        left.record.uploadId.localeCompare(right.record.uploadId)
      )
      .slice(0, limit)
      .map(({ record }) => structuredClone(record));
  }

  async create(record: FileUploadRecord): Promise<FileUploadRecord> {
    const current = this.records.get(record.uploadId);
    if (current) return structuredClone(current);
    const destination = this.file(record.uploadId);
    try {
      await durableCreate(destination, this.encrypt(record));
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error;
      const existing = this.decrypt(await readFile(destination), record.uploadId);
      this.records.set(record.uploadId, existing);
      return structuredClone(existing);
    }
    this.records.set(record.uploadId, structuredClone(record));
    return structuredClone(record);
  }

  async save(record: FileUploadRecord): Promise<void> {
    await atomicReplace(this.file(record.uploadId), this.encrypt(record));
    this.records.set(record.uploadId, structuredClone(record));
  }

  async existsOnDisk(uploadId: string): Promise<boolean> {
    try {
      await stat(this.file(uploadId));
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }

  private file(uploadId: string): string {
    return path.join(this.directory, `${uploadId}.json`);
  }

  private encrypt(record: FileUploadRecord): string {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.encryptionKey, nonce);
    cipher.setAAD(Buffer.from(record.uploadId, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(record), "utf8"),
      cipher.final(),
    ]);
    return JSON.stringify({
      version: 1,
      algorithm: "AES-256-GCM",
      nonce: nonce.toString("base64url"),
      tag: cipher.getAuthTag().toString("base64url"),
      ciphertext: ciphertext.toString("base64url"),
    });
  }

  private decrypt(encoded: Uint8Array, uploadId: string): FileUploadRecord {
    const value = JSON.parse(Buffer.from(encoded).toString("utf8")) as Record<string, unknown>;
    if (
      value.version !== 1 || value.algorithm !== "AES-256-GCM" ||
      typeof value.nonce !== "string" || typeof value.tag !== "string" ||
      typeof value.ciphertext !== "string"
    ) throw new Error("invalid encrypted file catalog record");
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.encryptionKey,
      Buffer.from(value.nonce, "base64url"),
    );
    decipher.setAAD(Buffer.from(uploadId, "utf8"));
    decipher.setAuthTag(Buffer.from(value.tag, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(value.ciphertext, "base64url")),
      decipher.final(),
    ]);
    const record = JSON.parse(plaintext.toString("utf8")) as FileUploadRecord;
    if (record.version !== FILE_UPLOAD_VERSION || record.uploadId !== uploadId) {
      throw new Error("invalid file catalog record identity");
    }
    return record;
  }
}

function searchable(value: string): string {
  return value.normalize("NFKC").toLocaleLowerCase("en-US").trim();
}

function fileScore(needle: string, record: FileUploadRecord): number | undefined {
  if (!needle) return 4;
  const values = [
    record.privateReference.externalId,
    record.privateReference.label,
    record.privateReference.kind,
    ...record.privateReference.aliases,
    record.fileName,
    record.uploadId,
    record.manifest?.result?.eventId ?? "",
  ].map(searchable);
  if (values[0] === needle) return 0;
  if (values.some((value) => value === needle)) return 1;
  if (values.some((value) => value.startsWith(needle))) return 2;
  const tokens = needle.split(/\s+/).filter(Boolean);
  return tokens.every((token) => values.some((value) => value.includes(token))) ? 3 : undefined;
}

async function durableCreate(destination: string, contents: string): Promise<void> {
  const file = await open(destination, "wx", 0o600);
  try {
    await file.writeFile(contents, "utf8");
    await file.sync();
  } finally {
    await file.close();
  }
}

async function atomicReplace(destination: string, contents: string): Promise<void> {
  const temporary = `${destination}.${crypto.randomUUID()}.tmp`;
  await durableCreate(temporary, contents);
  await rename(temporary, destination);
}

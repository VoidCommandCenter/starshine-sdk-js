import { open, mkdir, readFile, readdir, rename, stat, unlink } from "node:fs/promises";
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import path from "node:path";

import type { SerializedStoredBlob } from "./codec.js";
import { canonicalEventBytes, type RelayEventEnvelope } from "./schema.js";

export class IdempotencyConflictError extends Error {}

export interface RelayRecord {
  envelope: RelayEventEnvelope;
  acceptedAt: string;
  attempts: number;
  nextAttemptAt?: string;
  lastError?: string;
  logicalContentId?: string;
  prepared?: SerializedStoredBlob;
}

export type RelayStatus = "pending" | "processing" | "complete" | "dead" | "missing";

export interface LocatedRecord {
  status: RelayStatus;
  value?: unknown;
}

export class DurableOutbox {
  readonly root: string;
  private readonly encryptionKey: Uint8Array;
  private readonly directories: Record<Exclude<RelayStatus, "missing">, string>;

  constructor(root: string, encryptionKey: Uint8Array) {
    if (encryptionKey.length !== 32) {
      throw new Error("outbox encryption key must be 32 bytes");
    }
    this.root = path.resolve(root);
    this.encryptionKey = new Uint8Array(encryptionKey);
    this.directories = {
      pending: path.join(this.root, "pending"),
      processing: path.join(this.root, "processing"),
      complete: path.join(this.root, "complete"),
      dead: path.join(this.root, "dead"),
    };
  }

  async initialize(): Promise<void> {
    await Promise.all(Object.values(this.directories).map((directory) =>
      mkdir(directory, { recursive: true, mode: 0o700 })
    ));
    for (const file of await readdir(this.directories.processing)) {
      if (file.endsWith(".json")) {
        if (
          await exists(path.join(this.directories.complete, file)) ||
          await exists(path.join(this.directories.dead, file))
        ) {
          await unlink(path.join(this.directories.processing, file));
          continue;
        }
        await rename(
          path.join(this.directories.processing, file),
          path.join(this.directories.pending, file),
        );
      }
    }
  }

  async enqueue(envelope: RelayEventEnvelope): Promise<LocatedRecord> {
    const existing = await this.locate(envelope.sourceEventId);
    if (existing.status !== "missing") {
      const existingEnvelope = (existing.value as { envelope?: RelayEventEnvelope } | undefined)
        ?.envelope;
      if (
        !existingEnvelope ||
        !Buffer.from(canonicalEventBytes(existingEnvelope)).equals(
          Buffer.from(canonicalEventBytes(envelope)),
        )
      ) {
        throw new IdempotencyConflictError(
          "sourceEventId is already bound to a different event envelope",
        );
      }
      return existing;
    }
    const record: RelayRecord = {
      envelope,
      acceptedAt: new Date().toISOString(),
      attempts: 0,
    };
    const destination = this.file("pending", envelope.sourceEventId);
    try {
      await durableCreate(destination, this.encrypt(record, envelope.sourceEventId));
      return { status: "pending", value: record };
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EEXIST") {
        return this.enqueue(envelope);
      }
      throw error;
    }
  }

  async claimNext(): Promise<RelayRecord | undefined> {
    const files = (await readdir(this.directories.pending))
      .filter((file) => file.endsWith(".json"))
      .sort();
    for (const file of files) {
      const pending = path.join(this.directories.pending, file);
      const processing = path.join(this.directories.processing, file);
      let record: RelayRecord;
      try {
        record = this.decrypt(await readFile(pending), file.slice(0, -5)) as RelayRecord;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
      if (record.nextAttemptAt && Date.parse(record.nextAttemptAt) > Date.now()) continue;
      try {
        await rename(pending, processing);
        return record;
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code === "ENOENT") continue;
        throw error;
      }
    }
    return undefined;
  }

  async updateProcessing(record: RelayRecord): Promise<void> {
    await atomicReplace(
      this.file("processing", record.envelope.sourceEventId),
      this.encrypt(record, record.envelope.sourceEventId),
    );
  }

  async retry(record: RelayRecord): Promise<void> {
    await this.updateProcessing(record);
    await rename(
      this.file("processing", record.envelope.sourceEventId),
      this.file("pending", record.envelope.sourceEventId),
    );
  }

  async complete(record: RelayRecord, result: unknown): Promise<void> {
    await atomicReplace(
      this.file("complete", record.envelope.sourceEventId),
      this.encrypt(
        {
          envelope: record.envelope,
          acceptedAt: record.acceptedAt,
          completedAt: new Date().toISOString(),
          attempts: record.attempts,
          result,
        },
        record.envelope.sourceEventId,
      ),
    );
    await unlink(this.file("processing", record.envelope.sourceEventId));
  }

  async dead(record: RelayRecord): Promise<void> {
    await this.updateProcessing(record);
    await rename(
      this.file("processing", record.envelope.sourceEventId),
      this.file("dead", record.envelope.sourceEventId),
    );
  }

  async locate(id: string): Promise<LocatedRecord> {
    for (const status of ["complete", "dead", "processing", "pending"] as const) {
      const file = this.file(status, id);
      try {
        await stat(file);
        return { status, value: this.decrypt(await readFile(file), id) };
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
      }
    }
    return { status: "missing" };
  }

  private file(status: Exclude<RelayStatus, "missing">, id: string): string {
    return path.join(this.directories[status], `${id}.json`);
  }

  private encrypt(value: unknown, recordId: string): string {
    const nonce = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.encryptionKey, nonce);
    cipher.setAAD(Buffer.from(recordId, "utf8"));
    const ciphertext = Buffer.concat([
      cipher.update(JSON.stringify(value), "utf8"),
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

  private decrypt(encoded: Uint8Array, recordId: string): unknown {
    const record = JSON.parse(Buffer.from(encoded).toString("utf8")) as {
      version?: number;
      algorithm?: string;
      nonce?: string;
      tag?: string;
      ciphertext?: string;
    };
    if (
      record.version !== 1 ||
      record.algorithm !== "AES-256-GCM" ||
      !record.nonce ||
      !record.tag ||
      !record.ciphertext
    ) {
      throw new Error("invalid encrypted outbox record");
    }
    const decipher = createDecipheriv(
      "aes-256-gcm",
      this.encryptionKey,
      Buffer.from(record.nonce, "base64url"),
    );
    decipher.setAAD(Buffer.from(recordId, "utf8"));
    decipher.setAuthTag(Buffer.from(record.tag, "base64url"));
    const plaintext = Buffer.concat([
      decipher.update(Buffer.from(record.ciphertext, "base64url")),
      decipher.final(),
    ]);
    return JSON.parse(plaintext.toString("utf8")) as unknown;
  }
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

async function exists(file: string): Promise<boolean> {
  try {
    await stat(file);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
    throw error;
  }
}

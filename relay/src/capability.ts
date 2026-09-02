import { createHmac, hkdfSync, randomUUID, timingSafeEqual } from "node:crypto";

export const FILE_CAPABILITY_VERSION = "void.file-capability.v1";

export const FILE_SCOPES = [
  "files:create",
  "files:write",
  "files:read",
  "files:complete",
  "files:audit",
] as const;

export type FileScope = typeof FILE_SCOPES[number];

export interface FileCapability {
  version: typeof FILE_CAPABILITY_VERSION;
  jti: string;
  subject: string;
  tenantId: string;
  scopes: FileScope[];
  uploadId?: string;
  issuedAt: number;
  expiresAt: number;
}

export interface MintCapabilityInput {
  subject: string;
  tenantId: string;
  scopes: string[];
  uploadId?: string;
  ttlSeconds?: number;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SCOPE_SET = new Set<string>(FILE_SCOPES);

export class FileCapabilityAuthority {
  private readonly signingKey: Buffer;

  constructor(rootKey: Uint8Array, private readonly maximumTtlSeconds: number) {
    if (rootKey.length !== 32) throw new Error("capability root key must be 32 bytes");
    if (!Number.isInteger(maximumTtlSeconds) || maximumTtlSeconds < 1) {
      throw new Error("capability maximum TTL must be positive");
    }
    this.signingKey = Buffer.from(hkdfSync(
      "sha256",
      rootKey,
      Buffer.alloc(0),
      "void:file-capabilities:v1",
      32,
    ));
  }

  mint(input: MintCapabilityInput, now = Date.now()): { token: string; capability: FileCapability } {
    const subject = bounded(input.subject, "subject", 256);
    const tenantId = bounded(input.tenantId, "tenantId", 128);
    if (!Array.isArray(input.scopes) || input.scopes.length < 1) {
      throw new Error("scopes must contain at least one file scope");
    }
    const scopes = [...new Set(input.scopes)].map((scope) => {
      if (!SCOPE_SET.has(scope)) throw new Error(`unsupported file scope ${scope}`);
      return scope as FileScope;
    }).sort();
    if (input.uploadId !== undefined && !UUID.test(input.uploadId)) {
      throw new Error("uploadId must be a UUID");
    }
    const ttlSeconds = input.ttlSeconds ?? this.maximumTtlSeconds;
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 1 || ttlSeconds > this.maximumTtlSeconds) {
      throw new Error(`ttlSeconds must be between 1 and ${this.maximumTtlSeconds}`);
    }
    const issuedAt = Math.floor(now / 1000);
    const capability: FileCapability = {
      version: FILE_CAPABILITY_VERSION,
      jti: randomUUID(),
      subject,
      tenantId,
      scopes,
      uploadId: input.uploadId,
      issuedAt,
      expiresAt: issuedAt + ttlSeconds,
    };
    const payload = Buffer.from(JSON.stringify(capability)).toString("base64url");
    return { token: `${payload}.${this.sign(payload)}`, capability };
  }

  verify(
    token: string,
    requiredScope: FileScope,
    uploadId?: string,
    now = Date.now(),
  ): FileCapability {
    const parts = token.split(".");
    if (parts.length !== 2 || !parts[0] || !parts[1]) throw new Error("invalid file capability");
    const expected = Buffer.from(this.sign(parts[0]));
    const supplied = Buffer.from(parts[1]);
    if (expected.length !== supplied.length || !timingSafeEqual(expected, supplied)) {
      throw new Error("invalid file capability");
    }
    let value: unknown;
    try {
      value = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
    } catch {
      throw new Error("invalid file capability");
    }
    const capability = parseCapability(value);
    const nowSeconds = Math.floor(now / 1000);
    if (capability.issuedAt > nowSeconds + 30 || capability.expiresAt <= nowSeconds) {
      throw new Error("file capability expired or not yet valid");
    }
    if (capability.expiresAt - capability.issuedAt > this.maximumTtlSeconds) {
      throw new Error("file capability lifetime exceeds policy");
    }
    if (!capability.scopes.includes(requiredScope)) {
      throw new Error(`file capability lacks ${requiredScope}`);
    }
    if (capability.uploadId && capability.uploadId !== uploadId) {
      throw new Error("file capability is bound to another upload");
    }
    return capability;
  }

  private sign(payload: string): string {
    return createHmac("sha256", this.signingKey).update(payload).digest("base64url");
  }
}

function parseCapability(value: unknown): FileCapability {
  if (!isRecord(value) || value.version !== FILE_CAPABILITY_VERSION) {
    throw new Error("invalid file capability");
  }
  const scopes = Array.isArray(value.scopes) ? value.scopes : [];
  if (scopes.length < 1 || scopes.some((scope) => typeof scope !== "string" || !SCOPE_SET.has(scope))) {
    throw new Error("invalid file capability");
  }
  const jti = bounded(value.jti, "jti", 64);
  if (!UUID.test(jti)) throw new Error("invalid file capability");
  const uploadId = value.uploadId === undefined ? undefined : bounded(value.uploadId, "uploadId", 64);
  if (uploadId !== undefined && !UUID.test(uploadId)) throw new Error("invalid file capability");
  if (!Number.isSafeInteger(value.issuedAt) || !Number.isSafeInteger(value.expiresAt)) {
    throw new Error("invalid file capability");
  }
  return {
    version: FILE_CAPABILITY_VERSION,
    jti,
    subject: bounded(value.subject, "subject", 256),
    tenantId: bounded(value.tenantId, "tenantId", 128),
    scopes: scopes as FileScope[],
    uploadId,
    issuedAt: value.issuedAt as number,
    expiresAt: value.expiresAt as number,
  };
}

function bounded(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new Error(`${name} must be a non-empty string of at most ${maximum} characters`);
  }
  return value.trim();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

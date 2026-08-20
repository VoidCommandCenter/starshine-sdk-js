import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

export const VOID_SIGN_VERSION = 1;
export const MAX_VOID_SIGN_SKEW_MS = 5 * 60 * 1000;
export const VOID_SIGN_CONTEXT = new TextEncoder().encode(
  "starshine-void-ledger-v1",
);

export type VoidSignKind =
  | "faucet"
  | "transfer"
  | "put"
  | "get"
  | "delete";

export interface VoidSignPayload {
  v: typeof VOID_SIGN_VERSION;
  kind: VoidSignKind;
  from: string;
  to: string | null;
  amount: number;
  contentHash: string | null;
  nonce: string;
  issuedAt: string;
}

export interface VoidSignEnvelope {
  payload: VoidSignPayload;
  mldsaPublicKey: string;
  signature: string;
}

const encoder = new TextEncoder();

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

export function hexToBytes(hex: string): Uint8Array {
  const normalized = hex.trim().replace(/^0x/i, "").toLowerCase();
  if (normalized.length % 2 !== 0 || !/^[0-9a-f]+$/.test(normalized)) {
    throw new Error("invalid hex");
  }
  const out = new Uint8Array(normalized.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(normalized.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortValue);
  if (value != null && typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(obj).sort()) {
      sorted[key] = sortValue(obj[key]);
    }
    return sorted;
  }
  return value;
}

export function canonicalize(payload: VoidSignPayload): string {
  return JSON.stringify(sortValue(payload));
}

export function canonicalBytes(payload: VoidSignPayload): Uint8Array {
  return encoder.encode(canonicalize(payload));
}

function isKind(value: unknown): value is VoidSignKind {
  return (
    value === "faucet" ||
    value === "transfer" ||
    value === "put" ||
    value === "get" ||
    value === "delete"
  );
}

export function normalizeHpkePublicKey(value: string): string {
  const normalized = value.trim().replace(/^0x/i, "").toLowerCase();
  if (!/^[0-9a-f]{32,}$/.test(normalized)) {
    throw new Error("HPKE public key must be hex");
  }
  return normalized;
}

export function parseVoidSignPayload(raw: unknown): VoidSignPayload {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("signed payload must be an object");
  }
  const obj = raw as Record<string, unknown>;
  if (obj.v !== VOID_SIGN_VERSION) {
    throw new Error(`unsupported signed payload version ${String(obj.v)}`);
  }
  if (!isKind(obj.kind)) {
    throw new Error("signed payload kind is invalid");
  }
  if (typeof obj.from !== "string") {
    throw new Error("signed payload from is required");
  }
  if (obj.to != null && typeof obj.to !== "string") {
    throw new Error("signed payload to must be hex or null");
  }
  const amount = Number(obj.amount);
  if (!Number.isFinite(amount) || amount < 0) {
    throw new Error("signed payload amount must be a non-negative number");
  }
  if (obj.contentHash != null && typeof obj.contentHash !== "string") {
    throw new Error("signed payload contentHash must be hex or null");
  }
  if (typeof obj.nonce !== "string" || !obj.nonce.trim()) {
    throw new Error("signed payload nonce is required");
  }
  if (typeof obj.issuedAt !== "string" || !obj.issuedAt.trim()) {
    throw new Error("signed payload issuedAt is required");
  }
  const issuedAt = new Date(obj.issuedAt);
  if (Number.isNaN(issuedAt.getTime())) {
    throw new Error("signed payload issuedAt is invalid");
  }
  return {
    v: VOID_SIGN_VERSION,
    kind: obj.kind,
    from: normalizeHpkePublicKey(obj.from),
    to: obj.to == null || obj.to === "" ? null : normalizeHpkePublicKey(obj.to),
    amount: Math.floor(amount),
    contentHash:
      obj.contentHash == null || obj.contentHash === ""
        ? null
        : obj.contentHash.trim().replace(/^0x/i, "").toLowerCase(),
    nonce: obj.nonce.trim(),
    issuedAt: obj.issuedAt,
  };
}

export function assertFreshIssuedAt(
  issuedAt: string,
  nowMs = Date.now(),
  maxSkewMs = MAX_VOID_SIGN_SKEW_MS,
): void {
  const at = new Date(issuedAt).getTime();
  if (Number.isNaN(at)) {
    throw new Error("signed payload issuedAt is invalid");
  }
  if (Math.abs(nowMs - at) > maxSkewMs) {
    throw new Error("signed payload issuedAt is outside the allowed window");
  }
}

export function generateMlDsa65Keys(): {
  publicKeyHex: string;
  privateKeyHex: string;
} {
  const { publicKey, secretKey } = ml_dsa65.keygen();
  return {
    publicKeyHex: bytesToHex(publicKey),
    privateKeyHex: bytesToHex(secretKey),
  };
}

export function buildVoidSignPayload(input: {
  kind: VoidSignKind;
  from: string;
  to?: string | null;
  amount: number;
  contentHash?: string | null;
  nonce?: string;
  issuedAt?: string;
}): VoidSignPayload {
  return parseVoidSignPayload({
    v: VOID_SIGN_VERSION,
    kind: input.kind,
    from: input.from,
    to: input.to ?? null,
    amount: input.amount,
    contentHash: input.contentHash ?? null,
    nonce: input.nonce ?? crypto.randomUUID(),
    issuedAt: input.issuedAt ?? new Date().toISOString(),
  });
}

export function signVoidPayload(
  payload: VoidSignPayload,
  privateKeyHex: string,
): VoidSignEnvelope {
  const parsed = parseVoidSignPayload(payload);
  const signature = ml_dsa65.sign(
    canonicalBytes(parsed),
    hexToBytes(privateKeyHex),
    { context: VOID_SIGN_CONTEXT },
  );
  const publicKey = ml_dsa65.getPublicKey(hexToBytes(privateKeyHex));
  return {
    payload: parsed,
    mldsaPublicKey: bytesToHex(publicKey),
    signature: bytesToHex(signature),
  };
}

export function verifyVoidEnvelope(
  envelope: VoidSignEnvelope,
  expected?: {
    kind?: VoidSignKind;
    from?: string;
    nowMs?: number;
  },
): { payload: VoidSignPayload; canonical: string } {
  const payload = parseVoidSignPayload(envelope.payload);
  const canonical = canonicalize(payload);
  const ok = ml_dsa65.verify(
    hexToBytes(envelope.signature),
    encoder.encode(canonical),
    hexToBytes(envelope.mldsaPublicKey),
    { context: VOID_SIGN_CONTEXT },
  );
  if (!ok) {
    throw new Error("invalid ML-DSA-65 signature");
  }
  assertFreshIssuedAt(payload.issuedAt, expected?.nowMs);
  if (expected?.kind != null && payload.kind !== expected.kind) {
    throw new Error(
      `signed payload kind ${payload.kind} does not match ${expected.kind}`,
    );
  }
  if (expected?.from != null) {
    const from = normalizeHpkePublicKey(expected.from);
    if (payload.from !== from) {
      throw new Error("signed payload from does not match wallet HPKE key");
    }
  }
  return { payload, canonical };
}

export function envelopeFromHeaders(headers: {
  payload?: string;
  publicKey?: string;
  signature?: string;
}): VoidSignEnvelope {
  const payloadHeader = headers.payload?.trim();
  const publicKey = headers.publicKey?.trim();
  const signature = headers.signature?.trim();
  if (!payloadHeader || !publicKey || !signature) {
    throw new Error(
      "VOID signature headers required: X-Starshine-Void-Payload, X-Starshine-Void-Public-Key, X-Starshine-Void-Signature",
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(atob(payloadHeader));
  } catch {
    throw new Error("invalid X-Starshine-Void-Payload (expected base64 JSON)");
  }
  return {
    payload: parseVoidSignPayload(parsed),
    mldsaPublicKey: publicKey.toLowerCase().replace(/^0x/, ""),
    signature: signature.toLowerCase().replace(/^0x/, ""),
  };
}

export function envelopeToHeaders(envelope: VoidSignEnvelope): {
  "X-Starshine-Void-Payload": string;
  "X-Starshine-Void-Public-Key": string;
  "X-Starshine-Void-Signature": string;
} {
  const canonical = canonicalize(parseVoidSignPayload(envelope.payload));
  const payloadB64 = btoa(canonical);
  return {
    "X-Starshine-Void-Payload": payloadB64,
    "X-Starshine-Void-Public-Key": envelope.mldsaPublicKey,
    "X-Starshine-Void-Signature": envelope.signature,
  };
}

export function parseVoidSignEnvelope(raw: unknown): VoidSignEnvelope {
  if (raw == null || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("signed envelope must be an object");
  }
  const obj = raw as Record<string, unknown>;
  if (typeof obj.mldsaPublicKey !== "string" || typeof obj.signature !== "string") {
    throw new Error("signed envelope requires mldsaPublicKey and signature");
  }
  return {
    payload: parseVoidSignPayload(obj.payload),
    mldsaPublicKey: obj.mldsaPublicKey.trim().toLowerCase().replace(/^0x/, ""),
    signature: obj.signature.trim().toLowerCase().replace(/^0x/, ""),
  };
}

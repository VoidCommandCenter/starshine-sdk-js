import { randomUUID } from "node:crypto";

import { blake3 } from "blake3-bao";

const encoder = new TextEncoder();
const CONTENT_ID_DOMAIN = encoder.encode("starshine:logical-content:v1\0");

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const length = parts.reduce((sum, part) => sum + part.length, 0);
  const out = new Uint8Array(length);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/**
 * Generate a caller-controlled idempotency key. Persist and reuse this value
 * when retrying the same logical operation.
 */
export function createRequestId(): string {
  return randomUUID();
}

/**
 * Stable, domain-separated identity for plaintext bytes. This intentionally
 * reveals equality when shared; use a private namespace when that is sensitive.
 */
export function logicalContentId(
  plaintext: Uint8Array,
  namespace = "public",
): string {
  const normalizedNamespace = namespace.normalize("NFC").trim();
  if (!normalizedNamespace || normalizedNamespace.length > 256) {
    throw new Error("content identity namespace must contain 1-256 characters");
  }
  const digest = blake3.hash(
    concatBytes(
      CONTENT_ID_DOMAIN,
      encoder.encode(normalizedNamespace),
      new Uint8Array([0]),
      plaintext,
    ),
  );
  return `scid1:${hex(new Uint8Array(digest))}`;
}

export function isLogicalContentId(value: string): boolean {
  return /^scid1:[0-9a-f]{64}$/.test(value);
}

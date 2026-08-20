import { createHmac, randomBytes } from "node:crypto";

import { POREP_BLOCK_SIZE, replicaShardByteLen } from "./constants.js";

export const MIN_POREP_SECRET_LEN = 32;

export class PorepClientSecret {
  private readonly secret: Uint8Array;

  private constructor(secret: Uint8Array) {
    this.secret = secret;
  }

  static generate(): PorepClientSecret {
    return PorepClientSecret.fromBytes(randomBytes(MIN_POREP_SECRET_LEN));
  }

  static fromBytes(secret: Uint8Array): PorepClientSecret {
    if (secret.length < MIN_POREP_SECRET_LEN) {
      throw new Error(
        `PoRep secret must be at least ${MIN_POREP_SECRET_LEN} bytes (got ${secret.length})`,
      );
    }
    return new PorepClientSecret(secret);
  }

  asBytes(): Uint8Array {
    return this.secret;
  }
}

function hmacSha256(key: Uint8Array, data: Uint8Array): Uint8Array {
  return createHmac("sha256", key).update(data).digest();
}

function intToU64Le(value: number): Uint8Array {
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setBigUint64(0, BigInt(value), true);
  return buf;
}

export function deriveReplicaKey(
  clientSecret: Uint8Array,
  providerId: Uint8Array,
  fileId: Uint8Array,
): Uint8Array {
  const prefix = new TextEncoder().encode("PoRepV2:replica-key:v1:");
  const colon = new Uint8Array([0x3a]);
  const data = concatBytes(prefix, providerId, colon, fileId);
  return hmacSha256(clientSecret, data);
}

export function maskForBlock(
  replicaKey: Uint8Array,
  blockIndex: number,
  blockSize: number,
): Uint8Array {
  const prefix = new TextEncoder().encode("PoRepV2:block-mask:v1:");
  const output = new Uint8Array(blockSize);
  let offset = 0;
  let counter = 0;
  while (offset < blockSize) {
    const data = concatBytes(
      prefix,
      intToU64Le(blockIndex),
      intToU64Le(counter),
    );
    const digest = hmacSha256(replicaKey, data);
    const take = Math.min(digest.length, blockSize - offset);
    output.set(digest.subarray(0, take), offset);
    offset += take;
    counter += 1;
  }
  return output;
}

export function encodeShard(
  raw: Uint8Array,
  clientSecret: Uint8Array,
  providerId: Uint8Array,
  fileId: Uint8Array,
): Uint8Array {
  const replicaKey = deriveReplicaKey(clientSecret, providerId, fileId);
  const paddedLen = replicaShardByteLen(raw.length);
  const padded = new Uint8Array(paddedLen);
  padded.set(raw);

  const replica = new Uint8Array(paddedLen);
  for (let i = 0; i < paddedLen; i += POREP_BLOCK_SIZE) {
    const block = padded.subarray(i, i + POREP_BLOCK_SIZE);
    const mask = maskForBlock(replicaKey, i / POREP_BLOCK_SIZE, POREP_BLOCK_SIZE);
    for (let j = 0; j < POREP_BLOCK_SIZE; j++) {
      replica[i + j] = block[j]! ^ mask[j]!;
    }
  }
  return replica;
}

export function decodeShard(
  replica: Uint8Array,
  clientSecret: Uint8Array,
  providerId: Uint8Array,
  fileId: Uint8Array,
  rawShardSize: number,
): Uint8Array {
  const expectedLen = replicaShardByteLen(rawShardSize);
  if (replica.length !== expectedLen) {
    throw new Error(
      `replica length ${replica.length} != expected ${expectedLen}`,
    );
  }

  const replicaKey = deriveReplicaKey(clientSecret, providerId, fileId);
  const plaintext = new Uint8Array(expectedLen);
  for (let i = 0; i < expectedLen; i += POREP_BLOCK_SIZE) {
    const block = replica.subarray(i, i + POREP_BLOCK_SIZE);
    const mask = maskForBlock(replicaKey, i / POREP_BLOCK_SIZE, POREP_BLOCK_SIZE);
    for (let j = 0; j < POREP_BLOCK_SIZE; j++) {
      plaintext[i + j] = block[j]! ^ mask[j]!;
    }
  }
  return plaintext.subarray(0, rawShardSize);
}

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

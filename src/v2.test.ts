import assert from "node:assert/strict";
import { test } from "node:test";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { hash as blake3 } from "blake3-bao";

import {
  buildOperationAuthorization,
  buildLedgerAdminAuthorization,
  deriveActorId,
  ledgerAdminSigningBytes,
  LedgerAdminOperation,
  operationSigningBytes,
  StarshineFinality,
  StarshineOperation,
  verifyInclusionProof,
  type CheckpointCertificate,
  type InclusionProof,
} from "./v2.js";
import { generateMlDsa65Keys, hexToBytes } from "./void-sign.js";
import type { WalletFile } from "./wallet.js";

const context = new TextEncoder().encode("starshine-operation-v2");

test("v2 operation authorization binds every signed field", () => {
  const keys = generateMlDsa65Keys();
  const wallet = {
    mldsa_public_key_hex: keys.publicKeyHex,
    mldsa_private_key_hex: keys.privateKeyHex,
  } as WalletFile;
  const root = new Uint8Array(32).fill(7);
  const digest = new Uint8Array(32).fill(9);
  const authorization = buildOperationAuthorization({
    wallet,
    ledgerId: "00000000-0000-4000-8000-000000000001",
    operation: StarshineOperation.Append,
    artifactRoot: root,
    logicalContentId: "starshine:logical:v1:test",
    requestDigest: digest,
  });
  assert.deepEqual(
    authorization.actor_id,
    Buffer.from(deriveActorId(hexToBytes(keys.publicKeyHex))),
  );
  assert.equal(
    ml_dsa65.verify(
      authorization.mldsa_signature,
      operationSigningBytes(authorization),
      authorization.mldsa_public_key,
      { context },
    ),
    true,
  );
  const tampered = {
    ...authorization,
    logical_content_id: "starshine:logical:v1:tampered",
  };
  assert.equal(
    ml_dsa65.verify(
      authorization.mldsa_signature,
      operationSigningBytes(tampered),
      authorization.mldsa_public_key,
      { context },
    ),
    false,
  );
});

test("ledger admin authorization binds signer and lifecycle fields", () => {
  const keys = generateMlDsa65Keys();
  const wallet = {
    mldsa_public_key_hex: keys.publicKeyHex,
    mldsa_private_key_hex: keys.privateKeyHex,
  } as WalletFile;
  const authorization = buildLedgerAdminAuthorization({
    wallet,
    operation: LedgerAdminOperation.Create,
    ledgerId: "00000000-0000-4000-8000-000000000001",
    signerActorId: new Uint8Array(32).fill(4),
    displayName: "Test app",
    environment: "test",
    active: true,
  });
  assert.equal(
    ml_dsa65.verify(
      authorization.mldsa_signature,
      ledgerAdminSigningBytes(authorization),
      authorization.mldsa_public_key,
      { context: new TextEncoder().encode("starshine-ledger-admin-v2") },
    ),
    true,
  );
  assert.equal(
    ml_dsa65.verify(
      authorization.mldsa_signature,
      ledgerAdminSigningBytes({ ...authorization, active: false }),
      authorization.mldsa_public_key,
      { context: new TextEncoder().encode("starshine-ledger-admin-v2") },
    ),
    false,
  );
});

test("two-level checkpoint inclusion proof verifies and rejects tampering", () => {
  const encoder = new TextEncoder();
  const keys = generateMlDsa65Keys();
  const publicKey = hexToBytes(keys.publicKeyHex);
  const privateKey = hexToBytes(keys.privateKeyHex);
  const ledgerId = "00000000-0000-4000-8000-000000000001";
  const eventHash = new Uint8Array(32).fill(8);
  const ledgerRoot = digestPartsForTest(encoder.encode("starshine:event-leaf:v2\0"), eventHash);
  const ledgerCommitment = digestPartsForTest(
    encoder.encode("starshine:ledger-commitment:v2\0"),
    encoder.encode(ledgerId),
    ledgerRoot,
    u64beForTest(1n),
  );
  const certificate: CheckpointCertificate = {
    version: 1,
    checkpointHeight: 1n,
    createdAtUnixMs: 1n,
    globalRoot: ledgerCommitment,
    previousCheckpointHash: new Uint8Array(),
    checkpointHash: new Uint8Array(),
    nodeId: rawHash(encoder.encode("starshine:node-id:v2\0"), publicKey),
    nodeMlDsaPublicKey: publicKey,
    nodeMlDsaSignature: new Uint8Array(),
  };
  certificate.checkpointHash = rawHash(
    encoder.encode("starshine:checkpoint-hash:v2\0"),
    checkpointJsonForTest(certificate, false),
  );
  certificate.nodeMlDsaSignature = ml_dsa65.sign(
    concatForTest(
      encoder.encode("starshine:checkpoint-signature:v2\0"),
      checkpointJsonForTest(certificate, true),
    ),
    privateKey,
    { context: encoder.encode("starshine-checkpoint-v2") },
  );
  const proof: InclusionProof = {
    eventId: "00000000-0000-4000-8000-000000000002",
    eventHash,
    ledgerId,
    ledgerSequence: 1n,
    ledgerRoot,
    ledgerEventCount: 1n,
    ledgerPath: [],
    ledgerCommitment,
    eventIndex: 0n,
    ledgerIndex: 0n,
    ledgerCount: 1n,
    globalPath: [],
    checkpointRoot: ledgerCommitment,
    checkpointHeight: 1n,
    merklePath: [],
    checkpointCertificate: certificate,
    finality: StarshineFinality.LedgerCheckpointed,
  };
  verifyInclusionProof(proof);
  assert.throws(
    () => verifyInclusionProof({ ...proof, eventHash: new Uint8Array(32).fill(9) }),
    /event-to-ledger/,
  );
});

function checkpointJsonForTest(
  certificate: CheckpointCertificate,
  includeHash: boolean,
): Uint8Array {
  const body: Record<string, string | number> = {};
  if (includeHash) body.checkpoint_hash = Buffer.from(certificate.checkpointHash).toString("base64url");
  body.checkpoint_height = certificate.checkpointHeight.toString();
  body.created_at_unix_ms = certificate.createdAtUnixMs.toString();
  body.global_root = Buffer.from(certificate.globalRoot).toString("base64url");
  body.node_id = Buffer.from(certificate.nodeId).toString("base64url");
  body.node_mldsa_public_key = Buffer.from(certificate.nodeMlDsaPublicKey).toString("base64url");
  body.previous_checkpoint_hash = Buffer.from(certificate.previousCheckpointHash).toString("base64url");
  body.version = certificate.version;
  return new TextEncoder().encode(JSON.stringify(body));
}

function digestPartsForTest(domain: Uint8Array, ...parts: Uint8Array[]): Uint8Array {
  return blake3(concatForTest(domain, ...parts.flatMap((part) => [u64beForTest(BigInt(part.length)), part])));
}

function rawHash(domain: Uint8Array, body: Uint8Array): Uint8Array {
  return blake3(concatForTest(domain, body));
}

function u64beForTest(value: bigint): Uint8Array {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, value, false);
  return output;
}

function concatForTest(...parts: Uint8Array[]): Uint8Array {
  const result = new Uint8Array(parts.reduce((sum, part) => sum + part.length, 0));
  let offset = 0;
  for (const part of parts) {
    result.set(part, offset);
    offset += part.length;
  }
  return result;
}

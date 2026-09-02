import assert from "node:assert/strict";
import test from "node:test";

import {
  StarshineFinality,
  StarshineOperation,
  type EventReceipt,
  type InclusionProof,
} from "starshine-sdk-js";

import { publicEvent, publicProof } from "./scan.js";

const bytes = (value: number, length = 32) => new Uint8Array(length).fill(value);

function receipt(): EventReceipt {
  return {
    ledgerId: "e3f16aa3-3954-4347-a6e5-26f6bdc9d31d",
    eventId: "22d7766b-9519-4100-ac92-29b42c56f2cf",
    requestId: "6badde28-d69e-4f18-86ae-0a82e3a27526",
    requestDigest: bytes(1),
    operation: StarshineOperation.Append,
    actorId: bytes(2),
    artifactRoot: bytes(3),
    logicalContentId: "private-logical-content-id",
    accountSequence: 8n,
    previousEventHash: bytes(4),
    ledgerSequence: 12n,
    previousLedgerEventHash: bytes(5),
    eventHash: bytes(6),
    acceptedAtUnixMs: 1_788_322_000_000n,
    voidAmount: 99n,
    voidBalance: 101n,
    disposition: 1,
    finality: StarshineFinality.NodeAttested,
    nodeId: bytes(7),
    nodeMlDsaPublicKey: bytes(8, 1952),
    nodeMlDsaSignature: bytes(9, 3309),
  };
}

function proof(): InclusionProof {
  return {
    eventId: receipt().eventId,
    eventHash: bytes(6),
    ledgerId: receipt().ledgerId,
    ledgerSequence: 12n,
    ledgerRoot: bytes(10),
    ledgerEventCount: 12n,
    ledgerPath: [{ hash: bytes(11), siblingOnLeft: false }],
    ledgerCommitment: bytes(12),
    eventIndex: 11n,
    ledgerIndex: 0n,
    ledgerCount: 1n,
    globalPath: [],
    checkpointRoot: bytes(13),
    checkpointHeight: 12n,
    merklePath: [],
    checkpointCertificate: {
      version: 1,
      checkpointHeight: 12n,
      createdAtUnixMs: 1_788_322_000_001n,
      globalRoot: bytes(13),
      previousCheckpointHash: bytes(14),
      checkpointHash: bytes(15),
      nodeId: bytes(7),
      nodeMlDsaPublicKey: bytes(8, 1952),
      nodeMlDsaSignature: bytes(9, 3309),
    },
    finality: StarshineFinality.LedgerCheckpointed,
  };
}

test("public event projection excludes tenant identity and request metadata", () => {
  const projected = publicEvent(receipt());
  assert.equal(projected.operation, "append");
  assert.equal(projected.finality, "node-attested");
  assert.equal(projected.ledgerSequence, "12");
  const serialized = JSON.stringify(projected);
  for (const forbidden of [
    "requestId",
    "requestDigest",
    "actorId",
    "logicalContentId",
    "accountSequence",
    "voidAmount",
    "voidBalance",
    "nodeMlDsaPublicKey",
    "nodeMlDsaSignature",
    "private-logical-content-id",
  ]) {
    assert.equal(serialized.includes(forbidden), false, forbidden);
  }
});

test("public proof projection contains complete verified checkpoint evidence", () => {
  const projected = publicProof(proof());
  assert.equal(projected.verified, true);
  assert.equal(projected.finality, "ledger-checkpointed");
  assert.equal(projected.checkpointHeight, "12");
  assert.equal(projected.ledgerPath.length, 1);
  assert.equal(projected.checkpointCertificate.checkpointHeight, "12");
  assert.ok(projected.checkpointCertificate.nodeMlDsaPublicKey.length > 100);
  assert.ok(projected.checkpointCertificate.nodeMlDsaSignature.length > 100);
});

import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import { test } from "node:test";

import { DurableOutbox, IdempotencyConflictError } from "./outbox.js";
import { parseRelayEvent } from "./schema.js";

test("outbox deduplicates and survives processing recovery", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "starshine-relay-"));
  try {
    const envelope = parseRelayEvent({
      version: "void.relay.event.v1",
      sourceSystem: "test",
      sourceEventId: "00000000-0000-4000-8000-000000000001",
      eventType: "test.created",
      occurredAt: "2026-09-01T12:00:00Z",
      data: { ok: true },
    });
    const key = randomBytes(32);
    const outbox = new DurableOutbox(directory, key);
    await outbox.initialize();
    assert.equal((await outbox.enqueue(envelope)).status, "pending");
    const persisted = await readFile(
      path.join(directory, "pending", `${envelope.sourceEventId}.json`),
      "utf8",
    );
    assert.doesNotMatch(persisted, /test\.created|sourceSystem/);
    assert.equal((await outbox.enqueue(envelope)).status, "pending");
    await assert.rejects(
      () => outbox.enqueue({ ...envelope, data: { ok: false } }),
      IdempotencyConflictError,
    );
    assert.equal((await outbox.claimNext())?.envelope.sourceEventId, envelope.sourceEventId);
    assert.equal((await outbox.locate(envelope.sourceEventId)).status, "processing");

    const recovered = new DurableOutbox(directory, key);
    await recovered.initialize();
    assert.equal((await recovered.locate(envelope.sourceEventId)).status, "pending");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test("outbox privately indexes human references and recovers completed proof links", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "starshine-relay-reference-"));
  try {
    const envelope = parseRelayEvent({
      version: "void.relay.event.v1",
      sourceSystem: "hyper-nimbus",
      sourceEventId: "00000000-0000-4000-8000-000000000010",
      eventType: "assessment.completed",
      occurredAt: "2026-09-01T12:00:00Z",
      privateReference: {
        kind: "assessment",
        externalId: "HN-1042",
        label: "Quarterly assessment 1042",
        aliases: ["north-region", "renewal"],
      },
      data: { result: "passed" },
    });
    const key = randomBytes(32);
    const outbox = new DurableOutbox(directory, key);
    await outbox.initialize();
    await outbox.enqueue(envelope);

    assert.equal(outbox.searchPrivateReferences("hn-1042", 10)[0]?.sourceEventId, envelope.sourceEventId);
    assert.equal(outbox.searchPrivateReferences("quarterly 1042", 10)[0]?.reference.label, "Quarterly assessment 1042");
    assert.equal(outbox.searchPrivateReferences("north", 10)[0]?.reference.externalId, "HN-1042");
    assert.equal(outbox.searchPrivateReferences("unrelated", 10).length, 0);

    const record = await outbox.claimNext();
    assert.ok(record);
    await outbox.complete(record, {
      artifactRoot: "private-artifact-root",
      receipt: {
        eventId: "22d7766b-9519-4100-ac92-29b42c56f2cf",
        ledgerId: "e3f16aa3-3954-4347-a6e5-26f6bdc9d31d",
      },
    });
    const complete = outbox.privateReference(envelope.sourceEventId);
    assert.equal(complete?.status, "complete");
    assert.equal(complete?.eventId, "22d7766b-9519-4100-ac92-29b42c56f2cf");

    const persisted = await readFile(
      path.join(directory, "complete", `${envelope.sourceEventId}.json`),
      "utf8",
    );
    assert.doesNotMatch(persisted, /HN-1042|Quarterly|north-region/);

    const recovered = new DurableOutbox(directory, key);
    await recovered.initialize();
    const restored = recovered.searchPrivateReferences("renewal", 10)[0];
    assert.equal(restored?.status, "complete");
    assert.equal(restored?.ledgerId, "e3f16aa3-3954-4347-a6e5-26f6bdc9d31d");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

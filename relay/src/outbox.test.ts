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

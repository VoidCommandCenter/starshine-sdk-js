import assert from "node:assert/strict";
import { test } from "node:test";

import { canonicalEventBytes, parseRelayEvent } from "./schema.js";

test("relay envelope validation and canonicalization are stable", () => {
  const first = parseRelayEvent({
    version: "void.relay.event.v1",
    sourceSystem: "partner-app",
    sourceEventId: "00000000-0000-4000-8000-000000000001",
    eventType: "assessment.completed",
    occurredAt: "2026-09-01T12:00:00Z",
    data: { score: 42, answer: true },
  });
  const second = parseRelayEvent({
    data: { answer: true, score: 42 },
    occurredAt: "2026-09-01T12:00:00.000Z",
    eventType: "assessment.completed",
    sourceEventId: "00000000-0000-4000-8000-000000000001",
    sourceSystem: "partner-app",
    version: "void.relay.event.v1",
  });
  assert.deepEqual(canonicalEventBytes(first), canonicalEventBytes(second));
});

test("relay rejects non-UUID idempotency keys", () => {
  assert.throws(() => parseRelayEvent({
    version: "void.relay.event.v1",
    sourceSystem: "partner-app",
    sourceEventId: "not-stable",
    eventType: "assessment.completed",
    occurredAt: new Date().toISOString(),
    data: {},
  }), /UUID/);
});

test("relay accepts a bounded private human reference inside the sealed envelope", () => {
  const event = parseRelayEvent({
    version: "void.relay.event.v1",
    sourceSystem: "partner-app",
    sourceEventId: "00000000-0000-4000-8000-000000000002",
    eventType: "assessment.completed",
    occurredAt: "2026-09-01T12:00:00Z",
    privateReference: {
      kind: "assessment",
      externalId: "HN-1042",
      label: "Quarterly assessment 1042",
      aliases: ["renewal-1042", "north region"],
    },
    data: { score: 42 },
  });
  assert.deepEqual(event.privateReference, {
    kind: "assessment",
    externalId: "HN-1042",
    label: "Quarterly assessment 1042",
    aliases: ["renewal-1042", "north region"],
  });
  assert.match(Buffer.from(canonicalEventBytes(event)).toString("utf8"), /HN-1042/);
});

test("relay rejects duplicate or excessive private reference aliases", () => {
  const base = {
    version: "void.relay.event.v1",
    sourceSystem: "partner-app",
    sourceEventId: "00000000-0000-4000-8000-000000000003",
    eventType: "assessment.completed",
    occurredAt: "2026-09-01T12:00:00Z",
    data: {},
  };
  assert.throws(() => parseRelayEvent({
    ...base,
    privateReference: {
      kind: "assessment",
      externalId: "HN-1042",
      label: "Assessment 1042",
      aliases: ["North", "north"],
    },
  }), /unique/);
  assert.throws(() => parseRelayEvent({
    ...base,
    privateReference: {
      kind: "assessment",
      externalId: "HN-1042",
      label: "Assessment 1042",
      aliases: Array.from({ length: 17 }, (_, index) => `alias-${index}`),
    },
  }), /at most 16/);
});

import assert from "node:assert/strict";
import { test } from "node:test";

import { createRequestId, isLogicalContentId, logicalContentId } from "./identity.js";

test("logical content identity is stable and namespace separated", () => {
  const bytes = new TextEncoder().encode("same plaintext");
  const first = logicalContentId(bytes, "partner-a");
  const retry = logicalContentId(bytes, "partner-a");
  const otherNamespace = logicalContentId(bytes, "partner-b");

  assert.equal(first, retry);
  assert.notEqual(first, otherNamespace);
  assert.equal(isLogicalContentId(first), true);
});

test("request IDs are unique UUIDs", () => {
  const first = createRequestId();
  const second = createRequestId();
  assert.match(first, /^[0-9a-f-]{36}$/);
  assert.notEqual(first, second);
});

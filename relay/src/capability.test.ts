import assert from "node:assert/strict";
import test from "node:test";

import { FileCapabilityAuthority } from "./capability.js";

test("file capabilities are scoped, tenant-bound, expiring, and tamper-evident", () => {
  const authority = new FileCapabilityAuthority(new Uint8Array(32).fill(7), 900);
  const now = Date.parse("2026-09-02T12:00:00Z");
  const minted = authority.mint({
    subject: "user-pseudonym",
    tenantId: "hyper-nimbus",
    scopes: ["files:read", "files:write"],
    uploadId: "00000000-0000-4000-8000-000000000001",
    ttlSeconds: 120,
  }, now);
  const verified = authority.verify(
    minted.token,
    "files:read",
    "00000000-0000-4000-8000-000000000001",
    now + 1_000,
  );
  assert.equal(verified.tenantId, "hyper-nimbus");
  assert.throws(() => authority.verify(minted.token, "files:audit", verified.uploadId, now));
  assert.throws(() => authority.verify(
    minted.token,
    "files:read",
    "00000000-0000-4000-8000-000000000002",
    now,
  ));
  assert.throws(() => authority.verify(minted.token, "files:read", verified.uploadId, now + 121_000));
  assert.throws(() => authority.verify(`${minted.token}x`, "files:read", verified.uploadId, now));
});

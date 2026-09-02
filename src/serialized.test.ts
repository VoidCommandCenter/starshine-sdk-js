import assert from "node:assert/strict";
import test from "node:test";

import { generateDemoKeys } from "./keygen.js";
import { getXWingKem } from "./kem.js";
import { loadKeysFromJson } from "./keys.js";
import {
  deserializeStoredBlob,
  serializeStoredBlob,
} from "./serialized.js";
import { uploadWithProgress } from "./upload.js";

test("stored blobs serialize canonically and survive strict validation", async () => {
  const keys = await loadKeysFromJson(await generateDemoKeys(), getXWingKem());
  const stored = await uploadWithProgress(keys, new TextEncoder().encode("sealed client chunk"), 2, 1);
  const serialized = serializeStoredBlob(stored);
  const restored = deserializeStoredBlob(serialized, {
    allowedShardPolicies: new Set(["2+1"]),
    maxDecodedBytes: 10 * 1024 * 1024,
  });
  assert.deepEqual(restored, stored);
});

test("stored blob validation rejects mismatched roots and unsafe policies", async () => {
  const keys = await loadKeysFromJson(await generateDemoKeys(), getXWingKem());
  const serialized = serializeStoredBlob(
    await uploadWithProgress(keys, new TextEncoder().encode("sealed client chunk"), 2, 1),
  );
  assert.throws(
    () => deserializeStoredBlob(serialized, { allowedShardPolicies: new Set(["4+2"]) }),
    /not allowed/,
  );
  const tampered = structuredClone(serialized);
  tampered.blob.topRoot = Buffer.alloc(32, 7).toString("base64url");
  assert.throws(() => deserializeStoredBlob(tampered), /top root/);
});

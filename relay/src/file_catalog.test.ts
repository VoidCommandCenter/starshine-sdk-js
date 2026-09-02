import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import { FILE_UPLOAD_VERSION, FileCatalog, type FileUploadRecord } from "./file_catalog.js";

test("file catalog encrypts labels and rebuilds its private search index", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "void-file-catalog-"));
  try {
    const key = new Uint8Array(32).fill(9);
    const catalog = new FileCatalog(directory, key);
    await catalog.initialize();
    const record: FileUploadRecord = {
      version: FILE_UPLOAD_VERSION,
      uploadId: "00000000-0000-4000-8000-000000000020",
      status: "uploading",
      createdAt: "2026-09-02T12:00:00.000Z",
      updatedAt: "2026-09-02T12:00:00.000Z",
      tenantId: "hyper-nimbus",
      actorId: "actor-7",
      sourceSystem: "hyper-nimbus",
      mode: "gateway-sealed",
      fileName: "assessment.pdf",
      contentType: "application/pdf",
      byteLength: 12,
      chunkSize: 12,
      chunkCount: 1,
      privateReference: {
        kind: "assessment",
        externalId: "HN-2042",
        label: "Private assessment 2042",
        aliases: ["renewal"],
      },
      shardPolicy: { dataShards: 4, parityShards: 2 },
      routeId: "void-primary",
      failureDomains: 1,
      chunks: {},
    };
    await catalog.create(record);
    const persisted = await readFile(
      path.join(directory, "files", `${record.uploadId}.json`),
      "utf8",
    );
    assert.doesNotMatch(persisted, /HN-2042|Private assessment|assessment\.pdf/);
    assert.equal(catalog.list("renew", 10, "hyper-nimbus")[0]?.uploadId, record.uploadId);
    assert.equal(catalog.list("renew", 10, "another-tenant").length, 0);

    const restored = new FileCatalog(directory, key);
    await restored.initialize();
    assert.equal(restored.list("HN-2042", 10)[0]?.privateReference.label, "Private assessment 2042");
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

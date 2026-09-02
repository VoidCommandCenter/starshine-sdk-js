import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import type { SerializedStoredBlob } from "starshine-sdk-js";
import { FILE_UPLOAD_VERSION, FileCatalog } from "./file_catalog.js";
import {
  FileConflictError,
  FileGateway,
  type FileGatewayOperations,
  type GatewayRoute,
} from "./file_gateway.js";
import type { DurableOutbox } from "./outbox.js";

test("gateway seals chunks, labels a manifest, retrieves data, and emits typed audit events", async () => {
  const directory = await mkdtemp(path.join(tmpdir(), "void-file-gateway-"));
  try {
    const catalog = new FileCatalog(directory, new Uint8Array(32).fill(3));
    await catalog.initialize();
    const events: unknown[] = [];
    const outbox = {
      enqueue: async (envelope: unknown) => {
        events.push(envelope);
        return { status: "pending", value: { envelope } };
      },
    } as unknown as DurableOutbox;
    const route = {
      id: "void-primary",
      server: "grpcs://example.test:443",
      ledgerId: "e3f16aa3-3954-4347-a6e5-26f6bdc9d31d",
      wallet: {},
      keys: {},
      expectedNode: { nodeId: new Uint8Array(), publicKey: new Uint8Array() },
      failureDomains: 1,
    } as unknown as GatewayRoute;
    const stored = new Map<string, SerializedStoredBlob>();
    const operations: FileGatewayOperations = {
      seal: async (_route, plaintext) => ({
        version: "starshine.stored-blob.v1",
        fakePlaintext: Buffer.from(plaintext).toString("base64url"),
      } as unknown as SerializedStoredBlob),
      append: async (_route, prepared, _fileName, _logicalId, requestId) => {
        const root = createHash("sha256").update(JSON.stringify(prepared)).digest("base64url");
        stored.set(root, prepared);
        return {
          artifactRoot: root,
          eventId: requestId,
          ledgerId: route.ledgerId,
          requestId,
          acceptedAt: "2026-09-02T12:00:00.000Z",
        };
      },
      retrieve: async (_route, root, _logicalId, requestId) => {
        const encoded = Buffer.from(root).toString("base64url");
        const prepared = stored.get(encoded);
        assert.ok(prepared);
        return {
          stored: prepared,
          receipt: {
            artifactRoot: encoded,
            eventId: requestId,
            ledgerId: route.ledgerId,
            requestId,
            acceptedAt: "2026-09-02T12:00:01.000Z",
          },
        };
      },
      recover: async (_route, prepared) => new Uint8Array(Buffer.from(
        (prepared as unknown as { fakePlaintext: string }).fakePlaintext,
        "base64url",
      )),
    };
    const gateway = new FileGateway({
      maxChunkBytes: 4,
      maxFileBytes: 100,
      maxChunks: 100,
      allowedShardPolicies: new Set(["4+2"]),
      defaultRouteId: route.id,
      scanEnabled: true,
    }, catalog, outbox, new Map([[route.id, route]]), operations);
    const principal = { service: true, subject: "void-service", tenantId: "void-service" };
    const uploadId = "00000000-0000-4000-8000-000000000020";
    const created = await gateway.create({
      version: FILE_UPLOAD_VERSION,
      uploadId,
      tenantId: "hyper-nimbus",
      actorId: "user-pseudonym",
      sourceSystem: "hyper-nimbus",
      mode: "gateway-sealed",
      fileName: "evidence.bin",
      contentType: "application/octet-stream",
      byteLength: 6,
      chunkSize: 4,
      privateReference: {
        kind: "evidence",
        externalId: "HN-55",
        label: "Control evidence 55",
        aliases: ["annual review"],
      },
      shardPolicy: { dataShards: 4, parityShards: 2 },
    }, principal) as { chunkCount: number };
    assert.equal(created.chunkCount, 2);
    await gateway.putChunk(uploadId, 0, new TextEncoder().encode("abcd"), principal);
    await gateway.putChunk(uploadId, 0, new TextEncoder().encode("abcd"), principal);
    await assert.rejects(
      gateway.putChunk(uploadId, 0, new TextEncoder().encode("wxyz"), principal),
      FileConflictError,
    );
    await gateway.putChunk(uploadId, 1, new TextEncoder().encode("ef"), principal);
    const completed = await gateway.complete(uploadId, principal) as {
      status: string;
      privateReference: { label: string };
      manifest: { publicProofPath: string };
    };
    assert.equal(completed.status, "complete");
    assert.equal(completed.privateReference.label, "Control evidence 55");
    assert.match(completed.manifest.publicProofPath, /^\/scan\?event=/);
    assert.equal((events[0] as { eventType: string }).eventType, "file.uploaded");
    const retrieved = await gateway.retrieveChunk(uploadId, 1, principal);
    assert.equal(retrieved.mode, "gateway-sealed");
    if (retrieved.mode === "gateway-sealed") {
      assert.equal(Buffer.from(retrieved.body).toString(), "ef");
    }
    await gateway.action(uploadId, {
      sourceEventId: "00000000-0000-4000-8000-000000000099",
      eventType: "file.viewed",
      occurredAt: "2026-09-02T12:02:00Z",
      actorId: "user-pseudonym",
      data: { screen: "detail" },
    }, principal);
    assert.equal((events[1] as { eventType: string }).eventType, "file.viewed");
    const found = gateway.search("control 55", 10, principal) as { uploads: unknown[] };
    assert.equal(found.uploads.length, 1);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

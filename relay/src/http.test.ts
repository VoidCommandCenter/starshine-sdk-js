import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";

import type { RelayConfig } from "./config.js";
import { FileCapabilityAuthority } from "./capability.js";
import type { FileGateway, FilePrincipal } from "./file_gateway.js";
import { createRelayHttpServer } from "./http.js";
import type { DurableOutbox } from "./outbox.js";
import type { PublicScanProvider } from "./scan.js";

const ledger = {
  version: "void.scan.v1" as const,
  ledgerId: "e3f16aa3-3954-4347-a6e5-26f6bdc9d31d",
  name: "Hyper Nimbus",
  environment: "test",
  visibility: "public-proof-metadata" as const,
  payloads: "encrypted-not-exposed" as const,
};

const provider: PublicScanProvider = {
  ledger: () => ledger,
  list: async () => ({
    version: "void.scan.v1",
    ledger,
    events: [],
    ledgerEventCount: "0",
    indexedAt: new Date(0).toISOString(),
    nextCursor: "",
  }),
  detail: async (eventId) => ({
    version: "void.scan.v1",
    ledger,
    event: {
      eventId,
      ledgerId: ledger.ledgerId,
      operation: "append",
      acceptedAt: new Date(0).toISOString(),
      acceptedAtUnixMs: "0",
      ledgerSequence: "1",
      artifactRoot: "AA",
      eventHash: "AA",
      finality: "node-attested",
      nodeId: "AA",
    },
    proof: {
      verified: true,
      finality: "ledger-checkpointed",
      ledgerSequence: "1",
      ledgerEventCount: "1",
      eventIndex: "0",
      ledgerIndex: "0",
      ledgerCount: "1",
      eventHash: "AA",
      ledgerRoot: "AA",
      ledgerCommitment: "AA",
      checkpointRoot: "AA",
      checkpointHeight: "1",
      ledgerPath: [],
      globalPath: [],
      checkpointCertificate: {
        version: 1,
        checkpointHeight: "1",
        createdAt: new Date(0).toISOString(),
        createdAtUnixMs: "0",
        globalRoot: "AA",
        previousCheckpointHash: "AA",
        checkpointHash: "AA",
        nodeId: "AA",
        nodeMlDsaPublicKey: "AA",
        nodeMlDsaSignature: "AA",
      },
    },
  }),
};

function config(rateLimit = 60): RelayConfig {
  return {
    server: "grpcs://example.test:443",
    ledgerId: ledger.ledgerId,
    walletFile: "/tmp/wallet",
    dataDir: "/tmp/outbox",
    outboxKey: new Uint8Array(32),
    host: "127.0.0.1",
    port: 0,
    bearerToken: "private-token",
    scanEnabled: true,
    scanTitle: ledger.name,
    scanEnvironment: ledger.environment,
    scanRateLimitPerMinute: rateLimit,
    maxEventBytes: 1024,
    maxAttempts: 1,
    retryBaseMs: 10,
    dataShards: 1,
    parityShards: 1,
    gatewayEnabled: false,
    gatewayMaxChunkBytes: 8 * 1024 * 1024,
    gatewayMaxFileBytes: 1024 * 1024 * 1024,
    gatewayMaxChunks: 10_000,
    gatewayMaxJsonBytes: 128 * 1024 * 1024,
    gatewayCapabilityTtlSeconds: 900,
    gatewayAllowedShardPolicies: new Set(["1+1"]),
    gatewayAllowedOrigins: new Set(),
    gatewayDefaultRouteId: "void-primary",
    amqpPrefetch: 1,
  };
}

async function withServer(
  relayConfig: RelayConfig,
  run: (origin: string) => Promise<void>,
  relayOutbox: DurableOutbox = {} as DurableOutbox,
  gateway?: FileGateway,
  capabilities?: FileCapabilityAuthority,
): Promise<void> {
  const server = createRelayHttpServer(
    relayConfig,
    relayOutbox,
    provider,
    gateway,
    capabilities,
  );
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", resolve);
  });
  const port = (server.address() as AddressInfo).port;
  try {
    await run(`http://127.0.0.1:${port}`);
  } finally {
    await new Promise<void>((resolve, reject) =>
      server.close((error) => error ? reject(error) : resolve())
    );
  }
}

test("public scan is readable without the private relay bearer token", async () => {
  await withServer(config(), async (origin) => {
    const ledgerResponse = await fetch(`${origin}/v1/scan/ledger`);
    assert.equal(ledgerResponse.status, 200);
    assert.equal((await ledgerResponse.json()).ledgerId, ledger.ledgerId);

    const pageResponse = await fetch(`${origin}/scan`);
    assert.equal(pageResponse.status, 200);
    assert.match(pageResponse.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
    assert.match(await pageResponse.text(), /VOIDSCAN/);

    const privateResponse = await fetch(`${origin}/v1/events/${ledger.ledgerId}`);
    assert.equal(privateResponse.status, 401);
  });
});

test("file routes require scoped capabilities and exact CORS origins", async () => {
  const relayConfig = config();
  relayConfig.gatewayEnabled = true;
  relayConfig.gatewayAllowedOrigins = new Set(["https://app.example.test"]);
  const authority = new FileCapabilityAuthority(relayConfig.outboxKey, 900);
  let principal: FilePrincipal | undefined;
  const gateway = {
    create: async (_body: unknown, value: FilePrincipal) => {
      principal = value;
      return { version: "void.file-upload.v1", uploadId: "00000000-0000-4000-8000-000000000001" };
    },
  } as unknown as FileGateway;

  await withServer(relayConfig, async (origin) => {
    const mintedResponse = await fetch(`${origin}/v1/capabilities`, {
      method: "POST",
      headers: {
        authorization: "Bearer private-token",
        "content-type": "application/json",
      },
      body: JSON.stringify({
        subject: "user-pseudonym",
        tenantId: "hyper-nimbus",
        scopes: ["files:create"],
      }),
    });
    assert.equal(mintedResponse.status, 201);
    const minted = await mintedResponse.json() as { token: string };
    const uploadBody = JSON.stringify({
      version: "void.file-upload.v1",
      sourceSystem: "hyper-nimbus",
      mode: "gateway-sealed",
      fileName: "evidence.pdf",
      contentType: "application/pdf",
      byteLength: 1,
      privateReference: { kind: "evidence", externalId: "HN-1", label: "Evidence", aliases: [] },
    });
    const allowed = await fetch(`${origin}/v1/files/uploads`, {
      method: "POST",
      headers: {
        authorization: `VoidCapability ${minted.token}`,
        "content-type": "application/json",
        origin: "https://app.example.test",
      },
      body: uploadBody,
    });
    assert.equal(allowed.status, 201);
    assert.equal(allowed.headers.get("access-control-allow-origin"), "https://app.example.test");
    assert.equal(principal?.tenantId, "hyper-nimbus");
    assert.equal(principal?.service, false);

    const denied = await fetch(`${origin}/v1/files/uploads`, {
      method: "POST",
      headers: {
        authorization: `VoidCapability ${minted.token}`,
        "content-type": "application/json",
        origin: "https://evil.example.test",
      },
      body: uploadBody,
    });
    assert.equal(denied.status, 401);
  }, {} as DurableOutbox, gateway, authority);
});

test("public scan validates cursors and enforces a per-client rate limit", async () => {
  await withServer(config(2), async (origin) => {
    const invalid = await fetch(`${origin}/v1/scan/events?cursor=not-a-sequence`);
    assert.equal(invalid.status, 400);
    const allowed = await fetch(`${origin}/v1/scan/ledger`);
    assert.equal(allowed.status, 200);
    const limited = await fetch(`${origin}/v1/scan/ledger`);
    assert.equal(limited.status, 429);
    assert.equal(limited.headers.get("retry-after"), "60");
  });
});

test("private reference search requires bearer auth and returns a public proof path", async () => {
  const match = {
    sourceEventId: "00000000-0000-4000-8000-000000000010",
    sourceSystem: "hyper-nimbus",
    eventType: "assessment.completed",
    occurredAt: "2026-09-01T12:00:00.000Z",
    acceptedAt: "2026-09-01T12:00:01.000Z",
    status: "complete" as const,
    reference: {
      kind: "assessment",
      externalId: "HN-1042",
      label: "Quarterly assessment 1042",
      aliases: ["renewal"],
    },
    eventId: "22d7766b-9519-4100-ac92-29b42c56f2cf",
    ledgerId: ledger.ledgerId,
  };
  const privateOutbox = {
    searchPrivateReferences: (query: string) => query === "HN-1042" ? [match] : [],
    privateReference: (sourceEventId: string) =>
      sourceEventId === match.sourceEventId ? match : undefined,
  } as unknown as DurableOutbox;

  await withServer(config(), async (origin) => {
    const unauthorized = await fetch(`${origin}/v1/references?query=HN-1042`);
    assert.equal(unauthorized.status, 401);

    const headers = { authorization: "Bearer private-token" };
    const search = await fetch(`${origin}/v1/references?query=HN-1042`, { headers });
    assert.equal(search.status, 200);
    const searchBody = await search.json() as {
      references: Array<{ reference: { label: string }; publicProofPath: string }>;
    };
    assert.equal(searchBody.references[0]?.reference.label, "Quarterly assessment 1042");
    assert.equal(
      searchBody.references[0]?.publicProofPath,
      "/scan?event=22d7766b-9519-4100-ac92-29b42c56f2cf",
    );

    const detail = await fetch(`${origin}/v1/references/${match.sourceEventId}`, { headers });
    assert.equal(detail.status, 200);
    const missing = await fetch(
      `${origin}/v1/references/00000000-0000-4000-8000-000000000099`,
      { headers },
    );
    assert.equal(missing.status, 404);
  }, privateOutbox);
});

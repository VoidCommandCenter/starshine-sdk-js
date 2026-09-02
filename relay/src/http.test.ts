import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import test from "node:test";

import type { RelayConfig } from "./config.js";
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
    amqpPrefetch: 1,
  };
}

async function withServer(
  relayConfig: RelayConfig,
  run: (origin: string) => Promise<void>,
  relayOutbox: DurableOutbox = {} as DurableOutbox,
): Promise<void> {
  const server = createRelayHttpServer(
    relayConfig,
    relayOutbox,
    provider,
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

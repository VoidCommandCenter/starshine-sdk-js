import {
  appendV2,
  getCapabilitiesV2,
  getXWingKem,
  loadKeysFromJson,
  loadWallet,
  logicalContentId,
  uploadWithProgress,
  type EventReceipt,
  type WalletFile,
} from "starshine-sdk-js";

import { startAmqpConsumer } from "./amqp.js";
import { deserializeStoredBlob, jsonForStorage, serializeStoredBlob } from "./codec.js";
import { loadConfig, type RelayConfig } from "./config.js";
import { createRelayHttpServer } from "./http.js";
import { DurableOutbox } from "./outbox.js";
import { canonicalEventBytes } from "./schema.js";

const config = await loadConfig();
const outbox = new DurableOutbox(config.dataDir, config.outboxKey);
await outbox.initialize();
const wallet = await loadWallet(config.walletFile);
const keys = await loadKeysFromJson(wallet, getXWingKem());
const capabilities = await getCapabilitiesV2(config.server, {
  transport: serverTransport(config),
});
const expectedNode = {
  nodeId: capabilities.nodeId,
  publicKey: capabilities.nodeMlDsaPublicKey,
};

let stopping = false;
const worker = runWorker(config, outbox, wallet, keys, expectedNode);
const http = createRelayHttpServer(config, outbox);
await new Promise<void>((resolve, reject) => {
  http.once("error", reject);
  http.listen(config.port, config.host, () => resolve());
});
const amqp = await startAmqpConsumer(config, outbox);
console.log(JSON.stringify({
  level: "info",
  message: "starshine relay ready",
  host: config.host,
  port: config.port,
  ledgerId: config.ledgerId,
  nodeId: Buffer.from(capabilities.nodeId).toString("hex"),
  amqp: Boolean(amqp),
}));

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.once(signal, async () => {
    stopping = true;
    http.close();
    if (amqp) await amqp.close().catch(() => undefined);
  });
}
await worker;

async function runWorker(
  relayConfig: RelayConfig,
  relayOutbox: DurableOutbox,
  relayWallet: WalletFile,
  clientKeys: Awaited<ReturnType<typeof loadKeysFromJson>>,
  trustedNode: { nodeId: Uint8Array; publicKey: Uint8Array },
): Promise<void> {
  while (!stopping) {
    const record = await relayOutbox.claimNext();
    if (!record) {
      await delay(250);
      continue;
    }
    try {
      record.attempts += 1;
      const payload = canonicalEventBytes(record.envelope);
      if (!record.prepared) {
        const stored = await uploadWithProgress(
          clientKeys,
          payload,
          relayConfig.dataShards,
          relayConfig.parityShards,
        );
        record.prepared = serializeStoredBlob(stored);
        record.logicalContentId = logicalContentId(
          payload,
          `void-relay:${record.envelope.sourceSystem}:${record.envelope.eventType}`,
        );
        await relayOutbox.updateProcessing(record);
      }
      const result = await appendV2(
        relayConfig.server,
        relayWallet,
        deserializeStoredBlob(record.prepared),
        `${safeFilePart(record.envelope.eventType)}.json`,
        record.logicalContentId!,
        {
          ledgerId: relayConfig.ledgerId,
          requestId: record.envelope.sourceEventId,
          expectedNode: trustedNode,
          transport: serverTransport(relayConfig),
        },
      );
      await relayOutbox.complete(record, serializableResult(result.receipt, result.artifactRoot));
    } catch (error) {
      record.lastError = error instanceof Error ? error.message : String(error);
      if (record.attempts >= relayConfig.maxAttempts) {
        await relayOutbox.dead(record);
      } else {
        const exponent = Math.min(record.attempts - 1, 12);
        const retryMs = relayConfig.retryBaseMs * 2 ** exponent;
        record.nextAttemptAt = new Date(Date.now() + retryMs).toISOString();
        await relayOutbox.retry(record);
      }
    }
  }
}

function serverTransport(config: RelayConfig): { rootCertificates: Uint8Array } | undefined {
  return config.serverCa ? { rootCertificates: config.serverCa } : undefined;
}

function serializableResult(receipt: EventReceipt, artifactRoot: Uint8Array): unknown {
  return JSON.parse(jsonForStorage({
    artifactRoot,
    receipt,
  })) as unknown;
}

function safeFilePart(value: string): string {
  return value.replace(/[^a-z0-9._-]+/gi, "-").slice(0, 96) || "event";
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

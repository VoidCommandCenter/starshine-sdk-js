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
import { readFile, stat } from "node:fs/promises";

import { startAmqpConsumer } from "./amqp.js";
import { deserializeStoredBlob, jsonForStorage, serializeStoredBlob } from "./codec.js";
import { loadConfig, type RelayConfig } from "./config.js";
import { createRelayHttpServer } from "./http.js";
import { FileCapabilityAuthority } from "./capability.js";
import { FileCatalog } from "./file_catalog.js";
import { FileGateway, gatewayOptions, type GatewayRoute } from "./file_gateway.js";
import { DurableOutbox } from "./outbox.js";
import { StarshinePublicScan } from "./scan.js";
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
const publicScan = config.scanEnabled
  ? new StarshinePublicScan(config, wallet, expectedNode)
  : undefined;
const fileCatalog = config.gatewayEnabled
  ? new FileCatalog(config.dataDir, config.outboxKey)
  : undefined;
if (fileCatalog) await fileCatalog.initialize();
const gatewayRoutes = config.gatewayEnabled
  ? await loadGatewayRoutes(config, wallet, keys, expectedNode)
  : undefined;
const fileGateway = fileCatalog && gatewayRoutes
  ? new FileGateway(gatewayOptions(config), fileCatalog, outbox, gatewayRoutes)
  : undefined;
const capabilityAuthority = config.gatewayEnabled
  ? new FileCapabilityAuthority(config.outboxKey, config.gatewayCapabilityTtlSeconds)
  : undefined;

let stopping = false;
const worker = runWorker(config, outbox, wallet, keys, expectedNode);
const http = createRelayHttpServer(
  config,
  outbox,
  publicScan,
  fileGateway,
  capabilityAuthority,
);
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
  publicScan: config.scanEnabled,
  fileGateway: config.gatewayEnabled,
  gatewayRoutes: gatewayRoutes ? [...gatewayRoutes.keys()] : [],
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

async function loadGatewayRoutes(
  relayConfig: RelayConfig,
  primaryWallet: WalletFile,
  primaryKeys: Awaited<ReturnType<typeof loadKeysFromJson>>,
  primaryNode: { nodeId: Uint8Array; publicKey: Uint8Array },
): Promise<ReadonlyMap<string, GatewayRoute>> {
  const routes = new Map<string, GatewayRoute>();
  routes.set("void-primary", {
    id: "void-primary",
    server: relayConfig.server,
    ledgerId: relayConfig.ledgerId,
    wallet: primaryWallet,
    keys: primaryKeys,
    expectedNode: primaryNode,
    transport: serverTransport(relayConfig),
    failureDomains: 1,
  });
  if (!relayConfig.gatewayRoutesFile) return routes;
  const details = await stat(relayConfig.gatewayRoutesFile);
  if (process.platform !== "win32" && (details.mode & 0o077) !== 0) {
    throw new Error("STARSHINE_GATEWAY_ROUTES_FILE must not be readable by group or other users");
  }
  const document = JSON.parse(await readFile(relayConfig.gatewayRoutesFile, "utf8")) as unknown;
  if (!isRecord(document) || document.version !== "void.gateway-routes.v1" || !Array.isArray(document.routes)) {
    throw new Error("invalid gateway routes document");
  }
  for (const value of document.routes) {
    if (!isRecord(value)) throw new Error("gateway route must be an object");
    const id = routeString(value.id, "id", 64);
    if (id === "void-primary" || routes.has(id)) throw new Error(`duplicate gateway route ${id}`);
    const server = routeString(value.server, "server", 1024);
    const ledgerId = routeString(value.ledgerId, "ledgerId", 64);
    const walletFile = routeString(value.walletFile, "walletFile", 4096);
    const serverCaFile = value.serverCaFile === undefined
      ? undefined
      : routeString(value.serverCaFile, "serverCaFile", 4096);
    const serverCa = serverCaFile ? new Uint8Array(await readFile(serverCaFile)) : undefined;
    const routeWallet = await loadWallet(walletFile);
    const routeKeys = await loadKeysFromJson(routeWallet, getXWingKem());
    const routeCapabilities = await getCapabilitiesV2(server, {
      transport: serverCa ? { rootCertificates: serverCa } : undefined,
    });
    routes.set(id, {
      id,
      server,
      ledgerId,
      wallet: routeWallet,
      keys: routeKeys,
      expectedNode: {
        nodeId: routeCapabilities.nodeId,
        publicKey: routeCapabilities.nodeMlDsaPublicKey,
      },
      transport: serverCa ? { rootCertificates: serverCa } : undefined,
      failureDomains: routeInteger(value.failureDomains, "failureDomains", 1, 255),
    });
  }
  return routes;
}

function routeString(value: unknown, name: string, maximum: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum) {
    throw new Error(`gateway route ${name} must be a non-empty string`);
  }
  return value.trim();
}

function routeInteger(
  value: unknown,
  name: string,
  minimum: number,
  maximum: number,
): number {
  if (!Number.isInteger(value) || (value as number) < minimum || (value as number) > maximum) {
    throw new Error(`gateway route ${name} must be between ${minimum} and ${maximum}`);
  }
  return value as number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

import { readFile } from "node:fs/promises";

export interface RelayConfig {
  server: string;
  serverCa?: Uint8Array;
  ledgerId: string;
  walletFile: string;
  dataDir: string;
  outboxKey: Uint8Array;
  host: string;
  port: number;
  bearerToken?: string;
  scanEnabled: boolean;
  scanTitle: string;
  scanEnvironment: string;
  scanRateLimitPerMinute: number;
  maxEventBytes: number;
  maxAttempts: number;
  retryBaseMs: number;
  dataShards: number;
  parityShards: number;
  gatewayEnabled: boolean;
  gatewayMaxChunkBytes: number;
  gatewayMaxFileBytes: number;
  gatewayMaxChunks: number;
  gatewayMaxJsonBytes: number;
  gatewayCapabilityTtlSeconds: number;
  gatewayAllowedShardPolicies: ReadonlySet<string>;
  gatewayAllowedOrigins: ReadonlySet<string>;
  gatewayDefaultRouteId: string;
  gatewayRoutesFile?: string;
  amqpUrl?: string;
  amqpQueue?: string;
  amqpPrefetch: number;
}

export async function loadConfig(): Promise<RelayConfig> {
  const server = required("STARSHINE_SERVER");
  const serverCaFile = process.env.STARSHINE_SERVER_CA_FILE?.trim();
  const serverCa = serverCaFile ? new Uint8Array(await readFile(serverCaFile)) : undefined;
  if (serverCaFile && serverCa?.length === 0) {
    throw new Error("STARSHINE_SERVER_CA_FILE is empty");
  }
  const ledgerId = required("STARSHINE_LEDGER_ID");
  const walletFile = required("STARSHINE_WALLET_FILE");
  const dataDir = process.env.STARSHINE_RELAY_DATA_DIR ?? "/var/lib/starshine-relay";
  const outboxKey = await readSecretKey(required("STARSHINE_RELAY_OUTBOX_KEY_FILE"));
  const host = process.env.STARSHINE_RELAY_HOST ?? "127.0.0.1";
  const tokenFile = process.env.STARSHINE_RELAY_BEARER_TOKEN_FILE;
  const bearerToken = tokenFile ? (await readFile(tokenFile, "utf8")).trim() : undefined;
  if (tokenFile && !bearerToken) throw new Error("relay bearer-token file is empty");
  if (!isLoopback(host) && !bearerToken) {
    throw new Error(
      "refusing an unauthenticated non-loopback relay listener; configure STARSHINE_RELAY_BEARER_TOKEN_FILE",
    );
  }
  const amqpUrl = process.env.STARSHINE_RELAY_AMQP_URL?.trim() || undefined;
  const amqpQueue = process.env.STARSHINE_RELAY_AMQP_QUEUE?.trim() || undefined;
  if (!!amqpUrl !== !!amqpQueue) {
    throw new Error("STARSHINE_RELAY_AMQP_URL and STARSHINE_RELAY_AMQP_QUEUE must be set together");
  }
  const dataShards = integer("STARSHINE_RELAY_DATA_SHARDS", 4, 1, 255);
  const parityShards = integer("STARSHINE_RELAY_PARITY_SHARDS", 2, 1, 255);
  if (dataShards + parityShards > 255) {
    throw new Error("STARSHINE_RELAY_DATA_SHARDS + STARSHINE_RELAY_PARITY_SHARDS must not exceed 255");
  }
  const gatewayAllowedShardPolicies = shardPolicies(
    process.env.STARSHINE_GATEWAY_ALLOWED_SHARD_POLICIES ?? `${dataShards}+${parityShards}`,
  );
  return {
    server,
    serverCa,
    ledgerId,
    walletFile,
    dataDir,
    outboxKey,
    host,
    port: integer("STARSHINE_RELAY_PORT", 8787, 1, 65_535),
    bearerToken,
    scanEnabled: boolean("STARSHINE_RELAY_SCAN_ENABLED", false),
    scanTitle: process.env.STARSHINE_RELAY_SCAN_TITLE?.trim() || "VOID application ledger",
    scanEnvironment: process.env.STARSHINE_RELAY_SCAN_ENVIRONMENT?.trim() || "unspecified",
    scanRateLimitPerMinute: integer("STARSHINE_RELAY_SCAN_RATE_LIMIT", 60, 1, 10_000),
    maxEventBytes: integer("STARSHINE_RELAY_MAX_EVENT_BYTES", 1024 * 1024, 1, 64 * 1024 * 1024),
    maxAttempts: integer("STARSHINE_RELAY_MAX_ATTEMPTS", 20, 1, 10_000),
    retryBaseMs: integer("STARSHINE_RELAY_RETRY_BASE_MS", 1_000, 10, 3_600_000),
    dataShards,
    parityShards,
    gatewayEnabled: boolean("STARSHINE_GATEWAY_ENABLED", false),
    gatewayMaxChunkBytes: integer(
      "STARSHINE_GATEWAY_MAX_CHUNK_BYTES",
      8 * 1024 * 1024,
      1,
      64 * 1024 * 1024,
    ),
    gatewayMaxFileBytes: integer(
      "STARSHINE_GATEWAY_MAX_FILE_BYTES",
      1024 * 1024 * 1024,
      1,
      Number.MAX_SAFE_INTEGER,
    ),
    gatewayMaxChunks: integer("STARSHINE_GATEWAY_MAX_CHUNKS", 10_000, 1, 1_000_000),
    gatewayMaxJsonBytes: integer(
      "STARSHINE_GATEWAY_MAX_JSON_BYTES",
      128 * 1024 * 1024,
      1,
      1024 * 1024 * 1024,
    ),
    gatewayCapabilityTtlSeconds: integer(
      "STARSHINE_GATEWAY_CAPABILITY_TTL_SECONDS",
      900,
      1,
      3600,
    ),
    gatewayAllowedShardPolicies,
    gatewayAllowedOrigins: origins(process.env.STARSHINE_GATEWAY_ALLOWED_ORIGINS),
    gatewayDefaultRouteId: process.env.STARSHINE_GATEWAY_DEFAULT_ROUTE_ID?.trim() || "void-primary",
    gatewayRoutesFile: process.env.STARSHINE_GATEWAY_ROUTES_FILE?.trim() || undefined,
    amqpUrl,
    amqpQueue,
    amqpPrefetch: integer("STARSHINE_RELAY_AMQP_PREFETCH", 16, 1, 10_000),
  };
}

function shardPolicies(raw: string): ReadonlySet<string> {
  const policies = raw.split(",").map((value) => value.trim()).filter(Boolean);
  if (policies.length < 1) throw new Error("STARSHINE_GATEWAY_ALLOWED_SHARD_POLICIES must not be empty");
  for (const policy of policies) {
    const match = /^([1-9][0-9]{0,2})\+([1-9][0-9]{0,2})$/.exec(policy);
    if (!match || Number(match[1]) + Number(match[2]) > 255) {
      throw new Error(`invalid gateway shard policy ${policy}`);
    }
  }
  return new Set(policies);
}

function origins(raw: string | undefined): ReadonlySet<string> {
  const values = raw?.split(",").map((value) => value.trim()).filter(Boolean) ?? [];
  for (const value of values) {
    const parsed = new URL(value);
    if (parsed.origin !== value || (parsed.protocol !== "https:" && parsed.hostname !== "localhost")) {
      throw new Error(`invalid gateway CORS origin ${value}`);
    }
  }
  return new Set(values);
}

function required(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required`);
  return value;
}

function integer(name: string, fallback: number, minimum: number, maximum: number): number {
  const raw = process.env[name];
  const value = raw === undefined ? fallback : Number(raw);
  if (!Number.isInteger(value) || value < minimum || value > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }
  return value;
}

function boolean(name: string, fallback: boolean): boolean {
  const raw = process.env[name]?.trim().toLowerCase();
  if (raw === undefined || raw === "") return fallback;
  if (raw === "true") return true;
  if (raw === "false") return false;
  throw new Error(`${name} must be true or false`);
}

function isLoopback(host: string): boolean {
  return host === "127.0.0.1" || host === "::1" || host === "localhost";
}

async function readSecretKey(file: string): Promise<Uint8Array> {
  const raw = await readFile(file);
  if (raw.length === 32) return new Uint8Array(raw);
  const text = raw.toString("utf8").trim();
  const decoded = /^[0-9a-f]{64}$/i.test(text)
    ? Buffer.from(text, "hex")
    : Buffer.from(text, "base64url");
  if (decoded.length !== 32) {
    throw new Error("STARSHINE_RELAY_OUTBOX_KEY_FILE must contain 32 raw bytes, 64 hex digits, or unpadded base64url");
  }
  return new Uint8Array(decoded);
}

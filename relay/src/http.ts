import { createServer, type IncomingMessage, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";

import type { RelayConfig } from "./config.js";
import {
  FileAuthorizationError,
  FileConflictError,
  FileNotFoundError,
  type FileGateway,
  type FilePrincipal,
} from "./file_gateway.js";
import { FileCapabilityAuthority, type FileScope } from "./capability.js";
import {
  IdempotencyConflictError,
  type DurableOutbox,
  type LocatedRecord,
  type PrivateReferenceMatch,
} from "./outbox.js";
import { parseRelayEvent } from "./schema.js";
import type { PublicScanProvider } from "./scan.js";
import { scanAsset } from "./scan_assets.js";

const EVENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PRIVATE_REFERENCE_API_VERSION = "void.relay.references.v1";
const SCAN_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

export function createRelayHttpServer(
  config: RelayConfig,
  outbox: DurableOutbox,
  scan?: PublicScanProvider,
  gateway?: FileGateway,
  capabilities?: FileCapabilityAuthority,
): Server {
  const scanLimiter = new FixedWindowRateLimiter(config.scanRateLimitPerMinute);
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
      if (config.gatewayEnabled && url.pathname.startsWith("/v1/files")) {
        applyGatewayCors(config, request, response);
        if (request.method === "OPTIONS") {
          response.writeHead(204, { "content-length": "0" });
          return response.end();
        }
      }
      if (url.pathname === "/healthz" && request.method === "GET") {
        return json(response, 200, { ok: true });
      }
      if (config.scanEnabled && scan && request.method === "GET") {
        const asset = await scanAsset(url.pathname);
        if (asset) {
          return bytes(response, 200, asset.body, asset.contentType, {
            "cache-control": url.pathname.endsWith(".css") || url.pathname.endsWith(".js")
              ? "public, max-age=300"
              : "no-store",
            "content-security-policy": SCAN_CSP,
          });
        }
        if (url.pathname === "/v1/scan/ledger") {
          enforceScanRateLimit(scanLimiter, request);
          return json(response, 200, scan.ledger(), "public, max-age=60");
        }
        if (url.pathname === "/v1/scan/events") {
          enforceScanRateLimit(scanLimiter, request);
          const limit = scanLimit(url.searchParams.get("limit"));
          const cursor = scanCursor(url.searchParams.get("cursor"));
          return json(
            response,
            200,
            await scan.list(limit, cursor),
            "public, max-age=5, stale-while-revalidate=30",
          );
        }
        const scanMatch = /^\/v1\/scan\/events\/([^/]+)$/.exec(url.pathname);
        if (scanMatch) {
          enforceScanRateLimit(scanLimiter, request);
          const eventId = scanMatch[1]!;
          if (!EVENT_ID.test(eventId)) return json(response, 400, { error: "invalid event ID" });
          return json(
            response,
            200,
            await scan.detail(eventId),
            "public, max-age=60, stale-while-revalidate=300",
          );
        }
      }
      if (
        config.gatewayEnabled && gateway && capabilities &&
        url.pathname === "/v1/capabilities" && request.method === "POST"
      ) {
        if (!authorized(request, config.bearerToken)) throw new FileAuthorizationError("unauthorized");
        const body = await readJson(request, Math.min(config.gatewayMaxJsonBytes, 1024 * 1024));
        return json(response, 201, capabilities.mint(body as never));
      }
      if (config.gatewayEnabled && gateway && capabilities) {
        if (url.pathname === "/v1/files/uploads" && request.method === "POST") {
          const principal = filePrincipal(request, config.bearerToken, capabilities, "files:create");
          const body = await readJson(request, Math.min(config.gatewayMaxJsonBytes, 1024 * 1024));
          return json(response, 201, await gateway.create(body, principal));
        }
        if (url.pathname === "/v1/files" && request.method === "GET") {
          const principal = filePrincipal(request, config.bearerToken, capabilities, "files:read");
          const query = referenceQuery(url.searchParams.get("query"));
          const limit = referenceLimit(url.searchParams.get("limit"));
          return json(response, 200, gateway.search(query, limit, principal));
        }
        const chunk = /^\/v1\/files\/uploads\/([^/]+)\/chunks\/([0-9]+)$/.exec(url.pathname);
        if (chunk) {
          const uploadId = chunk[1]!;
          const index = Number(chunk[2]);
          if (request.method === "PUT") {
            const principal = filePrincipal(
              request,
              config.bearerToken,
              capabilities,
              "files:write",
              uploadId,
            );
            const contentType = request.headers["content-type"]?.split(";", 1)[0]?.trim();
            const body = contentType === "application/json"
              ? await readJson(request, config.gatewayMaxJsonBytes)
              : await readBytes(request, config.gatewayMaxChunkBytes);
            return json(response, 200, await gateway.putChunk(uploadId, index, body, principal));
          }
          if (request.method === "GET") {
            const principal = filePrincipal(
              request,
              config.bearerToken,
              capabilities,
              "files:read",
              uploadId,
            );
            const retrieved = await gateway.retrieveChunk(uploadId, index, principal);
            const receipt = Buffer.from(JSON.stringify(retrieved.receipt)).toString("base64url");
            if (retrieved.mode === "client-sealed") {
              response.setHeader("x-void-retrieve-receipt", receipt);
              return json(response, 200, {
                version: "void.client-sealed-chunk.v1",
                storedBlob: retrieved.body,
              });
            }
            return bytes(response, 200, Buffer.from(retrieved.body), retrieved.contentType, {
              "cache-control": "private, no-store",
              "content-disposition": "attachment",
              "x-void-retrieve-receipt": receipt,
            });
          }
        }
        const complete = /^\/v1\/files\/uploads\/([^/]+)\/complete$/.exec(url.pathname);
        if (complete && request.method === "POST") {
          const uploadId = complete[1]!;
          const principal = filePrincipal(
            request,
            config.bearerToken,
            capabilities,
            "files:complete",
            uploadId,
          );
          return json(response, 200, await gateway.complete(uploadId, principal));
        }
        const action = /^\/v1\/files\/uploads\/([^/]+)\/actions$/.exec(url.pathname);
        if (action && request.method === "POST") {
          const uploadId = action[1]!;
          const principal = filePrincipal(
            request,
            config.bearerToken,
            capabilities,
            "files:audit",
            uploadId,
          );
          const body = await readJson(request, Math.min(config.gatewayMaxJsonBytes, 1024 * 1024));
          return json(response, 202, await gateway.action(uploadId, body, principal));
        }
        const detail = /^\/v1\/files\/uploads\/([^/]+)$/.exec(url.pathname);
        if (detail && request.method === "GET") {
          const uploadId = detail[1]!;
          const principal = filePrincipal(
            request,
            config.bearerToken,
            capabilities,
            "files:read",
            uploadId,
          );
          return json(response, 200, gateway.detail(uploadId, principal));
        }
      }
      if (!authorized(request, config.bearerToken)) {
        response.setHeader("www-authenticate", "Bearer");
        return json(response, 401, { error: "unauthorized" });
      }
      if (url.pathname === "/v1/references" && request.method === "GET") {
        const query = referenceQuery(url.searchParams.get("query"));
        const limit = referenceLimit(url.searchParams.get("limit"));
        return json(response, 200, {
          version: PRIVATE_REFERENCE_API_VERSION,
          query,
          references: outbox.searchPrivateReferences(query, limit)
            .map((match) => referenceView(config, match)),
        });
      }
      const referenceMatch = /^\/v1\/references\/([^/]+)$/.exec(url.pathname);
      if (referenceMatch && request.method === "GET") {
        const sourceEventId = referenceMatch[1]!;
        if (!EVENT_ID.test(sourceEventId)) {
          return json(response, 400, { error: "invalid source event ID" });
        }
        const match = outbox.privateReference(sourceEventId);
        return match
          ? json(response, 200, {
            version: PRIVATE_REFERENCE_API_VERSION,
            reference: referenceView(config, match),
          })
          : json(response, 404, { error: "private reference not found" });
      }
      if (url.pathname === "/v1/events" && request.method === "POST") {
        const body = await readJson(request, config.maxEventBytes);
        const envelope = parseRelayEvent(body);
        const located = await outbox.enqueue(envelope);
        return json(response, statusCode(located), responseBody(envelope.sourceEventId, located));
      }
      const match = /^\/v1\/events\/([0-9a-f-]+)$/i.exec(url.pathname);
      if (match && request.method === "GET") {
        const located = await outbox.locate(match[1]!);
        return json(response, located.status === "missing" ? 404 : 200, {
          sourceEventId: match[1],
          status: located.status,
          record: located.value,
        });
      }
      return json(response, 404, { error: "not found" });
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      const status = error instanceof ScanRateLimitError
        ? 429
        : error instanceof FileAuthorizationError
        ? 401
        : error instanceof FileNotFoundError
        ? 404
        : error instanceof FileConflictError
        ? 409
        : error instanceof IdempotencyConflictError
        ? 409
        : message.includes("maximum")
          ? 413
          : 400;
      if (status === 429) response.setHeader("retry-after", "60");
      return json(response, status, { error: message });
    }
  });
}

function filePrincipal(
  request: IncomingMessage,
  bearerToken: string | undefined,
  authority: FileCapabilityAuthority,
  scope: FileScope,
  uploadId?: string,
): FilePrincipal {
  if (authorized(request, bearerToken)) {
    return { service: true, subject: "void-service", tenantId: "void-service" };
  }
  const value = request.headers.authorization;
  if (!value?.startsWith("VoidCapability ")) throw new FileAuthorizationError("unauthorized");
  try {
    const capability = authority.verify(value.slice("VoidCapability ".length), scope, uploadId);
    return {
      service: false,
      subject: capability.subject,
      tenantId: capability.tenantId,
    };
  } catch (error) {
    throw new FileAuthorizationError(error instanceof Error ? error.message : "unauthorized");
  }
}

function applyGatewayCors(
  config: RelayConfig,
  request: IncomingMessage,
  response: import("node:http").ServerResponse,
): void {
  const origin = request.headers.origin;
  if (!origin) return;
  if (!config.gatewayAllowedOrigins.has(origin)) {
    throw new FileAuthorizationError("origin is not allowed");
  }
  response.setHeader("access-control-allow-origin", origin);
  response.setHeader("vary", "Origin");
  response.setHeader("access-control-allow-methods", "GET, POST, PUT, OPTIONS");
  response.setHeader("access-control-allow-headers", "Authorization, Content-Type");
  response.setHeader("access-control-expose-headers", "X-Void-Retrieve-Receipt");
  response.setHeader("access-control-max-age", "600");
}

class ScanRateLimitError extends Error {}

class FixedWindowRateLimiter {
  private readonly clients = new Map<string, { count: number; resetAt: number }>();

  constructor(private readonly maximum: number) {}

  take(key: string): boolean {
    const now = Date.now();
    const current = this.clients.get(key);
    if (!current || current.resetAt <= now) {
      this.clients.set(key, { count: 1, resetAt: now + 60_000 });
      this.prune(now);
      return true;
    }
    if (current.count >= this.maximum) return false;
    current.count += 1;
    return true;
  }

  private prune(now: number): void {
    if (this.clients.size < 1_000) return;
    for (const [key, value] of this.clients) {
      if (value.resetAt <= now) this.clients.delete(key);
    }
  }
}

function enforceScanRateLimit(
  limiter: FixedWindowRateLimiter,
  request: IncomingMessage,
): void {
  const forwarded = request.headers["x-real-ip"];
  const key = (Array.isArray(forwarded) ? forwarded[0] : forwarded)
    ?? request.socket.remoteAddress
    ?? "unknown";
  if (!limiter.take(key)) throw new ScanRateLimitError("public scan rate limit exceeded");
}

function scanLimit(raw: string | null): number {
  if (raw === null || raw === "") return 50;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 100) {
    throw new Error("scan limit must be an integer between 1 and 100");
  }
  return value;
}

function scanCursor(raw: string | null): string {
  if (raw === null || raw === "") return "";
  if (!/^[1-9][0-9]{0,19}$/.test(raw)) throw new Error("invalid scan cursor");
  return raw;
}

function referenceQuery(raw: string | null): string {
  const value = raw?.trim() ?? "";
  if (!value || value.length > 256) {
    throw new Error("reference query must contain between 1 and 256 characters");
  }
  return value;
}

function referenceLimit(raw: string | null): number {
  if (raw === null || raw === "") return 25;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < 1 || value > 100) {
    throw new Error("reference limit must be an integer between 1 and 100");
  }
  return value;
}

function referenceView(config: RelayConfig, match: PrivateReferenceMatch): unknown {
  return {
    sourceEventId: match.sourceEventId,
    sourceSystem: match.sourceSystem,
    eventType: match.eventType,
    occurredAt: match.occurredAt,
    acceptedAt: match.acceptedAt,
    status: match.status,
    reference: match.reference,
    eventId: match.eventId,
    ledgerId: match.ledgerId,
    publicProofPath: config.scanEnabled && match.eventId
      ? `/scan?event=${encodeURIComponent(match.eventId)}`
      : undefined,
  };
}

function authorized(request: IncomingMessage, token: string | undefined): boolean {
  if (!token) return true;
  const value = request.headers.authorization;
  if (!value?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(value.slice(7));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(request: IncomingMessage, maximum: number): Promise<unknown> {
  return JSON.parse(Buffer.from(await readBytes(request, maximum)).toString("utf8")) as unknown;
}

async function readBytes(request: IncomingMessage, maximum: number): Promise<Uint8Array> {
  const declared = request.headers["content-length"];
  if (declared !== undefined && Number(declared) > maximum) {
    throw new Error(`request exceeds maximum of ${maximum} bytes`);
  }
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > maximum) throw new Error(`request exceeds maximum of ${maximum} bytes`);
    chunks.push(bytes);
  }
  if (size === 0) throw new Error("request body is required");
  return new Uint8Array(Buffer.concat(chunks));
}

function statusCode(located: LocatedRecord): number {
  return located.status === "complete" ? 200 : located.status === "dead" ? 409 : 202;
}

function responseBody(sourceEventId: string, located: LocatedRecord): unknown {
  return { sourceEventId, status: located.status, record: located.value };
}

function json(
  response: import("node:http").ServerResponse,
  status: number,
  body: unknown,
  cacheControl = "no-store",
): void {
  const encoded = Buffer.from(JSON.stringify(body));
  bytes(response, status, encoded, "application/json; charset=utf-8", {
    "cache-control": cacheControl,
  });
}

function bytes(
  response: import("node:http").ServerResponse,
  status: number,
  body: Buffer,
  contentType: string,
  headers: Record<string, string> = {},
): void {
  response.writeHead(status, {
    ...headers,
    "content-length": body.length,
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "x-frame-options": "DENY",
    "content-type": contentType,
  });
  response.end(body);
}

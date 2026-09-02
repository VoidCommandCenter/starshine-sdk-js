import { createServer, type IncomingMessage, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";

import type { RelayConfig } from "./config.js";
import {
  IdempotencyConflictError,
  type DurableOutbox,
  type LocatedRecord,
} from "./outbox.js";
import { parseRelayEvent } from "./schema.js";
import type { PublicScanProvider } from "./scan.js";
import { scanAsset } from "./scan_assets.js";

const EVENT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const SCAN_CSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'";

export function createRelayHttpServer(
  config: RelayConfig,
  outbox: DurableOutbox,
  scan?: PublicScanProvider,
): Server {
  const scanLimiter = new FixedWindowRateLimiter(config.scanRateLimitPerMinute);
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
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
      if (!authorized(request, config.bearerToken)) {
        response.setHeader("www-authenticate", "Bearer");
        return json(response, 401, { error: "unauthorized" });
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

function authorized(request: IncomingMessage, token: string | undefined): boolean {
  if (!token) return true;
  const value = request.headers.authorization;
  if (!value?.startsWith("Bearer ")) return false;
  const supplied = Buffer.from(value.slice(7));
  const expected = Buffer.from(token);
  return supplied.length === expected.length && timingSafeEqual(supplied, expected);
}

async function readJson(request: IncomingMessage, maximum: number): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const bytes = Buffer.from(chunk);
    size += bytes.length;
    if (size > maximum) throw new Error(`request exceeds maximum of ${maximum} bytes`);
    chunks.push(bytes);
  }
  if (size === 0) throw new Error("request body is required");
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown;
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

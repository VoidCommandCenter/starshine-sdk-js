import { createServer, type IncomingMessage, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";

import type { RelayConfig } from "./config.js";
import {
  IdempotencyConflictError,
  type DurableOutbox,
  type LocatedRecord,
} from "./outbox.js";
import { parseRelayEvent } from "./schema.js";

export function createRelayHttpServer(
  config: RelayConfig,
  outbox: DurableOutbox,
): Server {
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url ?? "/", `http://${request.headers.host ?? "localhost"}`);
      if (url.pathname === "/healthz" && request.method === "GET") {
        return json(response, 200, { ok: true });
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
      const status = error instanceof IdempotencyConflictError
        ? 409
        : message.includes("maximum")
          ? 413
          : 400;
      return json(response, status, { error: message });
    }
  });
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

function json(response: import("node:http").ServerResponse, status: number, body: unknown): void {
  const encoded = Buffer.from(JSON.stringify(body));
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": encoded.length,
    "cache-control": "no-store",
  });
  response.end(encoded);
}

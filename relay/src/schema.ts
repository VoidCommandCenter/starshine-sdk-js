export const RELAY_EVENT_VERSION = "void.relay.event.v1";

export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [key: string]: JsonValue };

export interface RelayEventEnvelope {
  version: typeof RELAY_EVENT_VERSION;
  sourceSystem: string;
  sourceEventId: string;
  eventType: string;
  occurredAt: string;
  subject?: { type: string; id: string };
  data: JsonValue;
  metadata?: Record<string, JsonValue>;
}

export function parseRelayEvent(value: unknown): RelayEventEnvelope {
  if (!isRecord(value)) throw new Error("event envelope must be a JSON object");
  if (value.version !== RELAY_EVENT_VERSION) {
    throw new Error(`version must be ${RELAY_EVENT_VERSION}`);
  }
  const sourceSystem = boundedString(value.sourceSystem, "sourceSystem", 128);
  const sourceEventId = boundedString(value.sourceEventId, "sourceEventId", 64);
  if (!isUuid(sourceEventId)) throw new Error("sourceEventId must be a UUID");
  const eventType = boundedString(value.eventType, "eventType", 128);
  const occurredAt = boundedString(value.occurredAt, "occurredAt", 64);
  const occurredAtMs = Date.parse(occurredAt);
  if (!Number.isFinite(occurredAtMs)) throw new Error("occurredAt must be an ISO-8601 timestamp");
  assertJson(value.data, "data");

  let subject: RelayEventEnvelope["subject"];
  if (value.subject !== undefined) {
    if (!isRecord(value.subject)) throw new Error("subject must be an object");
    subject = {
      type: boundedString(value.subject.type, "subject.type", 128),
      id: boundedString(value.subject.id, "subject.id", 256),
    };
  }
  let metadata: Record<string, JsonValue> | undefined;
  if (value.metadata !== undefined) {
    if (!isRecord(value.metadata)) throw new Error("metadata must be an object");
    assertJson(value.metadata, "metadata");
    metadata = value.metadata as Record<string, JsonValue>;
  }
  return {
    version: RELAY_EVENT_VERSION,
    sourceSystem,
    sourceEventId,
    eventType,
    occurredAt: new Date(occurredAtMs).toISOString(),
    subject,
    data: value.data as JsonValue,
    metadata,
  };
}

export function canonicalEventBytes(event: RelayEventEnvelope): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(sortJson(event as unknown as JsonValue)));
}

function sortJson(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(sortJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left < right ? -1 : left > right ? 1 : 0)
        .map(([key, entry]) => [key, sortJson(entry)]),
    );
  }
  return value;
}

function assertJson(value: unknown, path: string): asserts value is JsonValue {
  if (
    value === null ||
    typeof value === "string" ||
    typeof value === "boolean" ||
    (typeof value === "number" && Number.isFinite(value))
  ) return;
  if (Array.isArray(value)) {
    value.forEach((entry, index) => assertJson(entry, `${path}[${index}]`));
    return;
  }
  if (isRecord(value)) {
    for (const [key, entry] of Object.entries(value)) {
      if (!key || key.length > 256) throw new Error(`${path} contains an invalid key`);
      assertJson(entry, `${path}.${key}`);
    }
    return;
  }
  throw new Error(`${path} must contain only JSON values`);
}

function boundedString(value: unknown, name: string, max: number): string {
  if (typeof value !== "string" || !value.trim() || value.length > max) {
    throw new Error(`${name} must be a non-empty string of at most ${max} characters`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isUuid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

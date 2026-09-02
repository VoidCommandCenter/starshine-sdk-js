# Starshine application relay

This is the VOID-owned integration boundary for partner applications. It accepts a small, versioned JSON event over authenticated HTTP or RabbitMQ, durably records it, seals it locally with X-Wing HPKE, and appends it to one configured Starshine application ledger. Partner repositories do not contain Starshine wallets, cryptography, storage logic, or checkpoint code.

The relay is intentionally one application environment per deployment. Give development, staging, and production different `STARSHINE_LEDGER_ID` values and separate wallets.

## Event envelope

```json
{
  "version": "void.relay.event.v1",
  "sourceSystem": "partner-app",
  "sourceEventId": "018f9f4c-4c83-7f1d-8e5d-e0d646f48d8a",
  "eventType": "assessment.completed",
  "occurredAt": "2026-09-01T16:00:00.000Z",
  "subject": { "type": "assessment", "id": "a-123" },
  "data": { "result": "passed" },
  "metadata": { "schemaVersion": 1 }
}
```

`sourceEventId` must be a stable UUID that is unique across the application ledger. It becomes the Starshine request ID, so redelivery is exactly-once at the ledger boundary. Reusing it for different envelope bytes is rejected as a conflict. The event payload must not contain plaintext secrets unless they are intended to be preserved inside the encrypted Starshine artifact.

HTTP endpoints:

- `POST /v1/events` validates and durably enqueues an event.
- `GET /v1/events/{sourceEventId}` returns pending, processing, complete, or dead status and the final receipt when available.
- `GET /healthz` is unauthenticated for container probes.

Every other HTTP endpoint requires `Authorization: Bearer …` when a token file is configured. A non-loopback listener refuses to start without that file.

## Configuration

Required:

- `STARSHINE_SERVER`, normally `grpcs://api.void.gs:443`
- `STARSHINE_LEDGER_ID`
- `STARSHINE_WALLET_FILE`, a mounted mode-0600 Starshine wallet
- `STARSHINE_RELAY_OUTBOX_KEY_FILE`, a mounted 32-byte random key (raw, hex, or unpadded base64url)

Recommended:

- `STARSHINE_RELAY_BEARER_TOKEN_FILE`, a mounted token file
- `STARSHINE_RELAY_DATA_DIR`, default `/var/lib/starshine-relay`; this must be persistent storage
- `STARSHINE_RELAY_HOST`, default `127.0.0.1`
- `STARSHINE_RELAY_PORT`, default `8787`

RabbitMQ is enabled when both `STARSHINE_RELAY_AMQP_URL` and `STARSHINE_RELAY_AMQP_QUEUE` are present. Use an `amqps://` URL in production. Messages are acknowledged only after the normalized envelope is on the durable outbox.

## Retry and failure behavior

Every pending, prepared, completed, and dead outbox record is encrypted with AES-256-GCM under the mounted outbox key. AES-256 retains a 128-bit security margin against generic quantum search. Keep and back up this key for as long as the outbox volume must remain readable.

Before its first network append, the worker persists the fully sealed `StoredBlob` inside that encrypted outbox. A crash or ambiguous gRPC failure therefore retries byte-identical encrypted material with the same request UUID. Successful records move to `complete/`; repeated failures move to `dead/` after `STARSHINE_RELAY_MAX_ATTEMPTS` (default 20). Operators can inspect the recorded error through the authenticated status endpoint without losing the source envelope.

Run one replica per outbox volume. The supplied Helm chart uses a `Recreate` strategy and `ReadWriteOnce` PVC for that reason.

## Local development

From the repository root:

```bash
npm ci
npm run build
npm --workspace @void/starshine-relay test
npm --workspace @void/starshine-relay run build
```

Build the container with the repository root as its context:

```bash
docker build -f relay/Dockerfile -t starshine-relay .
```

The partner-side handoff is only the envelope contract and transport destination. Hyper Nimbus implementation should be reviewed separately before any changes are made in its repositories.

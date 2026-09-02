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
  "privateReference": {
    "kind": "assessment",
    "externalId": "HN-1042",
    "label": "Quarterly assessment 1042",
    "aliases": ["renewal-1042"]
  },
  "data": { "result": "passed" },
  "metadata": { "schemaVersion": 1 }
}
```

`sourceEventId` must be a stable UUID that is unique across the application ledger. It becomes the Starshine request ID, so redelivery is exactly-once at the ledger boundary. Reusing it for different envelope bytes is rejected as a conflict. The event payload must not contain plaintext secrets unless they are intended to be preserved inside the encrypted Starshine artifact.

`privateReference` is optional. It gives an authenticated application a human-readable lookup key without publishing that key in VOIDSCAN. The normalized reference is part of the canonical envelope, so it is X-Wing-encrypted in Starshine, covered by the artifact commitment, and AES-256-GCM-encrypted in the local durable outbox. It is immutable under the event's idempotency key. Avoid putting unnecessary personal data in labels or aliases.

HTTP endpoints:

- `POST /v1/events` validates and durably enqueues an event.
- `GET /v1/events/{sourceEventId}` returns pending, processing, complete, or dead status and the final receipt when available.
- `GET /healthz` is unauthenticated for container probes.

Every other HTTP endpoint requires `Authorization: Bearer …` when a token file is configured. A non-loopback listener refuses to start without that file.

## Private reference search

Application backends can resolve a private human reference to its Starshine event and public proof using bearer-authenticated endpoints:

- `GET /v1/references?query=HN-1042&limit=25` — case-insensitive search across external ID, label, kind, aliases, source event ID, and completed Starshine event ID.
- `GET /v1/references/{sourceEventId}` — exact reference lookup by the application's stable UUID.

Completed matches include `eventId`, `ledgerId`, and a `publicProofPath` such as `/scan?event=…`. That path opens the public proof directly, but the private label never appears in the path or public response. Keep the relay bearer token in a trusted application backend; do not embed it in a browser or public client. Events submitted before `privateReference` was supplied remain commitment-searchable in VOIDSCAN but have no human-reference match.

## File-protection gateway

Set `STARSHINE_GATEWAY_ENABLED=true` to add the versioned, chunked file boundary. The relay
supports server-side `gateway-sealed` uploads and opaque `client-sealed` uploads produced by the
JavaScript SDK. Its encrypted private catalog makes file names, labels, external IDs, and aliases
searchable to an authorized tenant without exposing them in VOIDSCAN.

- `POST /v1/capabilities` — service-bearer-only minting of a short-lived, scoped capability.
- `POST /v1/files/uploads` — create an idempotent upload session and private label.
- `PUT /v1/files/uploads/{uploadId}/chunks/{index}` — submit one exact-size binary or sealed chunk.
- `POST /v1/files/uploads/{uploadId}/complete` — ledger a sealed manifest and `file.uploaded` audit event.
- `GET /v1/files/uploads/{uploadId}` — private metadata, artifact IDs, and proof links.
- `GET /v1/files/uploads/{uploadId}/chunks/{index}` — ledger a technical retrieve and return plaintext or sealed bytes according to the mode.
- `POST /v1/files/uploads/{uploadId}/actions` — ledger a semantic application action.
- `GET /v1/files?query=…` — tenant-scoped search across label, external ID, aliases, file name, upload ID, and manifest event ID.

The service bearer is for a trusted backend. Browser-facing calls use `Authorization:
VoidCapability …`; capabilities are tenant-, scope-, expiry-, and optionally upload-bound. Hyper
Nimbus or another application remains responsible for deciding who may receive a capability.
Semantic reads such as `file.viewed` and `file.downloaded` must be sent by the application because
a chunk retrieval alone cannot tell whether the bytes were previewed, downloaded, or processed by
a background job.

The initial action vocabulary is `file.created`, `file.uploaded`, `file.viewed`, `file.previewed`,
`file.downloaded`, `file.exported`, `file.updated`, `file.version-created`, `file.renamed`,
`file.moved`, `file.shared`, `file.unshared`, `file.deleted`, `file.released`, `access.requested`,
`access.granted`, `access.denied`, `access.revoked`, `permission.changed`, `record.approved`,
`record.rejected`, and `record.status-changed`.

## Public VOIDSCAN

The relay can publish a metadata-only, read-only proof explorer without exposing its bearer-protected ingestion API. Set `STARSHINE_RELAY_SCAN_ENABLED=true`, then open `/scan` on the relay hostname. The versioned public API is:

- `GET /v1/scan/ledger` — public ledger identity and privacy policy.
- `GET /v1/scan/events?limit=50&cursor=…` — newest-first sanitized event commitments.
- `GET /v1/scan/events/{eventId}` — a cryptographically verified two-level checkpoint inclusion proof.

VOIDSCAN deliberately omits the actor ID, request ID and digest, logical content ID, balance, filename, application envelope, and encrypted artifact bytes. It publishes only canonical event/checkpoint commitments and the ML-DSA checkpoint evidence required for independent verification. Public scan calls are rate-limited, recent list results are indexed in memory, and immutable event proofs are cached.

## Configuration

Required:

- `STARSHINE_SERVER`, normally `grpcs://api.void.gs:443`
- `STARSHINE_LEDGER_ID`
- `STARSHINE_WALLET_FILE`, a mounted mode-0600 Starshine wallet
- `STARSHINE_RELAY_OUTBOX_KEY_FILE`, a mounted 32-byte random key (raw, hex, or unpadded base64url)

Recommended:

- `STARSHINE_RELAY_BEARER_TOKEN_FILE`, a mounted token file
- `STARSHINE_SERVER_CA_FILE`, a PEM trust root when the Starshine API uses a private deployment CA
- `STARSHINE_RELAY_SCAN_ENABLED`, default `false`; explicitly opts the configured ledger into public proof metadata
- `STARSHINE_RELAY_SCAN_TITLE`, public application/ledger display name
- `STARSHINE_RELAY_SCAN_ENVIRONMENT`, public environment label such as `staging` or `production`
- `STARSHINE_RELAY_SCAN_RATE_LIMIT`, public API requests per client per minute, default `60`
- `STARSHINE_RELAY_DATA_DIR`, default `/var/lib/starshine-relay`; this must be persistent storage
- `STARSHINE_RELAY_HOST`, default `127.0.0.1`
- `STARSHINE_RELAY_PORT`, default `8787`
- `STARSHINE_GATEWAY_ENABLED`, default `false`
- `STARSHINE_GATEWAY_MAX_CHUNK_BYTES`, default `8388608` (8 MiB)
- `STARSHINE_GATEWAY_MAX_FILE_BYTES`, default `1073741824` (1 GiB)
- `STARSHINE_GATEWAY_MAX_CHUNKS`, default `10000`
- `STARSHINE_GATEWAY_MAX_JSON_BYTES`, default `134217728`; sealed JSON is larger than plaintext
- `STARSHINE_GATEWAY_ALLOWED_SHARD_POLICIES`, comma-separated and defaulting to the relay's configured `k+m`
- `STARSHINE_GATEWAY_CAPABILITY_TTL_SECONDS`, default `900`, maximum `3600`
- `STARSHINE_GATEWAY_ALLOWED_ORIGINS`, exact comma-separated HTTPS origins for browser calls
- `STARSHINE_GATEWAY_DEFAULT_ROUTE_ID`, default `void-primary`
- `STARSHINE_GATEWAY_ROUTES_FILE`, optional mode-`0600` route document for separately provisioned Starshine nodes

The built-in `void-primary` route uses the relay's current Starshine node, wallet, ledger, and
Backblaze-backed storage and truthfully reports one storage failure domain. A route file uses this
shape:

```json
{
  "version": "void.gateway-routes.v1",
  "routes": [{
    "id": "customer-primary",
    "server": "grpcs://customer-node.example:443",
    "ledgerId": "018f9f4c-4c83-7f1d-8e5d-e0d646f48d8a",
    "walletFile": "/run/secrets/customer.wallet.json",
    "serverCaFile": "/run/secrets/customer-ca.pem",
    "failureDomains": 1
  }]
}
```

Adding a route does not move existing artifacts. A customer-specific route becomes active only
after its scoped node/storage credentials are provisioned and tested. Reed-Solomon `k+m` is
adjustable independently from placement; multiple logical shards in one Backblaze bucket are
still one failure domain.

RabbitMQ is enabled when both `STARSHINE_RELAY_AMQP_URL` and `STARSHINE_RELAY_AMQP_QUEUE` are present. Use an `amqps://` URL in production. Messages are acknowledged only after the normalized envelope is on the durable outbox.

## Railway

Build from the repository root with `RAILWAY_DOCKERFILE_PATH=relay/Dockerfile`, attach a persistent volume at `/var/lib/starshine-relay`, set `STARSHINE_RELAY_HOST=0.0.0.0`, and use `/healthz` as the healthcheck path.

The container starts only long enough as root to initialize Railway's mounted volume and its runtime-secret directory, then drops permanently to the unprivileged `node` user before starting the relay.

Railway-managed secret values can be supplied without committing secret files:

- `STARSHINE_WALLET_JSON` contains the complete application wallet JSON.
- `STARSHINE_RELAY_OUTBOX_KEY` contains a 32-byte key encoded as 64 hex digits or unpadded base64url.
- `STARSHINE_RELAY_BEARER_TOKEN` contains the inbound HTTP bearer token.
- `STARSHINE_SERVER_CA_PEM` contains the optional Starshine API trust root in PEM form.

The container entrypoint writes these values to mode-`0600` files under `/run/secrets/starshine`, exports the existing `*_FILE` settings, removes the value variables from the relay process environment, and then starts the worker. Do not put these files on the persistent outbox volume. The mounted-file settings remain the preferred interface for Kubernetes and other secret-volume platforms.

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

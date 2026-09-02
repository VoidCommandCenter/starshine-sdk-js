# Starshine file-protection gateway

Status: implemented contract target for the initial application-onboarding gateway. The public
whitepapers guide this design; this versioned contract and its tests define shipped behavior.

## Security boundary

The gateway supports two ingress modes that produce the same Starshine storage artifact and
application-ledger evidence:

- `gateway-sealed`: an authenticated application sends one plaintext chunk at a time over TLS.
  The gateway holds at most one chunk in memory, X-Wing-seals it immediately, and never writes
  plaintext to disk.
- `client-sealed`: a client uses `starshine-sdk-js` to seal each chunk locally and sends only a
  serialized `StoredBlob`. The gateway never receives file plaintext or client recovery keys.

The gateway's service bearer token authenticates a trusted application backend. Short-lived,
HMAC-SHA-256 capabilities derived from the relay outbox key authorize browser or application
clients for a narrow set of file operations. HMAC-SHA-256 retains a 128-bit security margin
against generic quantum search. Capabilities do not replace Hyper Nimbus identity or permission
checks; its backend mints them only after applying its existing policy.

Private labels and audit context are AES-256-GCM-encrypted on the relay volume and are included
in the encrypted Starshine file manifest. Public VOIDSCAN exposes only receipt/checkpoint
commitments.

## Upload lifecycle

1. `POST /v1/files/uploads` creates an encrypted upload session.
2. `PUT /v1/files/uploads/{uploadId}/chunks/{index}` submits one plaintext or pre-sealed chunk.
3. Each sealed chunk is persisted before its idempotent Starshine append.
4. `POST /v1/files/uploads/{uploadId}/complete` verifies the declared size and chunk set, seals
   an immutable manifest, and appends it to the configured application ledger.
5. `GET /v1/files/uploads/{uploadId}` returns authenticated human metadata and public proof links.
6. `GET /v1/files/uploads/{uploadId}/chunks/{index}` records a Starshine `retrieve` operation and
   returns plaintext for gateway-sealed files or a serialized `StoredBlob` for client recovery.
7. `GET /v1/files?query=...` searches private labels, aliases, external IDs, filenames, upload IDs,
   and completed manifest event IDs inside the encrypted tenant catalog.

Upload session and chunk request IDs are stable UUIDs. Retrying byte-identical input returns the
original receipt; changing bytes under an existing ID is rejected.

## Audit vocabulary

The gateway accepts only the following initial application actions:

- `file.created`, `file.uploaded`, `file.viewed`, `file.previewed`
- `file.downloaded`, `file.exported`, `file.updated`, `file.version-created`
- `file.renamed`, `file.moved`, `file.shared`, `file.unshared`
- `file.deleted`, `file.released`
- `access.requested`, `access.granted`, `access.denied`, `access.revoked`
- `permission.changed`
- `record.approved`, `record.rejected`, `record.status-changed`

`POST /v1/files/uploads/{uploadId}/actions` creates an immutable encrypted audit envelope. Actor
identifiers must be application-scoped pseudonyms, not public names or email addresses.
The application supplies the semantic action because a technical retrieval cannot distinguish a
preview, download, export, or background process. Every successful chunk retrieval separately
creates Starshine's signed technical `Retrieve` receipt.

## Shard policy

The gateway default is Reed-Solomon `4+2`. Allowed policies are configured by Void and selected
per upload; clients cannot reduce the policy below the configured allowlist. Every policy is
recorded in the encrypted manifest and committed by its Starshine artifact root.

Shard count and placement are separate. The current `api.void.gs` storage node persists all
logical provider shards in its configured Backblaze bucket. A route may point at a different
Starshine node backed by a customer bucket. Independent per-shard failure-domain placement needs
the multi-provider storage backend described below and must not be claimed merely because an
artifact contains multiple Reed-Solomon shards.

## Storage routes

Every session selects an allowlisted `routeId`. `void-primary` uses the relay's existing server,
wallet, application ledger, and configured Backblaze backend. Additional routes are described by
a mounted, mode-0600 JSON file and can point to a customer-specific Starshine node/bucket without
changing the gateway API or artifact format.

Route credentials remain server-side. Activating a Hyper Nimbus route requires its scoped
storage endpoint or bucket credentials; implementing a route does not authorize Void to create
or copy those credentials.

## Large files

The protocol is chunked at the HTTP boundary. The default maximum plaintext chunk is 8 MiB and
the default maximum file is 1 GiB. Each chunk is independently sealed, recoverable, and ledgered;
the final encrypted manifest commits the ordered chunk roots and declared total length. The
gateway never buffers the complete file.

For `client-sealed` uploads, a capability authorizes access to the encrypted `StoredBlob`; it does
not convey its client recovery key. Multi-user applications must distribute or wrap the recovery
key under their existing authorized-recipient policy. The current single-recipient X-Wing artifact
format must not be presented as a multi-recipient key-management system.

## Multi-provider placement

`api.void.gs` currently stores all shard objects in one backend. A future-compatible
multi-provider backend must:

1. map every shard index to an explicit failure-domain route;
2. replicate the small encrypted metadata/manifest needed for recovery;
3. retrieve any `k` verified shards across routes;
4. run proof-of-storage against the route that owns the challenged shard;
5. refuse a placement policy whose largest failure domain leaves fewer than `k` shards;
6. record only non-secret placement commitments publicly.

Until at least two additional scoped providers are configured and tested, production responses
must report `failureDomains: 1` even when `totalShards > 1`.

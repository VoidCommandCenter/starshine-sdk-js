# Starshine API v2 contract

Status: draft implementation contract for the onboarding network.

The v2 API separates four identities that v1 conflated:

- `ledger_id`: permanent opaque UUID for one application environment. Development, staging, and production use different IDs.
- `logical_content_id`: optional stable identity for the same plaintext bytes and namespace. Sharing it reveals equality.
- `artifact_root`: the BAO commitment to one randomized encrypted representation.
- `event_id`: the immutable ledger identity of an operation.

## Required invariants

### Authentication

Every state-changing request and private ledger read carries an ML-DSA-65 `OperationAuthorization`. The server derives `actor_id` from the signing key, reconstructs the canonical payload, verifies all request-bound fields, enforces timestamp skew, and permanently rejects nonce replay. Byte fields use unpadded base64url and uint64 fields use decimal strings in canonical JSON.

TLS is mandatory on non-loopback production endpoints. Application-layer HPKE and ML-DSA remain the post-quantum confidentiality and authorization boundary; TLS protects metadata and provides deployable channel authentication.

Operation signatures use ML-DSA-65 context `starshine-operation-v2` over the ASCII domain `starshine:operation:v2\0` followed by canonical JSON containing the snake_case proto fields `actor_id`, `artifact_root`, `event_id`, `issued_at_unix_ms`, `ledger_id`, `logical_content_id`, `max_void`, `nonce`, `operation`, `request_digest`, `request_id`, and `version` in lexicographic key order. Byte fields are unpadded base64url; uint64 values are decimal strings. The node rejects an otherwise valid actor unless it is active in that application ledger's signer set.

Request digests use BLAKE3 with an operation-specific ASCII domain. Every component is framed as an unsigned 64-bit big-endian byte length followed by its bytes. Append covers every public `SealedArtifact` field, every shard in order, and `file_name`; retrieve covers the artifact root and minimum-shards byte; release covers the artifact root and reason. The SDK implementation is the interoperability reference.

### Idempotency

`request_id` is caller-generated and stable across retries. The server stores:

```text
(ledger_id, actor_id, request_id) -> (request_digest, serialized_response)
```

An exact append retry returns the original serialized receipt unchanged, including its original `RECEIPT_DISPOSITION_CREATED` disposition. A different `request_digest` under the same key fails with `ALREADY_EXISTS`. An accepted request is never executed twice.

### Append-only history and release

`Append`, `Retrieve`, and `Release` each append an event to two hash-linked sequences: the actor's sequence inside the application ledger and the application ledger's global sequence. `Release` may remove physical artifact bytes after authorization, but it never removes event records, receipts, or checkpoint inclusion. Ownership records are ledger-scoped; a signer from another application cannot read or release the artifact through authenticated APIs.

### Application-ledger lifecycle

`LedgerAdmin` is disabled unless the node has `STARSHINE_LEDGER_ADMIN_PUBLIC_KEY`. Its create, grant, revoke, activate/deactivate, and get requests are signed by that configured ML-DSA-65 operator key. Application wallets never receive this key. A ledger cannot revoke its final signer. Deactivating a ledger immediately blocks new operations while retaining its immutable history and checkpoint commitments.

### Receipts and finality

Every accepted operation returns an ML-DSA-signed `EventReceipt` binding the ledger, actor, request, operation, logical identity, artifact root, cost, balance, both sequences, both previous event hashes, event hash, timestamp, and stated finality.

The event hash is BLAKE3 over `starshine:event-receipt-hash:v2\0` plus canonical JSON for all receipt fields except `event_hash`, `node_attestation`, and `inclusion_proof`. The node signature uses ML-DSA-65 context `starshine-event-receipt-v2` over `starshine:event-receipt-signature:v2\0` plus the same canonical JSON with `event_hash` included. Byte and uint64 encoding follows the operation rules above.

Operation receipts remain `FINALITY_NODE_ATTESTED`. `GetInclusionProof` returns `FINALITY_LEDGER_CHECKPOINTED` after constructing and signing a shared-ledger checkpoint. This proves durable inclusion under the current VOID node identity; it is deliberately distinct from the reserved future `FINALITY_NETWORK_FINALIZED` consensus state.

### Checkpoint inclusion

For every non-empty application ledger, events are ordered by `ledger_sequence`. An event leaf is:

```text
BLAKE3("starshine:event-leaf:v2\0" || frame(event_hash))
```

Binary Merkle parents use `starshine:merkle-parent:v2\0`; odd final leaves are duplicated. The application commitment is:

```text
BLAKE3("starshine:ledger-commitment:v2\0" ||
       frame(ledger_id) || frame(ledger_root) || frame(uint64be(event_count)))
```

Application commitments are sorted by `ledger_id` and placed into the same Merkle construction to obtain the shared VOID checkpoint root. Proofs carry direction-aware paths for both levels. The checkpoint certificate binds height, root, previous checkpoint hash, timestamp, node ID, and node ML-DSA key. SDK verification recomputes both paths, the commitment, certificate hash, node ID, and ML-DSA signature.

### Privacy

Account history is authenticated and scoped to the requesting actor and ledger. Ledger history is visible only to an authorized signer for that ledger. The shared checkpoint reveals commitments, not partner payloads. There is no unauthenticated node-wide transaction feed in v2. Public audit metadata excludes HPKE encapsulation data, owner identity, file names, logical content IDs, and account balances.

### Storage proofs

Public challenges bind the artifact root, file ID, provider ID, shard index, total shard count, epoch, randomness, and deterministically derived block indices. Verifiers check each BAO slice against the global artifact root without possessing client secrets.

## Migration

The Rust server exposes v2 by default and makes v1 an explicit opt-in migration surface. A v2-capable node advertises application-ledger and checkpoint support, its receipt key, and its optional ledger-admin public key through `System.GetCapabilities`.

Partner code should publish the versioned `void.relay.event.v1` envelope to the VOID-owned relay over authenticated HTTP or an existing RabbitMQ queue. The relay persists and seals the artifact before its first Starshine append, then reuses the same sealed bytes and `sourceEventId` UUID for every retry. This lets partner repositories evolve independently: only the versioned envelope is the integration boundary.

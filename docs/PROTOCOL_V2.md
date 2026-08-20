# Starshine API v2 contract

Status: draft implementation contract for the onboarding network.

The v2 API separates three identities that v1 conflated:

- `logical_content_id`: optional stable identity for the same plaintext bytes and namespace. Sharing it reveals equality.
- `artifact_root`: the BAO commitment to one randomized encrypted representation.
- `event_id`: the immutable ledger identity of an operation.

## Required invariants

### Authentication

Every state-changing request and private ledger read carries an ML-DSA-65 `OperationAuthorization`. The server derives `actor_id` from the signing key, reconstructs the canonical payload, verifies all request-bound fields, enforces timestamp skew, and permanently rejects nonce replay. Byte fields use unpadded base64url and uint64 fields use decimal strings in canonical JSON.

TLS is mandatory on non-loopback production endpoints. Application-layer HPKE and ML-DSA remain the post-quantum confidentiality and authorization boundary; TLS protects metadata and provides deployable channel authentication.

Operation signatures use ML-DSA-65 context `starshine-operation-v2` over the ASCII domain `starshine:operation:v2\0` followed by canonical JSON containing the snake_case proto fields `actor_id`, `artifact_root`, `event_id`, `issued_at_unix_ms`, `logical_content_id`, `max_void`, `nonce`, `operation`, `request_digest`, `request_id`, and `version` in lexicographic key order. Byte fields are unpadded base64url; uint64 values are decimal strings.

Request digests use BLAKE3 with an operation-specific ASCII domain. Every component is framed as an unsigned 64-bit big-endian byte length followed by its bytes. Append covers every public `SealedArtifact` field, every shard in order, and `file_name`; retrieve covers the artifact root and minimum-shards byte; release covers the artifact root and reason. The SDK implementation is the interoperability reference.

### Idempotency

`request_id` is caller-generated and stable across retries. The server stores:

```text
(actor_id, request_id) -> (request_digest, serialized_response)
```

An exact append retry returns the original serialized receipt unchanged, including its original `RECEIPT_DISPOSITION_CREATED` disposition. A different `request_digest` under the same key fails with `ALREADY_EXISTS`. An accepted request is never executed twice.

### Append-only history and release

`Append`, `Retrieve`, and `Release` each append an event to the actor's hash-linked sequence. `Release` may remove physical artifact bytes after authorization, but it never removes event records, receipts, or checkpoint inclusion. The server must verify that the releasing actor owns the artifact or holds an explicit delegated capability.

### Receipts and finality

Every accepted operation returns an ML-DSA-signed `EventReceipt` binding the actor, request, operation, logical identity, artifact root, cost, balance, sequence, previous event hash, event hash, timestamp, and stated finality.

The event hash is BLAKE3 over `starshine:event-receipt-hash:v2\0` plus canonical JSON for all receipt fields except `event_hash`, `node_attestation`, and `inclusion_proof`. The node signature uses ML-DSA-65 context `starshine-event-receipt-v2` over `starshine:event-receipt-signature:v2\0` plus the same canonical JSON with `event_hash` included. Byte and uint64 encoding follows the operation rules above.

The onboarding service initially reports `FINALITY_NODE_ATTESTED`. It must not label a receipt network-finalized until a verifiable VOID checkpoint certificate and inclusion path exist.

### Privacy

Account history is authenticated and scoped to the requesting actor. There is no unauthenticated node-wide transaction feed in v2. Public audit metadata excludes HPKE encapsulation data, owner identity, file names, logical content IDs, and account balances.

### Storage proofs

Public challenges bind the artifact root, file ID, provider ID, shard index, total shard count, epoch, randomness, and deterministically derived block indices. Verifiers check each BAO slice against the global artifact root without possessing client secrets.

## Migration

The Rust server exposes v2 by default and makes v1 an explicit opt-in migration surface. A v2-capable node advertises its implemented guarantees and node receipt key through `System.GetCapabilities`.

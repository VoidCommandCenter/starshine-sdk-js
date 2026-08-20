# Starshine API v2 contract

Status: draft implementation contract for the onboarding network.

The v2 API separates three identities that v1 conflated:

- `logical_content_id`: optional stable identity for the same plaintext bytes and namespace. Sharing it reveals equality.
- `artifact_root`: the BAO commitment to one randomized encrypted representation.
- `event_id`: the immutable ledger identity of an operation.

## Required invariants

### Authentication

Every state-changing request carries an ML-DSA-65 `OperationAuthorization`. The server derives `actor_id` from the signing key, reconstructs the canonical payload, verifies all request-bound fields, enforces timestamp skew, and permanently rejects nonce replay.

TLS is mandatory on non-loopback production endpoints. Application-layer HPKE and ML-DSA remain the post-quantum confidentiality and authorization boundary; TLS protects metadata and provides deployable channel authentication.

### Idempotency

`request_id` is caller-generated and stable across retries. The server stores:

```text
(actor_id, request_id) -> (request_digest, serialized_response)
```

An exact retry returns the original response with `RECEIPT_DISPOSITION_IDEMPOTENT_REPLAY`. A different `request_digest` under the same key fails with `ALREADY_EXISTS`. An accepted request is never executed twice.

### Append-only history and release

`Append`, `Retrieve`, and `Release` each append an event to the actor's hash-linked sequence. `Release` may remove physical artifact bytes after authorization, but it never removes event records, receipts, or checkpoint inclusion. The server must verify that the releasing actor owns the artifact or holds an explicit delegated capability.

### Receipts and finality

Every accepted operation returns an ML-DSA-signed `EventReceipt` binding the actor, request, operation, logical identity, artifact root, cost, balance, sequence, previous event hash, event hash, timestamp, and stated finality.

The onboarding service initially reports `FINALITY_NODE_ATTESTED`. It must not label a receipt network-finalized until a verifiable VOID checkpoint certificate and inclusion path exist.

### Privacy

Account history is authenticated and scoped to the requesting actor. There is no unauthenticated node-wide transaction feed. Public audit metadata excludes HPKE encapsulation data, file names, logical content IDs unless explicitly public, and account balances.

### Storage proofs

Public challenges bind the artifact root, file ID, provider ID, shard index, total shard count, epoch, randomness, and deterministically derived block indices. Verifiers check each BAO slice against the global artifact root without possessing client secrets.

## Migration

The JavaScript SDK can use v1 storage during the transition, but must label v1 receipts as node-local and must not claim server-enforced idempotency or ownership. A v2-capable node advertises these guarantees through `System.GetCapabilities`.

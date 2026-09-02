# Changelog

## Unreleased

- Add the opt-in Void file-protection gateway with chunked `gateway-sealed` and `client-sealed` uploads, encrypted private manifests, deterministic append retries, and signed retrieval receipts.
- Add tenant/scope/upload-bound short-lived capabilities, exact-origin CORS policy, adjustable allowlisted Reed-Solomon profiles, and server-side storage routes.
- Add private file-label search plus a closed application audit vocabulary for file, access, permission, and record actions.
- Export a strict versioned `StoredBlob` wire format and `FileGatewayClient` SDK helpers for upload, retrieval, local recovery, and semantic audit events.
- Add immutable private human references inside sealed relay envelopes and bearer-authenticated reference search that resolves to public VOIDSCAN proof links.
- Rebuild the private reference index only from AES-256-GCM-encrypted outbox records, without writing plaintext labels or aliases to disk.
- Add the opt-in, metadata-only VOIDSCAN public ledger explorer and `void.scan.v1` API to the application relay.
- Publish verified two-level checkpoint proofs while withholding tenant identities, request metadata, balances, filenames, and encrypted payloads.
- Add public scan rate limiting, incremental newest-first indexing, proof caching, and restrictive browser security headers.

## 2.0.0-alpha.3

- Add opaque per-application ledgers with independent signer authorization and lifecycle controls.
- Add ledger-wide sequence/hash chains alongside per-actor chains.
- Add signed two-level inclusion proofs: event to application root to shared VOID checkpoint root.
- Add ML-DSA-authenticated ledger provisioning and signer grant/revoke SDK calls.
- Add the standalone HTTP/RabbitMQ relay with durable sealed-artifact retries and Kubernetes assets.

## 2.0.0-alpha.2

- Switch high-level storage operations to authenticated `starshine.v2` append/retrieve/release.
- Add durable caller idempotency and an in-client sealed-artifact retry cache.
- Verify ML-DSA-65 node receipts and per-account hash chains locally.
- Add authenticated, wallet-scoped event history and owner-authorized physical release.
- Add v2 capability discovery, public artifact metadata, and storage-proof RPCs.
- Add a Rust/JavaScript cross-language integration test.

## 2.0.0-alpha.1

- Require explicit opt-in for plaintext gRPC to non-loopback hosts.
- Add TLS, private CA, mTLS, bearer-token, deadline, and cancellation support.
- Expose public artifact metadata and PoRep-v2 proof-of-storage challenges.
- Verify storage challenge derivation and BAO slices locally without client secrets.
- Return a stable, domain-separated logical content ID separately from the randomized artifact root.
- Always ML-DSA-sign destructive v1 requests.
- Reject mismatched roots, duplicate or insufficient shards, unsafe numeric metadata, and inconsistent recovered lengths.
- Publish a draft v2 append/idempotency, signed-receipt, authorized-release, and future-checkpoint contract.
- Produce compiled ESM and TypeScript declarations for package consumers.

# Changelog

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

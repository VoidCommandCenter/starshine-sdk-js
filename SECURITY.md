# Security policy

Starshine handles encryption and signing keys. Please do not disclose suspected vulnerabilities in a public issue.

Use GitHub's **Report a vulnerability** flow in the Security tab of this repository. Include the affected version, impact, a minimal reproduction, and whether the issue has been tested against a public service. Do not test destructive or privacy-impacting hypotheses against public nodes.

## Supported versions

The latest tagged v2 prerelease is supported. The historical `starshine-js-api` v1 client is retained only for migration and should not be used as a production security baseline.

## Cryptographic boundary

- Plaintext, HPKE private keys, PoRep secrets, and ML-DSA private keys remain client-side.
- Non-loopback production endpoints must use TLS. Application-layer X-Wing HPKE and ML-DSA remain the post-quantum security boundary.
- A v2 `FINALITY_NODE_ATTESTED` receipt is ML-DSA-signed by one node. It is not VOID consensus or checkpoint finality.
- Receipt verification establishes integrity and node-key identity. Production clients must authenticate or pin the expected node through TLS/capabilities.
- Stable logical content IDs reveal equality when disclosed.

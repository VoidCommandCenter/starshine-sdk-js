# Starshine JavaScript SDK

Post-quantum client-side sealing, resilient storage, public storage audits, and VOID node receipts for Node.js applications.

The SDK keeps plaintext and private keys in the application process. Data is compressed, encrypted with hybrid X-Wing HPKE, Reed-Solomon encoded, replica-sealed, and committed with BAO before it reaches a storage node. Operations are authorized with ML-DSA-65.

> v2 alpha: the SDK is compatible with the deployed `starshine.v1` storage service while the enforceable append/idempotency contract in [`proto/starshine/v2/starshine.proto`](./proto/starshine/v2/starshine.proto) is implemented by the Rust node. v1 receipts are node-local records, not signed node attestations or VOID network finality.

Requires Node.js 22 or newer.

## Install

```bash
npm install github:VoidCommandCenter/starshine-sdk-js#v2.0.0-alpha.1
```

## Connect securely

Production endpoints must use TLS:

```ts
import { Starshine } from "starshine-sdk-js";

const starshine = await Starshine.connect({
  server: "grpcs://starshine.example.com:443",
  keys: "./keys.json",
  transport: {
    // Optional: private CA, mTLS key/certificate, or bearer token.
    rootCertificates: privateCaPem,
    privateKey: clientKeyPem,
    certificateChain: clientCertificatePem,
  },
});
```

Plaintext gRPC is accepted automatically on loopback. A remote plaintext endpoint requires the explicit legacy override:

```ts
const legacy = await Starshine.connect({
  server: "grpc://legacy-node.example.com:50051",
  transport: { allowInsecureRemote: true },
});
```

Application-layer HPKE protects stored content and ML-DSA authorizes operations. TLS additionally protects metadata and authenticates the transport; enabling TLS does not replace the post-quantum application layer.

## Store and retrieve

```ts
const plaintext = new TextEncoder().encode("hello starshine");
const stored = await starshine.put(plaintext, {
  fileName: "hello.txt",
  contentNamespace: "my-application",
});

console.log(stored.logicalContentId); // stable for the same plaintext + namespace
console.log(stored.contentHash);      // unique encrypted artifact commitment

const retrieved = await starshine.get(stored.contentHash);
console.log(new TextDecoder().decode(retrieved.plaintext));
```

The two identities serve different purposes:

- `logicalContentId` is stable and reveals equality when shared.
- `contentHash` is the BAO root of one randomized encrypted upload.

Use `createRequestId()` for a persistent retry key when calling a v2-capable node. The current v1 server does not enforce idempotency; the SDK never claims otherwise.

## Public proof of storage

The SDK exposes the proof RPCs that already exist on the node and verifies returned BAO proofs locally without the client’s PoRep secret:

```ts
const audit = await starshine.auditStorage(stored.contentHash, {
  shardIndex: 0,
});

console.log(audit.verified); // true or throws on an invalid proof
console.log(audit.proof.challenge.providerId);
```

Lower-level functions are also exported: `getPublicBlobMeta()`, `requestStorageProof()`, `deriveChallengeIndices()`, and `verifyStorageProof()`.

## Release versus immutable history

The legacy `delete()` method now always signs the destructive request. It should only be used against a node that enforces ownership.

The v2 contract replaces deletion semantics with `Release`: an authorized owner may release physical storage, while the append-only event, receipt, and any checkpoint inclusion remain immutable. Full enforcement requires the matching Rust v2 node implementation.

## Wallet

```ts
const starshine = await Starshine.connect({ server: "grpcs://node.example.com" });
await starshine.saveWallet("./keys.json");
```

Wallet files contain HPKE, PoRep, and ML-DSA private material and are written with mode `0600` on Unix. Do not commit or transmit them.

## Request control

All unary calls have a 30-second deadline by default. Set a client default or override one call:

```ts
const starshine = await Starshine.connect({
  server: "grpcs://node.example.com",
  rpcTimeoutMs: 60_000,
});

const controller = new AbortController();
const result = await starshine.get(hash, {
  timeoutMs: 120_000,
  signal: controller.signal,
});
```

## Development

```bash
npm ci
npm run typecheck
npm test
npm run build
```

The mutating public-node test is intentionally separate:

```bash
STARSHINE_SERVER=grpc://host:port npm run test:e2e
```

## Security boundaries

- v1 has no server-enforced caller idempotency or append-only event API.
- v1 storage ownership enforcement must be upgraded server-side before partner use.
- v1 node-wide transaction listing can expose metadata and should not be enabled publicly.
- `FINALITY_NODE_ATTESTED` means one node recorded an event. It is not future VOID network consensus.
- Independent-provider sovereignty requires independently operated nodes; synthetic provider identifiers do not demonstrate it.

The normative migration requirements are in [`docs/PROTOCOL_V2.md`](./docs/PROTOCOL_V2.md). The Starshine and VOID whitepapers remain architectural guides rather than frozen implementation specifications.

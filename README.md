# Starshine JavaScript SDK

Post-quantum client-side sealing, resilient storage, public storage audits, and VOID node receipts for Node.js applications.

The SDK keeps plaintext and private keys in the application process. Data is compressed, encrypted with hybrid X-Wing HPKE, Reed-Solomon encoded, replica-sealed, and committed with BAO before it reaches a storage node. Operations are authorized with ML-DSA-65.

> v2 alpha: authenticated application ledgers, durable idempotency, append-only history, owner enforcement, two-level checkpoint inclusion proofs, and ML-DSA receipts are implemented in the SDK and matching Rust node. `LedgerCheckpointed` is node-attested shared-ledger inclusion, not future VOID network consensus.

Requires Node.js 22 or newer.

## Install

```bash
npm install github:VoidCommandCenter/starshine-sdk-js#v2.0.0-alpha.3
```

## Connect securely

Production endpoints must use TLS:

```ts
import { Starshine, createRequestId } from "starshine-sdk-js";

const starshine = await Starshine.connect({
  server: "grpcs://starshine.example.com:443",
  ledgerId: "018f9f4c-4c83-7f1d-8e5d-e0d646f48d8a", // issued by VOID
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
  ledgerId: process.env.STARSHINE_LEDGER_ID,
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
  requestId: createRequestId(), // persist until the request succeeds
});

console.log(stored.logicalContentId); // stable for the same plaintext + namespace
console.log(stored.contentHash);      // unique encrypted artifact commitment

const retrieved = await starshine.get(stored.contentHash);
console.log(new TextDecoder().decode(retrieved.plaintext));
console.log(stored.receipt.eventId);
```

The two identities serve different purposes:

- `logicalContentId` is stable and reveals equality when shared.
- `contentHash` is the BAO root of one randomized encrypted upload.

Use `createRequestId()` for a persistent retry key. During the lifetime of a `Starshine` client, `put()` caches the already-sealed artifact under that ID so an ambiguous network failure can be retried without resealing or executing twice. For restart-safe workflows, persist the sealed `StoredBlob` and call `appendV2()` with the same request ID. Reusing an ID for different request bytes fails with `ALREADY_EXISTS`.

## Public proof of storage

The SDK exposes the proof RPCs that already exist on the node and verifies returned BAO proofs locally without the client’s PoRep secret:

```ts
const audit = await starshine.auditStorage(stored.contentHash, {
  shardIndex: 0,
});

console.log(audit.verified); // true or throws on an invalid proof
console.log(audit.proof.challenge.providerId);
```

Lower-level v2 functions are also exported: `getPublicArtifactV2()`, `requestStorageProofV2()`, `deriveChallengeIndices()`, and `verifyStorageProof()`.

## Release versus immutable history

`delete()` is now a compatibility name for v2 `Release`: an ML-DSA-authorized owner may release physical storage, while the append-only event and signed receipt remain immutable. A different actor receives `PERMISSION_DENIED`.

```ts
const released = await starshine.delete(stored.contentHash, {
  reason: "retention period ended",
  logicalContentId: stored.logicalContentId,
});
console.log(released.physicalBytesReleased);
```

Actor history is authenticated and scoped to the wallet and application ledger:

```ts
const { receipts, nextCursor } = await starshine.events(100);
```

The application-ledger feed spans every signer VOID has authorized for that app:

```ts
const ledgerPage = await starshine.ledgerEvents(100);
const proof = await starshine.inclusionProof(ledgerPage.receipts[0].eventId);
// inclusionProof() verifies event -> app root -> shared VOID root and the
// ML-DSA checkpoint certificate before returning.
```

Each deployment receives a permanent opaque `ledgerId`; use distinct IDs for development, staging, and production. Ledger IDs delineate histories and authorization even though their commitments share a global VOID checkpoint.

## Application file gateway

`FileGatewayClient` integrates an existing application without putting a Starshine wallet or
storage credential in that application's repository. It supports both protection paths:

- `gateway-sealed`: upload bounded plaintext chunks over HTTPS; the Void relay X-Wing-seals each
  chunk immediately and never writes plaintext to disk.
- `client-sealed`: seal chunks locally with this SDK and send only validated serialized
  `StoredBlob` artifacts. The relay never receives the plaintext or recovery key.

```ts
import { FileGatewayClient } from "starshine-sdk-js";

const files = new FileGatewayClient({
  baseUrl: "https://relay.example.com",
  authorization: `VoidCapability ${shortLivedCapability}`,
});

const upload = await files.createUpload({
  sourceSystem: "my-application",
  mode: "gateway-sealed",
  fileName: "evidence.pdf",
  contentType: "application/pdf",
  byteLength: fileChunk.length,
  privateReference: {
    kind: "evidence",
    externalId: "CASE-1042",
    label: "Quarterly control evidence",
    aliases: ["renewal-2026"],
  },
  shardPolicy: { dataShards: 4, parityShards: 2 },
});

await files.uploadGatewayChunk(upload.uploadId, 0, fileChunk);
const completed = await files.completeUpload(upload.uploadId);
console.log(completed.manifest?.publicProofPath);
```

Labels, external IDs, aliases, file metadata, and application audit context are private: they are
encrypted in the relay catalog and in the sealed manifest, while VOIDSCAN exposes only proof
commitments. `search()` resolves those human labels through an authenticated endpoint. Calls to
`recordAction()` use the exported, closed `FILE_AUDIT_EVENT_TYPES` vocabulary for views,
downloads, shares, permission changes, deletes, and other application actions.

Short-lived file capabilities are HMAC-SHA-256 authenticated and tenant/scope/upload bound. The
trusted application backend mints them only after applying its existing authentication and access
policy. For `client-sealed` data, that application must also distribute the appropriate recovery
key to authorized recipients; a gateway capability authorizes retrieval of ciphertext but does
not grant decryption by itself.

## Wallet

```ts
const starshine = await Starshine.connect({
  server: "grpcs://node.example.com",
  ledgerId: process.env.STARSHINE_LEDGER_ID,
});
await starshine.saveWallet("./keys.json");
```

Wallet files contain HPKE, PoRep, and ML-DSA private material and are written with mode `0600` on Unix. Do not commit or transmit them.

## Request control

All unary calls have a 30-second deadline by default. Set a client default or override one call:

```ts
const starshine = await Starshine.connect({
  server: "grpcs://node.example.com",
  ledgerId: process.env.STARSHINE_LEDGER_ID,
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
npm --workspace @void/starshine-relay test
```

The mutating public-node test is intentionally separate:

```bash
STARSHINE_E2E_SERVER=grpc://127.0.0.1:50051 \
STARSHINE_E2E_LEDGER_ID=<provisioned-uuid> \
STARSHINE_E2E_WALLET=./application.wallet.json \
npm run test:e2e
```

## Security boundaries

- The Rust node disables legacy v1 services by default. Enabling them is an explicit migration exception and restores their weaker semantics.
- Exact append retries return the original signed receipt unchanged; they do not create a second event or store a second artifact.
- Physical release is not event deletion. Event records and public non-secret artifact metadata remain.
- `NodeAttested` means one node recorded an event. `LedgerCheckpointed` adds verifiable shared-ledger inclusion. Neither is future distributed VOID consensus (`NetworkFinalized`).
- Independent-provider sovereignty requires independently operated nodes; synthetic provider identifiers do not demonstrate it.

The implemented contracts are in [`docs/PROTOCOL_V2.md`](./docs/PROTOCOL_V2.md) and
[`docs/FILE_GATEWAY.md`](./docs/FILE_GATEWAY.md), operator provisioning is in
[`docs/OPERATIONS.md`](./docs/OPERATIONS.md), and the relay handoff is in
[`relay/README.md`](./relay/README.md). The Starshine and VOID whitepapers remain architectural
guides rather than frozen implementation specifications.

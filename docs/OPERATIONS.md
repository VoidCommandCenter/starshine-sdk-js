# Application-ledger operations

VOID operates the application registry; partners receive a ledger UUID and an application wallet but never the ledger-admin private key.

## One-time node setup

Generate a dedicated operator wallet on a secured machine. Its ML-DSA public key is converted from wallet hex to unpadded base64url and configured on the node:

```ts
import { generateWallet, saveWallet } from "starshine-sdk-js";

const wallet = await generateWallet();
await saveWallet("./ledger-admin.wallet.json", wallet);
console.log(Buffer.from(wallet.mldsa_public_key_hex, "hex").toString("base64url"));
```

Set only the printed public value on Railway as `STARSHINE_LEDGER_ADMIN_PUBLIC_KEY`, then redeploy. Keep `ledger-admin.wallet.json` offline or in an operator secret manager.

## Provision an application environment

Create or receive the application's Starshine wallet, derive its actor ID, generate a UUID, and sign the provisioning request with the operator wallet:

```ts
import {
  createLedgerV2,
  deriveActorId,
  loadWallet,
} from "starshine-sdk-js";

const admin = await loadWallet("./ledger-admin.wallet.json");
const application = await loadWallet("./application.wallet.json");
const actorId = deriveActorId(
  new Uint8Array(Buffer.from(application.mldsa_public_key_hex, "hex")),
);
const ledgerId = crypto.randomUUID();

const ledger = await createLedgerV2(
  "grpcs://api.void.gs:443",
  admin,
  {
    ledgerId,
    signerActorId: actorId,
    displayName: "Partner application",
    environment: "production",
    active: true,
  },
);

console.log(ledger.ledgerId);
```

Repeat with new UUIDs for development and staging. Store the resulting UUID beside deployment configuration as `STARSHINE_LEDGER_ID`; it is an identifier, not a secret.

## Rotation and suspension

Use `grantLedgerSignerV2` before deploying a new application wallet, verify it can operate, then call `revokeLedgerSignerV2` for the old actor. The node refuses to remove the final signer. `setLedgerActiveV2(..., false)` immediately suspends authenticated operations without deleting history or checkpoint evidence.

Every operator call uses a UUID request ID and nonce and is ML-DSA signed. Persist a request ID while retrying the same administrative action; do not reuse it for a different action.

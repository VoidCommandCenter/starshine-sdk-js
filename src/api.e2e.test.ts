import assert from "node:assert/strict";
import { test } from "node:test";

import { Starshine } from "./api.js";
import { createRequestId, logicalContentId } from "./identity.js";
import { getXWingKem } from "./kem.js";
import { loadKeysFromJson } from "./keys.js";
import { uploadWithProgress } from "./upload.js";
import { appendV2 } from "./v2.js";
import { generateWallet } from "./wallet.js";

const SERVER = process.env.STARSHINE_E2E_SERVER;

test(
  "Starshine v2 JS SDK interoperates with the Rust node",
  { skip: !SERVER },
  async () => {
    const wallet = await generateWallet();
    const starshine = await Starshine.connect({ server: SERVER!, keys: wallet });
    const capabilities = await starshine.capabilities();
    assert.equal(capabilities.authenticatedOperationsRequired, true);
    assert.equal(capabilities.idempotentAppend, true);
    assert.deepEqual(capabilities.supportedFinality, [1]);

    const plaintext = new TextEncoder().encode("starshine v2 cross-language e2e");
    const keys = await loadKeysFromJson(wallet, getXWingKem());
    const stored = await uploadWithProgress(keys, plaintext, 4, 2);
    const logical = logicalContentId(plaintext, "sdk-e2e");
    const requestId = createRequestId();
    const options = { requestId };
    const first = await appendV2(
      SERVER!,
      wallet,
      stored,
      "e2e.txt",
      logical,
      options,
    );
    const replay = await appendV2(
      SERVER!,
      wallet,
      stored,
      "e2e.txt",
      logical,
      options,
    );
    assert.deepEqual(replay.receipt, first.receipt);

    const got = await starshine.get(first.artifactRoot, {
      logicalContentId: logical,
    });
    assert.deepEqual(Buffer.from(got.plaintext), Buffer.from(plaintext));
    assert.equal(got.receipt.accountSequence, 2n);

    const history = await starshine.events();
    assert.equal(history.receipts.length, 2);
    assert.deepEqual(
      history.receipts[1]!.previousEventHash,
      history.receipts[0]!.eventHash,
    );

    const released = await starshine.delete(first.artifactRoot, {
      reason: "cross-language e2e complete",
      logicalContentId: logical,
    });
    assert.equal(released.physicalBytesReleased, true);
    const publicMetadata = await starshine.publicMetadata(first.artifactRoot);
    assert.equal(publicMetadata.released, true);
    await assert.rejects(() => starshine.get(first.artifactRoot));
  },
);

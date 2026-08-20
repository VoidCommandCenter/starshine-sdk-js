import assert from "node:assert/strict";
import { test } from "node:test";

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

import {
  buildOperationAuthorization,
  deriveActorId,
  operationSigningBytes,
  StarshineOperation,
} from "./v2.js";
import { generateMlDsa65Keys, hexToBytes } from "./void-sign.js";
import type { WalletFile } from "./wallet.js";

const context = new TextEncoder().encode("starshine-operation-v2");

test("v2 operation authorization binds every signed field", () => {
  const keys = generateMlDsa65Keys();
  const wallet = {
    mldsa_public_key_hex: keys.publicKeyHex,
    mldsa_private_key_hex: keys.privateKeyHex,
  } as WalletFile;
  const root = new Uint8Array(32).fill(7);
  const digest = new Uint8Array(32).fill(9);
  const authorization = buildOperationAuthorization({
    wallet,
    operation: StarshineOperation.Append,
    artifactRoot: root,
    logicalContentId: "starshine:logical:v1:test",
    requestDigest: digest,
  });
  assert.deepEqual(
    authorization.actor_id,
    Buffer.from(deriveActorId(hexToBytes(keys.publicKeyHex))),
  );
  assert.equal(
    ml_dsa65.verify(
      authorization.mldsa_signature,
      operationSigningBytes(authorization),
      authorization.mldsa_public_key,
      { context },
    ),
    true,
  );
  const tampered = {
    ...authorization,
    logical_content_id: "starshine:logical:v1:tampered",
  };
  assert.equal(
    ml_dsa65.verify(
      authorization.mldsa_signature,
      operationSigningBytes(tampered),
      authorization.mldsa_public_key,
      { context },
    ),
    false,
  );
});

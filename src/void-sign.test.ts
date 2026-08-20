import assert from "node:assert/strict";
import { test } from "node:test";

import {
  buildVoidSignPayload,
  canonicalize,
  envelopeFromHeaders,
  envelopeToHeaders,
  generateMlDsa65Keys,
  parseVoidSignPayload,
  signVoidPayload,
  verifyVoidEnvelope,
} from "./void-sign.js";

function signedFaucet(from: string, privateKeyHex: string, amount = 100) {
  const payload = buildVoidSignPayload({
    kind: "faucet",
    from,
    amount,
  });
  return signVoidPayload(payload, privateKeyHex);
}

test("canonicalize is stable for key order", () => {
  const a = parseVoidSignPayload({
    v: 1,
    nonce: "n1",
    kind: "faucet",
    issuedAt: "2026-08-17T00:00:00.000Z",
    from: "aa".repeat(16),
    to: null,
    amount: 100,
    contentHash: null,
  });
  const shuffled = {
    amount: 100,
    contentHash: null,
    from: "aa".repeat(16),
    issuedAt: "2026-08-17T00:00:00.000Z",
    kind: "faucet",
    nonce: "n1",
    to: null,
    v: 1,
  };
  assert.equal(canonicalize(a), canonicalize(parseVoidSignPayload(shuffled)));
});

test("sign then verify", () => {
  const keys = generateMlDsa65Keys();
  const from = "ab".repeat(16);
  const envelope = signedFaucet(from, keys.privateKeyHex);
  const { payload } = verifyVoidEnvelope(envelope, { kind: "faucet", from });
  assert.equal(payload.amount, 100);
  assert.equal(payload.from, from);
});

test("tampered payload fails verify", () => {
  const keys = generateMlDsa65Keys();
  const from = "ab".repeat(16);
  const envelope = signedFaucet(from, keys.privateKeyHex);
  envelope.payload = { ...envelope.payload, amount: 999 };
  assert.throws(
    () => verifyVoidEnvelope(envelope, { kind: "faucet", from }),
    /invalid ML-DSA-65 signature/,
  );
});

test("wrong key fails verify", () => {
  const signer = generateMlDsa65Keys();
  const other = generateMlDsa65Keys();
  const from = "ab".repeat(16);
  const envelope = signedFaucet(from, signer.privateKeyHex);
  envelope.mldsaPublicKey = other.publicKeyHex;
  assert.throws(
    () => verifyVoidEnvelope(envelope, { kind: "faucet", from }),
    /invalid ML-DSA-65 signature/,
  );
});

test("HPKE mismatch is rejected", () => {
  const keys = generateMlDsa65Keys();
  const envelope = signedFaucet("ab".repeat(16), keys.privateKeyHex);
  assert.throws(
    () =>
      verifyVoidEnvelope(envelope, {
        kind: "faucet",
        from: "cd".repeat(16),
      }),
    /does not match wallet HPKE key/,
  );
});

test("stale issuedAt is rejected", () => {
  const keys = generateMlDsa65Keys();
  const from = "ab".repeat(16);
  const payload = buildVoidSignPayload({
    kind: "faucet",
    from,
    amount: 100,
    issuedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString(),
  });
  const envelope = signVoidPayload(payload, keys.privateKeyHex);
  assert.throws(
    () => verifyVoidEnvelope(envelope, { kind: "faucet", from }),
    /outside the allowed window/,
  );
});

test("header envelope round-trips", () => {
  const keys = generateMlDsa65Keys();
  const from = "ab".repeat(16);
  const envelope = signedFaucet(from, keys.privateKeyHex);
  const headers = envelopeToHeaders(envelope);
  const restored = envelopeFromHeaders({
    payload: headers["X-Starshine-Void-Payload"],
    publicKey: headers["X-Starshine-Void-Public-Key"],
    signature: headers["X-Starshine-Void-Signature"],
  });
  verifyVoidEnvelope(restored, { kind: "faucet", from });
});

import assert from "node:assert/strict";
import { test } from "node:test";

import { Starshine } from "./api.js";
import { FAUCET_VOID_AMOUNT, InsufficientVoidError } from "./void.js";
import { generateWallet } from "./wallet.js";

const SERVER = process.env.STARSHINE_SERVER ?? "http://maglev.proxy.rlwy.net:27561";

test("Starshine JS API: faucet, transfer, put, get, delete", async () => {
  const alice = await Starshine.connect({
    server: SERVER,
    transport: { allowInsecureRemote: true },
  });
  const bobWallet = await generateWallet();

  const empty = await alice.account();
  assert.equal(empty.balance, 0);

  const funded = await alice.faucet();
  assert.equal(funded.balance, FAUCET_VOID_AMOUNT);

  const afterSend = await alice.transfer(bobWallet.hpke_public_key_hex, 1_000_000);
  assert.equal(afterSend.balance, FAUCET_VOID_AMOUNT - 1_000_000);

  const plaintext = new TextEncoder().encode("starshine js sdk e2e");
  const put = await alice.put(plaintext, { fileName: "e2e.txt" });
  assert.match(put.contentHash, /^[0-9a-f]{64}$/);
  assert.ok(put.ledger);
  assert.equal(put.ledger.amount, put.storedBytes);
  assert.equal(
    put.ledger.balance,
    FAUCET_VOID_AMOUNT - 1_000_000 - put.storedBytes,
  );

  const got = await alice.get(put.contentHash);
  assert.deepEqual(Buffer.from(got.plaintext), Buffer.from(plaintext));
  assert.ok(got.ledger);
  assert.ok(got.ledger.amount > 0);
  assert.ok(got.ledger.amount < put.storedBytes);

  const txs = await alice.transactions();
  const kinds = new Set(txs.map((tx) => tx.kind));
  assert.ok(kinds.has("faucet"));
  assert.ok(kinds.has("transfer"));
  assert.ok(kinds.has("put"));
  assert.ok(kinds.has("get"));

  const deleted = await alice.delete(put.contentHash, { fileName: "e2e.txt" });
  assert.equal(deleted.contentHash, put.contentHash);

  await assert.rejects(() => alice.get(put.contentHash, { pay: false }));

  const broke = await Starshine.connect({
    server: SERVER,
    transport: { allowInsecureRemote: true },
  });
  await assert.rejects(
    () => broke.put(plaintext, { fileName: "broke.txt" }),
    (error: unknown) => error instanceof InsufficientVoidError,
  );
});

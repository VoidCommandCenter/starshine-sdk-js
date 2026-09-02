/**
 * Clone, npm install, then run a v2 Rust node on 127.0.0.1:50051 and `npm start`.
 * Override the endpoint with STARSHINE_SERVER.
 */
import { access } from "node:fs/promises";
import { Starshine } from "starshine-sdk-js";

const KEYS = "./keys.json";
const SERVER =
  process.env.STARSHINE_SERVER ?? "http://127.0.0.1:50051";
const LEDGER_ID = process.env.STARSHINE_LEDGER_ID;
if (!LEDGER_ID) throw new Error("STARSHINE_LEDGER_ID is required");

async function fileExists(path: string): Promise<boolean> {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

const ss = await Starshine.connect({
  server: SERVER,
  ledgerId: LEDGER_ID,
  keys: (await fileExists(KEYS)) ? KEYS : undefined,
});
if (!(await fileExists(KEYS))) {
  await ss.saveWallet(KEYS);
  console.log(`wrote wallet ${KEYS} (keep this file private)`);
}

console.log("server ", SERVER);
console.log("wallet ", ss.hpkePublicKey.slice(0, 16) + "…");

const capabilities = await ss.capabilities();
console.log("protocol", capabilities.protocolVersion);

const plaintext = new TextEncoder().encode(
  `hello starshine ${new Date().toISOString()}`,
);
const put = await ss.put(plaintext, { fileName: "hello.txt" });
console.log("put    ", put.contentHash);
console.log("content", put.logicalContentId);
console.log("stored ", put.storedBytes, "bytes, event", put.receipt.eventId);

const got = await ss.get(put.contentHash, {
  logicalContentId: put.logicalContentId,
});
console.log("got    ", new TextDecoder().decode(got.plaintext));
console.log("served ", got.servedBytes, "bytes, event", got.receipt.eventId);

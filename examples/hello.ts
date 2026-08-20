/**
 * Clone, npm install, npm start — talks to the public Railway node.
 *
 * Override the endpoint with STARSHINE_SERVER if you run your own starshine-api.
 */
import { access } from "node:fs/promises";
import { Starshine } from "starshine-sdk-js";

const KEYS = "./keys.json";
const SERVER =
  process.env.STARSHINE_SERVER ?? "http://maglev.proxy.rlwy.net:27561";

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
  keys: (await fileExists(KEYS)) ? KEYS : undefined,
  // The current Railway TCP proxy is legacy plaintext transport. Production
  // partners should use a grpcs:// endpoint and omit this override.
  transport: { allowInsecureRemote: true },
});
if (!(await fileExists(KEYS))) {
  await ss.saveWallet(KEYS);
  console.log(`wrote wallet ${KEYS} (keep this file private)`);
}

console.log("server ", SERVER);
console.log("wallet ", ss.hpkePublicKey.slice(0, 16) + "…");

let account = await ss.account();
if (account.balance <= 0) {
  account = await ss.faucet();
  console.log("faucet ", account.balance, "VOID");
} else {
  console.log("balance", account.balance, "VOID");
}

const plaintext = new TextEncoder().encode(
  `hello starshine ${new Date().toISOString()}`,
);
const put = await ss.put(plaintext, { fileName: "hello.txt" });
console.log("put    ", put.contentHash);
console.log("content", put.logicalContentId);
console.log("stored ", put.storedBytes, "bytes,", "VOID left", put.ledger?.balance);

const got = await ss.get(put.contentHash);
console.log("got    ", new TextDecoder().decode(got.plaintext));
console.log("served ", got.servedBytes, "bytes,", "VOID left", got.ledger?.balance);

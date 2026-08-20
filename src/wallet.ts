import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname } from "node:path";

import { generateDemoKeys } from "./keygen.js";
import { parseKeysFile, type KeysFileV2 } from "./keys.js";
import { generateMlDsa65Keys } from "./void-sign.js";

/** On-disk wallet: HPKE + PoRep + ML-DSA-65 (same JSON the CLI writes). */
export interface WalletFile extends KeysFileV2 {
  mldsa_public_key_hex: string;
  mldsa_private_key_hex: string;
}

export function isWalletFile(file: KeysFileV2): file is WalletFile {
  return Boolean(file.mldsa_public_key_hex && file.mldsa_private_key_hex);
}

export async function generateWallet(): Promise<WalletFile> {
  const keys = await generateDemoKeys();
  const mldsa = generateMlDsa65Keys();
  return {
    ...keys,
    mldsa_public_key_hex: mldsa.publicKeyHex,
    mldsa_private_key_hex: mldsa.privateKeyHex,
  };
}

export function parseWalletFile(raw: unknown): WalletFile {
  const file = parseKeysFile(raw);
  if (!isWalletFile(file)) {
    throw new Error(
      "wallet is missing ML-DSA-65 keys; call generateWallet() or starshine-cli wallet generate",
    );
  }
  return file;
}

export async function loadWallet(path: string): Promise<WalletFile> {
  const raw = await readFile(path, "utf8");
  return parseWalletFile(JSON.parse(raw) as unknown);
}

export async function saveWallet(path: string, wallet: WalletFile): Promise<void> {
  const parent = dirname(path);
  if (parent && parent !== ".") {
    await mkdir(parent, { recursive: true });
  }
  await writeFile(path, `${JSON.stringify(wallet, null, 2)}\n`, "utf8");
  try {
    await chmod(path, 0o600);
  } catch {
    /* Windows / unsupported */
  }
}

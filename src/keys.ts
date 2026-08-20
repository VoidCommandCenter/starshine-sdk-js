import { readFile } from "node:fs/promises";

import type { XWing } from "@hpke/hybridkem-x-wing";

import { importHpkeKeys } from "./hpke.js";
import { PorepClientSecret } from "./porepv2.js";

export const KEYS_FILE_VERSION = 2;

export interface KeysFileV2 {
  version: number;
  hpke_public_key_hex: string;
  hpke_private_key_hex: string;
  porep_secret_hex: string;
  mldsa_public_key_hex?: string;
  mldsa_private_key_hex?: string;
}

export interface ClientKeys {
  hpkePublicKey: CryptoKey;
  hpkePrivateKey: CryptoKey;
  porep: PorepClientSecret;
}

function hexDecode(hexStr: string): Uint8Array {
  const bytes = Buffer.from(hexStr, "hex");
  if (bytes.length * 2 !== hexStr.length) {
    throw new Error(`invalid hex in keys file`);
  }
  return new Uint8Array(bytes);
}

export function parseKeysFile(raw: unknown): KeysFileV2 {
  const file = raw as KeysFileV2;
  if (!file || typeof file !== "object") {
    throw new Error("keys must be a JSON object");
  }
  if (file.version !== KEYS_FILE_VERSION) {
    throw new Error(
      `unsupported keys file version ${file.version} (expected ${KEYS_FILE_VERSION})`,
    );
  }
  for (const field of [
    "hpke_public_key_hex",
    "hpke_private_key_hex",
    "porep_secret_hex",
  ] as const) {
    if (typeof file[field] !== "string" || !/^[0-9a-fA-F]+$/.test(file[field])) {
      throw new Error(`keys file missing or invalid ${field}`);
    }
  }
  return file;
}

export async function loadKeysFromJson(
  file: KeysFileV2,
  kem: XWing,
): Promise<ClientKeys> {
  const parsed = parseKeysFile(file);
  const pkBytes = hexDecode(parsed.hpke_public_key_hex);
  const skBytes = hexDecode(parsed.hpke_private_key_hex);
  const { publicKey, privateKey } = await importHpkeKeys(kem, pkBytes, skBytes);

  const porep = PorepClientSecret.fromBytes(hexDecode(parsed.porep_secret_hex));

  return { hpkePublicKey: publicKey, hpkePrivateKey: privateKey, porep };
}

export async function loadKeys(path: string, kem: XWing): Promise<ClientKeys> {
  let raw: string;
  try {
    raw = await readFile(path, "utf8");
  } catch {
    throw new Error(
      `keys file not found: ${path}. Generate one with:\n  ` +
        `cargo run -p starshine -- --generate-keys ${path}`,
    );
  }

  let file: KeysFileV2;
  try {
    file = parseKeysFile(JSON.parse(raw));
  } catch (e) {
    throw new Error(`keys parse error: ${(e as Error).message}`);
  }

  return loadKeysFromJson(file, kem);
}

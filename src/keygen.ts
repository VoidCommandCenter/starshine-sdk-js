import { randomBytes } from "node:crypto";

import { hpkeSuite } from "./hpke.js";
import { KEYS_FILE_VERSION, type KeysFileV2 } from "./keys.js";
import { MIN_POREP_SECRET_LEN } from "./porepv2.js";

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

/** Generate demo/production keys (32-byte PoRep secret + HPKE). */
export async function generateDemoKeys(): Promise<KeysFileV2> {
  const { kem } = hpkeSuite();
  const rkp = await kem.generateKeyPair();
  const pkBytes = new Uint8Array(await kem.serializePublicKey(rkp.publicKey));
  const skBytes = new Uint8Array(await kem.serializePrivateKey(rkp.privateKey));

  return {
    version: KEYS_FILE_VERSION,
    hpke_public_key_hex: bytesToHex(pkBytes),
    hpke_private_key_hex: bytesToHex(skBytes),
    porep_secret_hex: bytesToHex(randomBytes(MIN_POREP_SECRET_LEN)),
  };
}

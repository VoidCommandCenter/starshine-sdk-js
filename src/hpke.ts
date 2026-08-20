import { Aes256Gcm, CipherSuite, HkdfSha256 } from "@hpke/core";
import type { XWing } from "@hpke/hybridkem-x-wing";

import { CHUNK_CT, CHUNK_PT } from "./constants.js";
import { getXWingKem } from "./kem.js";
import type { EncryptedPayload } from "./types.js";

let cachedSuite: CipherSuite | null = null;

export function hpkeSuite(): { suite: CipherSuite; kem: XWing } {
  const kem = getXWingKem();
  if (!cachedSuite) {
    cachedSuite = new CipherSuite({
      kem,
      kdf: new HkdfSha256(),
      aead: new Aes256Gcm(),
    });
  }
  return { suite: cachedSuite, kem };
}

export async function importHpkeKeys(
  kem: XWing,
  pkBytes: Uint8Array,
  skBytes: Uint8Array,
): Promise<{ publicKey: CryptoKey; privateKey: CryptoKey }> {
  const publicKey = await kem.deserializePublicKey(pkBytes);
  const privateKey = await kem.deserializePrivateKey(skBytes);
  await verifyHpkePair(publicKey, privateKey);
  return { publicKey, privateKey };
}

const HPKE_KEY_VERIFY_INFO = new TextEncoder().encode(
  "starshine-hpke-key-verify-v1",
);

async function verifyHpkePair(
  publicKey: CryptoKey,
  privateKey: CryptoKey,
): Promise<void> {
  const { suite } = hpkeSuite();
  const sender = await suite.createSenderContext({
    recipientPublicKey: publicKey,
    info: HPKE_KEY_VERIFY_INFO,
  });
  const ct = await sender.seal(new TextEncoder().encode("ok"));
  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: sender.enc,
    info: HPKE_KEY_VERIFY_INFO,
  });
  await recipient.open(ct);
}

function chunkAad(idx: number): Uint8Array {
  const aad = new Uint8Array(8);
  new DataView(aad.buffer).setBigUint64(0, BigInt(idx), true);
  return aad;
}

export async function clientSeal(
  data: Uint8Array,
  publicKey: CryptoKey,
  info: Uint8Array,
): Promise<EncryptedPayload> {
  const { suite } = hpkeSuite();
  const sender = await suite.createSenderContext({
    recipientPublicKey: publicKey,
    info,
  });

  const nChunks = Math.ceil(data.length / CHUNK_PT) || 0;
  const ciphertext = new Uint8Array(nChunks * CHUNK_CT);
  let offset = 0;

  for (let i = 0; i < nChunks; i++) {
    const block = new Uint8Array(CHUNK_PT);
    const start = i * CHUNK_PT;
    block.set(data.subarray(start, start + CHUNK_PT));
    const ct = new Uint8Array(
      await sender.seal(block, chunkAad(i)),
    );
    if (ct.length !== CHUNK_CT) {
      throw new Error(
        `invalid ciphertext chunk length ${ct.length}, expected ${CHUNK_CT}`,
      );
    }
    ciphertext.set(ct, offset);
    offset += CHUNK_CT;
  }

  return {
    encKey: new Uint8Array(sender.enc),
    ciphertext,
    plaintextLen: data.length,
  };
}

export async function clientOpenFull(
  privateKey: CryptoKey,
  encKey: Uint8Array,
  ciphertext: Uint8Array,
  info: Uint8Array,
  plaintextLen: number,
): Promise<Uint8Array> {
  if (ciphertext.length % CHUNK_CT !== 0) {
    throw new Error(
      `invalid ciphertext length ${ciphertext.length} (not multiple of ${CHUNK_CT})`,
    );
  }

  const { suite } = hpkeSuite();
  const recipient = await suite.createRecipientContext({
    recipientKey: privateKey,
    enc: encKey,
    info,
  });

  const nChunks = ciphertext.length / CHUNK_CT;
  const plaintext = new Uint8Array(nChunks * CHUNK_PT);
  let offset = 0;

  for (let i = 0; i < nChunks; i++) {
    const ct = ciphertext.subarray(i * CHUNK_CT, (i + 1) * CHUNK_CT);
    const pt = new Uint8Array(await recipient.open(ct, chunkAad(i)));
    plaintext.set(pt, offset);
    offset += pt.length;
  }

  return plaintext.subarray(0, plaintextLen);
}

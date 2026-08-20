import { compress, decompress } from "@mongodb-js/zstd";

import { ZSTD_LEVEL } from "./constants.js";

export async function zstdCompress(data: Uint8Array): Promise<Uint8Array> {
  const out = await compress(Buffer.from(data), ZSTD_LEVEL);
  return new Uint8Array(out);
}

export async function zstdDecompress(data: Uint8Array): Promise<Uint8Array> {
  const out = await decompress(Buffer.from(data));
  return new Uint8Array(out);
}

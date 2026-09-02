export {
  deserializeStoredBlob,
  serializeStoredBlob,
  type SerializedStoredBlob,
} from "starshine-sdk-js";

export function jsonForStorage(value: unknown): string {
  return JSON.stringify(value, (_key, entry: unknown) => {
    if (typeof entry === "bigint") return entry.toString();
    if (entry instanceof Uint8Array) return { base64url: encode(entry) };
    return entry;
  });
}

function encode(value: Uint8Array): string {
  return Buffer.from(value).toString("base64url");
}

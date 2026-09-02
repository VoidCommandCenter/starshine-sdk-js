import { readFile } from "node:fs/promises";

const ASSETS: Record<string, readonly [string, string]> = Object.freeze({
  "/scan": ["voidscan.html", "text/html; charset=utf-8"],
  "/scan/": ["voidscan.html", "text/html; charset=utf-8"],
  "/scan/voidscan.css": ["voidscan.css", "text/css; charset=utf-8"],
  "/scan/voidscan.js": ["voidscan.js", "text/javascript; charset=utf-8"],
});

export async function scanAsset(
  pathname: string,
): Promise<{ body: Buffer; contentType: string } | undefined> {
  const asset = ASSETS[pathname];
  if (!asset) return undefined;
  const [fileName, contentType] = asset;
  return {
    body: await readFile(new URL(`../public/${fileName}`, import.meta.url)),
    contentType,
  };
}

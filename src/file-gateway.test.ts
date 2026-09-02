import assert from "node:assert/strict";
import test from "node:test";

import { FILE_UPLOAD_VERSION, FileGatewayClient } from "./file-gateway.js";

test("file gateway client requires secure transport and sends private authorization", async () => {
  assert.throws(() => new FileGatewayClient({
    baseUrl: "http://api.example.test",
    authorization: "Bearer secret",
  }), /HTTPS/);

  let requestUrl = "";
  let authorization = "";
  const client = new FileGatewayClient({
    baseUrl: "https://relay.example.test",
    authorization: "VoidCapability narrow-token",
    fetch: (async (input, init) => {
      requestUrl = String(input);
      authorization = new Headers(init?.headers).get("authorization") ?? "";
      return new Response(JSON.stringify({
        version: FILE_UPLOAD_VERSION,
        uploadId: "00000000-0000-4000-8000-000000000001",
        status: "uploading",
      }), { status: 201, headers: { "content-type": "application/json" } });
    }) as typeof fetch,
  });
  await client.createUpload({
    sourceSystem: "partner-app",
    mode: "gateway-sealed",
    fileName: "evidence.pdf",
    contentType: "application/pdf",
    byteLength: 12,
    privateReference: {
      kind: "evidence",
      externalId: "HN-4",
      label: "Evidence four",
      aliases: [],
    },
  });
  assert.equal(requestUrl, "https://relay.example.test/v1/files/uploads");
  assert.equal(authorization, "VoidCapability narrow-token");
});

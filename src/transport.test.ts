import assert from "node:assert/strict";
import { test } from "node:test";

import { parseEndpoint } from "./transport.js";

test("remote plaintext transport is rejected by default", () => {
  assert.throws(
    () => parseEndpoint("grpc://example.com:50051"),
    /refusing insecure gRPC/,
  );
});

test("remote plaintext transport requires an explicit legacy opt-in", () => {
  const endpoint = parseEndpoint("http://example.com:27561", {
    allowInsecureRemote: true,
  });
  assert.equal(endpoint.address, "example.com:27561");
  assert.equal(endpoint.security, "insecure");
});

test("TLS and loopback endpoint parsing is unambiguous", () => {
  assert.deepEqual(parseEndpoint("grpcs://storage.example.com"), {
    address: "storage.example.com:443",
    host: "storage.example.com",
    port: "443",
    security: "tls",
  });
  assert.equal(parseEndpoint("127.0.0.1:50051").security, "insecure");
  assert.equal(parseEndpoint("grpc://[::1]:50051").address, "[::1]:50051");
});

test("endpoint paths and embedded credentials are rejected", () => {
  assert.throws(() => parseEndpoint("grpcs://example.com/api"), /scheme, host, and port/);
  assert.throws(() => parseEndpoint("grpcs://user@example.com"), /scheme, host, and port/);
});

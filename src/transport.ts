import { createHash } from "node:crypto";

import * as grpc from "@grpc/grpc-js";

export type TransportSecurity = "tls" | "insecure";

export interface TransportOptions {
  /**
   * Permit plaintext HTTP/2 to a non-loopback host. This is deliberately
   * opt-in; Starshine payload encryption does not protect gRPC metadata.
   */
  allowInsecureRemote?: boolean;
  /** PEM-encoded trust roots. Omit to use the operating-system trust store. */
  rootCertificates?: Uint8Array;
  /** PEM-encoded private key for mutual TLS. Must be paired with certificateChain. */
  privateKey?: Uint8Array;
  /** PEM-encoded client certificate chain for mutual TLS. */
  certificateChain?: Uint8Array;
  /** Optional bearer token. It is attached only to TLS channels. */
  bearerToken?: string;
}

export interface ParsedEndpoint {
  address: string;
  host: string;
  port: string;
  security: TransportSecurity;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "::1", "localhost"]);

function normalizeEndpoint(endpoint: string): URL {
  const trimmed = endpoint.trim();
  if (!trimmed) throw new Error("Starshine endpoint is required");

  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)
    ? trimmed
    : `grpc://${trimmed}`;

  let url: URL;
  try {
    url = new URL(withScheme);
  } catch {
    throw new Error(`invalid Starshine endpoint: ${endpoint}`);
  }
  if (
    url.username ||
    url.password ||
    (url.pathname !== "" && url.pathname !== "/") ||
    url.search ||
    url.hash
  ) {
    throw new Error("Starshine endpoint must contain only a scheme, host, and port");
  }
  return url;
}

export function parseEndpoint(
  endpoint: string,
  options: Pick<TransportOptions, "allowInsecureRemote"> = {},
): ParsedEndpoint {
  const url = normalizeEndpoint(endpoint);
  const protocol = url.protocol.toLowerCase();
  let security: TransportSecurity;
  if (protocol === "grpcs:" || protocol === "https:") {
    security = "tls";
  } else if (protocol === "grpc:" || protocol === "http:") {
    security = "insecure";
  } else {
    throw new Error(
      `unsupported Starshine endpoint scheme ${protocol}; use grpcs:// or grpc://`,
    );
  }

  const host = url.hostname.startsWith("[") && url.hostname.endsWith("]")
    ? url.hostname.slice(1, -1)
    : url.hostname;
  const port = url.port || (security === "tls" ? "443" : "50051");
  if (security === "insecure" && !LOOPBACK_HOSTS.has(host.toLowerCase())) {
    if (!options.allowInsecureRemote) {
      throw new Error(
        "refusing insecure gRPC to a remote host; use grpcs:// or set allowInsecureRemote: true for an explicitly accepted legacy connection",
      );
    }
  }

  const address = host.includes(":") ? `[${host}]:${port}` : `${host}:${port}`;
  return { address, host, port, security };
}

export function createChannelCredentials(
  endpoint: ParsedEndpoint,
  options: TransportOptions = {},
): grpc.ChannelCredentials {
  const hasPrivateKey = options.privateKey != null;
  const hasCertificate = options.certificateChain != null;
  if (hasPrivateKey !== hasCertificate) {
    throw new Error("mTLS privateKey and certificateChain must be provided together");
  }

  if (endpoint.security === "insecure") {
    if (
      options.rootCertificates ||
      options.privateKey ||
      options.certificateChain ||
      options.bearerToken
    ) {
      throw new Error("TLS credentials and bearer tokens require a grpcs:// endpoint");
    }
    return grpc.credentials.createInsecure();
  }

  const channel = grpc.credentials.createSsl(
    options.rootCertificates ? Buffer.from(options.rootCertificates) : undefined,
    options.privateKey ? Buffer.from(options.privateKey) : undefined,
    options.certificateChain ? Buffer.from(options.certificateChain) : undefined,
  );
  const token = options.bearerToken?.trim();
  if (!token) return channel;

  const call = grpc.credentials.createFromMetadataGenerator((_params, callback) => {
    const metadata = new grpc.Metadata();
    metadata.set("authorization", `Bearer ${token}`);
    callback(null, metadata);
  });
  return grpc.credentials.combineChannelCredentials(channel, call);
}

export function transportCacheKey(endpoint: string, options: TransportOptions = {}): string {
  const parsed = parseEndpoint(endpoint, options);
  const credentialHash = createHash("sha256");
  for (const material of [
    options.rootCertificates,
    options.privateKey,
    options.certificateChain,
    options.bearerToken == null
      ? undefined
      : new TextEncoder().encode(options.bearerToken),
  ]) {
    if (material) credentialHash.update(material);
    credentialHash.update(new Uint8Array([0]));
  }
  return [
    parsed.security,
    parsed.address,
    options.allowInsecureRemote === true,
    credentialHash.digest("hex"),
  ].join(":");
}

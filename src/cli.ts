#!/usr/bin/env node
/**
 * Pure Node.js Starshine v4 CLI — functionally identical to `starshine-cli` (Rust).
 *
 * Upload and download files through a running `starshine-api` server.
 * All cryptography (HPKE/X-Wing, Reed–Solomon, PoRep-v2, BAO) runs locally.
 */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { stdin, stdout } from "node:process";
import { dirname } from "node:path";
import { parseArgs } from "node:util";

import {
  DEFAULT_DATA_SHARDS,
  DEFAULT_KEYS_PATH,
  DEFAULT_PARITY_SHARDS,
  DEFAULT_SERVER,
} from "./constants.js";
import { getXWingKem } from "./kem.js";
import { loadKeys } from "./keys.js";
import {
  downloadShardPct,
  reportDownload,
  reportUpload,
  sealingPct,
} from "./progress.js";
import { recoverWithProgress } from "./recovery.js";
import {
  getBlob,
  getBlobMinimumShards,
  putBlob,
} from "./remote.js";
import { uploadWithProgress } from "./upload.js";

const { values, positionals } = parseArgs({
  allowPositionals: true,
  options: {
    keys: { type: "string", default: process.env.STARSHINE_KEYS ?? DEFAULT_KEYS_PATH },
    server: {
      type: "string",
      default: process.env.STARSHINE_SERVER ?? DEFAULT_SERVER,
    },
    progress: {
      type: "boolean",
      default:
        process.env.STARSHINE_PROGRESS === "1" ||
        process.env.STARSHINE_PROGRESS === "true",
    },
    verbose: {
      type: "boolean",
      short: "v",
      default:
        process.env.STARSHINE_VERBOSE === "1" ||
        process.env.STARSHINE_VERBOSE === "true",
    },
    help: { type: "boolean", short: "h", default: false },
    version: { type: "boolean", default: false },
    k: { type: "string" },
    m: { type: "string" },
    output: { type: "string", short: "o" },
    "minimum-shards": { type: "boolean", default: false },
    "allow-insecure-remote": { type: "boolean", default: false },
  },
});

function usage(): string {
  return `starshine-sdk-js — upload and download via the Starshine v4 storage API

Usage:
  npx tsx src/cli.ts [options] put <file>
  npx tsx src/cli.ts [options] get <hash> -o <file>

Global options:
  --keys <path>     Client keys (HPKE + PoRep secret); default: ${DEFAULT_KEYS_PATH}
  --server <url>    gRPC endpoint; default: ${DEFAULT_SERVER}
  --progress        Emit @starshine/progress JSON lines on stderr
  --allow-insecure-remote  Permit legacy plaintext gRPC to a non-loopback host
  -v, --verbose     Print each protocol step on stderr

Put options:
  -k, --k <n>       Reed–Solomon data shards (default: ${DEFAULT_DATA_SHARDS})
  -m, --m <n>       Reed–Solomon parity shards (default: ${DEFAULT_PARITY_SHARDS})

Get options:
  -o, --output <file>   Output file, or '-' for stdout
  --minimum-shards      Fetch only k data shards

This CLI Put/Get is unpaid. Prefer examples/hello.ts (faucet + paid put/get).

Environment:
  STARSHINE_KEYS, STARSHINE_SERVER, STARSHINE_PROGRESS, STARSHINE_VERBOSE, STARSHINE_MAX_PUT_BYTES
`;
}

async function readInput(path: string): Promise<Uint8Array> {
  if (path === "-") {
    const chunks: Buffer[] = [];
    for await (const chunk of stdin) {
      chunks.push(Buffer.from(chunk));
    }
    return new Uint8Array(Buffer.concat(chunks));
  }
  return new Uint8Array(await readFile(path));
}

async function writeOutput(path: string, data: Uint8Array): Promise<void> {
  if (path === "-") {
    await new Promise<void>((resolve, reject) => {
      stdout.write(Buffer.from(data), (err) => (err ? reject(err) : resolve()));
    });
    return;
  }
  const parent = dirname(path);
  if (parent && parent !== ".") {
    await mkdir(parent, { recursive: true });
  }
  await writeFile(path, data);
}

function parseContentHash(s: string): Uint8Array {
  const hexStr = s.startsWith("0x") ? s.slice(2) : s;
  if (!/^[0-9a-fA-F]{64}$/.test(hexStr)) {
    throw new Error(
      `content hash must be 32 bytes (64 hex digits), got ${hexStr.length / 2} bytes`,
    );
  }
  return new Uint8Array(Buffer.from(hexStr, "hex"));
}

function toHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

async function main(): Promise<void> {
  if (values.help) {
    console.log(usage());
    return;
  }
  if (values.version) {
    console.log("starshine-sdk-js 2.0.0-alpha.3");
    return;
  }

  const command = positionals[0];
  if (!command || (command !== "put" && command !== "get")) {
    console.error(usage());
    process.exit(1);
  }

  const keys = await loadKeys(values.keys!, getXWingKem());
  const progress = values.progress ?? false;
  const verbose = values.verbose ?? false;
  const reportSteps = progress || verbose;
  const remoteOptions = {
    transport: {
      allowInsecureRemote: values["allow-insecure-remote"] ?? false,
    },
  };

  if (command === "put") {
    const file = positionals[1];
    if (!file) {
      console.error("put requires a FILE argument");
      process.exit(1);
    }
    const dataShards = values.k
      ? Number.parseInt(values.k, 10)
      : DEFAULT_DATA_SHARDS;
    const parityShards = values.m
      ? Number.parseInt(values.m, 10)
      : DEFAULT_PARITY_SHARDS;

    const data = await readInput(file);

    if (!reportSteps) {
      console.error(
        `sealing ${data.length} bytes (k=${dataShards}, m=${parityShards})…`,
      );
    }

    const stored = await uploadWithProgress(
      keys,
      data,
      dataShards,
      parityShards,
      reportSteps
        ? (event) => reportUpload(event, progress, verbose)
        : undefined,
    );

    reportUpload(
      {
        phase: "grpc_put",
        pct: sealingPct("grpc_put", 0, dataShards + parityShards),
        shards: dataShards + parityShards,
        message: `Storing on ${values.server}`,
      },
      progress,
      verbose,
    );
    if (!reportSteps) {
      console.error(`uploading to ${values.server}…`);
    }

    const topRoot = await putBlob(values.server!, stored, remoteOptions);

    reportUpload(
      {
        phase: "done",
        pct: 100,
        message: "Upload complete",
      },
      progress,
      verbose,
    );

    console.log(toHex(topRoot));
    return;
  }

  // get
  const hashArg = positionals[1];
  const output = values.output;
  if (!hashArg || !output) {
    console.error("get requires HASH and -o/--output FILE");
    process.exit(1);
  }

  const contentHash = parseContentHash(hashArg);
  const minimumShards = values["minimum-shards"] ?? false;

  if (!reportSteps) {
    console.error(`fetching ${toHex(contentHash)}…`);
  }
  reportDownload(
    {
      phase: "grpc_get",
      pct: 5,
      message: `gRPC Get from ${values.server}`,
    },
    progress,
    verbose,
  );

  const stored = minimumShards
    ? await getBlobMinimumShards(values.server!, contentHash, remoteOptions)
    : await getBlob(values.server!, contentHash, remoteOptions);

  const k = stored.meta.dataShards;
  const n = stored.blob.shards.length;

  if (reportSteps) {
    reportDownload(
      {
        phase: "grpc_get",
        pct: 12,
        shards: k,
        message: `NODE returned ${n} sealed shards (minimum k=${k})`,
      },
      progress,
      verbose,
    );
    for (let i = 0; i < stored.blob.shards.length; i++) {
      const shard = stored.blob.shards[i]!;
      reportDownload(
        {
          phase: "shard_download",
          pct: downloadShardPct(i + 1, n),
          shard: i,
          shards: n,
          message: `Shard ${i + 1}/${n} received (index ${shard.index}, ${shard.data.length} sealed bytes)`,
        },
        progress,
        verbose,
      );
    }
  }

  const plaintext = await recoverWithProgress(
    keys,
    stored,
    reportSteps
      ? (event) => reportDownload(event, progress, verbose)
      : undefined,
  );

  await writeOutput(output, plaintext);
  if (!reportSteps) {
    console.error(`wrote ${plaintext.length} bytes`);
  }
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : String(err));
  process.exit(1);
});

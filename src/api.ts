import {
  DEFAULT_DATA_SHARDS,
  DEFAULT_PARITY_SHARDS,
  DEFAULT_SERVER,
  FAUCET_VOID_AMOUNT,
} from "./constants.js";
import { randomBytes } from "node:crypto";

import {
  verifyStorageProof,
  type PublicBlobMeta,
  type StorageProof,
} from "./audit.js";
import { getXWingKem } from "./kem.js";
import { logicalContentId } from "./identity.js";
import { loadKeysFromJson, type ClientKeys } from "./keys.js";
import { aggregateStoredServedBytes, recoverWithProgress } from "./recovery.js";
import { uploadWithProgress } from "./upload.js";
import type { StoredBlob } from "./types.js";
import {
  faucet as voidFaucet,
  getAccount,
  listTransactions,
  transfer as voidTransfer,
  type VoidAccount,
  type VoidReceipt,
  type VoidTransaction,
} from "./void.js";
import {
  buildVoidSignPayload,
  signVoidPayload,
  type VoidSignEnvelope,
  type VoidSignKind,
} from "./void-sign.js";
import {
  generateWallet,
  isWalletFile,
  loadWallet,
  parseWalletFile,
  saveWallet,
  type WalletFile,
} from "./wallet.js";
import type { UnaryRequestOptions } from "./grpc.js";
import { parseEndpoint, type TransportOptions } from "./transport.js";
import {
  appendV2,
  getCapabilitiesV2,
  getInclusionProofV2,
  getPublicArtifactV2,
  listAccountEventsV2,
  listLedgerEventsV2,
  releaseV2,
  requestStorageProofV2,
  retrieveV2,
  type EventReceipt,
  type InclusionProof,
  type StarshineCapabilities,
} from "./v2.js";

export interface StarshineOptions {
  /** gRPC endpoint. Use `grpcs://` for every non-local production endpoint. */
  server?: string;
  /** Opaque application-ledger UUID provisioned by the VOID operator. */
  ledgerId?: string;
  /** Wallet JSON object, or path to a keys file. Omit to generate in memory. */
  keys?: WalletFile | string;
  dataShards?: number;
  parityShards?: number;
  transport?: TransportOptions;
  /** Default unary RPC timeout. Individual calls may override it. */
  rpcTimeoutMs?: number;
  /** Verify v2 capabilities and pin the node receipt key during connect. Default true. */
  verifyCapabilities?: boolean;
}

export interface RequestOptions extends UnaryRequestOptions {
  /** Stable retry UUID. Persist and reuse it until the operation succeeds. */
  requestId?: string;
}

export interface PutOptions extends RequestOptions {
  fileName?: string;
  /** Domain for the stable plaintext identity returned as `logicalContentId`. */
  contentNamespace?: string;
  /** Legacy v1 compatibility option; v2 onboarding storage is currently zero-cost. */
  pay?: boolean;
  dataShards?: number;
  parityShards?: number;
}

export interface GetOptions extends RequestOptions {
  fileName?: string;
  /** Legacy v1 compatibility option; v2 onboarding storage is currently zero-cost. */
  pay?: boolean;
  /** Fetch only k data shards (cheaper VOID). Default true. */
  minimumShards?: boolean;
  /** Optional stable identity to bind into the retrieve event. */
  logicalContentId?: string;
}

export interface DeleteOptions extends RequestOptions {
  fileName?: string;
  /** Legacy v1 compatibility option; v2 Release authorization is always signed. */
  pay?: boolean;
  reason?: string;
  /** Optional stable identity to bind into the release event. */
  logicalContentId?: string;
}

export interface AuditStorageOptions extends RequestOptions {
  shardIndex?: number;
  epoch?: bigint | number;
  randomness?: Uint8Array;
  /** Verify the returned proof locally. Defaults to true. */
  verify?: boolean;
}

export interface AuditStorageResult {
  meta: PublicBlobMeta;
  proof: StorageProof;
  verified: boolean;
}

export interface PutResult {
  /** Stable, plaintext-derived identity. Same bytes + namespace => same value. */
  logicalContentId: string;
  /** Per-upload encrypted artifact commitment. Fresh HPKE makes this unique. */
  contentHash: string;
  storedBytes: number;
  receipt: EventReceipt;
  /** Legacy v1 field. v2 storage operations return `receipt`. */
  ledger?: VoidReceipt;
}

export interface GetResult {
  plaintext: Uint8Array;
  servedBytes: number;
  receipt: EventReceipt;
  /** Legacy v1 field. v2 storage operations return `receipt`. */
  ledger?: VoidReceipt;
}

export interface DeleteResult {
  contentHash: string;
  receipt: EventReceipt;
  physicalBytesReleased: boolean;
  /** Legacy v1 field. v2 storage operations return `receipt`. */
  ledger?: VoidReceipt;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function parseHash(hash: string | Uint8Array): Uint8Array {
  if (hash instanceof Uint8Array) {
    if (hash.length !== 32) {
      throw new Error(`content hash must be 32 bytes, got ${hash.length}`);
    }
    return hash;
  }
  const hex = hash.trim().replace(/^0x/i, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) {
    throw new Error("content hash must be 64 hex digits");
  }
  return new Uint8Array(Buffer.from(hex, "hex"));
}

/**
 * JavaScript client for authenticated `starshine.v2` storage. Legacy VOID
 * balance methods remain available only for nodes that explicitly enable v1.
 * Seals locally; the node never receives HPKE/PoRep/ML-DSA secrets.
 */
export class Starshine {
  readonly server: string;
  readonly ledgerId: string;
  readonly dataShards: number;
  readonly parityShards: number;
  readonly transport: Readonly<TransportOptions>;
  readonly rpcTimeoutMs: number;
  wallet: WalletFile;
  private clientKeys: ClientKeys | null = null;
  private trustedNode?: { nodeId: Uint8Array; publicKey: Uint8Array };
  private readonly sealedAppendCache = new Map<
    string,
    {
      stored: StoredBlob;
      logicalContentId: string;
      fileName: string;
      dataShards: number;
      parityShards: number;
      storedBytes: number;
    }
  >();

  private constructor(
    server: string,
    ledgerId: string,
    wallet: WalletFile,
    dataShards: number,
    parityShards: number,
    transport: TransportOptions,
    rpcTimeoutMs: number,
  ) {
    this.server = server;
    this.ledgerId = ledgerId;
    this.wallet = wallet;
    this.dataShards = dataShards;
    this.parityShards = parityShards;
    this.transport = Object.freeze({ ...transport });
    this.rpcTimeoutMs = rpcTimeoutMs;
  }

  static async connect(options: StarshineOptions = {}): Promise<Starshine> {
    const server = options.server ?? process.env.STARSHINE_SERVER ?? DEFAULT_SERVER;
    const ledgerId = options.ledgerId ?? process.env.STARSHINE_LEDGER_ID;
    if (!ledgerId) {
      throw new Error(
        "ledgerId is required (set StarshineOptions.ledgerId or STARSHINE_LEDGER_ID)",
      );
    }
    const dataShards = options.dataShards ?? DEFAULT_DATA_SHARDS;
    const parityShards = options.parityShards ?? DEFAULT_PARITY_SHARDS;
    const transport = options.transport ?? {};
    parseEndpoint(server, transport);
    const rpcTimeoutMs = options.rpcTimeoutMs ?? 30_000;
    if (!Number.isFinite(rpcTimeoutMs) || rpcTimeoutMs <= 0) {
      throw new Error("rpcTimeoutMs must be a positive number");
    }
    let wallet: WalletFile;
    if (typeof options.keys === "string") {
      wallet = await loadWallet(options.keys);
    } else if (options.keys) {
      wallet = parseWalletFile(options.keys);
    } else {
      wallet = await generateWallet();
    }
    const starshine = new Starshine(
      server,
      ledgerId,
      wallet,
      dataShards,
      parityShards,
      transport,
      rpcTimeoutMs,
    );
    if (options.verifyCapabilities ?? true) {
      await starshine.capabilities();
    }
    return starshine;
  }

  get hpkePublicKey(): string {
    return this.wallet.hpke_public_key_hex;
  }

  async saveWallet(path: string): Promise<void> {
    await saveWallet(path, this.wallet);
  }

  private async keys(): Promise<ClientKeys> {
    if (!this.clientKeys) {
      this.clientKeys = await loadKeysFromJson(this.wallet, getXWingKem());
    }
    return this.clientKeys;
  }

  private sign(
    kind: VoidSignKind,
    amount: number,
    extra?: { to?: string; contentHash?: string },
  ): VoidSignEnvelope {
    if (!isWalletFile(this.wallet)) {
      throw new Error("wallet is missing ML-DSA-65 keys");
    }
    const payload = buildVoidSignPayload({
      kind,
      from: this.wallet.hpke_public_key_hex,
      amount,
      to: extra?.to,
      contentHash: extra?.contentHash,
    });
    return signVoidPayload(payload, this.wallet.mldsa_private_key_hex);
  }

  private request(options: RequestOptions = {}): {
    transport: TransportOptions;
    rpc: UnaryRequestOptions;
  } {
    return {
      transport: this.transport,
      rpc: {
        timeoutMs: options.timeoutMs ?? this.rpcTimeoutMs,
        signal: options.signal,
      },
    };
  }

  async account(options: RequestOptions = {}): Promise<VoidAccount> {
    return getAccount(
      this.server,
      this.hpkePublicKey,
      this.request(options),
    );
  }

  async capabilities(options: RequestOptions = {}): Promise<StarshineCapabilities> {
    const capabilities = await getCapabilitiesV2(this.server, this.request(options));
    this.trustedNode = {
      nodeId: capabilities.nodeId,
      publicKey: capabilities.nodeMlDsaPublicKey,
    };
    return capabilities;
  }

  async events(
    limit = 100,
    cursor = "",
    options: RequestOptions = {},
  ): Promise<{ receipts: EventReceipt[]; nextCursor: string }> {
    return listAccountEventsV2(
      this.server,
      this.wallet,
      limit,
      cursor,
      {
        transport: this.transport,
        ledgerId: this.ledgerId,
        rpc: this.request(options).rpc,
        requestId: options.requestId,
        expectedNode: this.trustedNode,
      },
    );
  }

  /** All events committed to this application ledger, across authorized signers. */
  async ledgerEvents(
    limit = 100,
    cursor = "",
    options: RequestOptions = {},
  ): Promise<{ receipts: EventReceipt[]; nextCursor: string }> {
    return listLedgerEventsV2(
      this.server,
      this.wallet,
      limit,
      cursor,
      {
        ledgerId: this.ledgerId,
        transport: this.transport,
        rpc: this.request(options).rpc,
        requestId: options.requestId,
        expectedNode: this.trustedNode,
      },
    );
  }

  /** Available once the node advertises network-checkpoint finality. */
  async inclusionProof(
    eventId: string,
    options: RequestOptions = {},
  ): Promise<InclusionProof> {
    return getInclusionProofV2(this.server, this.wallet, eventId, {
      ledgerId: this.ledgerId,
      transport: this.transport,
      rpc: this.request(options).rpc,
      requestId: options.requestId,
      expectedNode: this.trustedNode,
    });
  }

  async faucet(options: RequestOptions = {}): Promise<VoidAccount> {
    return voidFaucet(
      this.server,
      this.sign("faucet", FAUCET_VOID_AMOUNT),
      this.request(options),
    );
  }

  async transfer(
    toPublicKey: string,
    amount: number,
    options: RequestOptions = {},
  ): Promise<VoidAccount> {
    return voidTransfer(
      this.server,
      this.sign("transfer", amount, { to: toPublicKey }),
      this.request(options),
    );
  }

  /** Node-wide legacy transaction feed. Prefer `account().transactions`. */
  async transactions(
    limit = 1000,
    options: RequestOptions = {},
  ): Promise<VoidTransaction[]> {
    return listTransactions(this.server, limit, this.request(options));
  }

  async put(data: Uint8Array, options: PutOptions = {}): Promise<PutResult> {
    const dataShards = options.dataShards ?? this.dataShards;
    const parityShards = options.parityShards ?? this.parityShards;
    const fileName = options.fileName ?? "blob.bin";
    const logical = logicalContentId(data, options.contentNamespace);
    let cached = options.requestId
      ? this.sealedAppendCache.get(options.requestId)
      : undefined;
    if (cached) {
      if (
        cached.logicalContentId !== logical ||
        cached.fileName !== fileName ||
        cached.dataShards !== dataShards ||
        cached.parityShards !== parityShards
      ) {
        throw new Error(
          "requestId is already bound to different append parameters in this client",
        );
      }
    } else {
      const keys = await this.keys();
      const stored = await uploadWithProgress(keys, data, dataShards, parityShards);
      cached = {
        stored,
        logicalContentId: logical,
        fileName,
        dataShards,
        parityShards,
        storedBytes: aggregateStoredServedBytes(stored),
      };
      if (options.requestId) {
        this.sealedAppendCache.set(options.requestId, cached);
        if (this.sealedAppendCache.size > 128) {
          const oldest = this.sealedAppendCache.keys().next().value;
          if (oldest) this.sealedAppendCache.delete(oldest);
        }
      }
    }
    const result = await appendV2(
      this.server,
      this.wallet,
      cached.stored,
      fileName,
      logical,
      {
        ledgerId: this.ledgerId,
        transport: this.transport,
        rpc: this.request(options).rpc,
        requestId: options.requestId,
        expectedNode: this.trustedNode,
      },
    );
    return {
      logicalContentId: logical,
      contentHash: bytesToHex(result.artifactRoot),
      storedBytes: cached.storedBytes,
      receipt: result.receipt,
    };
  }

  async get(hash: string | Uint8Array, options: GetOptions = {}): Promise<GetResult> {
    const minimumShards = options.minimumShards ?? true;
    const contentHash = parseHash(hash);
    const keys = await this.keys();
    const fetched = await retrieveV2(
      this.server,
      this.wallet,
      contentHash,
      minimumShards,
      {
        ledgerId: this.ledgerId,
        transport: this.transport,
        rpc: this.request(options).rpc,
        requestId: options.requestId,
        logicalContentId: options.logicalContentId,
        expectedNode: this.trustedNode,
      },
    );
    const plaintext = await recoverWithProgress(keys, fetched.stored);
    return {
      plaintext,
      servedBytes: aggregateStoredServedBytes(fetched.stored),
      receipt: fetched.receipt,
    };
  }

  async delete(hash: string | Uint8Array, options: DeleteOptions = {}): Promise<DeleteResult> {
    const contentHash = parseHash(hash);
    const result = await releaseV2(
      this.server,
      this.wallet,
      contentHash,
      options.reason ?? "owner requested release",
      {
        ledgerId: this.ledgerId,
        transport: this.transport,
        rpc: this.request(options).rpc,
        requestId: options.requestId,
        logicalContentId: options.logicalContentId,
        expectedNode: this.trustedNode,
      },
    );
    return {
      contentHash: bytesToHex(contentHash),
      receipt: result.receipt,
      physicalBytesReleased: result.physicalBytesReleased,
    };
  }

  async publicMetadata(
    hash: string | Uint8Array,
    options: RequestOptions = {},
  ): Promise<PublicBlobMeta & { released: boolean }> {
    return getPublicArtifactV2(
      this.server,
      parseHash(hash),
      this.request(options),
    );
  }

  async auditStorage(
    hash: string | Uint8Array,
    options: AuditStorageOptions = {},
  ): Promise<AuditStorageResult> {
    const contentHash = parseHash(hash);
    const meta = await getPublicArtifactV2(
      this.server,
      contentHash,
      this.request(options),
    );
    const totalShards = meta.dataShards + meta.parityShards;
    const shardIndex = options.shardIndex ?? 0;
    if (!Number.isInteger(shardIndex) || shardIndex < 0 || shardIndex >= totalShards) {
      throw new Error(`shardIndex must be between 0 and ${totalShards - 1}`);
    }
    const epochInput = options.epoch ?? BigInt(Math.floor(Date.now() / 1_000));
    const epoch = typeof epochInput === "bigint" ? epochInput : BigInt(epochInput);
    const randomness = options.randomness ?? randomBytes(32);
    const proof = await requestStorageProofV2(
      this.server,
      contentHash,
      shardIndex,
      epoch,
      randomness,
      this.request(options),
    );
    const verify = options.verify ?? true;
    if (verify) verifyStorageProof(meta, proof);
    return { meta, proof, verified: verify };
  }
}

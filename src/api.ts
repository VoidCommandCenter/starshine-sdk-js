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
import {
  deleteBlob,
  getPublicBlobMeta,
  getBlobResult,
  putBlobResult,
  requestStorageProof,
} from "./remote.js";
import { uploadWithProgress } from "./upload.js";
import {
  envelopeToWire,
  faucet as voidFaucet,
  getAccount,
  listTransactions,
  mapVoidError,
  receiptFromWire,
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

export interface StarshineOptions {
  /** gRPC endpoint. Use `grpcs://` for every non-local production endpoint. */
  server?: string;
  /** Wallet JSON object, or path to a keys file. Omit to generate in memory. */
  keys?: WalletFile | string;
  dataShards?: number;
  parityShards?: number;
  transport?: TransportOptions;
  /** Default unary RPC timeout. Individual calls may override it. */
  rpcTimeoutMs?: number;
}

export interface RequestOptions extends UnaryRequestOptions {}

export interface PutOptions extends RequestOptions {
  fileName?: string;
  /** Domain for the stable plaintext identity returned as `logicalContentId`. */
  contentNamespace?: string;
  /** Charge VOID (default true). */
  pay?: boolean;
  dataShards?: number;
  parityShards?: number;
}

export interface GetOptions extends RequestOptions {
  fileName?: string;
  /** Charge VOID (default true). */
  pay?: boolean;
  /** Fetch only k data shards (cheaper VOID). Default true. */
  minimumShards?: boolean;
}

export interface DeleteOptions extends RequestOptions {
  fileName?: string;
  /** Retained for source compatibility. Delete authorization is always signed. */
  pay?: boolean;
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
  ledger?: VoidReceipt;
}

export interface GetResult {
  plaintext: Uint8Array;
  servedBytes: number;
  ledger?: VoidReceipt;
}

export interface DeleteResult {
  contentHash: string;
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
 * JavaScript client for `starshine.v1.Storage` and `starshine.v1.Void`.
 * Seals locally; the node never receives HPKE/PoRep/ML-DSA secrets.
 */
export class Starshine {
  readonly server: string;
  readonly dataShards: number;
  readonly parityShards: number;
  readonly transport: Readonly<TransportOptions>;
  readonly rpcTimeoutMs: number;
  wallet: WalletFile;
  private clientKeys: ClientKeys | null = null;

  private constructor(
    server: string,
    wallet: WalletFile,
    dataShards: number,
    parityShards: number,
    transport: TransportOptions,
    rpcTimeoutMs: number,
  ) {
    this.server = server;
    this.wallet = wallet;
    this.dataShards = dataShards;
    this.parityShards = parityShards;
    this.transport = Object.freeze({ ...transport });
    this.rpcTimeoutMs = rpcTimeoutMs;
  }

  static async connect(options: StarshineOptions = {}): Promise<Starshine> {
    const server = options.server ?? process.env.STARSHINE_SERVER ?? DEFAULT_SERVER;
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
    return new Starshine(
      server,
      wallet,
      dataShards,
      parityShards,
      transport,
      rpcTimeoutMs,
    );
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
    const pay = options.pay ?? true;
    const dataShards = options.dataShards ?? this.dataShards;
    const parityShards = options.parityShards ?? this.parityShards;
    const fileName = options.fileName ?? "blob.bin";
    const keys = await this.keys();
    const stored = await uploadWithProgress(keys, data, dataShards, parityShards);
    const storedBytes = aggregateStoredServedBytes(stored);
    const contentHash = bytesToHex(stored.meta.topRoot);
    const envelope = pay
      ? envelopeToWire(
          this.sign("put", storedBytes, { contentHash }),
        )
      : undefined;
    try {
      const result = await putBlobResult(this.server, stored, {
        envelope,
        fileName,
        expectedVoid: pay ? storedBytes : 0,
        ...this.request(options),
      });
      return {
        logicalContentId: logicalContentId(data, options.contentNamespace),
        contentHash: bytesToHex(result.contentHash),
        storedBytes,
        ledger: receiptFromWire(result.ledger),
      };
    } catch (error) {
      mapVoidError(error);
    }
  }

  async get(hash: string | Uint8Array, options: GetOptions = {}): Promise<GetResult> {
    const pay = options.pay ?? true;
    const minimumShards = options.minimumShards ?? true;
    const contentHash = parseHash(hash);
    const hashHex = bytesToHex(contentHash);
    const keys = await this.keys();
    let envelope;
    if (pay) {
      const account = await this.account(options);
      if (account.balance <= 0) {
        throw new Error("VOID balance is 0; call faucet() first");
      }
      envelope = envelopeToWire(
        this.sign("get", account.balance, { contentHash: hashHex }),
      );
    }
    try {
      const fetched = await getBlobResult(this.server, contentHash, {
        envelope,
        fileName: options.fileName,
        minimumShards,
        ...this.request(options),
      });
      const plaintext = await recoverWithProgress(keys, fetched.stored);
      return {
        plaintext,
        servedBytes: aggregateStoredServedBytes(fetched.stored),
        ledger: receiptFromWire(fetched.ledger),
      };
    } catch (error) {
      mapVoidError(error);
    }
  }

  async delete(hash: string | Uint8Array, options: DeleteOptions = {}): Promise<DeleteResult> {
    const contentHash = parseHash(hash);
    const hashHex = bytesToHex(contentHash);
    // Authentication is not payment. Always sign destructive requests, including
    // calls made against a node configured for zero-cost storage operations.
    const envelope = envelopeToWire(
      this.sign("delete", 0, { contentHash: hashHex }),
    );
    try {
      const result = await deleteBlob(this.server, contentHash, {
        envelope,
        fileName: options.fileName,
        ...this.request(options),
      });
      return {
        contentHash: hashHex,
        ledger: receiptFromWire(result.ledger),
      };
    } catch (error) {
      mapVoidError(error);
    }
  }

  async publicMetadata(
    hash: string | Uint8Array,
    options: RequestOptions = {},
  ): Promise<PublicBlobMeta> {
    return getPublicBlobMeta(
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
    const meta = await getPublicBlobMeta(
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
    const proof = await requestStorageProof(
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

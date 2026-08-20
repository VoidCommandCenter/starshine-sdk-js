import type { ServiceError } from "@grpc/grpc-js";

import { FAUCET_VOID_AMOUNT } from "./constants.js";
import {
  getVoidClient,
  unaryRequest,
  type UnaryRequestOptions,
  type VoidAccountWire,
  type VoidEnvelopeWire,
  type VoidReceiptWire,
  type VoidTransactionWire,
} from "./grpc.js";
import type { TransportOptions } from "./transport.js";
import type { VoidSignEnvelope } from "./void-sign.js";

export { FAUCET_VOID_AMOUNT };

export interface VoidReceipt {
  balance: number;
  txId: string;
  amount: number;
}

export interface VoidTransaction {
  id: string;
  kind: string;
  status: string;
  fromPublicKey: string | null;
  toPublicKey: string | null;
  amount: number;
  shardBytes?: number;
  contentHash?: string;
  fileName?: string;
  plaintextBytes?: number;
  message?: string;
  createdAt: string;
  signature?: string;
  mldsaPublicKey?: string;
  nonce?: string;
  payloadHash?: string;
}

export interface VoidAccount {
  publicKey: string;
  balance: number;
  createdAt: string;
  faucetAmount: number;
  transactions: VoidTransaction[];
}

export class InsufficientVoidError extends Error {
  readonly need: number;
  readonly have: number;

  constructor(need: number, have: number) {
    super(`Insufficient VOID (need ${need}, have ${have})`);
    this.name = "InsufficientVoidError";
    this.need = need;
    this.have = have;
  }
}

export class SignedVoidExceededError extends Error {
  readonly actual: number;
  readonly signed: number;

  constructor(actual: number, signed: number) {
    super(`actual VOID cost ${actual} exceeds signed amount ${signed}`);
    this.name = "SignedVoidExceededError";
    this.actual = actual;
    this.signed = signed;
  }
}

export function envelopeToWire(envelope: VoidSignEnvelope): VoidEnvelopeWire {
  return {
    v: envelope.payload.v,
    kind: envelope.payload.kind,
    from_hpke: envelope.payload.from,
    to_hpke: envelope.payload.to ?? "",
    amount: envelope.payload.amount,
    content_hash: envelope.payload.contentHash ?? "",
    nonce: envelope.payload.nonce,
    issued_at: envelope.payload.issuedAt,
    mldsa_public_key_hex: envelope.mldsaPublicKey,
    signature_hex: envelope.signature,
  };
}

export function receiptFromWire(ledger?: VoidReceiptWire | null): VoidReceipt | undefined {
  if (!ledger?.tx_id) return undefined;
  return {
    balance: asNumber(ledger.balance),
    txId: ledger.tx_id,
    amount: asNumber(ledger.amount),
  };
}

function asNumber(value: number | string | undefined, fallback = 0): number {
  const n = typeof value === "number" ? value : Number(value);
  return Number.isFinite(n) ? n : fallback;
}

function emptyToNull(value: string | undefined): string | null {
  const trimmed = value?.trim() ?? "";
  return trimmed ? trimmed : null;
}

function txFromWire(tx: VoidTransactionWire): VoidTransaction {
  return {
    id: tx.id,
    kind: tx.kind,
    status: tx.status,
    fromPublicKey: emptyToNull(tx.from_public_key),
    toPublicKey: emptyToNull(tx.to_public_key),
    amount: asNumber(tx.amount),
    shardBytes: asNumber(tx.shard_bytes) || undefined,
    contentHash: emptyToNull(tx.content_hash) ?? undefined,
    fileName: emptyToNull(tx.file_name) ?? undefined,
    plaintextBytes: asNumber(tx.plaintext_bytes) || undefined,
    message: emptyToNull(tx.message) ?? undefined,
    createdAt: tx.created_at,
    signature: emptyToNull(tx.signature) ?? undefined,
    mldsaPublicKey: emptyToNull(tx.mldsa_public_key) ?? undefined,
    nonce: emptyToNull(tx.nonce) ?? undefined,
    payloadHash: emptyToNull(tx.payload_hash) ?? undefined,
  };
}

function accountFromWire(account: VoidAccountWire): VoidAccount {
  return {
    publicKey: account.public_key,
    balance: asNumber(account.balance),
    createdAt: account.created_at,
    faucetAmount: asNumber(account.faucet_amount, FAUCET_VOID_AMOUNT),
    transactions: (account.transactions ?? []).map(txFromWire),
  };
}

export function mapVoidError(error: unknown): never {
  const status = error as ServiceError;
  const message = status.details || status.message || String(error);
  const insufficient = /Insufficient VOID \(need (\d+), have (\d+)\)/.exec(message);
  if (insufficient) {
    throw new InsufficientVoidError(Number(insufficient[1]), Number(insufficient[2]));
  }
  const signed = /actual VOID cost (\d+) exceeds signed amount (\d+)/.exec(message);
  if (signed) {
    throw new SignedVoidExceededError(Number(signed[1]), Number(signed[2]));
  }
  throw new Error(message);
}

export interface VoidRequestOptions {
  transport?: TransportOptions;
  rpc?: UnaryRequestOptions;
}

async function mappedUnary<T>(request: Promise<T>): Promise<T> {
  try {
    return await request;
  } catch (error) {
    mapVoidError(error);
  }
}

export async function getAccount(
  endpoint: string,
  hpkePublicKey: string,
  options: VoidRequestOptions = {},
): Promise<VoidAccount> {
  const client = getVoidClient(endpoint, options.transport);
  const raw = await mappedUnary(
    unaryRequest<VoidAccountWire>(
      (callOptions, callback) =>
        client.getAccount({ hpke_public_key: hpkePublicKey }, callOptions, callback),
      options.rpc,
    ),
  );
  return accountFromWire(raw);
}

export async function listTransactions(
  endpoint: string,
  limit = 1000,
  options: VoidRequestOptions = {},
): Promise<VoidTransaction[]> {
  const client = getVoidClient(endpoint, options.transport);
  const raw = await mappedUnary(
    unaryRequest<{ transactions: VoidTransactionWire[] }>(
      (callOptions, callback) =>
        client.listTransactions({ limit }, callOptions, callback),
      options.rpc,
    ),
  );
  return (raw.transactions ?? []).map(txFromWire);
}

export async function faucet(
  endpoint: string,
  envelope: VoidSignEnvelope,
  options: VoidRequestOptions = {},
): Promise<VoidAccount> {
  const client = getVoidClient(endpoint, options.transport);
  const raw = await mappedUnary(
    unaryRequest<VoidAccountWire>(
      (callOptions, callback) =>
        client.faucet(envelopeToWire(envelope), callOptions, callback),
      options.rpc,
    ),
  );
  return accountFromWire(raw);
}

export async function transfer(
  endpoint: string,
  envelope: VoidSignEnvelope,
  options: VoidRequestOptions = {},
): Promise<VoidAccount> {
  const client = getVoidClient(endpoint, options.transport);
  const raw = await mappedUnary(
    unaryRequest<VoidAccountWire>(
      (callOptions, callback) =>
        client.transfer(envelopeToWire(envelope), callOptions, callback),
      options.rpc,
    ),
  );
  return accountFromWire(raw);
}

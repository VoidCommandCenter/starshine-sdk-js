import {
  getEventV2,
  getInclusionProofV2,
  listLedgerEventsV2,
  StarshineFinality,
  StarshineOperation,
  type EventReceipt,
  type InclusionProof,
  type WalletFile,
} from "starshine-sdk-js";

import type { RelayConfig } from "./config.js";

export const SCAN_API_VERSION = "void.scan.v1";

export interface PublicScanProvider {
  ledger(): PublicScanLedger;
  list(limit: number, cursor: string): Promise<PublicScanPage>;
  detail(eventId: string): Promise<PublicScanDetail>;
}

export interface PublicScanLedger {
  version: typeof SCAN_API_VERSION;
  ledgerId: string;
  name: string;
  environment: string;
  visibility: "public-proof-metadata";
  payloads: "encrypted-not-exposed";
}

export interface PublicScanEvent {
  eventId: string;
  ledgerId: string;
  operation: string;
  acceptedAt: string;
  acceptedAtUnixMs: string;
  ledgerSequence: string;
  artifactRoot: string;
  eventHash: string;
  finality: string;
  nodeId: string;
}

export interface PublicScanPage {
  version: typeof SCAN_API_VERSION;
  ledger: PublicScanLedger;
  events: PublicScanEvent[];
  ledgerEventCount: string;
  indexedAt: string;
  nextCursor: string;
}

export interface PublicScanDetail {
  version: typeof SCAN_API_VERSION;
  ledger: PublicScanLedger;
  event: PublicScanEvent;
  proof: ReturnType<typeof publicProof>;
}

interface TrustedNode {
  nodeId: Uint8Array;
  publicKey: Uint8Array;
}

interface CacheEntry<T> {
  expiresAt: number;
  value: T;
}

export class StarshinePublicScan implements PublicScanProvider {
  private readonly detailCache = new Map<string, CacheEntry<PublicScanDetail>>();
  private readonly indexedEvents: EventReceipt[] = [];
  private readonly indexedEventIds = new Set<string>();
  private lastLedgerSequence = 0n;
  private lastSyncAt = 0;
  private syncPromise?: Promise<void>;

  constructor(
    private readonly config: RelayConfig,
    private readonly wallet: WalletFile,
    private readonly trustedNode: TrustedNode,
  ) {}

  ledger(): PublicScanLedger {
    return {
      version: SCAN_API_VERSION,
      ledgerId: this.config.ledgerId,
      name: this.config.scanTitle,
      environment: this.config.scanEnvironment,
      visibility: "public-proof-metadata",
      payloads: "encrypted-not-exposed",
    };
  }

  async list(limit: number, cursor: string): Promise<PublicScanPage> {
    await this.syncLedger();
    const before = cursor ? BigInt(cursor) : undefined;
    const eligible = before === undefined
      ? this.indexedEvents
      : this.indexedEvents.filter((receipt) => receipt.ledgerSequence < before);
    const selected = eligible.slice(Math.max(eligible.length - limit, 0)).reverse();
    const oldest = selected.at(-1)?.ledgerSequence;
    return {
      version: SCAN_API_VERSION,
      ledger: this.ledger(),
      events: selected.map(publicEvent),
      ledgerEventCount: this.lastLedgerSequence.toString(),
      indexedAt: new Date(this.lastSyncAt).toISOString(),
      nextCursor: oldest !== undefined && eligible.length > selected.length
        ? oldest.toString()
        : "",
    };
  }

  async detail(eventId: string): Promise<PublicScanDetail> {
    const cached = fresh(this.detailCache.get(eventId));
    if (cached) return cached;
    const options = this.callOptions();
    const [receipt, proof] = await Promise.all([
      getEventV2(this.config.server, this.wallet, eventId, options),
      getInclusionProofV2(this.config.server, this.wallet, eventId, options),
    ]);
    if (receipt.ledgerId !== this.config.ledgerId || proof.ledgerId !== this.config.ledgerId) {
      throw new Error("event does not belong to the configured public ledger");
    }
    const detail: PublicScanDetail = {
      version: SCAN_API_VERSION,
      ledger: this.ledger(),
      event: publicEvent(receipt),
      proof: publicProof(proof),
    };
    putBounded(this.detailCache, eventId, detail, 300_000, 500);
    return detail;
  }

  private callOptions() {
    return {
      ledgerId: this.config.ledgerId,
      expectedNode: this.trustedNode,
      transport: this.config.serverCa
        ? { rootCertificates: this.config.serverCa }
        : undefined,
    };
  }

  private async syncLedger(): Promise<void> {
    if (Date.now() - this.lastSyncAt < 5_000) return;
    if (this.syncPromise) return this.syncPromise;
    this.syncPromise = this.loadNewEvents().finally(() => {
      this.syncPromise = undefined;
    });
    return this.syncPromise;
  }

  private async loadNewEvents(): Promise<void> {
    let upstreamCursor = this.lastLedgerSequence === 0n
      ? ""
      : this.lastLedgerSequence.toString();
    for (;;) {
      const result = await listLedgerEventsV2(
        this.config.server,
        this.wallet,
        100,
        upstreamCursor,
        this.callOptions(),
      );
      for (const receipt of result.receipts) {
        if (!this.indexedEventIds.has(receipt.eventId)) {
          this.indexedEventIds.add(receipt.eventId);
          this.indexedEvents.push(receipt);
        }
        if (receipt.ledgerSequence > this.lastLedgerSequence) {
          this.lastLedgerSequence = receipt.ledgerSequence;
        }
      }
      if (!result.nextCursor) break;
      upstreamCursor = result.nextCursor;
    }
    this.indexedEvents.sort((a, b) =>
      a.ledgerSequence < b.ledgerSequence ? -1 : a.ledgerSequence > b.ledgerSequence ? 1 : 0
    );
    this.lastSyncAt = Date.now();
  }
}

export function publicEvent(receipt: EventReceipt): PublicScanEvent {
  return {
    eventId: receipt.eventId,
    ledgerId: receipt.ledgerId,
    operation: operationName(receipt.operation),
    acceptedAt: new Date(Number(receipt.acceptedAtUnixMs)).toISOString(),
    acceptedAtUnixMs: receipt.acceptedAtUnixMs.toString(),
    ledgerSequence: receipt.ledgerSequence.toString(),
    artifactRoot: encoded(receipt.artifactRoot),
    eventHash: encoded(receipt.eventHash),
    finality: finalityName(receipt.finality),
    nodeId: encoded(receipt.nodeId),
  };
}

export function publicProof(proof: InclusionProof) {
  return {
    verified: true as const,
    finality: finalityName(proof.finality),
    ledgerSequence: proof.ledgerSequence.toString(),
    ledgerEventCount: proof.ledgerEventCount.toString(),
    eventIndex: proof.eventIndex.toString(),
    ledgerIndex: proof.ledgerIndex.toString(),
    ledgerCount: proof.ledgerCount.toString(),
    eventHash: encoded(proof.eventHash),
    ledgerRoot: encoded(proof.ledgerRoot),
    ledgerCommitment: encoded(proof.ledgerCommitment),
    checkpointRoot: encoded(proof.checkpointRoot),
    checkpointHeight: proof.checkpointHeight.toString(),
    ledgerPath: proof.ledgerPath.map((sibling) => ({
      hash: encoded(sibling.hash),
      siblingOnLeft: sibling.siblingOnLeft,
    })),
    globalPath: proof.globalPath.map((sibling) => ({
      hash: encoded(sibling.hash),
      siblingOnLeft: sibling.siblingOnLeft,
    })),
    checkpointCertificate: {
      version: proof.checkpointCertificate.version,
      checkpointHeight: proof.checkpointCertificate.checkpointHeight.toString(),
      createdAt: new Date(
        Number(proof.checkpointCertificate.createdAtUnixMs),
      ).toISOString(),
      createdAtUnixMs: proof.checkpointCertificate.createdAtUnixMs.toString(),
      globalRoot: encoded(proof.checkpointCertificate.globalRoot),
      previousCheckpointHash: encoded(proof.checkpointCertificate.previousCheckpointHash),
      checkpointHash: encoded(proof.checkpointCertificate.checkpointHash),
      nodeId: encoded(proof.checkpointCertificate.nodeId),
      nodeMlDsaPublicKey: encoded(proof.checkpointCertificate.nodeMlDsaPublicKey),
      nodeMlDsaSignature: encoded(proof.checkpointCertificate.nodeMlDsaSignature),
    },
  };
}

function operationName(operation: StarshineOperation): string {
  switch (operation) {
    case StarshineOperation.Append:
      return "append";
    case StarshineOperation.Retrieve:
      return "retrieve";
    case StarshineOperation.Release:
      return "release";
    case StarshineOperation.Transfer:
      return "transfer";
    case StarshineOperation.Faucet:
      return "faucet";
    case StarshineOperation.ReadEvent:
      return "read-event";
    case StarshineOperation.ListEvents:
      return "list-events";
    case StarshineOperation.GetInclusionProof:
      return "get-inclusion-proof";
    case StarshineOperation.ListLedgerEvents:
      return "list-ledger-events";
    default:
      return `unknown-${Number(operation)}`;
  }
}

function finalityName(finality: StarshineFinality): string {
  switch (finality) {
    case StarshineFinality.NodeAttested:
      return "node-attested";
    case StarshineFinality.LedgerCheckpointed:
      return "ledger-checkpointed";
    case StarshineFinality.NetworkFinalized:
      return "network-finalized";
    default:
      return "unspecified";
  }
}

function encoded(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function fresh<T>(entry: CacheEntry<T> | undefined): T | undefined {
  return entry && entry.expiresAt > Date.now() ? entry.value : undefined;
}

function putBounded<T>(
  cache: Map<string, CacheEntry<T>>,
  key: string,
  value: T,
  ttlMs: number,
  maximum: number,
): void {
  if (cache.size >= maximum) {
    const oldest = cache.keys().next().value as string | undefined;
    if (oldest) cache.delete(oldest);
  }
  cache.set(key, { expiresAt: Date.now() + ttlMs, value });
}

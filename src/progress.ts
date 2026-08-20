import type { DownloadPhase, DownloadProgressEvent, UploadPhase, UploadProgressEvent } from "./types.js";
import { PROGRESS_LINE_PREFIX } from "./constants.js";

export function emitProgress(event: UploadProgressEvent): void {
  process.stderr.write(`${PROGRESS_LINE_PREFIX}${JSON.stringify(event)}\n`);
}

export function emitDownload(event: DownloadProgressEvent): void {
  process.stderr.write(`${PROGRESS_LINE_PREFIX}${JSON.stringify(event)}\n`);
}

function formatVerboseUpload(event: UploadProgressEvent): string {
  let line = `[${event.phase}]`;
  if (event.shard !== undefined && event.shards !== undefined) {
    line += ` ${event.shard + 1}/${event.shards}`;
  }
  if (event.message) {
    line += `: ${event.message}`;
  }
  return line;
}

function formatVerboseDownload(event: DownloadProgressEvent): string {
  let line = `[${event.phase}]`;
  if (event.shard !== undefined && event.shards !== undefined) {
    line += ` ${event.shard + 1}/${event.shards}`;
  }
  if (event.message) {
    line += `: ${event.message}`;
  }
  return line;
}

export function emitVerboseUpload(event: UploadProgressEvent): void {
  process.stderr.write(`${formatVerboseUpload(event)}\n`);
}

export function emitVerboseDownload(event: DownloadProgressEvent): void {
  process.stderr.write(`${formatVerboseDownload(event)}\n`);
}

export function reportUpload(
  event: UploadProgressEvent,
  progress: boolean,
  verbose: boolean,
): void {
  if (progress) emitProgress(event);
  if (verbose) emitVerboseUpload(event);
}

export function reportDownload(
  event: DownloadProgressEvent,
  progress: boolean,
  verbose: boolean,
): void {
  if (progress) emitDownload(event);
  if (verbose) emitVerboseDownload(event);
}

export function sealingPct(
  phase: UploadPhase,
  shard: number,
  totalShards: number,
): number {
  const BASE = 5;
  const t = Math.max(totalShards, 1);
  switch (phase) {
    case "zstd":
      return Math.min(BASE + 1, 99);
    case "hpke":
      return Math.min(BASE + 5, 99);
    case "reed_solomon":
      return Math.min(BASE + 8, 99);
    case "porep_seal": {
      const frac = (shard + 1) / t;
      return Math.min(BASE + 10 + Math.floor(frac * 45), 99);
    }
    case "bao":
      return Math.min(BASE + 78, 99);
    case "grpc_put":
      return 92;
    case "done":
      return 100;
    default:
      return BASE;
  }
}

export function downloadShardPct(shard: number, total: number): number {
  const t = Math.max(total, 1);
  return Math.round(5 + (shard / t) * 35);
}

export function downloadDecodePct(shard: number, total: number): number {
  const t = Math.max(total, 1);
  return Math.round(40 + (shard / t) * 45);
}

export function downloadPhaseLabel(phase: DownloadPhase): string {
  return phase;
}

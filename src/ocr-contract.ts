// Shared OCR contract. WP1 (worker), WP2 (capture/replay), WP3 (HTTP/CLI), WP4 (9Router) build against this.
import type { DetectorOptions, Finding } from "./detector.ts";
import type { ImageInput } from "./body.ts";

export type { ImageInput };
export type OcrStatus = "scanned" | "partial" | "empty" | "failed" | "skipped";
export type OcrReason =
  | "queue_full" | "oversize" | "invalid_base64" | "unsupported"
  | "pixel_limit" | "timeout" | "output_limit" | "engine_error"
  | "low_confidence" | "closed";
/** Hit fields safe to log, cache, and return. Never raw text, offsets, or bytes. */
export type SafeHit = Pick<Finding, "rule" | "name" | "kind" | "hash">;

export interface OcrResult {
  status: OcrStatus;
  reason?: OcrReason;
  findings: SafeHit[];
  sha256?: string;
  /** Caller's image source with "/ocr" appended. */
  source: string;
  path: string;
  cache: "hit" | "miss" | "coalesced" | "none";
  ocrMs: number;
  queueMs: number;
  meanConfidence?: number;
  chars: number;
}

export interface CaptureOptions { dir: string; maxBytes: number; ttlMs: number }

export interface OcrOptions {
  detector: DetectorOptions;
  /** Concurrent tesseract processes. Default 1. */
  concurrency?: number;
  /** Per-image engine timeout. Default 20_000. */
  timeoutMs?: number;
  /** Off unless set. */
  capture?: CaptureOptions;
}

export interface OcrWorker {
  /** Returns immediately. false = admission rejected; caller records "skipped"/"queue_full". Accepted work calls done exactly once. */
  enqueue(image: ImageInput, done: (result: OcrResult) => void): boolean;
  /** Awaitable variant for sidecar/CLI callers. Resolves with status "skipped" on rejection. */
  scan(image: ImageInput): Promise<OcrResult>;
  close(): Promise<void>;
}

/** Capture store (WP2). Called by the worker off the request path; errors never affect OCR. */
export interface CaptureStore {
  /** Writes bytes once under sha256 name; duplicates are no-ops and do not refresh TTL. */
  put(sha256: string, data: Uint8Array): Promise<void>;
  /** Deletes expired files and evicts oldest past maxBytes. */
  sweep(): Promise<{ files: number; bytes: number; removed: number }>;
}

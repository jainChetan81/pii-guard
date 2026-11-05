import { spawn, type ChildProcess } from "node:child_process";
import { createHash } from "node:crypto";
import { join } from "node:path";
import { createDetector, type Finding } from "./detector.ts";
import { isSupportedImage, parseTesseractTsv } from "./media.ts";
import { createCaptureStore, startSweeper } from "./capture.ts";
import type { CaptureStore, ImageInput, OcrOptions, OcrReason, OcrResult, OcrWorker, SafeHit } from "./ocr-contract.ts";

const MAX_DECODED_BYTES = 20 * 1024 * 1024;
const MAX_PENDING_IMAGES = 32;
const MAX_PENDING_ENCODED_BYTES = 32 * 1024 * 1024;
const MAX_PIXELS = 25_000_000;
const MAX_STDOUT_BYTES = 4 * 1024 * 1024;
const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
const CACHE_MAX_ENTRIES = 1024;

type CachedFields = Pick<OcrResult, "status" | "reason" | "findings" | "meanConfidence" | "chars" | "ocrMs">;
interface CacheEntry { expiresAt: number; fields: CachedFields }
const resultCache = new Map<string, CacheEntry>();
let resultCacheLimit = CACHE_MAX_ENTRIES;

interface Subscriber {
  data: string;
  source: string;
  path: string;
  done: (result: OcrResult) => void;
  enqueuedAt: number;
  encodedBytes: number;
  admitted: boolean;
  completed: boolean;
  sha?: string;
  resultCache?: OcrResult["cache"];
}

interface Work {
  sha: string;
  bytes: Buffer;
  subscribers: Subscriber[];
  startedAt: number;
  child?: ChildProcess;
  forcedReason?: OcrReason;
  reaped?: Promise<void>;
  resolveReaped?: () => void;
}

function copyFields(fields: CachedFields): CachedFields {
  return {
    status: fields.status,
    ...(fields.reason && { reason: fields.reason }),
    findings: fields.findings.map(hit => ({ ...hit })),
    ...(fields.meanConfidence !== undefined && { meanConfidence: fields.meanConfidence }),
    chars: fields.chars,
    ocrMs: fields.ocrMs,
  };
}

function getCached(sha: string): CachedFields | undefined {
  const entry = resultCache.get(sha);
  if (!entry) return undefined;
  if (entry.expiresAt <= Date.now()) {
    resultCache.delete(sha);
    return undefined;
  }
  resultCache.delete(sha);
  resultCache.set(sha, entry);
  return copyFields(entry.fields);
}

function putCached(sha: string, fields: CachedFields): void {
  if (fields.status === "failed" || fields.reason === "timeout" || fields.reason === "engine_error" || fields.reason === "queue_full" || fields.reason === "closed") return;
  resultCache.delete(sha);
  resultCache.set(sha, { expiresAt: Date.now() + CACHE_TTL_MS, fields: copyFields(fields) });
  while (resultCache.size > resultCacheLimit) resultCache.delete(resultCache.keys().next().value!);
}

/** Internal cache hook for bounded LRU tests; not re-exported from the package entry point. */
export function __resetOcrCacheForTests(maxEntries = CACHE_MAX_ENTRIES): void {
  if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new RangeError("Cache size must be a positive integer");
  resultCache.clear();
  resultCacheLimit = maxEntries;
}

function dimensions(data: Buffer): { width: number; height: number } | undefined {
  if (data.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) {
    if (data.length >= 24 && data.toString("ascii", 12, 16) === "IHDR") return { width: data.readUInt32BE(16), height: data.readUInt32BE(20) };
    return undefined;
  }
  if (data[0] === 0xff && data[1] === 0xd8) {
    let offset = 2;
    while (offset + 3 < data.length) {
      if (data[offset] !== 0xff) return undefined;
      while (data[offset] === 0xff) offset++;
      const marker = data[offset++];
      if (marker === 0xd8 || marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
      if (marker === 0xd9 || marker === 0xda || offset + 1 >= data.length) return undefined;
      const length = data.readUInt16BE(offset);
      if (length < 2 || offset + length > data.length) return undefined;
      if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker) && length >= 7) {
        return { height: data.readUInt16BE(offset + 3), width: data.readUInt16BE(offset + 5) };
      }
      offset += length;
    }
    return undefined;
  }
  if (data.toString("ascii", 0, 4) !== "RIFF" || data.toString("ascii", 8, 12) !== "WEBP" || data.length < 20) return undefined;
  const chunk = data.toString("ascii", 12, 16);
  if (chunk === "VP8X" && data.length >= 30) {
    return {
      width: 1 + data[24] + (data[25] << 8) + (data[26] << 16),
      height: 1 + data[27] + (data[28] << 8) + (data[29] << 16),
    };
  }
  if (chunk === "VP8L" && data.length >= 25 && data[20] === 0x2f) {
    return {
      width: 1 + data[21] + ((data[22] & 0x3f) << 8),
      height: 1 + (data[22] >> 6) + (data[23] << 2) + ((data[24] & 0x0f) << 10),
    };
  }
  if (chunk === "VP8 " && data.length >= 30 && data[23] === 0x9d && data[24] === 0x01 && data[25] === 0x2a) {
    return { width: data.readUInt16LE(26) & 0x3fff, height: data.readUInt16LE(28) & 0x3fff };
  }
  return undefined;
}

const SAFE_LABEL = /^[A-Za-z0-9_.\[\]\/:-]{1,200}$/;
const label = (value: unknown, fallback: string) => typeof value === "string" && SAFE_LABEL.test(value) ? value : fallback;

function safeHits(findings: Finding[]): SafeHit[] {
  return findings.map(({ rule, name, kind, hash }) => ({ rule, ...(name !== undefined && { name }), kind, hash }));
}

export function createOcrWorker(options: OcrOptions, deps: { captureStore?: CaptureStore } = {}): OcrWorker {
  const concurrency = options.concurrency ?? 1;
  const timeoutMs = options.timeoutMs ?? 20_000;
  if (!Number.isInteger(concurrency) || concurrency < 1) throw new RangeError("OCR concurrency must be a positive integer");
  if (!Number.isFinite(timeoutMs) || timeoutMs < 1) throw new RangeError("OCR timeout must be positive");

  const detector = createDetector(options.detector);
  // Cache key includes a fingerprint of the detector config: findings never cross known lists, rules, or salts.
  const generation = createHash("sha256").update(JSON.stringify(options.detector, (_k, v) =>
    typeof v === "function" || v instanceof RegExp ? String(v) : v)).digest("hex").slice(0, 16);
  const key = (sha: string) => `${generation}:${sha}`;
  const captureStore = options.capture ? deps.captureStore || createCaptureStore(options.capture) : undefined;
  const stopSweeper = options.capture && captureStore && !deps.captureStore ? startSweeper(captureStore, 60 * 60 * 1000) : undefined;
  if (stopSweeper) void captureStore!.sweep();
  const queue: Work[] = [];
  const works = new Set<Work>();
  const inFlight = new Map<string, Work>();
  const submissions = new Set<Subscriber>();
  let active = 0;
  let pendingImages = 0;
  let pendingEncodedBytes = 0;
  let closed = false;
  let closePromise: Promise<void> | undefined;
  let resolveClose: (() => void) | undefined;

  function releaseAdmission(sub: Subscriber): void {
    if (!sub.admitted) return;
    sub.admitted = false;
    pendingImages--;
    pendingEncodedBytes -= sub.encodedBytes;
  }

  function resultFor(sub: Subscriber, fields: CachedFields, cache: OcrResult["cache"], queueMs: number): OcrResult {
    return {
      ...copyFields(fields),
      ...(sub.sha && { sha256: sub.sha }),
      source: `${sub.source}/ocr`,
      path: sub.path,
      cache,
      queueMs: Math.max(0, queueMs),
    };
  }

  function skipped(sub: Subscriber, reason: OcrReason, queueMs = Date.now() - sub.enqueuedAt): OcrResult {
    return resultFor(sub, { status: "skipped", reason, findings: [], chars: 0, ocrMs: 0 }, "none", queueMs);
  }

  function complete(sub: Subscriber, result: OcrResult): void {
    if (sub.completed) return;
    sub.completed = true;
    releaseAdmission(sub);
    submissions.delete(sub);
    try { sub.done(result); } catch { /* Caller callbacks cannot stop OCR work. */ }
  }

  function capture(sha: string, bytes: Buffer): void {
    if (!captureStore) return;
    void Promise.resolve().then(() => captureStore.put(sha, bytes)).catch(() => {});
  }

  function finishWork(work: Work, fields: CachedFields): void {
    active--;
    works.delete(work);
    if (inFlight.get(work.sha) === work) inFlight.delete(work.sha);
    if (!closed) {
      if (fields.status !== "failed") putCached(key(work.sha), fields);
      for (const sub of work.subscribers) {
        complete(sub, resultFor(sub, fields, sub.resultCache ?? "miss", work.startedAt - sub.enqueuedAt));
      }
    }
    work.subscribers.length = 0;
    pump();
  }

  function start(work: Work): void {
    active++;
    work.startedAt = Date.now();
    for (const sub of work.subscribers) releaseAdmission(sub);
    work.reaped = new Promise(resolve => { work.resolveReaped = resolve; });
    const bin = process.env.PII_GUARD_OCR_BIN_DIR ? join(process.env.PII_GUARD_OCR_BIN_DIR, "tesseract") : "tesseract";
    let child: ChildProcess;
    try {
      child = spawn(bin, ["stdin", "stdout", "-l", "eng", "--psm", "11", "tsv"], {
        env: { ...process.env, OMP_THREAD_LIMIT: "1" },
        stdio: ["pipe", "pipe", "ignore"],
      });
    } catch {
      finishWork(work, { status: "failed", reason: "engine_error", findings: [], chars: 0, ocrMs: Date.now() - work.startedAt });
      work.resolveReaped?.();
      return;
    }
    work.child = child;
    let outputBytes = 0;
    const chunks: Buffer[] = [];
    let failedReason: OcrReason | undefined;
    const timer = setTimeout(() => {
      if (!failedReason) failedReason = "timeout";
      child.kill("SIGKILL");
    }, timeoutMs);
    child.stdout?.on("data", (chunk: Buffer | string) => {
      if (failedReason) return;
      const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      if (outputBytes + bytes.length > MAX_STDOUT_BYTES) {
        failedReason = "output_limit";
        child.kill("SIGKILL");
        return;
      }
      outputBytes += bytes.length;
      chunks.push(bytes);
    });
    child.stdout?.on("error", () => {
      if (!failedReason) failedReason = "engine_error";
      child.kill("SIGKILL");
    });
    child.stdin?.on("error", () => {});
    child.on("error", () => { if (!failedReason) failedReason = "engine_error"; });
    child.on("close", code => {
      clearTimeout(timer);
      work.child = undefined;
      const ocrMs = Date.now() - work.startedAt;
      if (closed || work.forcedReason === "closed") {
        finishWork(work, { status: "skipped", reason: "closed", findings: [], chars: 0, ocrMs: 0 });
      } else if (failedReason) {
        finishWork(work, { status: "failed", reason: failedReason, findings: [], chars: 0, ocrMs });
      } else if (code !== 0) {
        finishWork(work, { status: "failed", reason: "engine_error", findings: [], chars: 0, ocrMs });
      } else {
        try {
          const parsed = parseTesseractTsv(Buffer.concat(chunks, outputBytes).toString("utf8"), detector);
          if (parsed.status === "failed" || parsed.status === "unsupported") throw Error("Unexpected parsed OCR status");
          const fields: CachedFields = {
            status: parsed.status,
            ...(parsed.status === "partial" && { reason: "low_confidence" as const }),
            findings: safeHits(parsed.findings),
            ...(parsed.meanConfidence !== undefined && { meanConfidence: parsed.meanConfidence }),
            chars: parsed.chars,
            ocrMs,
          };
          finishWork(work, fields);
        } catch {
          finishWork(work, { status: "failed", reason: "engine_error", findings: [], chars: 0, ocrMs });
        }
      }
      work.resolveReaped?.();
    });
    try { child.stdin?.end(work.bytes); }
    catch {
      failedReason = "engine_error";
      child.kill("SIGKILL");
    }
  }

  function pump(): void {
    if (closed) return;
    while (active < concurrency && queue.length) {
      const work = queue.shift()!;
      if (works.has(work)) start(work);
    }
  }

  function preflight(sub: Subscriber): void {
    if (sub.completed || closed) return;
    try {
      const encoded = /\s/.test(sub.data) ? sub.data.replace(/\s/g, "") : sub.data;
      if (!encoded || encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) {
        complete(sub, skipped(sub, "invalid_base64"));
        return;
      }
      if (encoded.length > Math.ceil(MAX_DECODED_BYTES / 3) * 4 + 4) {
        complete(sub, skipped(sub, "oversize"));
        return;
      }
      const bytes = Buffer.from(encoded, "base64");
      if (!bytes.length) {
        complete(sub, skipped(sub, "invalid_base64"));
        return;
      }
      if (bytes.length > MAX_DECODED_BYTES) {
        complete(sub, skipped(sub, "oversize"));
        return;
      }
      if (!isSupportedImage(bytes)) {
        complete(sub, skipped(sub, "unsupported"));
        return;
      }
      const sha = createHash("sha256").update(bytes).digest("hex");
      sub.sha = sha;
      capture(sha, bytes);
      const cached = getCached(key(sha));
      if (cached) {
        complete(sub, resultFor(sub, cached, "hit", Date.now() - sub.enqueuedAt));
        return;
      }
      const size = dimensions(bytes);
      if (size && size.width * size.height > MAX_PIXELS) {
        const fields: CachedFields = { status: "skipped", reason: "pixel_limit", findings: [], chars: 0, ocrMs: 0 };
        putCached(key(sha), fields);
        complete(sub, resultFor(sub, fields, "miss", Date.now() - sub.enqueuedAt));
        return;
      }
      const existing = inFlight.get(sha);
      if (existing) {
        if (existing.subscribers.length >= 64) {
          complete(sub, skipped(sub, "queue_full"));
          return;
        }
        sub.resultCache = "coalesced";
        sub.data = "";
        existing.subscribers.push(sub);
        releaseAdmission(sub);
        return;
      }
      sub.resultCache = "miss";
      sub.data = "";
      const work: Work = { sha, bytes, subscribers: [sub], startedAt: 0 };
      works.add(work);
      inFlight.set(sha, work);
      queue.push(work);
      pump();
    } catch {
      complete(sub, skipped(sub, "invalid_base64"));
    }
  }

  function enqueue(image: ImageInput, done: (result: OcrResult) => void): boolean {
    if (closed) return false;
    const data = typeof image?.data === "string" ? image.data : "";
    const encodedBytes = data.length;
    if (pendingImages >= MAX_PENDING_IMAGES || pendingEncodedBytes + encodedBytes > MAX_PENDING_ENCODED_BYTES) return false;
    const sub: Subscriber = {
      data,
      source: label(image?.source, "-"),
      path: label(image?.path, "-"),
      done,
      enqueuedAt: Date.now(),
      encodedBytes,
      admitted: true,
      completed: false,
    };
    pendingImages++;
    pendingEncodedBytes += encodedBytes;
    submissions.add(sub);
    setImmediate(() => preflight(sub));
    return true;
  }

  function scan(image: ImageInput): Promise<OcrResult> {
    return new Promise(resolve => {
      if (!enqueue(image, resolve)) {
        const data = typeof image?.data === "string" ? image.data : "";
        const sub: Subscriber = {
          data,
          source: label(image?.source, "-"),
          path: label(image?.path, "-"),
          done: resolve,
          enqueuedAt: Date.now(),
          encodedBytes: data.length,
          admitted: false,
          completed: false,
        };
        resolve(skipped(sub, closed ? "closed" : "queue_full", 0));
      }
    });
  }

  function close(): Promise<void> {
    if (closePromise) return closePromise;
    closePromise = new Promise(resolve => { resolveClose = resolve; });
    closed = true;
    stopSweeper?.();
    for (const sub of [...submissions]) complete(sub, skipped(sub, "closed"));
    pendingImages = 0;
    pendingEncodedBytes = 0;
    queue.length = 0;
    for (const work of [...works]) {
      if (inFlight.get(work.sha) === work) inFlight.delete(work.sha);
      work.subscribers.length = 0;
      if (work.child) {
        work.forcedReason = "closed";
        work.child.kill("SIGKILL");
      } else {
        works.delete(work);
      }
    }
    const activeReaps = [...works].map(work => work.reaped).filter((value): value is Promise<void> => !!value);
    void Promise.all(activeReaps).then(() => resolveClose?.());
    if (!activeReaps.length) resolveClose?.();
    return closePromise;
  }

  return { enqueue, scan, close };
}

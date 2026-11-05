// Offline observation only. OCR text stays inside this process.
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { scanBody, type ImageInput } from "./body.ts";
import type { Detector, Finding } from "./detector.ts";
import { scanOcrText, type OcrMode } from "./ocr-text.ts";

const MAX_BYTES = 20 * 1024 * 1024;
const MAX_PAGES = 10;
export interface MediaScan {
  status: "scanned" | "empty" | "unsupported" | "failed" | "partial";
  findings: Finding[];
  chars: number;
  pages: number;
  meanConfidence?: number;
}

export const ocrBin = (name: string) => process.env.PII_GUARD_OCR_BIN_DIR ? join(process.env.PII_GUARD_OCR_BIN_DIR, name) : name;

function command(name: string, args: string[], input?: Buffer): string | null {
  const r = spawnSync(ocrBin(name), args, { input, encoding: "utf8", timeout: 20_000, maxBuffer: 4 * 1024 * 1024, env: { ...process.env, OMP_THREAD_LIMIT: "1" } });
  return r.error || r.status !== 0 ? null : r.stdout;
}

/** Tesseract arguments per mode. Enhanced reads uniform text blocks (psm 6), which keeps long tokens whole. */
export const tesseractArgs = (mode: OcrMode = "enhanced") => ["stdin", "stdout", "-l", "eng", "--psm", mode === "enhanced" ? "6" : "11", "tsv"];
/** Enhanced pre-pass: grayscale, plus 2x bicubic upscale for images up to 1 MP. Larger (Retina) screenshots read worse when upscaled. */
export const FFMPEG_ARGS = ["-v", "error", "-nostdin", "-threads", "1", "-i", "pipe:0", "-vf", "format=rgba,split[a][b];[a]drawbox=c=white:t=fill:replace=1[bg];[bg][b]overlay=format=rgb,scale='if(lte(iw*ih,1000000),iw*2,iw)':-1:flags=bicubic,format=gray", "-frames:v", "1", "-f", "image2pipe", "-c:v", "png", "pipe:1"];
export const MAX_PREPROCESSED_BYTES = 64 * 1024 * 1024;

/** Returns the upscaled PNG, or the input unchanged when ffmpeg is missing or fails. */
function preprocess(data: Buffer): Buffer {
  const r = spawnSync(ocrBin("ffmpeg"), FFMPEG_ARGS, { input: data, timeout: 20_000, maxBuffer: MAX_PREPROCESSED_BYTES });
  return !r.error && r.status === 0 && r.stdout?.length && isSupportedImage(r.stdout) ? r.stdout : data;
}

export function isSupportedImage(data: Uint8Array): boolean {
  const bytes = Buffer.from(data.buffer, data.byteOffset, data.byteLength);
  return bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ||
    (bytes[0] === 0xff && bytes[1] === 0xd8 && bytes[2] === 0xff) ||
    (bytes.toString("ascii", 0, 4) === "RIFF" && bytes.toString("ascii", 8, 12) === "WEBP");
}

export function parseTesseractTsv(tsv: string, detector: Detector, mode: OcrMode = "enhanced"): MediaScan {
  const words = tsv.split("\n").slice(1).map(line => line.split("\t")).filter(row => row.length >= 12 && row[0] === "5" && row[11].trim());
  let previous = "", text = "", confidence = 0;
  for (const row of words) {
    const line = row.slice(1, 5).join("/");
    text += (text ? line === previous ? " " : "\n" : "") + row.slice(11).join("\t");
    previous = line;
    confidence += Number.isFinite(+row[10]) ? Math.max(0, +row[10]) : 0;
  }
  const meanConfidence = words.length ? Math.round(confidence / words.length) : 0;
  // ponytail: mean confidence below 60 flags review; use labeled documents to calibrate before enforcement.
  const status = !text ? "empty" : meanConfidence < 60 ? "partial" : "scanned";
  return { status, findings: scanOcrText(text, detector, mode), chars: text.length, pages: 1, meanConfidence };
}

export function scanImage(data: Buffer, detector: Detector, mode: OcrMode = "enhanced"): MediaScan {
  if (!data.length || data.length > MAX_BYTES || !isSupportedImage(data)) return { status: "unsupported", findings: [], chars: 0, pages: 0 };
  const tsv = command("tesseract", tesseractArgs(mode), mode === "enhanced" ? preprocess(data) : data);
  if (tsv === null) return { status: "failed", findings: [], chars: 0, pages: 0 };
  return parseTesseractTsv(tsv, detector, mode);
}

export function scanFile(path: string, detector: Detector, mode: OcrMode = "enhanced"): MediaScan {
  const file = resolve(path), stat = statSync(file);
  if (!stat.isFile() || stat.size > MAX_BYTES) throw Error("Unsupported file or size");
  const data = readFileSync(file);
  if (!data.subarray(0, 5).equals(Buffer.from("%PDF-"))) return scanImage(data, detector, mode);
  const info = command("pdfinfo", [file]);
  const count = Number(info?.match(/^Pages:\s+(\d+)/m)?.[1]);
  if (!Number.isSafeInteger(count) || count < 1) return { status: "failed", findings: [], chars: 0, pages: 0 };
  const pages = Math.min(count, MAX_PAGES);
  const dir = mkdtempSync(join(tmpdir(), "pii-ocr-"));
  try {
    // Always inspect pixels too: a PDF text layer can omit the sensitive image.
    const text = command("pdftotext", ["-f", "1", "-l", String(pages), "-layout", file, "-"]);
    const rendered = command("pdftoppm", ["-f", "1", "-l", String(pages), "-scale-to", "2200", "-png", file, join(dir, "page")]);
    const result: MediaScan = { status: count > MAX_PAGES ? "partial" : "scanned", findings: text ? scanOcrText(text, detector, mode) : [], chars: text?.length || 0, pages: 0 };
    if (rendered === null || text === null) result.status = "partial";
    for (const page of readdirSync(dir).filter(p => p.endsWith(".png")).sort()) {
      const scan = scanImage(readFileSync(join(dir, page)), detector, mode);
      result.findings.push(...scan.findings);
      result.chars += scan.chars;
      result.pages += scan.pages;
      if (scan.status !== "scanned") result.status = "partial";
    }
    if (result.pages !== pages) result.status = "partial";
    if (!result.pages && rendered === null && text === null) result.status = "failed";
    else if (!result.chars && result.status === "scanned") result.status = "empty";
    return result;
  } finally { rmSync(dir, { recursive: true, force: true }); }
}

export function scanBodyWithOcr(body: unknown, detector: Detector, mode: OcrMode = "enhanced") {
  const images: ImageInput[] = [];
  const result = scanBody(body, detector, image => images.push(image));
  const ocr = { scanned: 0, partial: 0, empty: 0, failed: 0, skipped: 0 };
  const cache = new Map<string, MediaScan>();
  let bytes = 0;
  for (const [index, image] of images.entries()) {
    // ponytail: bounded per-request cache; add a private bounded process cache before live OCR.
    if (!image.data || image.data.length > MAX_BYTES * 4 / 3 + 4 || index >= 8) { ocr.skipped++; continue; }
    const encoded = image.data.replace(/\s/g, "");
    if (encoded.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) { ocr.failed++; continue; }
    const data = Buffer.from(encoded, "base64");
    const key = createHash("sha256").update(data).digest("hex");
    let scan = cache.get(key);
    if (!scan) {
      bytes += data.length;
      if (bytes > MAX_BYTES) { ocr.skipped++; continue; }
      scan = scanImage(data, detector, mode);
      cache.set(key, scan);
    }
    if (scan.status === "scanned") { ocr.scanned++; result.unscanned.images--; }
    else if (scan.status === "partial") ocr.partial++;
    else if (scan.status === "empty") ocr.empty++;
    else if (scan.status === "failed") ocr.failed++;
    else ocr.skipped++;
    result.chars += scan.chars;
    result.findings.push(...scan.findings.map(f => ({ ...f, source: `${image.source}/ocr`, path: image.path })));
  }
  return { ...result, ocr };
}

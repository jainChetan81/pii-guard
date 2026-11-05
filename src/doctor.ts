// Reports which local OCR tools exist, so a host can tell what it must install. Nothing is downloaded.
import { spawnSync } from "node:child_process";
import { ocrBin } from "./media.ts";
import type { OcrMode } from "./ocr-text.ts";

export interface ToolStatus { name: string; found: boolean; version?: string; neededFor: string; install: string }
export interface DoctorReport { tools: ToolStatus[]; languages: string[]; modes: Record<OcrMode, boolean>; pdf: boolean }

const TOOLS: Array<[name: string, args: string[], neededFor: string, install: string]> = [
  ["tesseract", ["--version"], "all image OCR", "apt install tesseract-ocr tesseract-ocr-eng | brew install tesseract"],
  ["ffmpeg", ["-hide_banner", "-version"], "enhanced mode (falls back to basic preprocessing without it)", "apt install ffmpeg | brew install ffmpeg"],
  ["pdfinfo", ["-v"], "PDF scans", "apt install poppler-utils | brew install poppler"],
  ["pdftotext", ["-v"], "PDF scans", "apt install poppler-utils | brew install poppler"],
  ["pdftoppm", ["-v"], "PDF scans", "apt install poppler-utils | brew install poppler"],
];

function probe(name: string, args: string[]): { found: boolean; version?: string } {
  const r = spawnSync(ocrBin(name), args, { encoding: "utf8", timeout: 5000 });
  if (r.error) return { found: false };
  const line = `${r.stdout || ""}\n${r.stderr || ""}`.split("\n").map(l => l.trim()).find(Boolean);
  return { found: true, ...(line && { version: line.slice(0, 80) }) };
}

export function doctor(): DoctorReport {
  const tools = TOOLS.map(([name, args, neededFor, install]) => ({ name, ...probe(name, args), neededFor, install }));
  const langs = spawnSync(ocrBin("tesseract"), ["--list-langs"], { encoding: "utf8", timeout: 5000 });
  const languages = langs.error ? [] : `${langs.stdout}`.split("\n").slice(1).map(l => l.trim()).filter(Boolean);
  const has = (n: string) => tools.find(t => t.name === n)!.found;
  const basic = has("tesseract") && languages.includes("eng");
  return { tools, languages, modes: { basic, enhanced: basic && has("ffmpeg") }, pdf: basic && has("pdfinfo") && has("pdftotext") && has("pdftoppm") };
}

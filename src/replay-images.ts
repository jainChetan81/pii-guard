import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { readFile, readdir } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { Detector } from "./detector.ts";
import { isSupportedImage, scanImage } from "./media.ts";
import type { OcrMode } from "./ocr-text.ts";

type Counts = { tp: number; fp: number; fn: number; precision: number | null; recall: number | null };
export interface ReplayReport {
  total: number; ignored: number; statusCounts: Record<string, number>; imagesWithHits: number; hitRate: number;
  perRule: Record<string, number>; latencyMs: { p50: number; p95: number; max: number };
  childCpuMs: number; accuracy: "unknown" | { overall: Counts; perRule: Record<string, Counts> };
}

export async function replayImages(opts: { folder: string; detector: Detector; labels?: Record<string, Array<string | { rule: string; hash?: string }>>; mode?: OcrMode }): Promise<ReplayReport> {
  const ticks = Number(spawnSync("getconf", ["CLK_TCK"], { encoding: "utf8" }).stdout);
  if (!Number.isFinite(ticks) || ticks <= 0) throw Error("Cannot determine CPU clock ticks");
  const childCpu = () => { const stat = readFileSync("/proc/self/stat", "utf8").split(") ").pop()!.split(" "); return (+stat[13] + +stat[14]) * 1000 / ticks; };
  const startCpu = childCpu(), latency: number[] = [];
  const report: ReplayReport = { total: 0, ignored: 0, statusCounts: Object.create(null), imagesWithHits: 0, hitRate: 0, perRule: Object.create(null), latencyMs: { p50: 0, p95: 0, max: 0 }, childCpuMs: 0, accuracy: "unknown" };
  const counts: Record<string, Counts> = Object.create(null);
  const count = (rule: string) => counts[rule] ??= { tp: 0, fp: 0, fn: 0, precision: null, recall: null };
  for (const entry of await readdir(opts.folder, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const data = await readFile(join(opts.folder, entry.name));
    if (!isSupportedImage(data)) { report.ignored++; continue; } // labels.json, notes, other files
    const hash = createHash("sha256").update(data).digest("hex"), start = performance.now();
    const result = scanImage(data, opts.detector, opts.mode);
    latency.push(performance.now() - start); report.total++;
    report.statusCounts[result.status] = (report.statusCounts[result.status] || 0) + 1;
    if (result.findings.length) report.imagesWithHits++;
    for (const hit of result.findings) report.perRule[hit.rule] = (report.perRule[hit.rule] || 0) + 1;
    if (opts.labels) {
      const remaining = [...result.findings];
      // Match specific hashes first, then rule-only labels.
      // Labels key by sha256 or by file name; reports never include either.
      const expected = (opts.labels[hash] || opts.labels[entry.name] || []).map(l => typeof l === "string" ? { rule: l } : l).sort((a, b) => Number(!!b.hash) - Number(!!a.hash));
      for (const label of expected) {
        const index = remaining.findIndex(hit => hit.rule === label.rule && (!label.hash || hit.hash === label.hash));
        if (index < 0) count(label.rule).fn++;
        else { count(label.rule).tp++; remaining.splice(index, 1); }
      }
      for (const hit of remaining) count(hit.rule).fp++;
    }
  }
  report.childCpuMs = childCpu() - startCpu;
  report.hitRate = report.total ? report.imagesWithHits / report.total : 0;
  latency.sort((a, b) => a - b);
  const percentile = (p: number) => latency[Math.ceil(latency.length * p) - 1] ?? 0;
  report.latencyMs = { p50: percentile(0.5), p95: percentile(0.95), max: percentile(1) };
  if (opts.labels) {
    const overall: Counts = { tp: 0, fp: 0, fn: 0, precision: null, recall: null };
    const finish = (c: Counts) => { c.precision = c.tp + c.fp ? c.tp / (c.tp + c.fp) : null; c.recall = c.tp + c.fn ? c.tp / (c.tp + c.fn) : null; };
    for (const c of Object.values(counts)) { overall.tp += c.tp; overall.fp += c.fp; overall.fn += c.fn; finish(c); }
    finish(overall); report.accuracy = { overall, perRule: counts };
  }
  return report;
}

export function formatReport(report: ReplayReport): string { return JSON.stringify(report, null, 2); }

import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { createDetector } from "../../src/detector.ts";
import { ocrBin, scanImage } from "../../src/ocr/media.ts";
import { replayImages } from "../../src/ocr/replay-images.ts";

const available = ["tesseract", "ffmpeg"].every(name => spawnSync(ocrBin(name), [name === "tesseract" ? "--version" : "-version"], { stdio: "ignore" }).status === 0);
const folder = join(import.meta.dir, "../fixtures/ocr-corpus");
const labels = JSON.parse(readFileSync(join(folder, "labels.json"), "utf8")) as Record<string, Array<string | { rule: string }>>;

test.skipIf(!available)("enhanced corpus accuracy exceeds basic and clean images stay clean", async () => {
  const detector = createDetector({ salt: "corpus-test" });
  const enhanced = await replayImages({ folder, detector, labels, mode: "enhanced" });
  const basic = await replayImages({ folder, detector, labels, mode: "basic" });
  expect(enhanced.accuracy).not.toBe("unknown");
  expect(basic.accuracy).not.toBe("unknown");
  if (enhanced.accuracy === "unknown" || basic.accuracy === "unknown") throw Error("Missing accuracy");
  expect(enhanced.accuracy.overall.precision).toBe(1);
  expect(enhanced.accuracy.overall.recall!).toBeGreaterThanOrEqual(0.95);
  // Current corpus: basic 27/37, enhanced 37/37.
  expect(basic.accuracy.overall.recall!).toBeLessThan(enhanced.accuracy.overall.recall!);
  expect(enhanced.ignored).toBeGreaterThanOrEqual(1);
  for (const [name, entries] of Object.entries(labels)) {
    if (entries.length) continue;
    const data = readFileSync(join(folder, name));
    expect(scanImage(data, detector, "enhanced").findings).toEqual([]);
  }
}, 60_000);

// Holdout: different fonts, themes, and seed; generated after tuning on ocr-corpus.
// Current: basic 26/42, enhanced 40/42. Extra hits (both modes) are only assigned_secret on KEY=value lines,
// which is a correct second label for the same secret, not a false alarm.
test.skipIf(!available)("enhanced mode generalizes to the holdout set", async () => {
  const holdout = join(import.meta.dir, "../fixtures/ocr-holdout");
  const holdoutLabels = JSON.parse(readFileSync(join(holdout, "labels.json"), "utf8"));
  const detector = createDetector({ salt: "holdout-test" });
  const r = await replayImages({ folder: holdout, detector, labels: holdoutLabels, mode: "enhanced" });
  if (r.accuracy === "unknown") throw Error("Missing accuracy");
  expect(r.accuracy.overall.recall!).toBeGreaterThanOrEqual(0.9);
  for (const [rule, c] of Object.entries(r.accuracy.perRule)) if (rule !== "assigned_secret") expect([rule, c.fp]).toEqual([rule, 0]);
  for (const [name, entries] of Object.entries(holdoutLabels as Record<string, string[]>)) {
    if (!entries.length) expect(scanImage(readFileSync(join(holdout, name)), detector, "enhanced").findings).toEqual([]);
  }
}, 60_000);

test.skipIf(!available)("scan --file honours --ocr-mode for images", () => {
  const file = join(folder, "07_heading.png"), cli = join(import.meta.dir, "../../bin/pii-guard.ts");
  const run = (mode: string) => spawnSync("bun", [cli, "scan", "--file", file, "--ocr-mode", mode, "--home", tmpdir()], { encoding: "utf8" }).stdout;
  expect(run("basic")).not.toContain("vehicle_in");
  expect(run("enhanced")).toContain("vehicle_in");
}, 30_000);

test.skipIf(!available)("enhanced reads dark text on a transparent background", () => {
  const data = readFileSync(join(import.meta.dir, "../fixtures/ocr-transparent.png"));
  const detector = createDetector({ salt: "alpha-test" });
  expect(scanImage(data, detector, "enhanced").findings.map(f => f.rule)).toContain("email");
});

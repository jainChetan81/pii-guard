import { expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDetector } from "../src/detector.ts";
import { replayImages, formatReport } from "../src/replay-images.ts";

test("replay computes labeled and unlabeled metrics without exposing content", async () => {
  const root = await mkdtemp(join(tmpdir(), "replay-test-")), folder = join(root, "images"), bin = join(root, "bin");
  const previous = process.env.PII_GUARD_OCR_BIN_DIR;
  try {
    await mkdir(folder); await mkdir(bin);
    await writeFile(join(bin, "tesseract"), "#!/bin/sh\nprintf 'header\\n5\\t1\\t1\\t1\\t1\\t0\\t0\\t0\\t0\\t0\\t95\\talice@private.test\\n'\n", { mode: 0o755 });
    process.env.PII_GUARD_OCR_BIN_DIR = bin;
    const data = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);
    await writeFile(join(folder, "secret-filename.png"), data);
    await symlink(join(folder, "secret-filename.png"), join(folder, "link.png"));
    const hash = createHash("sha256").update(data).digest("hex"), detector = createDetector({ salt: "test" });
    const unknown = await replayImages({ folder, detector });
    expect(unknown.accuracy).toBe("unknown"); expect(unknown.total).toBe(1); expect(unknown.imagesWithHits).toBe(1);
    const report = await replayImages({ folder, detector, labels: { [hash]: [{ rule: "email" }, { rule: "pan" }] } });
    expect(report.accuracy).toEqual({ overall: { tp: 1, fp: 0, fn: 1, precision: 1, recall: 0.5 }, perRule: { email: { tp: 1, fp: 0, fn: 0, precision: 1, recall: 1 }, pan: { tp: 0, fp: 0, fn: 1, precision: null, recall: 0 } } });
    const output = formatReport(report); expect(output).not.toContain("secret-filename"); expect(output).not.toContain("alice@private.test");
  } finally {
    if (previous === undefined) delete process.env.PII_GUARD_OCR_BIN_DIR; else process.env.PII_GUARD_OCR_BIN_DIR = previous;
    await rm(root, { recursive: true, force: true });
  }
});

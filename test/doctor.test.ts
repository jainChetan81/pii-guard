import { expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { doctor } from "../src/ocr/doctor.ts";

test("doctor reports unavailable enhanced and PDF tools", () => {
  const dir = mkdtempSync(join(tmpdir(), "pii-doctor-"));
  const previous = process.env.PII_GUARD_OCR_BIN_DIR;
  try {
    writeFileSync(join(dir, "tesseract"), '#!/bin/sh\nif [ "$1" = "--list-langs" ]; then printf "List of available languages (1):\\neng\\n"; else echo tesseract; fi\n', { mode: 0o700 });
    process.env.PII_GUARD_OCR_BIN_DIR = dir;
    const report = doctor();
    expect(report.modes).toEqual({ basic: true, enhanced: false });
    expect(report.pdf).toBe(false);
    expect(report.languages).toContain("eng");
    expect(report.tools.find(t => t.name === "ffmpeg")).toMatchObject({ found: false, install: expect.stringContaining("ffmpeg") });
  } finally {
    if (previous === undefined) delete process.env.PII_GUARD_OCR_BIN_DIR; else process.env.PII_GUARD_OCR_BIN_DIR = previous;
    rmSync(dir, { recursive: true, force: true });
  }
});

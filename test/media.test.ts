import { expect, test } from "bun:test";
import { readFileSync, mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import { spawnSync } from "node:child_process";
import { createDetector } from "../src/detector.ts";
import { ocrImage, scanBodyWithOcr, scanFile, scanImage } from "../src/media.ts";

const binary = (name: string) => process.env.PII_GUARD_OCR_BIN_DIR ? join(process.env.PII_GUARD_OCR_BIN_DIR, name) : name;
const hasOcr = spawnSync(binary("tesseract"), ["--version"]).status === 0;
const hasPdf = spawnSync(binary("pdftoppm"), ["-v"]).status === 0;
const image = readFileSync(join(import.meta.dir, "fixtures/presidio-ocr.png"));
const d = createDetector({ known: [
  { name: "sample.person", value: "David Johnson" },
  { name: "sample.phone", value: "(212) 555-1234" },
  { name: "sample.email", value: "opencode@microsoft.com" },
] });

test.skipIf(!hasOcr)("public image finds known values without returning raw OCR", () => {
  const r = scanImage(image, d);
  expect(r.status).toBe("scanned");
  expect(new Set(r.findings.map(f => f.name)).size).toBe(3);
  expect(JSON.stringify(r)).not.toContain("David Johnson");
});

test.skipIf(!hasOcr)("OCR covers Anthropic, Chat, Responses, and Gemini image envelopes", () => {
  const data = image.toString("base64");
  const body = { messages: [{ role: "user", content: [
    { type: "image", source: { type: "base64", media_type: "image/png", data } },
    { type: "image_url", image_url: { url: `data:image/png;base64,${data}` } },
    { type: "input_image", image_url: `data:image/png;base64,${data}` },
    { inlineData: { mimeType: "image/png", data } },
  ] }] };
  const before = JSON.stringify(body), r = scanBodyWithOcr(body, d);
  expect(r.ocr).toEqual({ scanned: 4, partial: 0, empty: 0, skipped: 0, failed: 0 });
  expect(r.unscanned.images).toBe(0);
  expect(r.findings).toHaveLength(12);
  expect(JSON.stringify(body)).toBe(before);
});

test("unsupported media and remote references never look scanned", () => {
  expect(scanImage(Buffer.from("not an image"), d).status).toBe("unsupported");
  const r = scanBodyWithOcr({ input: [
    { type: "input_image", image_url: "http://127.0.0.1/private" },
    { type: "input_image", image_url: "data:image/png;base64,invalid!" },
    { type: "input_image", file_id: "file-123" },
  ] }, d);
  expect(r.ocr).toEqual({ scanned: 0, partial: 0, empty: 0, skipped: 2, failed: 1 });
  expect(r.unscanned.images).toBe(3);
});

test("failed PDF tools and weak OCR do not look like complete scans", () => {
  const dir = mkdtempSync(join(tmpdir(), "pii-media-test-"));
  const prior = process.env.PII_GUARD_OCR_BIN_DIR;
  try {
    process.env.PII_GUARD_OCR_BIN_DIR = dir;
    writeFileSync(join(dir, "pdfinfo"), '#!/bin/sh\nprintf "Pages: 1\\n"\n', { mode: 0o700 });
    for (const name of ["pdftotext", "pdftoppm"]) writeFileSync(join(dir, name), '#!/bin/sh\nexit 1\n', { mode: 0o700 });
    const file = join(dir, "synthetic.pdf"); writeFileSync(file, "%PDF-1.4\n");
    expect(scanFile(file, d).status).toBe("failed");
    writeFileSync(join(dir, "tesseract"), '#!/bin/sh\nprintf "level\\tpage\\tblock\\tpar\\tline\\tword\\tleft\\ttop\\twidth\\theight\\tconf\\ttext\\n5\\t1\\t1\\t1\\t1\\t1\\t0\\t0\\t10\\t10\\t12\\tgarbled\\n"\n', { mode: 0o700 });
    expect(scanImage(image, d).status).toBe("partial");
    const r=scanBodyWithOcr({type:"input_image",image_url:`data:image/png;base64,${image.toString("base64")}`},d);
    expect(r.ocr.partial).toBe(1);
    expect(r.unscanned.images).toBe(1);
  } finally {
    if (prior === undefined) delete process.env.PII_GUARD_OCR_BIN_DIR; else process.env.PII_GUARD_OCR_BIN_DIR = prior;
    rmSync(dir, { recursive: true, force: true });
  }
});

function pdf(text: string): Buffer {
  const stream = `BT /F1 24 Tf 50 750 Td ${text.split("\n").map(line => `(${line}) Tj 0 -40 Td`).join(" ")} ET`;
  const objects = [
    "<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
    "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
    "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", `<< /Length ${stream.length} >>\nstream\n${stream}\nendstream`,
  ];
  let out = "%PDF-1.4\n";
  const offsets = [0];
  objects.forEach((obj, i) => { offsets.push(out.length); out += `${i + 1} 0 obj\n${obj}\nendobj\n`; });
  const xref = out.length;
  out += `xref\n0 6\n0000000000 65535 f \n${offsets.slice(1).map(n => `${String(n).padStart(10, "0")} 00000 n \n`).join("")}trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return Buffer.from(out);
}

test.skipIf(!hasOcr || !hasPdf)("PDF text and rasterized page both detect synthetic India IDs", () => {
  const dir = mkdtempSync(join(tmpdir(), "pii-pdf-test-"));
  try {
    const file = join(dir, "synthetic.pdf");
    writeFileSync(file, pdf("PAN: ABCPE1234F\nRegistration: KA22MN5678"));
    const r = scanFile(file, createDetector());
    expect(r.status).toBe("scanned");
    expect(r.pages).toBe(1);
    expect(r.findings.filter(f => f.rule === "pan").length).toBeGreaterThanOrEqual(2);
    expect(r.findings.filter(f => f.rule === "vehicle_in").length).toBeGreaterThanOrEqual(2);
    expect(JSON.stringify(r)).not.toContain("ABCPE1234F");
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test.skipIf(!hasOcr)("ocrImage returns text and matches for a test UI", async () => {
  const r = await ocrImage(image, d);
  expect(r.status).toBe("scanned");
  expect(r.text).toContain("David Johnson");
  const person = r.findings.find(f => f.name === "sample.person");
  expect(person?.match).toBe("David Johnson");
  expect(r.ocrMs).toBeGreaterThan(0);
  expect((await ocrImage(Buffer.from("not an image"), d)).status).toBe("unsupported");
  const basic = await ocrImage(image, d, "basic");
  expect(basic.mode).toBe("basic");
  expect(basic.findings.length).toBeGreaterThan(0);
});

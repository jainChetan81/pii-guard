import { afterAll, beforeAll, expect, test } from "bun:test";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { AddressInfo } from "node:net";
import { createScanServer, listen } from "../src/server.ts";

const header = "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n";
const tsv = `${header}5\t1\t1\t1\t1\t1\t0\t0\t10\t10\t95\tDavid Johnson\n`;
const png = Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10, 0, 0, 0, 13]), Buffer.from("IHDR"), Buffer.from([0, 0, 0, 9, 0, 0, 0, 9, 8, 2, 0, 0, 0, 7])]);
const known = { salt: "server-test-salt", known: [{ name: "sample.person", value: "David Johnson" }] };
const dir = mkdtempSync(join(tmpdir(), "pii-server-test-")), previous = process.env.PII_GUARD_OCR_BIN_DIR;
const server = createScanServer({ detector: known, token: "t0ken" });
let base = "";
const auth = { authorization: "Bearer t0ken" };

beforeAll(async () => {
  writeFileSync(join(dir, "tesseract"), `#!/bin/sh\ncat >/dev/null\nprintf '%s' '${tsv}'\n`, { mode: 0o700 });
  process.env.PII_GUARD_OCR_BIN_DIR = dir;
  await listen(server, "127.0.0.1", 0);
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});
afterAll(() => {
  server.close();
  rmSync(dir, { recursive: true, force: true });
  if (previous === undefined) delete process.env.PII_GUARD_OCR_BIN_DIR; else process.env.PII_GUARD_OCR_BIN_DIR = previous;
});

test("rejects missing token and refuses public bind without one", async () => {
  expect((await fetch(`${base}/health`)).status).toBe(401);
  expect(listen(createScanServer({ detector: known }), "0.0.0.0", 0)).rejects.toThrow("PII_GUARD_TOKEN");
  expect(listen(createScanServer({ detector: known, token: "" }), "0.0.0.0", 0)).rejects.toThrow("PII_GUARD_TOKEN");
});

test("POST /scan returns text and OCR hits as hashes only", async () => {
  const body = { messages: [{ role: "user", content: [
    { type: "text", text: "call David Johnson" },
    { type: "image", source: { type: "base64", media_type: "image/png", data: png.toString("base64") } },
  ] }] };
  const res = await fetch(`${base}/scan`, { method: "POST", headers: auth, body: JSON.stringify({ body }) });
  expect(res.status).toBe(200);
  const raw = await res.text(), json = JSON.parse(raw);
  expect(json.text.findings[0].name).toBe("sample.person");
  expect(json.ocr[0].status).toBe("scanned");
  expect(json.ocr[0].source).toEndWith("/ocr");
  expect(json.ocr[0].findings[0].name).toBe("sample.person");
  expect(raw).not.toContain("David Johnson");
});

test("POST /scan/image maps errors to status codes", async () => {
  expect((await fetch(`${base}/scan/image`, { method: "POST", headers: auth, body: png })).status).toBe(200);
  expect((await fetch(`${base}/scan/image`, { method: "POST", headers: auth, body: "not an image" })).status).toBe(415);
  expect((await fetch(`${base}/scan`, { method: "POST", headers: auth, body: "{" })).status).toBe(400);
  expect((await fetch(`${base}/scan/image`, { method: "POST", headers: auth, body: Buffer.alloc(21 * 1024 * 1024, 1) })).status).toBe(413);
  expect((await fetch(`${base}/nope`, { method: "POST", headers: auth })).status).toBe(404);
});

import { expect, test } from "bun:test";
import { spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { tmpdir } from "node:os";
import type { KnownCategory } from "../../src/detector.ts";
import { __resetOcrCacheForTests, createOcrWorker } from "../../src/ocr/worker.ts";
import type { ImageInput } from "../../src/ocr/contract.ts";

const header = "level\tpage\tblock\tpar\tline\tword\tleft\ttop\twidth\theight\tconf\ttext\n";
const tsv = `${header}5\t1\t1\t1\t1\t1\t0\t0\t10\t10\t95\tDavid Johnson\n`;
const imageData = (id: number, width = 100, height = 100) => {
  const data = Buffer.alloc(33);
  Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]).copy(data);
  data.writeUInt32BE(13, 8);
  data.write("IHDR", 12, 4, "ascii");
  data.writeUInt32BE(width, 16);
  data.writeUInt32BE(height, 20);
  data[24] = 8;
  data[25] = 2;
  data.writeUInt32BE(id, 29);
  return data.toString("base64");
};
const image = (id: number, width?: number, height?: number): ImageInput => ({
  data: imageData(id, width, height), mime: "image/png", source: "user/image", path: "messages[0].content[0]",
});
const shellQuote = (value: string) => `'${value.replace(/'/g, `'\\''`)}'`;

async function withFake(script: string, run: (dir: string) => Promise<void>): Promise<void> {
  const dir = mkdtempSync(join(tmpdir(), "pii-ocr-worker-test-"));
  const previous = process.env.PII_GUARD_OCR_BIN_DIR;
  writeFileSync(join(dir, "tesseract"), `#!/bin/sh\n${script}\n`, { mode: 0o700 });
  process.env.PII_GUARD_OCR_BIN_DIR = dir;
  try { await run(dir); }
  finally {
    if (previous === undefined) delete process.env.PII_GUARD_OCR_BIN_DIR;
    else process.env.PII_GUARD_OCR_BIN_DIR = previous;
    rmSync(dir, { recursive: true, force: true });
  }
}

const printTsv = `cat >/dev/null\nprintf '%s' ${shellQuote(tsv)}`;
const worker = (extra: { concurrency?: number; timeoutMs?: number; capture?: { dir: string; maxBytes: number; ttlMs: number } } = {}) => createOcrWorker({ detector: { salt: "worker-test-salt", known: [{ name: "sample.person", value: "David Johnson" }] }, ...extra });

test("cache crosses worker calls and results contain safe hits only", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const firstWorker = worker();
    const first = await firstWorker.scan(image(1));
    await firstWorker.close();
    const secondWorker = worker();
    const second = await secondWorker.scan(image(1));
    await secondWorker.close();
    expect(first.cache).toBe("miss");
    expect(second.cache).toBe("hit");
    expect(first.source).toBe("user/image/ocr");
    expect(first.path).toBe("messages[*].content[*]");
    expect(first.findings).toEqual([{ rule: "known", name: "sample.person", kind: "known", hash: expect.any(String) }]);
    expect(JSON.stringify(first)).not.toContain("David Johnson");
    expect(first.sha256).toMatch(/^[0-9a-f]{64}$/);
  });
});

test("capture stores decoded bytes once per unique image", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const puts: string[] = [];
    const w = createOcrWorker({ detector: { salt: "worker-test-salt" }, capture: { dir: "unused", maxBytes: 1024, ttlMs: 1000 } }, {
      captureStore: { put: async sha => { puts.push(sha); }, sweep: async () => ({ files: 0, bytes: 0, removed: 0 }) },
    });
    await w.scan(image(18));
    await w.scan(image(18));
    await w.close();
    expect(puts).toHaveLength(1);
    expect(puts[0]).toMatch(/^[0-9a-f]{64}$/);
  });
});

test("low mean confidence returns partial with low_confidence reason", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv.replace("\t95\t", "\t12\t"), async () => {
    const w = worker();
    const result = await w.scan(image(19));
    await w.close();
    expect(result).toMatchObject({ status: "partial", reason: "low_confidence", meanConfidence: 12 });
  });
});

test("same image in flight coalesces subscribers", async () => {
  __resetOcrCacheForTests();
  await withFake(`sleep 0.15\n${printTsv}`, async () => {
    const w = worker();
    const [first, second] = await Promise.all([w.scan(image(2)), w.scan(image(2))]);
    await w.close();
    expect(first.cache).toBe("miss");
    expect(second.cache).toBe("coalesced");
    expect(first.findings).toEqual(second.findings);
  });
});

test("LRU evicts oldest image", async () => {
  __resetOcrCacheForTests(2);
  try {
    await withFake(printTsv, async () => {
      const w = worker();
      await w.scan(image(3));
      await w.scan(image(4));
      await w.scan(image(5));
      expect((await w.scan(image(3))).cache).toBe("miss");
      await w.close();
    });
  } finally { __resetOcrCacheForTests(); }
});

test("timeout kills and reaps tesseract", async () => {
  __resetOcrCacheForTests();
  await withFake("exec sleep 5", async () => {
    const w = worker({ timeoutMs: 50 });
    const result = await w.scan(image(6));
    const repeated = await w.scan(image(6));
    await w.close();
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("timeout");
    expect(result.cache).toBe("miss");
    expect(repeated.reason).toBe("timeout");
    expect(repeated.cache).toBe("miss");
  });
});

test("stdout over four MiB fails without retaining output", async () => {
  __resetOcrCacheForTests();
  await withFake("exec head -c 5000000 /dev/zero", async () => {
    const w = worker({ timeoutMs: 5000 });
    const result = await w.scan(image(7));
    await w.close();
    expect(result.status).toBe("failed");
    expect(result.reason).toBe("output_limit");
    expect(JSON.stringify(result)).not.toContain("David Johnson");
  });
});

test("malformed base64 and unsupported images are skipped", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const w = worker();
    const malformed = await w.scan({ ...image(8), data: "%%%" });
    const unsupported = await w.scan({ ...image(9), data: Buffer.from("not an image").toString("base64") });
    await w.close();
    expect(malformed).toMatchObject({ status: "skipped", reason: "invalid_base64" });
    expect(unsupported).toMatchObject({ status: "skipped", reason: "unsupported" });
  });
});

test("cache hits and duplicates skip the queue; unique misses past 32 report queue_full", async () => {
  __resetOcrCacheForTests();
  await withFake(`sleep 0.1\n${printTsv}`, async () => {
    const w = worker();
    // 40 copies of one image coalesce into one OCR run; none overflow.
    const same = await Promise.all(Array.from({ length: 40 }, () => w.scan(image(10))));
    expect(same.filter(r => r.reason === "queue_full")).toHaveLength(0);
    // Cached now: a later burst never touches the queue.
    expect((await w.scan(image(10))).cache).toBe("hit");
    // 40 unique misses: one runs, 32 wait, the rest overflow.
    const unique = await Promise.all(Array.from({ length: 40 }, (_, i) => w.scan(image(100 + i))));
    const full = unique.filter(r => r.reason === "queue_full").length;
    expect(full).toBeGreaterThan(0);
    expect(full).toBeLessThanOrEqual(8);
    const large = { ...image(11), data: "A".repeat(17 * 1024 * 1024) };
    expect(w.enqueue(large, () => {})).toBe(true);
    expect(w.enqueue(large, () => {})).toBe(false);
    await w.close();
  });
});

test("close completes pending work, rejects new scans, and kills active child", async () => {
  __resetOcrCacheForTests();
  await withFake("", async dir => {
    const marker = join(dir, "started");
    writeFileSync(join(dir, "tesseract"), `#!/bin/sh\necho started > ${shellQuote(marker)}\nexec sleep 5\n`, { mode: 0o700 });
    const w = worker();
    const pending = w.scan(image(12));
    for (let i = 0; i < 100 && !existsSync(marker); i++) await new Promise(resolve => setTimeout(resolve, 10));
    expect(existsSync(marker)).toBe(true);
    const closing = w.close();
    const result = await pending;
    await closing;
    expect(result).toMatchObject({ status: "skipped", reason: "closed" });
    expect((await w.scan(image(13))).reason).toBe("closed");
  });
});

test("throwing callback does not stop worker", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const w = worker();
    let called = false;
    expect(w.enqueue(image(14), () => { called = true; throw Error("callback failure"); })).toBe(true);
    const result = await w.scan(image(15));
    await w.close();
    expect(called).toBe(true);
    expect(result.status).toBe("scanned");
  });
});

test("pixel limit rejects dimensions read from PNG header", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const w = worker();
    const result = await w.scan(image(16, 5001, 5000));
    await w.close();
    expect(result).toMatchObject({ status: "skipped", reason: "pixel_limit" });
  });
});

test("event loop timer fires while tesseract runs", async () => {
  __resetOcrCacheForTests();
  await withFake(`sleep 0.2\n${printTsv}`, async () => {
    const w = worker();
    let fired = false;
    setTimeout(() => { fired = true; }, 20);
    const result = await w.scan(image(17));
    await w.close();
    expect(fired).toBe(true);
    expect(result.status).toBe("scanned");
  });
});

const tesseract = process.env.PII_GUARD_OCR_BIN_DIR ? join(process.env.PII_GUARD_OCR_BIN_DIR, "tesseract") : "tesseract";
const hasOcr = spawnSync(tesseract, ["--version"], { stdio: "ignore" }).status === 0;
test.skipIf(!hasOcr)("real tesseract scans the public fixture", async () => {
  const data = readFileSync(join(import.meta.dir, "../fixtures/presidio-ocr.png"));
  const w = createOcrWorker({ detector: {
    salt: "real-ocr-test",
    known: [
      { name: "sample.person", value: "David Johnson" },
      { name: "sample.phone", value: "(212) 555-1234" },
      { name: "sample.email", value: "opencode@microsoft.com" },
    ],
  } });
  const result = await w.scan({ data: data.toString("base64"), mime: "image/png", source: "user/image", path: "fixture" });
  await w.close();
  expect(result.status).toBe("scanned");
  expect(new Set(result.findings.map(hit => hit.name)).size).toBe(3);
  expect(JSON.stringify(result)).not.toContain("David Johnson");
});

test("cache never crosses detector generations and unsafe labels are replaced", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const a = worker(), first = await a.scan(image(42));
    await a.close();
    const b = createOcrWorker({ detector: { salt: "other-salt", known: [] } });
    const second = await b.scan({ ...image(42), source: "Alice/9876543210", path: "messages[0].Alice" });
    const indexed = await b.scan({ ...image(46), path: "messages[9876543210].content[1]" });
    const spaced = await b.scan({ ...image(47), data: imageData(47).replace(/(.{7})/g, "$1\n") });
    await b.close();
    const k = (category?: KnownCategory) => createOcrWorker({ detector: { salt: "s", known: [{ name: "n", value: "AB12CD", ...(category && { category }) }] } });
    const e = k(), f = k("id");
    expect((await e.scan(image(49))).cache).toBe("miss");
    expect((await f.scan(image(49))).cache).toBe("miss"); // category changes matching
    await e.close(); await f.close();
    // Names with separators must not let two lists serialize alike.
    const g = createOcrWorker({ detector: { salt: "s", known: [{ name: "a\tid", value: "ALPHA1" }] } });
    const h = createOcrWorker({ detector: { salt: "s", known: [{ name: "a", value: "ALPHA1", category: "id" }] } });
    expect((await g.scan(image(50))).cache).toBe("miss");
    expect((await h.scan(image(50))).cache).toBe("miss");
    await g.close(); await h.close();
    const c = createOcrWorker({ detector: {} }), d = createOcrWorker({ detector: {} });
    const third = await c.scan(image(43)), fourth = await d.scan(image(43));
    await c.close(); await d.close();
    expect(first.cache).toBe("miss");
    expect(first.findings).toHaveLength(1);
    expect(second.cache).toBe("miss");
    expect(second.findings).toHaveLength(0);
    expect(second.source).toBe("-/ocr");
    expect(second.path).toBe("-");
    expect(indexed.path).toBe("messages[*].content[*]");
    expect(spaced.status).toBe("scanned");
    expect(third.cache).toBe("miss");
    expect(fourth.cache).toBe("miss"); // random salts never share
  });
});

test("structural labels from scanBody pass through", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const w = worker();
    const r = await w.scan({ ...image(44), source: "user/image_url", path: "messages[3].content[1].image_url.url" });
    await w.close();
    expect(r.source).toBe("user/image_url/ocr");
    expect(r.path).toBe("messages[*].content[*].image_url.url");
    for (const path of ["contents[0].parts[1].inlineData", "input[2].content[0].input_audio", "messages[0].content[1].file", "messages[0].content[0].[field:3]"]) {
      const w2 = worker();
      expect((await w2.scan({ ...image(48), path })).path).not.toBe("-");
      await w2.close();
    }
  });
});

test("a large image decodes without holding the event loop", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const big = Buffer.alloc(15 * 1024 * 1024, 7);
    Buffer.from(imageData(45), "base64").copy(big);
    const w = worker();
    let worst = 0, last = performance.now();
    const tick = setInterval(() => { const now = performance.now(); worst = Math.max(worst, now - last); last = now; }, 1);
    const r = await w.scan({ ...image(45), data: big.toString("base64") });
    clearInterval(tick);
    await w.close();
    expect(r.status).toBe("scanned");
    expect(worst).toBeLessThan(100);
  });
});

test("enhanced worker uses supported preprocessed bytes", async () => {
  __resetOcrCacheForTests();
  await withFake('', async dir => {
    const marker = join(dir, "marker");
    writeFileSync(marker, Buffer.from(imageData(60), "base64"));
    writeFileSync(join(dir, "ffmpeg"), `#!/bin/sh\ncat >/dev/null\ncat ${shellQuote(marker)}\n`, { mode: 0o700 });
    writeFileSync(join(dir, "tesseract"), `#!/bin/sh\ncmp -s - ${shellQuote(marker)} || exit 1\nprintf '%s' ${shellQuote(tsv)}\n`, { mode: 0o700 });
    const w = createOcrWorker({ detector: { salt: "worker-test-salt", known: [{ name: "sample.person", value: "David Johnson" }] }, mode: "enhanced" });
    const result = await w.scan(image(61));
    await w.close();
    expect(result.status).toBe("scanned");
    expect(result.findings).toHaveLength(1);
  });
});

test.each(["missing", "invalid", "failed"])("enhanced worker falls back to raw bytes when ffmpeg is %s", async kind => {
  __resetOcrCacheForTests();
  await withFake('', async dir => {
    const raw = join(dir, "raw");
    writeFileSync(raw, Buffer.from(imageData(62), "base64"));
    if (kind !== "missing") writeFileSync(join(dir, "ffmpeg"), `#!/bin/sh\ncat >/dev/null\n${kind === "invalid" ? "printf invalid" : "exit 1"}\n`, { mode: 0o700 });
    writeFileSync(join(dir, "tesseract"), `#!/bin/sh\ncmp -s - ${shellQuote(raw)} || exit 1\nprintf '%s' ${shellQuote(tsv)}\n`, { mode: 0o700 });
    const w = createOcrWorker({ detector: { salt: "worker-test-salt" }, mode: "enhanced" });
    const result = await w.scan(image(62));
    await w.close();
    expect(result.status).toBe("scanned");
  });
});

test("enhanced timeout kills and reaps ffmpeg", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async dir => {
    const pidFile = join(dir, "pid");
    writeFileSync(join(dir, "ffmpeg"), `#!/bin/sh\necho $$ > ${shellQuote(pidFile)}\nexec sleep 5\n`, { mode: 0o700 });
    const w = createOcrWorker({ detector: { salt: "worker-test-salt" }, mode: "enhanced", timeoutMs: 200 });
    const result = await w.scan(image(63));
    await w.close();
    expect(result).toMatchObject({ status: "failed", reason: "timeout" });
    const pid = Number(readFileSync(pidFile, "utf8"));
    expect(() => process.kill(pid, 0)).toThrow();
  });
});

test("worker rejects invalid OCR mode", () => {
  expect(() => createOcrWorker({ detector: {}, mode: "bogus" as never })).toThrow(RangeError);
});

test("worker cache separates OCR modes", async () => {
  __resetOcrCacheForTests();
  await withFake(printTsv, async () => {
    const opts = { detector: { salt: "worker-test-salt" } };
    const basic = createOcrWorker({ ...opts, mode: "basic" });
    const enhanced = createOcrWorker({ ...opts, mode: "enhanced" });
    expect((await basic.scan(image(64))).cache).toBe("miss");
    expect((await enhanced.scan(image(64))).cache).toBe("miss");
    await basic.close(); await enhanced.close();
  });
});

import { afterEach, expect, test } from "bun:test";
import { mkdtemp, chmod, lstat, readdir, rm, symlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createCaptureStore } from "../src/ocr/capture.ts";

const dirs: string[] = [];
async function setup(maxBytes = 100, ttlMs = 10000) {
  const root = await mkdtemp(join(tmpdir(), "capture-test-")); dirs.push(root);
  const dir = join(root, "images");
  return { root, dir, store: createCaptureStore({ dir, maxBytes, ttlMs }) };
}
afterEach(async () => { for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });

test("private permissions and duplicate mtime", async () => {
  const { dir, store } = await setup(); const hash = "a".repeat(64);
  await store.put(hash, Buffer.from("data"));
  const path = join(dir, `${hash}.bin`), date = new Date(Date.now() - 1000);
  await utimes(path, date, date); await store.put(hash, Buffer.from("data"));
  expect((await lstat(dir)).mode & 0o777).toBe(0o700);
  expect((await lstat(path)).mode & 0o777).toBe(0o600);
  expect((await lstat(path)).mtimeMs).toBe(date.getTime());
  await chmod(dir, 0o755); await store.sweep(); expect((await lstat(dir)).mode & 0o777).toBe(0o700);
});

test("rejects symlink and reports errors", async () => {
  const { root, dir } = await setup(); await symlink(root, dir);
  const errors: string[] = [], store = createCaptureStore({ dir, maxBytes: 1, ttlMs: 1, onError: e => errors.push(e) });
  await store.put("a".repeat(64), Buffer.from("x"));
  expect(errors).toEqual(["invalid_directory"]);
});

test("expires old captures and evicts oldest first", async () => {
  const { dir, store } = await setup(3, 10000);
  await store.put("a".repeat(64), Buffer.from("aa"));
  const old = join(dir, `${"a".repeat(64)}.bin`), date = new Date(Date.now() - 1000);
  await utimes(old, date, date); await store.put("b".repeat(64), Buffer.from("bb"));
  expect(await readdir(dir)).toEqual([`${"b".repeat(64)}.bin`]);
  const expired = new Date(Date.now() - 20000); await utimes(join(dir, `${"b".repeat(64)}.bin`), expired, expired);
  expect(await store.sweep()).toEqual({ files: 0, bytes: 0, removed: 1 });
});

test("write failure reports error without throwing", async () => {
  const { root } = await setup(); const dir = join(root, "file"); await writeFile(dir, "x");
  const errors: string[] = []; const store = createCaptureStore({ dir, ttlMs: 1, maxBytes: 1, onError: code => errors.push(code) });
  await store.put("a".repeat(64), Buffer.from("x")); expect(errors.length).toBe(1);
});

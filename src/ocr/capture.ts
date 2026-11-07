import { randomBytes } from "node:crypto";
import { chmod, link, lstat, mkdir, readdir, unlink, writeFile } from "node:fs/promises";
import { join } from "node:path";
import type { CaptureOptions, CaptureStore } from "./contract.ts";

export function createCaptureStore(options: CaptureOptions & { onError?: (code: string) => void }): CaptureStore {
  let chain: Promise<unknown> = Promise.resolve();
  const report = (error: unknown) => { try { options.onError?.((error as NodeJS.ErrnoException)?.code || "capture_error"); } catch {} };
  const queue = <T>(work: () => Promise<T>, fallback: T): Promise<T> => {
    const result = chain.then(work).catch(error => { report(error); return fallback; });
    chain = result;
    return result;
  };
  // ponytail: path-based checks; a writer that can swap the capture dir between lstat and write can redirect it.
  // The dir sits under a 0700 home folder, so only this user can. Move to openat/O_NOFOLLOW if that changes.
  async function directory() {
    try { await mkdir(options.dir, { mode: 0o700 }); } catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    const stat = await lstat(options.dir);
    if (!stat.isDirectory() || stat.isSymbolicLink()) throw Object.assign(new Error(), { code: "invalid_directory" });
    await chmod(options.dir, 0o700);
  }
  async function sweep() {
    await directory();
    const entries: { path: string; size: number; mtime: number }[] = [];
    let removed = 0;
    for (const name of await readdir(options.dir)) {
      if (!/^(?:[a-f0-9]{64}\.(?:png|jpg|webp|bin)|\.capture-[a-f0-9]+\.tmp)$/.test(name)) continue;
      const path = join(options.dir, name), stat = await lstat(path);
      if (!stat.isFile()) continue;
      if (Date.now() - stat.mtimeMs > options.ttlMs) { await unlink(path); removed++; }
      else entries.push({ path, size: stat.size, mtime: stat.mtimeMs });
    }
    entries.sort((a, b) => a.mtime - b.mtime);
    let bytes = entries.reduce((sum, entry) => sum + entry.size, 0);
    while (bytes > options.maxBytes && entries.length) {
      const entry = entries.shift()!;
      await unlink(entry.path); bytes -= entry.size; removed++;
    }
    return { files: entries.length, bytes, removed };
  }
  return {
    put(sha256, data) { return queue(async () => {
      if (!/^[a-f0-9]{64}$/.test(sha256)) throw Object.assign(new Error(), { code: "invalid_hash" });
      await directory();
      const b = Buffer.from(data);
      const ext = b.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) ? "png" :
        b[0] === 255 && b[1] === 216 && b[2] === 255 ? "jpg" :
        b.toString("ascii", 0, 4) === "RIFF" && b.toString("ascii", 8, 12) === "WEBP" ? "webp" : "bin";
      const target = join(options.dir, `${sha256}.${ext}`), temp = join(options.dir, `.capture-${randomBytes(16).toString("hex")}.tmp`);
      try {
        await writeFile(temp, data, { flag: "wx", mode: 0o600 });
        // Linking publishes atomically without overwriting a concurrent capture.
        try { await link(temp, target); } catch (error) { if ((error as NodeJS.ErrnoException).code === "EEXIST") return; throw error; }
      } finally { await unlink(temp).catch(() => {}); }
      await sweep();
    }, undefined); },
    sweep() { return queue(sweep, { files: 0, bytes: 0, removed: 0 }); },
  };
}

export function startSweeper(store: CaptureStore, intervalMs: number): () => void {
  const timer = setInterval(() => { void store.sweep(); }, intervalMs);
  timer.unref();
  return () => clearInterval(timer);
}

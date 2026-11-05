#!/usr/bin/env node
import { readFileSync, existsSync, mkdirSync, chmodSync, renameSync, unlinkSync, openSync, closeSync, writeFileSync, readdirSync, createReadStream } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname, basename, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { parseArgs, type ParseArgsOptionsConfig } from 'node:util';
import { createDetector } from '../src/detector.ts';
import { scanBody, type BodyScanResult } from '../src/body.ts';
import { scanFile, scanBodyWithOcr } from '../src/media.ts';
import { replayImages, formatReport } from '../src/replay-images.ts';
import { createScanServer, listen } from '../src/server.ts';

const opts: ParseArgsOptionsConfig = { 'bw-json': { type: 'string' }, 'from-text': { type: 'string', multiple: true }, out: { type: 'string' }, folder: { type: 'string' }, collection: { type: 'string' }, org: { type: 'string' }, known: { type: 'string' }, source: { type: 'string' }, stdin: { type: 'boolean' }, label: { type: 'string' }, home: { type: 'string' }, since: { type: 'string' }, context: { type: 'boolean' }, events: { type: 'string' } };
const args = process.argv.slice(2);
opts.file = { type: 'string', multiple: true };
opts.ocr = { type: 'boolean' };
opts.labels = { type: 'string' };
opts.host = { type: 'string' };
opts.port = { type: 'string' };
const command = args.shift();
const knownCommand = command === 'known' ? args.shift() : undefined;
if (command === 'known' && !['export', 'check'].includes(knownCommand || '')) fail('Expected known export|check');
function fail(message: string): never { console.error(message); process.exit(1); }
let o: Record<string, any> = {};
try { o = parseArgs({ args, options: opts, strict: true }).values; } catch { fail('Invalid arguments'); }
const home = resolve(o.home || homedir());
const knownPath = o.known || join(home, '.config/pii-guard/known.json');
let patternDetector = createDetector();
let literalValues: string[] = [];
// Labels are untrusted metadata. Mask detected values and markdown controls.
function label(s: unknown) {
  let str = patternDetector.redact(String(s ?? '-'), '[V]').text;
  for (const value of literalValues) str = str.replaceAll(value, '[V]');
  return str.replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}|`<>]/gu, '_').slice(0, 200);
}
function sinceDate(s?: string): number | null {
  if (!s) return null;
  let t;
  if (/^\d+[dh]$/.test(s)) t = Date.now() - Number(s.slice(0, -1)) * (s.endsWith('d') ? 86400000 : 3600000);
  else if (/^\d{4}-\d{2}-\d{2}$/.test(s) && new Date(s).toISOString().slice(0, 10) === s) t = Date.parse(s);
  else throw Error('Invalid --since');
  if (!Number.isFinite(t)) throw Error('Invalid --since');
  return t;
}
function stamp(v: unknown) {
  if (typeof v === 'number') return v < 1e11 ? v * 1000 : v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return stamp(Number(v));
  return typeof v === 'string' ? Date.parse(v) : NaN;
}
function rowStamp(v: unknown) {
  if (!v || typeof v !== 'object' || Array.isArray(v)) return NaN;
  const row = v as Record<string, unknown>;
  for (const key of ['timestamp', 'ts', 'createdAt']) {
    const t = stamp(row[key]);
    if (Number.isFinite(t)) return t;
  }
  return NaN;
}
function readKnown(path: string, optional: boolean = false) {
  if (optional && !existsSync(path)) { console.error('Known list missing; using patterns only'); return null; }
  const k = JSON.parse(readFileSync(path, 'utf8'));
  if (k?.version !== 1 || !/^[a-f0-9]{64}$/i.test(k.salt) || !Array.isArray(k.items) || k.items.some((x: any) => !x || typeof x !== 'object' || Array.isArray(x) || typeof x.name !== 'string' || !x.name.trim() || typeof x.value !== 'string' || !x.value.trim() || !['secret', 'id', 'contact'].includes(x.category))) throw Error('Invalid known list');
  literalValues = k.items.map((x: any) => x.value).sort((a: string, b: string) => b.length - a.length);
  return k;
}
const secretLike = (s: unknown) => typeof s === 'string' && s.length >= 12 && /^[A-Za-z0-9_\-.@+/=]+$/.test(s) && /[A-Za-z]/.test(s) && /\d/.test(s) && !/^(?:http|\/|~)/i.test(s);
const tokens = (s: unknown) => typeof s === 'string' ? (s.match(/[A-Za-z0-9_~\-.@+/=]+/g) || []).filter(secretLike) : [];
function exportKnown() {
  const out = resolve(o.out || knownPath);
  const prior = existsSync(out) ? readKnown(out) : null;
  const items: { name: string; value: string; category: string }[] = [], seen = new Set<string>();
  const add = (name: string, value: unknown, category: string = 'secret', minimum: number = category === 'id' ? 6 : 8) => {
    if (typeof value !== 'string' || !value.trim() || value.length < minimum || seen.has(value)) return;
    seen.add(value); items.push({ name, value, category });
  };
  function addText(name: string, text: unknown, context = '') {
    if (typeof text !== 'string') return;
    const prefix = context ? context + '\n' : '', input = prefix + text;
    for (const [i, f] of patternDetector.scan(input).entries()) {
      if (f.start < prefix.length) continue;
      const category = f.kind === 'secret' ? 'secret' : ['email', 'in_phone', 'upi'].includes(f.rule) ? 'contact' : 'id';
      add(`${name}.pattern-${i + 1}`, input.slice(f.start, f.end), category);
    }
    tokens(text).forEach((value, i) => add(`${name}.token-${i + 1}`, value));
  }
  let bw: any[] = [];
  if (o['bw-json']) bw = JSON.parse(readFileSync(o['bw-json'], 'utf8'));
  else if (!o['from-text']?.length || o.folder || o.collection || o.org) {
    const a = ['list', 'items'];
    for (const [key, flag] of [['folder','--folderid'], ['collection','--collectionid'], ['org','--organizationid']]) if (o[key]) a.push(flag, o[key]);
    const r = spawnSync(process.env.BW_BIN || 'bw', a, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
    if (r.error || r.status !== 0) throw Error('Bitwarden export failed');
    bw = JSON.parse(r.stdout);
  }
  if (!Array.isArray(bw)) throw Error('Invalid Bitwarden export');
  for (const item of bw) {
    if (!item || typeof item !== 'object') continue;
    const slug = String(item.name || 'item').toLowerCase().match(/[a-z0-9]+/g)?.join('-') || 'item';
    const put = (field: string, value: unknown, category: string = 'secret', minimum?: number) => add(`${slug}.${field}`, value, category, minimum);
    if (item.type === 1) {
      put('password', item.login?.password, 'secret', 1);
      let totp = item.login?.totp;
      if (typeof totp === 'string' && /^otpauth:\/\//i.test(totp)) { try { totp = new URL(totp).searchParams.get('secret'); } catch { totp = null; } }
      put('totp', totp);
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item.login?.username || '')) put('username', item.login.username, 'contact');
    }
    if (item.type === 3) { put('number', item.card?.number); }
    if (item.type === 4) {
      for (const f of ['ssn', 'passportNumber', 'licenseNumber']) put(f, item.identity?.[f], 'id');
      for (const f of ['phone', 'email', 'address1']) put(f, item.identity?.[f], 'contact', f === 'phone' ? 6 : 8);
    }
    if (item.type === 5) put('privateKey', item.sshKey?.privateKey);
    for (const [i, field] of (Array.isArray(item.fields) ? item.fields : []).entries()) {
      const name = `field-${i + 1}`;
      if (field?.type === 1) put(name, field.value, 'secret', 1);
      else if (field?.type === 0 && /(?:plate|vehicle|registration|reg(?:\s|_)?no|\bid\b|passport|licen[cs]e|ssn|tax|\bpan\b|aadhaar|aadhar)/i.test(field.name || '')) put(name, field.value, 'id', 1);
      else if (field?.type === 0 && secretLike(field.value)) put(name, field.value, 'secret');
      else if (field?.type === 0 && typeof field.value === 'string' && /^(?=.*\d)[A-Za-z0-9][A-Za-z0-9 ._/#:-]{3,}$/.test(field.value)) put(name, field.value, 'id', 1);
    }
    addText(`${slug}.notes`, item.notes, typeof item.name === 'string' ? item.name : '');
  }
  for (const file of o['from-text'] || []) addText(basename(file), readFileSync(file, 'utf8'));
  literalValues = items.map(x => x.value).sort((a, b) => b.length - a.length);
  mkdirSync(dirname(out), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(out), `.known-${randomBytes(12).toString('hex')}.tmp`);
  try {
    const fd = openSync(tmp, 'wx', 0o600);
    try { writeFileSync(fd, JSON.stringify({ version: 1, salt: prior?.salt || randomBytes(32).toString('hex'), createdAt: new Date().toISOString(), items }, null, 2) + '\n'); } finally { closeSync(fd); }
    chmodSync(tmp, 0o600); renameSync(tmp, out);
  } finally { if (existsSync(tmp)) unlinkSync(tmp); }
  console.log(`Exported: secret ${items.filter(x => x.category === 'secret').length}, id ${items.filter(x => x.category === 'id').length}, contact ${items.filter(x => x.category === 'contact').length}\nOutput: ${label(out)}`);
}
async function* lines(stream: any): AsyncGenerator<string> { const rl = createInterface({ input: stream, crlfDelay: Infinity }); for await (const line of rl) yield line; }
function checkKnown() {
  const known = readKnown(knownPath);
  const detector = createDetector({ known: known.items, salt: known.salt });
  let checks = 0, failed = 0;
  for (const item of new Map<string, { value: string }>(known.items.map((x: { value: string }) => [x.value, x])).values()) {
    const bodies = [
      { messages: [{ role: 'user', content: item.value }] },
      { messages: [{ role: 'user', content: [{ type: 'tool_result', content: item.value }] }] },
      { input: [{ type: 'function_call_output', output: item.value }] },
      { contents: [{ role: 'user', parts: [{ text: item.value }] }] },
    ];
    for (const body of bodies) {
      const before = JSON.stringify(body);
      const found = scanBody(body, detector).findings.some(f => f.rule === 'known' && f.hash === detector.hash(item.value));
      checks++;
      if (!found || JSON.stringify(body) !== before) failed++;
    }
  }
  console.log(`Known-list self-check: ${checks - failed}/${checks} passed; ${detector.knownCount} distinct configured values; ${failed} failures.\nChecks inject each value into four text envelopes locally. This is not OCR accuracy or a transcript exposure rate.`);
  if (failed || !checks) process.exitCode = 2;
}
function* files(dir: string): Generator<string> {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) yield* files(p);
    else if (entry.isFile() && p.endsWith('.jsonl')) yield p;
  }
}
async function database(path: string): Promise<any> {
  if (globalThis.Bun) { const { Database } = await import('bun:sqlite'); return new Database(path, { readonly: true }); }
  const { DatabaseSync } = await import('node:sqlite'); return new DatabaseSync(path, { readOnly: true });
}
function top(map: Map<string, number>, n: number) { return [...map].sort((a,b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0,n).map(([k,v]) => `${label(k)}: ${v}`).join(', ') || '-'; }
function inc(map: Map<string, number>, key: string, n: number = 1) { map.set(key, (map.get(key) || 0) + n); }
async function replay() {
  const cutoff = sinceDate(o.since), known = readKnown(knownPath, !o.known);
  const detector = createDetector({ known: known?.items || [], ...(known ? { salt: known.salt } : {}) });
  patternDetector = detector;
  const categories = new Map((known?.items || []).map((x: any) => [x.name, x.category]));
  const selected: string[] = o.source ? o.source.split(',') : o.stdin ? [] : ['claude','codex','t3','9router'];
  if (selected.some(s => !['claude','codex','t3','9router'].includes(s))) throw Error('Invalid source');
  if (o.stdin && !o.label) throw Error('--stdin requires --label');
  const reports: any[] = [], seen = new Set<string>();
  function aggregate(name: string) {
    const stats = { name, files: 0, rows: 0, skipped: 0, undated: 0, chars: 0, errors: 0, scanErrors: 0, images: 0, bytes: 0, unscannedImages: 0, unscannedFiles: 0, opaque: 0, ocr: { scanned: 0, partial: 0, empty: 0, failed: 0, skipped: 0 }, keys: new Map() }; reports.push(stats); return stats;
  }
  function withinCutoff(stats: any, timestamp: unknown) {
    if (cutoff === null) return true;
    const t = stamp(timestamp);
    if (!Number.isFinite(t)) { stats.undated++; return false; }
    if (t < cutoff) { stats.skipped++; return false; }
    return true;
  }
  function scan(stats: any, body: any) {
    const scanner = o.context ? { scan(text: string) { const fs = detector.scan(text); for (const f of fs) (f as any).context = (text.slice(Math.max(0,f.start-14), f.start) + '[V]' + text.slice(f.end,f.end+8)).replace(/\S/gu, 'x'); return fs; } } : detector;
    let r: BodyScanResult & { ocr?: Record<string, number> };
    try { r = (o.ocr ? scanBodyWithOcr : scanBody)(body, scanner as any); }
    catch { stats.scanErrors++; return; }
    stats.rows++; stats.chars += r.chars; stats.images += r.images; stats.bytes += r.imageBytes;
    stats.unscannedImages += r.unscanned.images; stats.unscannedFiles += r.unscanned.files; stats.opaque += r.unscanned.opaque;
    if (r.ocr) for (const [key, count] of Object.entries(r.ocr)) stats.ocr[key] += count;
    for (const f of r.findings) {
      const key = f.name || f.rule; if (f.name) seen.add(f.hash);
      if (!stats.keys.has(key)) stats.keys.set(key, { kind: categories.get(key) || f.kind, hits: 0, hashes: new Set(), sources: new Map(), contexts: new Map() });
      const k = stats.keys.get(key); k.hits++; k.hashes.add(f.hash); inc(k.sources, f.source); if ((f as any).context) inc(k.contexts, (f as any).context);
    }
  }
  async function jsonl(stats: any, stream: any) { for await (const line of lines(stream)) { let v; try { v = JSON.parse(line); } catch { stats.errors++; if (cutoff !== null) stats.undated++; continue; } if (!withinCutoff(stats, rowStamp(v))) continue; scan(stats, v); } }
  for (const source of selected) {
    if (source === 'claude' || source === 'codex') {
      const dir = join(home, source === 'claude' ? '.claude/projects' : '.codex/sessions');
      if (!existsSync(dir)) continue;
      const stats = aggregate(source);
      for (const path of files(dir)) { stats.files++; await jsonl(stats, createReadStream(path)); }
    } else {
      const path = join(home, source === 't3' ? '.t3/userdata/statev2.sqlite' : '.9router/db/data.sqlite');
      if (!existsSync(path)) continue;
      const stats = aggregate(source); stats.files++;
      const db = await database(path);
      try {
        const sql = source === 't3' ? 'SELECT payload_json AS payload, updated_at AS timestamp FROM orchestration_v2_projection_turn_items' : 'SELECT data AS payload, timestamp FROM requestDetails';
        for (const row of (db.prepare(sql).iterate() as Iterable<any>)) {
          if (!withinCutoff(stats, row.timestamp)) continue;
          let v; try { v = JSON.parse(row.payload); } catch { stats.errors++; continue; } scan(stats, v);
        }
      } finally { db.close(); }
    }
  }
  if (o.stdin) { const stats = aggregate(o.label); stats.files++; await jsonl(stats, process.stdin); }
  const out = ['# Replay report', '', `Known values seen: ${seen.size} / ${detector.knownCount}`, '', `Cutoff: ${cutoff === null ? 'all available rows' : new Date(cutoff).toISOString()}; inline OCR: ${o.ocr ? 'enabled' : 'disabled'}.`, 'Transcript findings show stored exposure, not proof of provider receipt. OCR misses and truncated logs remain possible.', ''];
  for (const s of reports) {
    out.push(`## ${label(s.name)}`, '', `Files: ${s.files}; rows: ${s.rows}; skipped by --since: ${s.skipped}; undated: ${s.undated}; chars: ${s.chars}; parse errors: ${s.errors}; images: ${s.images}; image bytes: ${s.bytes}`, '', '| Key | Category/kind | Hits | Distinct hashes | Top sources |', '| --- | --- | ---: | ---: | --- |');
    for (const [key, k] of s.keys) { out.push(`| ${label(key)} | ${label(k.kind)} | ${k.hits} | ${k.hashes.size} | ${top(k.sources,3)} |`); if (o.context) out.push(`| Context | - | - | - | ${top(k.contexts,5)} |`); }
    out.push('', `Unscanned images: ${s.unscannedImages}; unscanned file/audio blocks: ${s.unscannedFiles}; opaque signed/encrypted fields: ${s.opaque}; scan errors: ${s.scanErrors}.`, '');
    if (o.ocr) out.push(`OCR: scanned ${s.ocr.scanned}; partial ${s.ocr.partial}; empty ${s.ocr.empty}; failed ${s.ocr.failed}; skipped ${s.ocr.skipped}.`, '');
    if (s.scanErrors || s.errors) process.exitCode = 2;
    if (o.ocr && (s.unscannedImages || s.unscannedFiles || s.opaque)) process.exitCode = 2;
  }
  const now = new Date().toISOString().replace(/[-:]/g, '').slice(0,15).replace('T','-');
  const path = o.out ? resolve(o.out) : resolve('reports', `replay-${now}-${randomBytes(6).toString('hex')}.md`);
  mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
  const fd = openSync(path, 'wx', 0o600);
  try { writeFileSync(fd, out.join('\n')); } finally { closeSync(fd); }
  console.log(`Replay: ${reports.length} sources, ${reports.reduce((n: number, s: any) => n+s.rows,0)} rows, ${seen.size}/${detector.knownCount} known values\nReport: ${label(path)}`);
}
async function report() {
  const known = readKnown(knownPath, !o.known);
  patternDetector = createDetector({ known: known?.items || [], ...(known ? { salt: known.salt } : {}) });
  const cutoff = sinceDate(o.since), path = o.events || join(home, '.9router/pii-guard/events.jsonl');
  let total = 0, hits = 0, errors = 0, windowRequests = 0, windowHits = 0; const times: number[] = [], counts = new Map<string, number>(), fresh = new Map<string, number>(), sources = new Map<string, number>(), uas = new Map<string, number>(), endpoints = new Map<string, number>();
  for await (const line of lines(createReadStream(path))) {
    let e: any; try { e = JSON.parse(line); } catch { errors++; continue; }
    if (!e || typeof e !== 'object' || Array.isArray(e)) { errors++; continue; }
    if (cutoff !== null && (!Number.isFinite(stamp(e.ts)) || stamp(e.ts) < cutoff)) continue;
    if (e.type === 'stats') {
      if (Number.isSafeInteger(e.requests) && e.requests >= 0 && Number.isSafeInteger(e.withFindings) && e.withFindings >= 0 && e.withFindings <= e.requests) { windowRequests += e.requests; windowHits += e.withFindings; }
      else errors++;
      continue;
    }
    total++; if (Number.isFinite(e.scanMs) && e.scanMs >= 0) times.push(e.scanMs);
    if (typeof e.ua === 'string') inc(uas,e.ua); if (typeof e.endpoint === 'string') inc(endpoints,e.endpoint);
    let has = false;
    if (e.counts && typeof e.counts === 'object' && !Array.isArray(e.counts)) for (const [k,v] of Object.entries(e.counts as Record<string, unknown>)) if (typeof v === 'number' && Number.isSafeInteger(v) && v > 0) { inc(counts,k,v); has = true; }
    if (has) hits++;
    if (Array.isArray(e.new)) for (const f of e.new) if (f && typeof f === 'object' && typeof (f.name || f.rule) === 'string') { inc(fresh,f.name || f.rule); if (typeof f.source === 'string') inc(sources,f.source); }
  }
  times.sort((a,b) => a-b); const p = (n: number) => times.length ? times[Math.ceil(n*times.length)-1] : 0;
  console.log(`Requests with findings: ${hits} / ${total} recorded events\nCompleted stats windows: ${windowHits} / ${windowRequests} requests\nCoverage: legacy events omit clean requests; stats windows can cross the cutoff.\nParse errors: ${errors}\nRecorded scan ms p50/p95/max: ${p(.5)} / ${p(.95)} / ${times.at(-1) ?? 0}\nTotals: ${top(counts,counts.size)}\nNew hashes by key: ${top(fresh,fresh.size)}\nNew hashes by source: ${top(sources,sources.size)}\nUser agents: ${top(uas,5)}\nEndpoints: ${top(endpoints,5)}`);
}
function inspectFiles() {
  if (!o.file?.length) throw Error('scan requires --file');
  const known = readKnown(knownPath, !o.known);
  const detector = createDetector({ known: known?.items || [], ...(known ? { salt: known.salt } : {}) });
  patternDetector = detector;
  for (const [i, path] of o.file.entries()) {
    const r = scanFile(path, detector), counts = new Map<string, number>();
    for (const f of r.findings) inc(counts, f.name || f.rule);
    console.log(`File ${i + 1}: ${r.status}; pages: ${r.pages}; chars: ${r.chars}; findings: ${r.findings.length}\nTypes: ${top(counts, counts.size)}`);
    if (r.status !== 'scanned') process.exitCode = 2;
  }
}
async function replayImageFolder() {
  if (!o.folder) throw Error('replay-images requires --folder');
  const known = readKnown(knownPath, !o.known);
  const detector = createDetector({ known: known?.items || [], ...(known ? { salt: known.salt } : {}) });
  const labels = o.labels ? JSON.parse(readFileSync(o.labels, 'utf8')) : undefined;
  console.log(formatReport(await replayImages({ folder: resolve(o.folder), detector, labels })));
}
async function serve() {
  const known = readKnown(knownPath, !o.known);
  const token = process.env.PII_GUARD_TOKEN || undefined, host = o.host || '127.0.0.1', port = Number(o.port || 20130);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Invalid --port');
  const server = createScanServer({ detector: { known: known?.items || [], ...(known ? { salt: known.salt } : {}) }, token });
  await listen(server, host, port, token);
  console.error(`pii-guard serving on http://${host}:${port}`);
  await new Promise(() => {});
}
try {
  if (command === 'replay-images') await replayImageFolder(); else if (command === 'serve') await serve(); else if (command === 'known') { if (knownCommand === 'check') checkKnown(); else exportKnown(); } else if (command === 'replay') await replay(); else if (command === 'report') await report(); else if (command === 'scan') inspectFiles(); else fail('Usage: pii-guard known export|check, replay, replay-images, report, scan, serve');
} catch { fail('Command failed; check input files and options'); }

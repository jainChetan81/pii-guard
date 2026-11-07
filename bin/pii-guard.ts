#!/usr/bin/env node
import { readFileSync, existsSync, mkdirSync, chmodSync, renameSync, unlinkSync, openSync, closeSync, writeFileSync, readdirSync, createReadStream } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname, basename, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { createDetector, KNOWN_CATEGORIES, type KnownCategory, type KnownItem } from '../src/detector.ts';
import { scanBody, type BodyScanResult } from '../src/body.ts';
import type { Detector } from '../src/detector.ts';
import { scanFile, scanBodyWithOcr } from '../src/ocr/media.ts';
import { replayImages, formatReport } from '../src/ocr/replay-images.ts';
import { createScanServer, listen } from '../src/server.ts';
import { isOcrMode } from '../src/ocr/text.ts';
import { doctor } from '../src/ocr/doctor.ts';

const opts = {
  'bw-json': { type: 'string' }, 'from-text': { type: 'string', multiple: true }, out: { type: 'string' }, folder: { type: 'string' },
  collection: { type: 'string' }, org: { type: 'string' }, known: { type: 'string' }, source: { type: 'string' }, stdin: { type: 'boolean' },
  label: { type: 'string' }, home: { type: 'string' }, since: { type: 'string' }, context: { type: 'boolean' }, events: { type: 'string' },
  file: { type: 'string', multiple: true }, ocr: { type: 'boolean' }, labels: { type: 'string' }, host: { type: 'string' }, port: { type: 'string' },
  'ocr-mode': { type: 'string' },
} as const;
const args = process.argv.slice(2);
const command = args.shift();
const knownCommand = command === 'known' ? args.shift() : undefined;
if (command === 'known' && !['export', 'check'].includes(knownCommand || '')) fail('Expected known export|check');
function fail(message: string): never { console.error(message); process.exit(1); }
function parseOptions() { try { return parseArgs({ args, options: opts, strict: true }).values; } catch { fail('Invalid arguments'); } }
const o = parseOptions();
const home = resolve(o.home || homedir());
const knownPath = o.known || join(home, '.config/pii-guard/known.json');
// --ocr-mode wins over PII_GUARD_OCR_MODE; default enhanced. basic is the fallback for hosts without ffmpeg or for comparison.
const ocrModeInput = o['ocr-mode'] || process.env.PII_GUARD_OCR_MODE || 'enhanced';
if (!isOcrMode(ocrModeInput)) fail('Invalid --ocr-mode; expected basic or enhanced');
const ocrMode = ocrModeInput;
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
const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);
const rec = (v: unknown): Record<string, unknown> => isRecord(v) ? v : {};
function rowStamp(v: unknown) {
  if (!isRecord(v)) return NaN;
  for (const key of ['timestamp', 'ts', 'createdAt']) {
    const t = stamp(v[key]);
    if (Number.isFinite(t)) return t;
  }
  return NaN;
}
type KnownList = { version: 1; salt: string; items: Required<KnownItem>[] };
const count = (v: unknown): v is number => typeof v === 'number' && Number.isSafeInteger(v) && v >= 0;
const nonBlank = (v: unknown): v is string => typeof v === 'string' && !!v.trim();
const isCategory = (v: unknown): v is KnownCategory => KNOWN_CATEGORIES.some(c => c === v);
const isKnownEntry = (x: unknown): x is Required<KnownItem> => isRecord(x) && nonBlank(x.name) && nonBlank(x.value) && isCategory(x.category);
function isKnownList(k: unknown): k is KnownList {
  return isRecord(k) && k.version === 1 && typeof k.salt === 'string' && /^[a-f0-9]{64}$/i.test(k.salt) && Array.isArray(k.items) && k.items.every(isKnownEntry);
}
function readKnown(path: string, optional: boolean): KnownList | null;
function readKnown(path: string): KnownList;
function readKnown(path: string, optional = false): KnownList | null {
  if (optional && !existsSync(path)) { console.error('Known list missing; using patterns only'); return null; }
  const k: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (!isKnownList(k)) throw Error('Invalid known list');
  literalValues = k.items.map(x => x.value).sort((a, b) => b.length - a.length);
  return k;
}
const detectorOptions = (known: KnownList | null) => known ? { known: known.items, salt: known.salt } : { known: [] };
const secretLike = (s: unknown) => typeof s === 'string' && s.length >= 12 && /^[A-Za-z0-9_\-.@+/=]+$/.test(s) && /[A-Za-z]/.test(s) && /\d/.test(s) && !/^(?:http|\/|~)/i.test(s);
const tokens = (s: unknown) => typeof s === 'string' ? (s.match(/[A-Za-z0-9_~\-.@+/=]+/g) || []).filter(secretLike) : [];
function exportKnown() {
  const out = resolve(o.out || knownPath);
  const prior = existsSync(out) ? readKnown(out) : null;
  const items: Required<KnownItem>[] = [], seen = new Set<string>();
  const add = (name: string, value: unknown, category: KnownCategory = 'secret', minimum: number = category === 'id' ? 6 : 8) => {
    if (typeof value !== 'string' || !value.trim() || value.length < minimum || seen.has(value)) return;
    seen.add(value); items.push({ name, value, category });
  };
  function addText(name: string, text: unknown, context = '') {
    if (typeof text !== 'string') return;
    const prefix = context ? context + '\n' : '', input = prefix + text;
    for (const [i, f] of patternDetector.scan(input).entries()) {
      if (f.start < prefix.length) continue;
      const category: KnownCategory = f.kind === 'secret' ? 'secret' : ['email', 'in_phone', 'upi'].includes(f.rule) ? 'contact' : 'id';
      add(`${name}.pattern-${i + 1}`, input.slice(f.start, f.end), category);
    }
    tokens(text).forEach((value, i) => add(`${name}.token-${i + 1}`, value));
  }
  let bw: unknown = [];
  if (o['bw-json']) bw = JSON.parse(readFileSync(o['bw-json'], 'utf8'));
  else if (!o['from-text']?.length || o.folder || o.collection || o.org) {
    const a = ['list', 'items'];
    for (const [value, flag] of [[o.folder,'--folderid'], [o.collection,'--collectionid'], [o.org,'--organizationid']] as const) if (value) a.push(flag, value);
    const r = spawnSync(process.env.BW_BIN || 'bw', a, { encoding: 'utf8', maxBuffer: 256 * 1024 * 1024 });
    if (r.error || r.status !== 0) throw Error('Bitwarden export failed');
    bw = JSON.parse(r.stdout);
  }
  if (!Array.isArray(bw)) throw Error('Invalid Bitwarden export');
  for (const item of bw) {
    if (!isRecord(item)) continue;
    const login = rec(item.login), identity = rec(item.identity);
    const slug = String(item.name || 'item').toLowerCase().match(/[a-z0-9]+/g)?.join('-') || 'item';
    const put = (field: string, value: unknown, category: KnownCategory = 'secret', minimum?: number) => add(`${slug}.${field}`, value, category, minimum);
    if (item.type === 1) {
      put('password', login.password, 'secret', 1);
      let totp = login.totp;
      if (typeof totp === 'string' && /^otpauth:\/\//i.test(totp)) { try { totp = new URL(totp).searchParams.get('secret'); } catch { totp = null; } }
      put('totp', totp);
      if (typeof login.username === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(login.username)) put('username', login.username, 'contact');
    }
    if (item.type === 3) { put('number', rec(item.card).number); }
    if (item.type === 4) {
      for (const f of ['ssn', 'passportNumber', 'licenseNumber']) put(f, identity[f], 'id');
      for (const f of ['phone', 'email', 'address1']) put(f, identity[f], 'contact', f === 'phone' ? 6 : 8);
    }
    if (item.type === 5) put('privateKey', rec(item.sshKey).privateKey);
    for (const [i, raw] of (Array.isArray(item.fields) ? item.fields : []).entries()) {
      const name = `field-${i + 1}`, field = rec(raw);
      if (field.type === 1) put(name, field.value, 'secret', 1);
      else if (field.type === 0 && /(?:plate|vehicle|registration|reg(?:\s|_)?no|\bid\b|passport|licen[cs]e|ssn|tax|\bpan\b|aadhaar|aadhar)/i.test(typeof field.name === 'string' ? field.name : '')) put(name, field.value, 'id', 1);
      else if (field.type === 0 && secretLike(field.value)) put(name, field.value, 'secret');
      else if (field.type === 0 && typeof field.value === 'string' && /^(?=.*\d)[A-Za-z0-9][A-Za-z0-9 ._/#:-]{3,}$/.test(field.value)) put(name, field.value, 'id', 1);
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
async function* lines(stream: NodeJS.ReadableStream): AsyncGenerator<string> { const rl = createInterface({ input: stream, crlfDelay: Infinity }); for await (const line of rl) yield line; }
function checkKnown() {
  const known = readKnown(knownPath);
  const detector = createDetector({ known: known.items, salt: known.salt });
  let checks = 0, failed = 0;
  for (const item of new Map(known.items.map(x => [x.value, x])).values()) {
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
// Both drivers expose prepare().iterate() and close(); rows are untyped until checked.
type ReadonlyDb = { prepare(sql: string): { iterate(): Iterable<unknown> }; close(): void };
async function database(path: string): Promise<ReadonlyDb> {
  if (globalThis.Bun) { const { Database } = await import('bun:sqlite'); return new Database(path, { readonly: true }); }
  const { DatabaseSync } = await import('node:sqlite'); return new DatabaseSync(path, { readOnly: true });
}
function top(map: Map<string, number>, n: number) { return [...map].sort((a,b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0,n).map(([k,v]) => `${label(k)}: ${v}`).join(', ') || '-'; }
function inc(map: Map<string, number>, key: string, n: number = 1) { map.set(key, (map.get(key) || 0) + n); }
async function replay() {
  const cutoff = sinceDate(o.since), known = readKnown(knownPath, !o.known);
  const detector = createDetector(detectorOptions(known));
  patternDetector = detector;
  const categories = new Map<string, string>((known?.items || []).map(x => [x.name, x.category]));
  const selected: string[] = o.source ? o.source.split(',') : o.stdin ? [] : ['claude','codex','t3','9router'];
  if (selected.some(s => !['claude','codex','t3','9router'].includes(s))) throw Error('Invalid source');
  if (o.stdin && !o.label) throw Error('--stdin requires --label');
  type KeyStats = { kind: string; hits: number; hashes: Set<string>; sources: Map<string, number>; contexts: Map<string, number> };
  const newStats = (name: string) => ({ name, files: 0, rows: 0, skipped: 0, undated: 0, chars: 0, errors: 0, scanErrors: 0, images: 0, bytes: 0, unscannedImages: 0, unscannedFiles: 0, opaque: 0, ocr: { scanned: 0, partial: 0, empty: 0, failed: 0, skipped: 0 } as Record<string, number>, keys: new Map<string, KeyStats>() });
  type Stats = ReturnType<typeof newStats>;
  const reports: Stats[] = [], seen = new Set<string>();
  function aggregate(name: string) { const stats = newStats(name); reports.push(stats); return stats; }
  function withinCutoff(stats: Stats, timestamp: unknown) {
    if (cutoff === null) return true;
    const t = stamp(timestamp);
    if (!Number.isFinite(t)) { stats.undated++; return false; }
    if (t < cutoff) { stats.skipped++; return false; }
    return true;
  }
  // With --context, each finding carries a masked shape of its surroundings; scanBody copies it onto the body finding.
  function scan(stats: Stats, body: unknown) {
    const scanner: Detector = o.context ? { ...detector, scan(text, context) { return detector.scan(text, context).map(f => ({ ...f, context: (text.slice(Math.max(0,f.start-14), f.start) + '[V]' + text.slice(f.end,f.end+8)).replace(/\S/gu, 'x') })); } } : detector;
    let r: BodyScanResult & { ocr?: Record<string, number> };
    try { r = o.ocr ? scanBodyWithOcr(body, scanner, ocrMode) : scanBody(body, scanner); }
    catch { stats.scanErrors++; return; }
    stats.rows++; stats.chars += r.chars; stats.images += r.images; stats.bytes += r.imageBytes;
    stats.unscannedImages += r.unscanned.images; stats.unscannedFiles += r.unscanned.files; stats.opaque += r.unscanned.opaque;
    if (r.ocr) for (const [key, count] of Object.entries(r.ocr)) stats.ocr[key] = (stats.ocr[key] ?? 0) + count;
    for (const f of r.findings) {
      const key = f.name || f.rule; if (f.name) seen.add(f.hash);
      if (!stats.keys.has(key)) stats.keys.set(key, { kind: categories.get(key) || f.kind, hits: 0, hashes: new Set(), sources: new Map(), contexts: new Map() });
      const k = stats.keys.get(key)!; k.hits++; k.hashes.add(f.hash); inc(k.sources, f.source); if ('context' in f && typeof f.context === 'string') inc(k.contexts, f.context);
    }
  }
  async function jsonl(stats: Stats, stream: NodeJS.ReadableStream) { for await (const line of lines(stream)) { let v; try { v = JSON.parse(line); } catch { stats.errors++; if (cutoff !== null) stats.undated++; continue; } if (!withinCutoff(stats, rowStamp(v))) continue; scan(stats, v); } }
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
        for (const row of db.prepare(sql).iterate()) {
          if (!isRecord(row) || !withinCutoff(stats, row.timestamp)) continue;
          let v; try { v = JSON.parse(String(row.payload)); } catch { stats.errors++; continue; } scan(stats, v);
        }
      } finally { db.close(); }
    }
  }
  if (o.stdin && o.label) { const stats = aggregate(o.label); stats.files++; await jsonl(stats, process.stdin); }
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
  console.log(`Replay: ${reports.length} sources, ${reports.reduce((n, s) => n+s.rows,0)} rows, ${seen.size}/${detector.knownCount} known values\nReport: ${label(path)}`);
}
async function report() {
  const known = readKnown(knownPath, !o.known);
  patternDetector = createDetector(detectorOptions(known));
  const cutoff = sinceDate(o.since), path = o.events || join(home, '.9router/pii-guard/events.jsonl');
  let total = 0, hits = 0, errors = 0, windowRequests = 0, windowHits = 0; const times: number[] = [], counts = new Map<string, number>(), fresh = new Map<string, number>(), sources = new Map<string, number>(), uas = new Map<string, number>(), endpoints = new Map<string, number>();
  for await (const line of lines(createReadStream(path))) {
    let e: unknown; try { e = JSON.parse(line); } catch { errors++; continue; }
    if (!isRecord(e)) { errors++; continue; }
    if (cutoff !== null && (!Number.isFinite(stamp(e.ts)) || stamp(e.ts) < cutoff)) continue;
    if (e.type === 'stats') {
      const { requests, withFindings } = e;
      if (count(requests) && count(withFindings) && withFindings <= requests) { windowRequests += requests; windowHits += withFindings; }
      else errors++;
      continue;
    }
    total++; if (typeof e.scanMs === 'number' && Number.isFinite(e.scanMs) && e.scanMs >= 0) times.push(e.scanMs);
    if (typeof e.ua === 'string') inc(uas,e.ua); if (typeof e.endpoint === 'string') inc(endpoints,e.endpoint);
    let has = false;
    if (isRecord(e.counts)) for (const [k,v] of Object.entries(e.counts)) if (count(v) && v > 0) { inc(counts,k,v); has = true; }
    if (has) hits++;
    if (Array.isArray(e.new)) for (const f of e.new) { if (!isRecord(f)) continue; const key = f.name || f.rule; if (typeof key !== 'string') continue; inc(fresh,key); if (typeof f.source === 'string') inc(sources,f.source); }
  }
  times.sort((a,b) => a-b); const p = (n: number) => times.length ? times[Math.ceil(n*times.length)-1] : 0;
  console.log(`Requests with findings: ${hits} / ${total} recorded events\nCompleted stats windows: ${windowHits} / ${windowRequests} requests\nCoverage: legacy events omit clean requests; stats windows can cross the cutoff.\nParse errors: ${errors}\nRecorded scan ms p50/p95/max: ${p(.5)} / ${p(.95)} / ${times.at(-1) ?? 0}\nTotals: ${top(counts,counts.size)}\nNew hashes by key: ${top(fresh,fresh.size)}\nNew hashes by source: ${top(sources,sources.size)}\nUser agents: ${top(uas,5)}\nEndpoints: ${top(endpoints,5)}`);
}
function inspectFiles() {
  if (!o.file?.length) throw Error('scan requires --file');
  const known = readKnown(knownPath, !o.known);
  const detector = createDetector(detectorOptions(known));
  patternDetector = detector;
  for (const [i, path] of o.file.entries()) {
    const r = scanFile(path, detector, ocrMode), counts = new Map<string, number>();
    for (const f of r.findings) inc(counts, f.name || f.rule);
    console.log(`File ${i + 1}: ${r.status}; pages: ${r.pages}; chars: ${r.chars}; findings: ${r.findings.length}\nTypes: ${top(counts, counts.size)}`);
    if (r.status !== 'scanned') process.exitCode = 2;
  }
}
async function replayImageFolder() {
  if (!o.folder) throw Error('replay-images requires --folder');
  const known = readKnown(knownPath, !o.known);
  const detector = createDetector(detectorOptions(known));
  const labels = o.labels ? JSON.parse(readFileSync(o.labels, 'utf8')) : undefined;
  console.log(formatReport(await replayImages({ folder: resolve(o.folder), detector, labels, mode: ocrMode })));
}
async function serve() {
  const known = readKnown(knownPath, !o.known);
  const token = process.env.PII_GUARD_TOKEN || undefined, host = o.host || '127.0.0.1', port = Number(o.port || 20130);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw Error('Invalid --port');
  const server = createScanServer({ detector: detectorOptions(known), token, mode: ocrMode });
  await listen(server, host, port);
  console.error(`pii-guard serving on http://${host}:${port} (OCR mode ${ocrMode})`);
  await new Promise(() => {});
}
function runDoctor() {
  const r = doctor();
  for (const t of r.tools) console.log(`${t.found ? 'ok     ' : 'missing'} ${t.name.padEnd(10)} ${t.found ? t.version || '' : `needed for ${t.neededFor}; install: ${t.install}`}`);
  console.log(`languages: ${r.languages.join(', ') || 'none'}\nmodes: basic ${r.modes.basic ? 'ready' : 'unavailable'}; enhanced ${r.modes.enhanced ? 'ready' : 'unavailable'}; pdf ${r.pdf ? 'ready' : 'unavailable'}`);
  if (!r.modes[ocrMode]) process.exitCode = 2;
}
try {
  if (command === 'doctor') runDoctor(); else if (command === 'replay-images') await replayImageFolder(); else if (command === 'serve') await serve(); else if (command === 'known') { if (knownCommand === 'check') checkKnown(); else exportKnown(); } else if (command === 'replay') await replay(); else if (command === 'report') await report(); else if (command === 'scan') inspectFiles(); else fail('Usage: pii-guard doctor, known export|check, replay, replay-images, report, scan, serve [--ocr-mode basic|enhanced]');
} catch { fail('Command failed; check input files and options'); }

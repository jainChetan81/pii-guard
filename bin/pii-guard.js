#!/usr/bin/env node
import { readFileSync, existsSync, mkdirSync, chmodSync, renameSync, unlinkSync, openSync, closeSync, writeFileSync, statSync, readdirSync, createReadStream } from 'node:fs';
import { homedir } from 'node:os';
import { join, dirname, basename, resolve } from 'node:path';
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { createInterface } from 'node:readline';
import { parseArgs } from 'node:util';
import { createDetector } from '../src/detector.js';
import { scanBody } from '../src/body.js';

const opts = { 'bw-json': { type: 'string' }, 'from-text': { type: 'string', multiple: true }, out: { type: 'string' }, folder: { type: 'string' }, collection: { type: 'string' }, org: { type: 'string' }, known: { type: 'string' }, source: { type: 'string' }, stdin: { type: 'boolean' }, label: { type: 'string' }, home: { type: 'string' }, since: { type: 'string' }, context: { type: 'boolean' }, events: { type: 'string' } };
const args = process.argv.slice(2);
const command = args.shift();
if (command === 'known' && args.shift() !== 'export') fail('Expected known export');
function fail(message) { console.error(message); process.exit(1); }
let o;
try { o = parseArgs({ args, options: opts, strict: true }).values; } catch { fail('Invalid arguments'); }
const home = resolve(o.home || homedir());
const knownPath = o.known || join(home, '.config/pii-guard/known.json');
let patternDetector = createDetector();
// Labels are untrusted metadata. Mask detected values and markdown controls.
function label(s) {
  s = String(s ?? '-').replace(/[\r\n\x00-\x1f|`<>]/g, '_').slice(0, 200);
  // Names and paths stay readable; only pattern-detected values are masked.
  for (const f of patternDetector.scan(s).reverse()) s = s.slice(0, f.start) + '[V]' + s.slice(f.end);
  return s;
}
function sinceDate(s) {
  if (!s) return 0;
  let t;
  if (/^\d+[dh]$/.test(s)) t = Date.now() - Number(s.slice(0, -1)) * (s.endsWith('d') ? 86400000 : 3600000);
  else if (/^\d{4}-\d{2}-\d{2}$/.test(s) && new Date(s).toISOString().slice(0, 10) === s) t = Date.parse(s);
  else throw Error('Invalid --since');
  if (!Number.isFinite(t)) throw Error('Invalid --since');
  return t;
}
function stamp(v) {
  if (typeof v === 'number') return v < 1e11 ? v * 1000 : v;
  if (typeof v === 'string' && /^\d+$/.test(v)) return stamp(Number(v));
  return Date.parse(v);
}
function readKnown(path, optional = false) {
  if (optional && !existsSync(path)) { console.error('Known list missing; using patterns only'); return null; }
  const k = JSON.parse(readFileSync(path, 'utf8'));
  if (k?.version !== 1 || !/^[a-f0-9]{64}$/i.test(k.salt) || !Array.isArray(k.items) || k.items.some(x => !x || typeof x.name !== 'string' || typeof x.value !== 'string' || !['secret', 'id', 'contact'].includes(x.category))) throw Error('Invalid known list');
  return k;
}
const secretLike = s => typeof s === 'string' && s.length >= 12 && /^[A-Za-z0-9_\-.@+/=]+$/.test(s) && /[A-Za-z]/.test(s) && /\d/.test(s) && !/^(?:http|\/|~)/i.test(s);
const tokens = s => typeof s === 'string' ? (s.match(/[A-Za-z0-9_~\-.@+/=]+/g) || []).filter(secretLike) : [];
function exportKnown() {
  const out = resolve(o.out || join(homedir(), '.config/pii-guard/known.json'));
  const prior = existsSync(out) ? readKnown(out) : null;
  const items = [], seen = new Set();
  const add = (name, value, category = 'secret', phone = false) => {
    if (typeof value !== 'string' || value.length < (category === 'id' || phone ? 6 : 8) || seen.has(value)) return;
    seen.add(value); items.push({ name, value, category });
  };
  let bw = [];
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
    const put = (field, value, category, phone) => add(`${slug}.${field}`, value, category, phone);
    if (item.type === 1) {
      put('password', item.login?.password);
      let totp = item.login?.totp;
      if (typeof totp === 'string' && /^otpauth:\/\//i.test(totp)) { try { totp = new URL(totp).searchParams.get('secret'); } catch { totp = null; } }
      put('totp', totp);
      if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(item.login?.username || '')) put('username', item.login.username, 'contact');
    }
    if (item.type === 3) { put('number', item.card?.number); put('code', item.card?.code); }
    if (item.type === 4) {
      for (const f of ['ssn', 'passportNumber', 'licenseNumber']) put(f, item.identity?.[f], 'id');
      for (const f of ['phone', 'email', 'address1']) put(f, item.identity?.[f], 'contact', f === 'phone');
    }
    if (item.type === 5) put('privateKey', item.sshKey?.privateKey);
    for (const [i, field] of (Array.isArray(item.fields) ? item.fields : []).entries()) {
      if (field?.type === 1 || (field?.type === 0 && secretLike(field.value))) put(`field-${i + 1}`, field.value, 'secret');
      else if (field?.type === 0 && typeof field.value === 'string' && /^(?=.*\d)[A-Za-z0-9 -]{6,}$/.test(field.value)) put(`field-${i + 1}`, field.value, 'id');
    }
    tokens(item.notes).forEach((v, i) => put(`notes-${i + 1}`, v));
  }
  for (const file of o['from-text'] || []) tokens(readFileSync(file, 'utf8')).forEach((v, i) => add(`${basename(file)}#${i + 1}`, v));
  mkdirSync(dirname(out), { recursive: true, mode: 0o700 });
  const tmp = join(dirname(out), `.known-${randomBytes(12).toString('hex')}.tmp`);
  try {
    const fd = openSync(tmp, 'wx', 0o600);
    try { writeFileSync(fd, JSON.stringify({ version: 1, salt: prior?.salt || randomBytes(32).toString('hex'), createdAt: new Date().toISOString(), items }, null, 2) + '\n'); } finally { closeSync(fd); }
    chmodSync(tmp, 0o600); renameSync(tmp, out);
  } finally { if (existsSync(tmp)) unlinkSync(tmp); }
  console.log(`Exported: secret ${items.filter(x => x.category === 'secret').length}, id ${items.filter(x => x.category === 'id').length}, contact ${items.filter(x => x.category === 'contact').length}\nOutput: ${label(out)}`);
}
async function* lines(stream) { const rl = createInterface({ input: stream, crlfDelay: Infinity }); for await (const line of rl) yield line; }
function* files(dir) {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, entry.name);
    if (entry.isDirectory()) yield* files(p);
    else if (entry.isFile() && p.endsWith('.jsonl')) yield p;
  }
}
async function database(path) {
  if (globalThis.Bun) { const { Database } = await import('bun:sqlite'); return new Database(path, { readonly: true }); }
  const { DatabaseSync } = await import('node:sqlite'); return new DatabaseSync(path, { readOnly: true });
}
function top(map, n) { return [...map].sort((a,b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0,n).map(([k,v]) => `${label(k)}: ${v}`).join(', ') || '-'; }
function inc(map, key, n = 1) { map.set(key, (map.get(key) || 0) + n); }
async function replay() {
  const cutoff = sinceDate(o.since), known = readKnown(knownPath, true);
  const detector = createDetector({ known: known?.items || [], ...(known ? { salt: known.salt } : {}) });
  patternDetector = detector;
  const categories = new Map((known?.items || []).map(x => [x.name, x.category]));
  const selected = o.source ? o.source.split(',') : o.stdin ? [] : ['claude','codex','t3','9router'];
  if (selected.some(s => !['claude','codex','t3','9router'].includes(s))) throw Error('Invalid source');
  if (o.stdin && !o.label) throw Error('--stdin requires --label');
  const reports = [], seen = new Set();
  function aggregate(name) {
    const stats = { name, files: 0, rows: 0, chars: 0, errors: 0, images: 0, bytes: 0, keys: new Map() }; reports.push(stats); return stats;
  }
  function scan(stats, body) {
    // Capture context at scan time; scanBody paths are not unique for arrays.
    const scanner = o.context ? { scan(text) { const fs = detector.scan(text); for (const f of fs) f.context = (text.slice(Math.max(0,f.start-14), f.start) + '[V]' + text.slice(f.end,f.end+8)).replace(/[A-Za-z0-9]/g, 'x'); return fs; } } : detector;
    const r = scanBody(body, scanner); stats.rows++; stats.chars += r.chars; stats.images += r.images; stats.bytes += r.imageBytes;
    for (const f of r.findings) {
      const key = f.name || f.rule; if (f.name) seen.add(f.name);
      if (!stats.keys.has(key)) stats.keys.set(key, { kind: categories.get(key) || f.kind, hits: 0, hashes: new Set(), sources: new Map(), contexts: new Map() });
      const k = stats.keys.get(key); k.hits++; k.hashes.add(f.hash); inc(k.sources, f.source); if (f.context) inc(k.contexts, f.context);
    }
  }
  async function jsonl(stats, stream) { for await (const line of lines(stream)) { let v; try { v = JSON.parse(line); } catch { stats.errors++; continue; } scan(stats, v); } }
  for (const source of selected) {
    if (source === 'claude' || source === 'codex') {
      const dir = join(home, source === 'claude' ? '.claude/projects' : '.codex/sessions');
      if (!existsSync(dir)) continue;
      const stats = aggregate(source);
      for (const path of files(dir)) { if (cutoff && statSync(path).mtimeMs < cutoff) continue; stats.files++; await jsonl(stats, createReadStream(path)); }
    } else {
      const path = join(home, source === 't3' ? '.t3/userdata/statev2.sqlite' : '.9router/db/data.sqlite');
      if (!existsSync(path)) continue;
      const stats = aggregate(source); stats.files++;
      const db = await database(path);
      try {
        const sql = source === 't3' ? 'SELECT payload_json AS payload, updated_at AS timestamp FROM orchestration_v2_projection_turn_items' : 'SELECT data AS payload, timestamp FROM requestDetails';
        for (const row of db.prepare(sql).iterate()) {
          if (cutoff && (!Number.isFinite(stamp(row.timestamp)) || stamp(row.timestamp) < cutoff)) continue;
          let v; try { v = JSON.parse(row.payload); } catch { stats.errors++; continue; } scan(stats, v);
        }
      } finally { db.close(); }
    }
  }
  if (o.stdin) { const stats = aggregate(o.label); stats.files++; await jsonl(stats, process.stdin); }
  const out = ['# Replay report', '', `Known values seen: ${seen.size} / ${detector.knownCount}`, ''];
  for (const s of reports) {
    out.push(`## ${label(s.name)}`, '', `Files: ${s.files}; rows: ${s.rows}; chars: ${s.chars}; parse errors: ${s.errors}; images: ${s.images}; image bytes: ${s.bytes}`, '', '| Key | Category/kind | Hits | Distinct hashes | Top sources |', '| --- | --- | ---: | ---: | --- |');
    for (const [key, k] of s.keys) { out.push(`| ${label(key)} | ${label(k.kind)} | ${k.hits} | ${k.hashes.size} | ${top(k.sources,3)} |`); if (o.context) out.push(`| Context | - | - | - | ${top(k.contexts,5)} |`); }
    out.push('');
  }
  const now = new Date().toISOString().replace(/[-:]/g, '').slice(0,13).replace('T','-');
  const dir = resolve('reports'); mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, `replay-${now}.md`); writeFileSync(path, out.join('\n'), { mode: 0o600 });
  console.log(`Replay: ${reports.length} sources, ${reports.reduce((n,s) => n+s.rows,0)} rows, ${seen.size}/${detector.knownCount} known values\nReport: ${label(path)}`);
}
async function report() {
  const cutoff = sinceDate(o.since), path = o.events || join(homedir(), '.9router/pii-guard/events.jsonl');
  let total = 0, hits = 0, errors = 0; const times = [], counts = new Map(), fresh = new Map(), sources = new Map(), uas = new Map(), endpoints = new Map();
  for await (const line of lines(createReadStream(path))) {
    let e; try { e = JSON.parse(line); } catch { errors++; continue; }
    if (!e || typeof e !== 'object' || Array.isArray(e)) { errors++; continue; }
    if (cutoff && (!Number.isFinite(stamp(e.ts)) || stamp(e.ts) < cutoff)) continue;
    total++; if (Number.isFinite(e.scanMs) && e.scanMs >= 0) times.push(e.scanMs);
    if (typeof e.ua === 'string') inc(uas,e.ua); if (typeof e.endpoint === 'string') inc(endpoints,e.endpoint);
    let has = false;
    if (e.counts && typeof e.counts === 'object' && !Array.isArray(e.counts)) for (const [k,v] of Object.entries(e.counts)) if (Number.isSafeInteger(v) && v > 0) { inc(counts,k,v); has = true; }
    if (has) hits++;
    if (Array.isArray(e.new)) for (const f of e.new) if (f && typeof f === 'object' && typeof (f.name || f.rule) === 'string') { inc(fresh,f.name || f.rule); if (typeof f.source === 'string') inc(sources,f.source); }
  }
  times.sort((a,b) => a-b); const p = n => times.length ? times[Math.ceil(n*times.length)-1] : 0;
  console.log(`Requests with findings: ${hits} / ${total}\nParse errors: ${errors}\nScan ms p50/p95/max: ${p(.5)} / ${p(.95)} / ${times.at(-1) ?? 0}\nTotals: ${top(counts,counts.size)}\nNew hashes by key: ${top(fresh,fresh.size)}\nNew hashes by source: ${top(sources,sources.size)}\nUser agents: ${top(uas,5)}\nEndpoints: ${top(endpoints,5)}`);
}
try {
  if (command === 'known') exportKnown(); else if (command === 'replay') await replay(); else if (command === 'report') await report(); else fail('Usage: pii-guard known export|replay|report');
} catch { fail('Command failed; check input files and options'); }

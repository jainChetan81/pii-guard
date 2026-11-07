// Core detector: own-list exact match first, then rule patterns.
// No runtime deps; runs as .ts in Bun and Node >= 22.18 with type stripping.
// Node builds without TypeScript (Debian /usr/bin/node) load `bun run build` output, dist/index.js.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { RULES, KEYWORD_WINDOW, type Rule } from "./rules.ts";

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Digit-only values (phones, card numbers) may appear with spaces or dashes,
// and phones with a +91 / 0 prefix. Match the bare digits with optional separators.
function knownPattern(value: string, category?: KnownCategory): string {
  if (category === "id" && /^[A-Z0-9 -]{6,30}$/.test(value)) {
    // Digit-only IDs keep digit boundaries so they never match inside a longer number.
    if (/^[\d -]+$/.test(value)) return `(?<!\\d)(?:${esc(value)}|${value.replace(/[ -]/g, "").split("").join("[ \\t-]*")})(?!\\d)`;
    return `${esc(value)}|(?<![A-Za-z0-9])${value.replace(/[ -]/g, "").split("").map(esc).join("[ \\t-]*")}(?![A-Za-z0-9])`;
  }
  const digits = value.replace(/[\s-]/g, "");
  if (/^\+?\d{10,19}$/.test(digits)) {
    const raw = digits.replace(/^\+/, "");
    const core = raw.replace(/^(?:91|0)(?=[6-9]\d{9}$)/, "");
    const prefix = /^[6-9]\d{9}$/.test(core) ? "(?:(?:\\+?91|0)[ \\t-]*)?" : "(?:\\+[ \\t-]*)?";
    return `(?<![\\d+])(?:${esc(value)}|${prefix}${core.split("").join("[ \\t-]*")})(?!\\d)`;
  }
  if (/^\d+$/.test(value)) return `(?<!\\d)${esc(value)}(?!\\d)`;
  return esc(value);
}

export const KNOWN_CATEGORIES = ["secret", "id", "contact"] as const;
export type KnownCategory = (typeof KNOWN_CATEGORIES)[number];

export interface KnownItem {
  name: string;
  value: string;
  category?: KnownCategory;
}

export interface Finding {
  start: number;
  end: number;
  rule: string;
  kind: string;
  name?: string;
  hash: string;
}

export interface DetectorOptions {
  known?: KnownItem[];
  salt?: string | Buffer;
  rules?: Rule[];
}

export interface RedactResult {
  text: string;
  findings: Finding[];
}

export interface Detector {
  scan: (text: string, context?: string) => Finding[];
  redact: (text: string, replacement?: string) => RedactResult;
  placeholder: (f: Finding) => string;
  hash: (v: string) => string;
  knownCount: number;
}

export function createDetector({ known = [], salt = randomBytes(16), rules = RULES }: DetectorOptions = {}): Detector {
  const hash = (v: string) => createHmac("sha256", salt).update(v).digest("hex").slice(0, 12);
  // Keyed by a digest so the cache never holds request text; only findings (offsets and hashes) are kept.
  const scanCache = new Map<string, Finding[]>();
  const MAX_CACHE_ENTRIES = 20_000;
  const digest = (t: string, c = "") => createHash("sha256").update(t).update("\0").update(c).digest("base64");

  const byValue = new Map<string, KnownItem>();
  for (const k of known) {
    if (!k || typeof k.value !== "string" || !k.value || typeof k.name !== "string" || !k.name) throw Error("Invalid known item");
    if (!byValue.has(k.value)) byValue.set(k.value, k);
  }
  // Longest first so a value that contains another value wins.
  const entries = [...byValue].sort((a, b) => b[0].length - a[0].length);
  const knownRe = entries.length
    ? new RegExp(entries.map(([v, k], i) => `(?<k${i}>${knownPattern(v, k.category)})`).join("|"), "g")
    : null;

  function scan(text: string, context?: string): Finding[] {
    if (typeof text !== "string" || !text.length) return [];
    const cacheKey = text.length >= 256 ? digest(text, context) : undefined;
    if (cacheKey !== undefined) {
      const cached = scanCache.get(cacheKey);
      if (cached) {
        scanCache.delete(cacheKey);
        scanCache.set(cacheKey, cached);
        return cached.map(f => ({ ...f }));
      }
    }
    const out: Finding[] = [];
    if (knownRe) {
      for (const m of text.matchAll(knownRe)) {
        if (!m.groups || m.index === undefined) continue;
        const key = Object.keys(m.groups).find((g) => m.groups![g] !== undefined);
        if (!key) continue;
        const i = +key.slice(1);
        // A formatted alias must not steal the identity of an exact configured value.
        const { value, name } = byValue.get(m[0]) ?? entries[i]![1]; // SAFETY: group k<i> exists only for entries[i]
        out.push({ start: m.index, end: m.index + m[0].length, rule: "known", kind: "known", name, hash: hash(value) });
      }
    }
    for (const r of rules) {
      r.re.lastIndex = 0;
      for (const m of text.matchAll(r.re)) {
        if (m.index === undefined) continue;
        const v = m[0];
        if (r.check && !r.check(v)) continue;
        if (r.keyword) {
          const near = text.slice(Math.max(0, m.index - KEYWORD_WINDOW), m.index + v.length + KEYWORD_WINDOW);
          if (!r.keyword.test(near) && !(context && r.keyword.test(context))) continue;
        }
        out.push({ start: m.index, end: m.index + v.length, rule: r.id, kind: r.kind, hash: hash(v) });
      }
    }
    const findings = dedupe(out);
    if (cacheKey !== undefined) {
      if (scanCache.size >= MAX_CACHE_ENTRIES) scanCache.delete(scanCache.keys().next().value!);
      scanCache.set(cacheKey, findings.map(f => ({ ...f })));
    }
    return findings;
  }

  const placeholder = (f: Finding) => (f.rule === "known" ? `{{vault:#${f.hash.slice(0, 6)}}}` : `{{pii:${f.rule}#${f.hash.slice(0, 6)}}}`);

  // Redact mode is not wired anywhere yet; observe mode only calls scan().
  function redact(text: string, replacement?: string): RedactResult {
    const findings = scan(text);
    let s = text;
    for (const f of mergeSpans(findings).reverse()) s = s.slice(0, f.start) + (replacement ?? placeholder(f)) + s.slice(f.end);
    return { text: s, findings };
  }

  return { scan, redact, placeholder, hash, knownCount: entries.length };
}

function dedupe(findings: Finding[]): Finding[] {
  findings.sort((a, b) => a.start - b.start || (a.rule === "known" ? 0 : 1) - (b.rule === "known" ? 0 : 1) || b.end - a.end);
  let knownEnd = -1, patternEnd = -1;
  return findings.filter(f => {
    if (f.rule === "known") { knownEnd = Math.max(knownEnd, f.end); return true; }
    if (f.end <= Math.max(knownEnd, patternEnd)) return false;
    patternEnd = f.end;
    return true;
  });
}

// Observation retains identities; redaction must cover the complete overlapping span.
function mergeSpans(findings: Finding[]): Finding[] {
  const out: Finding[] = [];
  for (const f of findings) {
    const last = out[out.length - 1];
    if (last && f.start < last.end) {
      const winner = f.rule === "known" && last.rule !== "known" ? f : last;
      out[out.length - 1] = { ...winner, start: last.start, end: Math.max(last.end, f.end) };
      continue;
    }
    out.push(f);
  }
  return out;
}

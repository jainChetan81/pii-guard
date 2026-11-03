// Core detector: own-list exact match first, then rule patterns.
// Pure JS, no deps; runs in Bun and Node >= 20.
import { createHmac, randomBytes } from "node:crypto";
import { RULES, KEYWORD_WINDOW } from "./rules.ts";

const esc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

// Digit-only values (phones, card numbers) may appear with spaces or dashes,
// and phones with a +91 / 0 prefix. Match the bare digits with optional separators.
function knownPattern(value) {
  const digits = value.replace(/[\s-]/g, "");
  if (/^\+?\d{10,19}$/.test(digits)) {
    const core = digits.replace(/^(?:\+?91|0)(?=[6-9]\d{9}$)/, "");
    const prefix = /^[6-9]\d{9}$/.test(core) ? "(?:(?:\\+?91|0)[ -]?)?" : "";
    return `(?<![\\d+])${prefix}${core.split("").join("[ -]?")}(?!\\d)`;
  }
  return esc(value);
}

/**
 * @param {{ known?: {name:string, value:string}[], salt?: string|Buffer, rules?: typeof RULES }} opts
 */
export function createDetector({ known = [], salt = randomBytes(16), rules = RULES } = {}) {
  const hash = (v) => createHmac("sha256", salt).update(v).digest("hex").slice(0, 12);

  const byValue = new Map();
  for (const k of known) if (k?.value && !byValue.has(k.value)) byValue.set(k.value, k.name);
  // Longest first so a value that contains another value wins.
  const entries = [...byValue].sort((a, b) => b[0].length - a[0].length);
  const knownRe = entries.length
    ? new RegExp(entries.map(([v], i) => `(?<k${i}>${knownPattern(v)})`).join("|"), "g")
    : null;

  function scan(text) {
    if (typeof text !== "string" || text.length < 6) return [];
    const out = [];
    if (knownRe) {
      for (const m of text.matchAll(knownRe)) {
        const i = +Object.keys(m.groups).find((g) => m.groups[g] !== undefined).slice(1);
        const [value, name] = entries[i];
        out.push({ start: m.index, end: m.index + m[0].length, rule: "known", kind: "known", name, hash: hash(value) });
      }
    }
    for (const r of rules) {
      r.re.lastIndex = 0;
      for (const m of text.matchAll(r.re)) {
        const v = m[0];
        if (r.check && !r.check(v)) continue;
        if (r.keyword) {
          const near = text.slice(Math.max(0, m.index - KEYWORD_WINDOW), m.index + v.length + KEYWORD_WINDOW);
          if (!r.keyword.test(near)) continue;
        }
        out.push({ start: m.index, end: m.index + v.length, rule: r.id, kind: r.kind, hash: hash(v) });
      }
    }
    return dedupe(out);
  }

  const placeholder = (f) => (f.rule === "known" ? `{{vault:${f.name}}}` : `{{pii:${f.rule}#${f.hash.slice(0, 6)}}}`);

  // Redact mode is not wired anywhere yet; observe mode only calls scan().
  function redact(text) {
    const findings = scan(text);
    let s = text;
    for (const f of [...findings].sort((a, b) => b.start - a.start)) s = s.slice(0, f.start) + placeholder(f) + s.slice(f.end);
    return { text: s, findings };
  }

  return { scan, redact, placeholder, hash, knownCount: entries.length };
}

// Overlapping spans: keep own-list matches over pattern matches, then the longer span.
function dedupe(findings) {
  findings.sort((a, b) => a.start - b.start || (a.rule === "known" ? -1 : 1) || b.end - a.end);
  const out = [];
  for (const f of findings) {
    const last = out[out.length - 1];
    if (last && f.start < last.end) {
      if (f.rule === "known" && last.rule !== "known") out[out.length - 1] = f;
      continue;
    }
    out.push(f);
  }
  return out;
}

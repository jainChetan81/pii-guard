import type { Finding } from "./detector.ts";

const DOTS = "•••••";
const CONTEXT = 20;

/** Masked value: a few edge chars plus a fixed-length mask, so length is not leaked. Vault values show nothing. */
export function maskValue(value: string, rule?: string): string {
  if (rule === "known" || value.length < 6) return DOTS;
  const [head, tail] = value.length >= 16 ? [6, 3] : [2, 1];
  return value.slice(0, head) + DOTS + value.slice(-tail);
}

/** Mask every finding in a slice, and every digit outside them, so context never carries a raw number. */
function maskSpan(text: string, from: number, to: number, findings: Finding[]): string {
  let out = "", at = from;
  for (const f of [...findings].sort((a, b) => a.start - b.start)) {
    if (f.end <= at || f.start >= to) continue;
    out += text.slice(at, Math.max(at, f.start)).replace(/\d/g, "#");
    out += DOTS;
    at = Math.min(to, f.end);
  }
  return (out + text.slice(at, to).replace(/\d/g, "#")).replace(/\s+/g, " ");
}

/** Masked value and about 20 chars of masked context each side. Never returns raw finding text. */
export function preview(text: string, f: Finding, all: Finding[]): { preview: string; context: string } {
  const from = Math.max(0, f.start - CONTEXT), to = Math.min(text.length, f.end + CONTEXT);
  const others = all.filter(o => o !== f);
  const masked = maskValue(text.slice(f.start, f.end), f.rule);
  const context = `${from ? "…" : ""}${maskSpan(text, from, f.start, others)}${masked}${maskSpan(text, f.end, to, others)}${to < text.length ? "…" : ""}`;
  return { preview: masked, context };
}

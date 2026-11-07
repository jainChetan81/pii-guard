import type { Finding } from "./detector.ts";

const DOTS = "•••••";
const CONTEXT = 20;

// Public key prefixes that name the provider, not the secret.
const KEY_PREFIX = /^(?:sk-ant-|sk-or-v1-|sk-proj-|sk-svcacct-|sk-|gh[pousr]_|github_pat_|AKIA|ASIA|ABIA|ACCA|xox[abps]-|AIza)/;

/** Masked value; the mask length is fixed, so the value length is not leaked.
 *  Vault values and short values: nothing. Secrets: provider prefix and last 3 of a long key only.
 *  Emails: domain only. Other PII: 2 + 1 edge chars (6 + 3 from 16 chars). */
export function maskValue(value: string, rule?: string, kind?: string): string {
  if (rule === "known" || value.length < 8) return DOTS;
  if (kind === "secret") {
    const prefix = value.match(KEY_PREFIX)?.[0] || "";
    return prefix && value.length >= 24 ? prefix + DOTS + value.slice(-3) : prefix + DOTS;
  }
  const at = value.lastIndexOf("@");
  if (rule?.startsWith("email") && at > 0) return DOTS + value.slice(at);
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
  const masked = maskValue(text.slice(f.start, f.end), f.rule, f.kind);
  const context = `${from ? "…" : ""}${maskSpan(text, from, f.start, others)}${masked}${maskSpan(text, f.end, to, others)}${to < text.length ? "…" : ""}`;
  return { preview: masked, context };
}

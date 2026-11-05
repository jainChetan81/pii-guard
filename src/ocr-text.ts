// Enhanced OCR text scanning. OCR breaks secrets in predictable ways: unicode dashes,
// spaces around punctuation, a token split by a space, and O/0 or l/1 swaps next to digits.
// Each repair is a separate scan variant; variants only add findings, never remove them.
import type { Detector, Finding } from "./detector.ts";

export type OcrMode = "basic" | "enhanced";
export const OCR_MODES: readonly OcrMode[] = ["basic", "enhanced"];

/** Folds typographic punctuation that OCR emits for ASCII characters. */
export function foldOcrText(text: string): string {
  return text
    .replace(/[\u2010-\u2015\u2212\u2500\u2501\uFE58\uFE63\uFF0D]/g, "-")
    .replace(/[\u2018\u2019\u201A\u2032\u00B4`]/g, "'")
    .replace(/[\u201C\u201D\u201E\u2033]/g, '"')
    .replace(/[\u00A0\u2000-\u200B\u3000]/g, " ");
}

/** Removes spaces OCR inserts around URL and assignment punctuation: "postgres: //a@db. host". */
const tighten = (line: string) => line.replace(/[ \t]*([.:/=])[ \t]*/g, "$1");
/** Joins a token split by OCR word breaks, keeping the space after short words such as "Bearer". */
const joinTokens = (line: string) => line.replace(/(?<=[A-Za-z0-9_.+/=-]{8}) (?=[A-Za-z0-9_.+/=-])/g, "");
/** Joins one line into one token, for long secrets split by a false word break. */
const despace = (line: string) => line.replace(/\s+/g, "");
/** Glyphs OCR reads inside tokens: "@" for 0 before digits ("ICIC@449627"), "¢" for c. */
const glyphFix = (line: string) => line.replace(/\bA[lI1|][zZ2]a(?=[0-9A-Za-z_-])/g, "AIza").replace(/-{3,}(?=(?:BEGIN|END) )/g, "-----").replace(/(?<=(?:BEGIN|END) [A-Z ]*KEY)-{3,}/g, "-----").replace(/(?<=[A-Z0-9])@(?=\d)/g, "0").replace(/\u00A2/g, "c");
/** Fixes letter/digit swaps inside tokens that already mix letters and digits: "KAO1AB1234". */
const digitFix = (line: string) => line.replace(/\b(?=[A-Za-z0-9|]*\d)[A-Za-z0-9|]{4,}\b/g, token =>
  token.replace(/(?<=\d)[Oo]|[Oo](?=\d)/g, "0").replace(/(?<=\d)[Il|]|[Il|](?=\d)/g, "1"));

/**
 * Scans OCR text. Basic mode scans the text as read. Enhanced mode also scans repaired
 * per-line variants. Variant hits keep their rule and value hash; their offsets refer to
 * the variant, so callers must treat OCR offsets as approximate.
 */
export function scanOcrText(text: string, detector: Detector, mode: OcrMode = "enhanced"): Finding[] {
  if (mode === "basic") return detector.scan(text);
  // Raw findings always stay; every repair below only adds. Folding keeps lengths and newlines.
  const findings = detector.scan(text), folded = foldOcrText(text), lines = folded.split("\n");
  const starts: number[] = [];
  for (let i = 0, at = 0; i < lines.length; at += lines[i].length + 1, i++) starts.push(at);
  const lineOf = (offset: number) => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= offset) lo = mid; else hi = mid - 1; } return lo; };
  // One value read two ways must not count twice: a variant hit is new only when its value hash is
  // new and its line has no hit for the same rule and known name. Distinct known values differ by name.
  // ponytail: two different pattern values of one rule on one line, one only visible after repair,
  // count once. Track occurrence spans per variant if labeled data shows this matters.
  const hashes = new Set<string>(), slots = new Set<string>(), lineFor = new Map<Finding, number>();
  const slot = (i: number, f: Finding) => `${i}:${f.rule}:${f.name ?? ""}`;
  const keep = (i: number, f: Finding) => { hashes.add(f.hash); slots.add(slot(i, f)); lineFor.set(f, i); };
  for (const f of findings) keep(lineOf(f.start), f);
  const add = (i: number, f: Finding, span = 1) => {
    if (hashes.has(f.hash)) return;
    for (let k = 0; k < span; k++) if (slots.has(slot(i + k, f))) return;
    for (let k = 1; k < span; k++) slots.add(slot(i + k, f));
    keep(i, f);
    findings.push(f);
  };
  for (const f of detector.scan(folded)) add(lineOf(f.start), f);
  // Whole-line joins can fabricate "scheme://user:pass@host" from separate words, so they
  // only keep distinctive token formats. PII keyword windows would also match across words.
  const joinable = (f: Finding) => f.kind === "secret" && f.rule !== "assigned_secret" && f.rule !== "connection_string";
  for (const [i, line] of lines.entries()) {
    // ponytail: repairs skip lines over 1000 chars, so a text-heavy image cannot stall the event loop.
    // The raw and folded scans above still cover them. Raise the cap if long secret lines show up.
    if (!line.trim() || line.length > 1000) continue;
    const fixed = glyphFix(line);
    const variants = new Set([tighten(line), digitFix(fixed), digitFix(tighten(fixed))]);
    variants.delete(line);
    for (const v of variants) for (const f of detector.scan(v)) add(i, f);
    const joined = joinTokens(tighten(fixed));
    // A joined URL counts only when OCR already read "scheme://user:" as one token, so the
    // join repaired a split password; it never builds credentials from separate words.
    const credentialUrl = /[a-z][a-z0-9+.-]{1,20}:\/\/[^\s/@:]+:\S/i.test(tighten(fixed));
    for (const v of [joined, digitFix(joined)]) for (const f of detector.scan(v)) if (joinable(f)) add(i, f);
    if (credentialUrl) {
      // Join only spaces inside the credential part ("user:pa ss@host"), never across words.
      const url = tighten(fixed).replace(/(:\/\/[^\s/@:]+:)([^@\n]{1,80})(?=@)/, (_, head, pw) => head + pw.replace(/\s+/g, ""));
      for (const f of detector.scan(url)) if (f.rule === "connection_string") add(i, f);
    }
    for (const v of [despace(fixed), digitFix(despace(fixed))]) for (const f of detector.scan(v)) if (joinable(f)) add(i, f);
    // A long token can wrap onto the next line ("Bearer" then the JWT); a pair hit holds both lines.
    if (lines[i + 1]?.trim()) {
      const pair = `${fixed} ${glyphFix(lines[i + 1])}`;
      for (const v of [despace(pair), joinTokens(tighten(pair))]) for (const f of detector.scan(v)) if (joinable(f)) add(i, f, 2);
    }
  }
  // "user:pass@host.net" inside a database URL also reads as an email, even when OCR splits the
  // password. Drop emails on a URL line only when no "@" is left once the URLs are removed.
  // ponytail: a line with a URL and another address keeps the URL email too; fail closed, use spans if noisy.
  const urlLines = new Set(findings.filter(f => f.rule === "connection_string").map(f => lineFor.get(f)));
  const onlyUrlAt = (i: number) => !tighten(lines[i]).replace(/[a-z][a-z0-9+.-]{1,20}:\/\/[^\n]*?@[\w.-]+\.[a-z]{2,}\S*/gi, " ").includes("@");
  return findings.filter(f => f.rule !== "email" || !urlLines.has(lineFor.get(f)) || !onlyUrlAt(lineFor.get(f)!));
}

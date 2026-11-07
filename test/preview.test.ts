import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";
import { maskText, maskValue, preview } from "../src/preview.ts";
const maskValueShort = (v: string) => maskValue(v, "pan", "pii");

test("preview and context never carry raw values or digits", () => {
  const pan = ["ABCPE", "1234", "F"].join("");
  const key = "sk-ant-" + "a1B2c3D4e5F6g7H8i9J0kLmN";
  const vault = "hunter2-staging";
  const d = createDetector({ salt: "s", known: [{ name: "db", value: vault }] });
  const text = `My PAN is ${pan} and key ${key} pass ${vault} call 9876543210 now`;
  const all = d.scan(text);
  expect(all.length).toBeGreaterThanOrEqual(3);
  for (const f of all) {
    const { preview: p, context } = preview(text, f, all);
    for (const raw of [pan, key, vault, "9876543210", "1234"]) {
      expect(p).not.toContain(raw);
      expect(context).not.toContain(raw);
    }
    expect(context).not.toMatch(/\d{3}/);
    expect(context).toContain(p);
  }
  const k = all.find(f => f.rule === "anthropic_key")!;
  expect(preview(text, all.find(f => f.rule === "known")!, all).preview).toBe("•••••");
  expect(preview(text, k, all).preview).toBe("sk-ant-•••••LmN");
});

test("passwords, emails and short values show no raw part", () => {
  const d = createDetector({ salt: "s" });
  const pw = "correct-horse-battery";
  const mail = ["ananya.sharma", "corpmail.in"].join("@");
  const text = `password: ${pw} mail ${mail}`;
  const all = d.scan(text);
  const masks = all.map(f => preview(text, f, all));
  const joined = JSON.stringify(masks);
  for (const raw of [pw, "correct", "ery", "ananya", "sharma"]) expect(joined).not.toContain(raw);
  expect(masks.map(m => m.preview)).toContain("•••••@corpmail.in");
  expect(maskValueShort("AB12CD")).toBe("•••••");
});

test("overlapping findings never leak known values in preview or context", () => {
  const knownValue = "private-domain.test";
  const d = createDetector({ known: [{ name: "domain", value: knownValue }] });
  const text = `user@${knownValue}`;
  const all = d.scan(text);
  expect(all.some(f => f.rule === "email")).toBe(true);
  expect(all.some(f => f.rule === "known")).toBe(true);
  for (const f of all) {
    const result = preview(text, f, all);
    expect(result.preview).not.toContain(knownValue);
    expect(result.context).not.toContain(knownValue);
  }
});

test("maskText masks every finding and merges overlaps", () => {
  const pan = ["ABCPE", "1234", "F"].join("");
  const d = createDetector({ known: [{ name: "frag", value: "PE1234F" }] });
  const text = `Repeat this: PAN ${pan}, mail priya.sharma@corpmail.in end`;
  const out = maskText(text, d.scan(text));
  expect(out).toStartWith("Repeat this: PAN ");
  expect(out).toEndWith(" end");
  expect(out).toContain("•••••@corpmail.in");
  for (const raw of [pan, "PE1234F", "priya.sharma"]) expect(out).not.toContain(raw);
  expect(d.scan(out)).toEqual([]);
});

import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";
import { maskValue, preview } from "../src/preview.ts";
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

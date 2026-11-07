import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";
import { preview } from "../src/preview.ts";

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
  expect(preview(text, k, all).preview).toBe("sk-ant•••••LmN");
  expect(preview(text, all.find(f => f.rule === "known")!, all).preview).toBe("•••••");
});

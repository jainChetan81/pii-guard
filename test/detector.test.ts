// All values here are synthetic. Aadhaar values are random digits with a valid
// Verhoeff check digit; tokens are random strings in real formats.
import { describe, expect, test } from "bun:test";
import { verhoeff } from "../src/rules.ts";
import { createDetector } from "../src/detector.ts";
import { scanBody } from "../src/body.ts";

const INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9];
const D = [[0,1,2,3,4,5,6,7,8,9],[1,2,3,4,0,6,7,8,9,5],[2,3,4,0,1,7,8,9,5,6],[3,4,0,1,2,8,9,5,6,7],[4,0,1,2,3,9,5,6,7,8],[5,9,8,7,6,0,4,3,2,1],[6,5,9,8,7,1,0,4,3,2],[7,6,5,9,8,2,1,0,4,3],[8,7,6,5,9,3,2,1,0,4],[9,8,7,6,5,4,3,2,1,0]];
const P = [[0,1,2,3,4,5,6,7,8,9],[1,5,7,6,2,8,3,0,9,4],[5,8,0,3,7,9,6,1,4,2],[8,9,1,6,0,4,3,5,2,7],[9,4,5,3,1,2,6,8,7,0],[4,2,8,6,5,7,3,9,0,1],[2,7,9,3,8,0,6,4,1,5],[7,0,4,6,9,1,3,2,5,8]];
function withCheck(base: string): string {
  let c = 0;
  for (let i = 0; i < base.length; i++) c = D[c][P[(i + 1) % 8][+base[base.length - 1 - i]]];
  return base + INV[c];
}
const AADHAAR = withCheck("23456789012");
const SECRET = "sk-or-v1-" + "a1b2c3d4".repeat(8);

describe("verhoeff", () => {
  test("accepts valid, rejects one-digit change", () => {
    expect(verhoeff(AADHAAR)).toBe(true);
    const bad = AADHAAR.slice(0, -1) + ((+AADHAAR.at(-1)! + 1) % 10);
    expect(verhoeff(bad)).toBe(false);
  });
});

describe("own list", () => {
  const d = createDetector({ known: [{ name: "pan", value: "ABCPE1234F" }, { name: "phone", value: "+91 98765 43210" }, { name: "openrouter.key", value: SECRET }] });
  test("exact value without keyword", () => {
    expect(d.scan("value is ABCPE1234F here").map((f) => f.name)).toEqual(["pan"]);
  });
  test("phone matches other formatting", () => {
    for (const s of ["9876543210", "98765-43210", "+919876543210", "+91 98765 43210"]) {
      expect(d.scan(`call ${s} now`).map((f) => f.name)).toEqual(["phone"]);
    }
  });
  test("phone does not match inside a longer number", () => {
    expect(d.scan("ts 19876543210123")).toEqual([]);
  });
  test("own-list beats pattern on same span", () => {
    const f = d.scan(`OPENROUTER_API_KEY=${SECRET}`);
    expect(f).toHaveLength(1);
    expect(f[0].rule).toBe("known");
  });
  test("redact uses stable placeholders", () => {
    const a = d.redact("pan ABCPE1234F and ABCPE1234F").text;
    expect(a).toMatch(/^pan (\{\{vault:#[0-9a-f]{6}\}\}) and \1$/);
    expect(a).not.toContain("pan}}");
  });
});

describe("patterns need keywords for weak formats", () => {
  const d = createDetector();
  test("aadhaar with keyword is found", () => {
    expect(d.scan(`Aadhaar: ${AADHAAR.replace(/(\d{4})(?=\d)/g, "$1 ")}`).map((f) => f.rule)).toEqual(["aadhaar"]);
  });
  test("aadhaar-shaped number without keyword is ignored", () => {
    expect(d.scan(`id=${AADHAAR}&x=1`)).toEqual([]);
  });
  test("UUID fragments are ignored", () => {
    expect(d.scan(`aadhaar 550e8400-${AADHAAR.slice(0, 4)}-${AADHAAR.slice(4, 8)}-${AADHAAR.slice(8)}`)).toEqual([]);
  });
  test("phone needs keyword", () => {
    expect(d.scan("ts 9876543210 ms")).toEqual([]);
    expect(d.scan("mobile: 9876543210").map((f) => f.rule)).toEqual(["in_phone"]);
  });
  test("tokens need no keyword", () => {
    expect(d.scan(`x ${SECRET} y`).map((f) => f.rule)).toEqual(["openrouter_key"]);
    expect(d.scan("AKIAABCDEFGHIJKLMNOP").map((f) => f.rule)).toEqual(["aws_access_key"]);
  });
  test("hash is stable per detector and hides value", () => {
    const [a] = d.scan(`x ${SECRET}`);
    const [b] = d.scan(`y ${SECRET}`);
    expect(a.hash).toBe(b.hash);
    expect(a.hash).not.toContain("a1b2");
  });
});

describe("scanBody", () => {
  const d = createDetector({ known: [{ name: "pan", value: "ABCPE1234F" }] });
  test("Anthropic tool_result source and skipped blobs", () => {
    const body = {
      model: "x",
      messages: [
        { role: "user", content: [{ type: "tool_result", tool_use_id: "t1", content: [{ type: "text", text: "PAN ABCPE1234F" }] }] },
        { role: "assistant", content: [{ type: "thinking", thinking: "ok", signature: "ABCPE1234F" }] },
        { role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "A".repeat(4000) } }] },
      ],
    };
    const r = scanBody(body, d);
    expect(r.findings.map((f) => f.source)).toEqual(["user/tool_result"]);
    expect(r.images).toBe(1);
  });
  test("OpenAI Responses function_call_output", () => {
    const body = { input: [{ type: "function_call_output", call_id: "c", output: "ABCPE1234F" }] };
    expect(scanBody(body, d).findings[0].source).toBe("-/function_call_output");
  });
});

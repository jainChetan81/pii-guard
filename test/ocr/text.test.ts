import { expect, test } from "bun:test";
import { createDetector } from "../../src/detector.ts";
import { foldOcrText, OCR_MODES, scanOcrText } from "../../src/ocr/text.ts";

const detector = createDetector({ salt: "ocr-text-test" });
const scan = (text: string) => scanOcrText(text, detector, "enhanced");

test("basic mode preserves detector results and punctuation folds", () => {
  const text = "Contact person@acme.io";
  expect(scanOcrText(text, detector, "basic")).toEqual(detector.scan(text));
  expect(OCR_MODES).toEqual(["basic", "enhanced"]);
  expect(foldOcrText("‘hello’ “world” — test text")).toBe("'hello' \"world\" - test text");
});

test("enhanced repairs OCR breaks without exposing values", () => {
  const jwt = "eyJ" + "a".repeat(12) + ".eyJ" + "b".repeat(12) + "." + "c".repeat(16);
  const router = "sk-or-v1-" + "a".repeat(64);
  const google = "AlZa" + "a".repeat(35);
  const cases: Array<[string, string, string]> = [
    ["postgres: //admin: s3cretPassw0rd@db. internal .acme.io:5432/prod", "connection_string", "s3cretPassw0rd"],
    [jwt.slice(0, 20) + " " + jwt.slice(20), "jwt", jwt],
    ["Vehicle: KAO1AB1234", "vehicle_in", "KAO1AB1234"],
    ["Driving licence: KAO1 2020 1234567", "driving_license_in", "KAO1 2020 1234567"],
    ["Google key: " + google, "google_api_key", google],
    [router.slice(0, 30) + " " + router.slice(30), "openrouter_key", router],
  ];
  for (const [text, rule, value] of cases) {
    const findings = scan(text);
    expect(findings.map(f => f.rule)).toContain(rule);
    expect(JSON.stringify(findings)).not.toContain(value);
    if (rule === "openrouter_key") expect(findings.map(f => f.rule)).not.toContain("openai_key");
  }
});

test("enhanced deduplicates each rule per line", () => {
  const key = "sk-or-v1-" + "a".repeat(64);
  expect(scan(key).filter(f => f.rule === "openrouter_key")).toHaveLength(1);
});

test.each(["see you @ home. Call me at 5 pm.", "Build 0.5.112 deployed at 10:30", "version 1.2.3 released 2026-11-05", "Requests today: 4,812", "This is ordinary prose with no sensitive data."])("enhanced ignores clean text: %s", text => {
  expect(scan(text)).toEqual([]);
});

test("enhanced repairs OCR private key dashes", () => {
  expect(scan("----BEGIN RSA PRIVATE KEY-——-").map(f => f.rule)).toContain("private_key");
});

// Review regressions.
test("raw findings survive folding and distinct repaired known values both count", () => {
  const d = createDetector({ salt: "review", known: [{ name: "a", value: "first.value123" }, { name: "b", value: "second.value456" }, { name: "c", value: "Vault—Value123" }] });
  expect(scanOcrText("first.value123 second . value456", d, "enhanced").map(f => f.name)).toEqual(["a", "b"]);
  expect(scanOcrText("Vault—Value123", d, "enhanced").map(f => f.name)).toEqual(["c"]);
});

test("URL handling keeps unrelated emails and never builds credentials from separate words", () => {
  const d = createDetector({ salt: "review" }), pw = "pg" + "_secret_" + "Ab12";
  const rules = (t: string) => scanOcrText(t, d, "enhanced").map(f => f.rule).sort();
  expect(rules(`Contact ops@acme.io postgres://svc:${pw}@db.internal.net:5432/app`)).toEqual(["connection_string", "email"]);
  expect(rules("Visit https://docs.acme.io Contact: noreply@acme.io")).toEqual([]);
  expect(rules(`postgres://svc:${pw}@db.internal.net Contact: ops@acme.io`)).toEqual(["connection_string", "email"]);
  expect(rules(`postgres://svc:${pw}@db.internal.net:5432/app`)).toEqual(["connection_string"]);
  expect(rules(`DATABASE_URL=postgresql://svc_abcd:${pw.slice(0, 6)} ${pw.slice(6)}@pg-ab9c.internal.net:5432/app`)).toEqual(["connection_string"]);
});

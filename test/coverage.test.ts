import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";
import { scanBody } from "../src/body.ts";

test("known short secrets, foreign phones, and formatted IDs", () => {
  const d = createDetector({ known: [
    { name: "pin", value: "1234" },
    { name: "foreign", value: "+442079460958" },
    { name: "plate", value: "KA01AB1234", category: "id" },
    { name: "numid", value: "234567890123", category: "id" },
  ], rules: [] });
  expect(d.scan("12345678901234").some((f) => f.name === "numid")).toBe(false);
  expect(d.scan("id 2345 6789 0123")[0]!.name).toBe("numid");
  expect(d.scan("1234")[0]!.name).toBe("pin");
  expect(d.scan("+44 2079 460958")[0]!.name).toBe("foreign");
  expect(d.scan("KA-01-AB-1234")[0]!.name).toBe("plate");
  expect(d.scan("prefixKA01AB1234suffix")[0]!.name).toBe("plate");
});

test("redaction covers whole overlapping spans", () => {
  const token = "sk-or-v1-" + "abcdef12".repeat(8);
  const d = createDetector({ known: [{ name: "fragment", value: "abcdef12" }] });
  expect(d.redact(token).text).toMatch(/^\{\{vault:#[0-9a-f]{6}\}\}$/);
});

test("exact configured identity wins over a formatted alias", () => {
  const known = [
    { name: "formatted", value: "4111 1111 1111 1111" },
    { name: "compact", value: "4111111111111111" },
  ];
  const d = createDetector({ known, rules: [] });
  for (const item of known) {
    expect(d.scan(item.value)[0]!.name).toBe(item.name);
    expect(d.scan(item.value)[0]!.hash).toBe(d.hash(item.value));
  }
});

test("short numeric secrets match whole numbers rather than larger number fragments", () => {
  const d = createDetector({ known: [{ name: "pin", value: "909" }], rules: [] });
  expect(d.scan("pin=909")).toHaveLength(1);
  expect(d.scan("1909 9090 19090")).toHaveLength(0);
});

test("observation retains distinct known identities inside one pattern", () => {
  const d = createDetector({ known: [{ name: "mail.user", value: "alice" }, { name: "mail.host", value: "example.test" }] });
  expect(d.scan("alice@example.test").filter(f => f.rule === "known").map(f => f.name)).toEqual(["mail.user", "mail.host"]);
  expect(d.redact("alice@example.test", "[V]").text).toBe("[V]");
});

test("plaintext and arbitrary fields cannot hide as base64 or metadata", () => {
  const value = "syntheticsecret";
  const d = createDetector({ known: [{ name: "secret", value }], rules: [] });
  const r = scanBody({ text: "A".repeat(2048) + value, role: value, type: value, data: value, signature: value, image_url: value }, d);
  expect(r.findings).toHaveLength(6);
  expect(r.findings.every(f => f.source === "-/-")).toBe(true);
});

test("media accounting distinguishes binary data, references, and files", () => {
  const d = createDetector({ known: [{ name: "query", value: "syntheticsecret" }] });
  const r = scanBody({ input: [
    { type: "input_image", image_url: "data:image/png;base64,YQ==" },
    { type: "input_image", image_url: "https://example.test/syntheticsecret" },
    { type: "input_image", file_id: "file-123" },
    { inlineData: { mimeType: "audio/wav", data: "syntheticsecret" } },
    { type: "input_file", file_data: "syntheticsecret" },
  ] }, d);
  expect(r.images).toBe(3);
  expect(r.imageBytes).toBe(1);
  expect(r.unscanned).toEqual({ images: 3, files: 2, opaque: 0 });
  expect(r.findings).toHaveLength(1);
});

test("object keys and media metadata remain observable without leaking paths", () => {
  const secret = "syntheticsecret";
  const d = createDetector({ known: [{ name: "secret", value: secret }], rules: [] });
  const r = scanBody({ [secret]: "value", file_data: secret, inlineData: secret, content: [
    { type: "image", source: { type: "base64", media_type: "image/png", data: "YQ==", note: secret } },
  ] }, d);
  expect(r.findings).toHaveLength(4);
  expect(JSON.stringify(r)).not.toContain(secret);
});

test("plaintext document sources are scanned and audio coverage stays explicit", () => {
  const secret = "SyntheticSecret987";
  const d = createDetector({ known: [{ name: "secret", value: secret }] });
  for (const source of [
    { type: "text", media_type: "text/plain", data: secret },
    { type: "content", content: [{ type: "text", text: secret }] },
    { type: "url", url: `https://example.test/${secret}` },
  ]) expect(scanBody({ type: "document", source }, d).findings).toHaveLength(1);
  const r = scanBody({ type: "input_audio", input_audio: { data: "U1lOVEhFVElD", format: "wav" } }, d);
  expect(r.unscanned.files).toBe(1);
  expect(r.chars).toBeLessThan(20);
});

test("Gemini inline media scans metadata and keys but excludes encoded data", () => {
  const secret = "SyntheticSecret987";
  const d = createDetector({ known: [{ name: "secret", value: secret }], rules: [] });
  const r = scanBody([
    {inlineData:{mimeType:"image/png",data:secret,displayName:secret,[secret]:"label"}},
    {inline_data:{mime_type:secret,data:secret,displayName:secret}},
  ],d);
  expect(r.findings).toHaveLength(4);
  expect(r.unscanned).toEqual({images:1,files:1,opaque:0});
  expect(JSON.stringify(r)).not.toContain(secret);
});

test("India document rules and common PII reject nearby lookalikes", () => {
  const d = createDetector();
  for (const [text, rule] of [
    ["Registration: KA 01 AB 1234", "vehicle_in"],
    ["Vehicle: 22 BH 1234 AA", "vehicle_in"],
    ["Driving licence: KA0120201234567", "driving_license_in"],
    ["card: 4111 1111 1111 1111", "credit_card"],
    ["contact: demo@example.test", "email"],
  ] as const) expect(d.scan(text).some(f => f.rule === rule)).toBe(true);
  for (const text of ["KA01AB1234", "id 4111111111111111", "card: 4111111111111112", "registration XX01AB1234"])
    expect(d.scan(text)).toHaveLength(0);
});

test("all text message formats and tool outputs preserve body", () => {
  const d = createDetector({ known: [{ name: "pan", value: "ABCPE1234F" }] });
  const bodies = [
    { messages: [{ role: "user", content: "ABCPE1234F" }] },
    { messages: [{ role: "tool", content: "ABCPE1234F" }] },
    { messages: [{ role: "user", content: [{ type: "tool_result", content: "ABCPE1234F" }] }] },
    { input: [{ type: "function_call_output", output: "ABCPE1234F" }] },
    { contents: [{ role: "model", parts: [{ text: "ABCPE1234F" }] }] },
  ];
  for (const body of bodies) {
    const before = JSON.stringify(body);
    expect(scanBody(body, d).findings).toHaveLength(1);
    expect(JSON.stringify(body)).toBe(before);
  }
});

test("numeric JSON fields expose known IDs without mutating the body", () => {
  const d = createDetector({ known: [{ name: "numeric-id", value: "234567890123", category: "id" }] });
  const body = { input: [{ type: "function_call_output", output: { identifier: 234567890123 } }] };
  const before = JSON.stringify(body);
  expect(scanBody(body, d).findings.map(f => f.name)).toEqual(["numeric-id"]);
  expect(JSON.stringify(body)).toBe(before);
});

test("configured phone values survive repeated separators and exact whitespace", () => {
  const value = "+91  98765\t 43210";
  const d = createDetector({ known: [{ name: "phone", value, category: "contact" }], rules: [] });
  for (const text of [value, "+91 98765 43210", "+91--98765--43210"])
    expect(d.scan(text)[0]?.name).toBe("phone");
  expect(d.scan("+91 98765 432100")).toHaveLength(0);
});

test("Chat files and Gemini file references keep coverage and metadata visible", () => {
  const value = "SyntheticSecret987";
  const d = createDetector({ known: [{ name: "secret", value }], rules: [] });
  const r = scanBody([
    { type: "file", file: { file_id: "file-synthetic", filename: value, file_data: value } },
    { file_data: { mime_type: "application/pdf", file_uri: `https://example.test/${value}` } },
    { fileData: { mimeType: "application/pdf", fileUri: `https://example.test/${value}` } },
  ], d);
  expect(r.unscanned.files).toBe(3);
  expect(r.findings).toHaveLength(3);
  expect(JSON.stringify(r)).not.toContain(value);
});

test("redacted thinking remains opaque instead of scanning ciphertext", () => {
  const value = "U1lOVEhFVElD";
  const d = createDetector({ known: [{ name: "ciphertext", value }], rules: [] });
  const r = scanBody({ type: "redacted_thinking", data: value }, d);
  expect(r.unscanned.opaque).toBe(1);
  expect(r.findings).toHaveLength(0);
});

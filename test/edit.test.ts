// scanBody(edit) must rewrite every string it scans, so redaction covers what blocking sees.
import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";
import { scanBody } from "../src/body.ts";

const KEY = "sk-proj-" + "Ab3dEf6hIj9kLm2nOp5qRs8tUv1wXy4z";
const d = createDetector();
const shapes: Record<string, unknown> = {
  anthropicSystemString: { system: `key ${KEY}`, messages: [] },
  anthropicSystemBlocks: { system: [{ type: "text", text: KEY }], messages: [] },
  assistantHistory: { messages: [{ role: "assistant", content: KEY }] },
  toolUseInput: { messages: [{ role: "assistant", content: [{ type: "tool_use", id: "t", name: "bash", input: { command: `curl -H "x: ${KEY}"` } }] }] },
  toolResult: { messages: [{ role: "user", content: [{ type: "tool_result", tool_use_id: "t", content: KEY }] }] },
  toolDescription: { tools: [{ name: "x", description: `uses ${KEY}`, input_schema: { type: "object" } }], messages: [] },
  openaiSystem: { messages: [{ role: "system", content: KEY }] },
  openaiToolCalls: { messages: [{ role: "assistant", tool_calls: [{ id: "c", type: "function", function: { name: "f", arguments: JSON.stringify({ k: KEY }) } }] }] },
  openaiTool: { messages: [{ role: "tool", tool_call_id: "c", content: KEY }] },
  responsesInstructions: { instructions: KEY, input: "hi" },
  responsesInputString: { input: `hi ${KEY}` },
  responsesOutput: { input: [{ type: "function_call_output", call_id: "c", output: KEY }] },
  geminiSystem: { systemInstruction: { parts: [{ text: KEY }] }, contents: [] },
  geminiUser: { contents: [{ role: "user", parts: [{ text: KEY }] }] },
  geminiFunctionResponse: { contents: [{ role: "user", parts: [{ functionResponse: { name: "f", response: { out: KEY } } }] }] },
};

test("edit rewrites every scanned string in every request shape", () => {
  for (const [name, body] of Object.entries(shapes)) {
    let calls = 0;
    const r = scanBody(body, d, undefined, (text, found) => { calls++; expect(found.length).toBeGreaterThan(0); return d.redact(text).text; });
    expect([name, r.findings.length > 0]).toEqual([name, true]);
    expect([name, JSON.stringify(body).includes(KEY.slice(8))]).toEqual([name, false]);
    expect(r.findings.some(f => f.readonly)).toBe(false);
    expect(calls).toBeGreaterThan(0);
  }
});

test("keys and media metadata are reported readonly, not silently kept", () => {
  const body = { messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/png", data: "AAAA", note: KEY } }] }], metadata: { [KEY]: 1 } };
  const r = scanBody(body, d, undefined, t => d.redact(t).text);
  expect(r.findings.filter(f => f.readonly).length).toBe(2);
});

test("no edit callback leaves body unchanged", () => {
  const body = { system: KEY, messages: [{ role: "user", content: KEY }] };
  const before = JSON.stringify(body);
  scanBody(body, d);
  expect(JSON.stringify(body)).toBe(before);
});

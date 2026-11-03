// Walk an LLM request body (Anthropic Messages, OpenAI Chat, OpenAI Responses,
// Gemini) and scan every text leaf. Reports where each finding came from.

// Opaque blobs: provider signatures, encrypted reasoning, base64 media.
const SKIP_KEYS = new Set(["signature", "encrypted_content", "data", "image_url", "file_data", "inline_data", "inlineData"]);
const BASE64_BLOB = /^[A-Za-z0-9+/=\r\n]{1024,}$/;

const IMAGE_TYPES = new Set(["image", "input_image", "image_url"]);

/**
 * @returns {{ findings: Array<object>, images: number, imageBytes: number, chars: number }}
 */
export function scanBody(body, detector) {
  const findings = [];
  let images = 0, imageBytes = 0, chars = 0;

  // ctx carries the nearest role and block type, e.g. "user/tool_result".
  function walk(node, ctx, path) {
    if (typeof node === "string") {
      if (node.length > 1024 && BASE64_BLOB.test(node)) return;
      chars += node.length;
      for (const f of detector.scan(node)) findings.push({ ...f, source: `${ctx.role}/${ctx.type}`, path });
      return;
    }
    if (Array.isArray(node)) {
      for (const item of node) walk(item, ctx, path + "[]");
      return;
    }
    if (!node || typeof node !== "object") return;

    // The outermost block type in a message wins: text inside a tool_result
    // reports as tool_result. "message" wrappers do not count as a block type.
    const own = typeof node.type === "string" && node.type !== "message" ? node.type : "-";
    const next = typeof node.role === "string"
      ? { role: node.role, type: own }
      : { role: ctx.role, type: ctx.type === "-" ? own : ctx.type };
    if (IMAGE_TYPES.has(node.type) || node.inline_data || node.inlineData) {
      images++;
      const raw = node.source?.data || node.image_url?.url || node.image_url || node.inline_data?.data || node.inlineData?.data || "";
      if (typeof raw === "string") imageBytes += Math.floor((raw.length * 3) / 4);
    }
    for (const [k, v] of Object.entries(node)) {
      if (SKIP_KEYS.has(k) || k === "role" || k === "type") continue;
      walk(v, next, path ? `${path}.${k}` : k);
    }
  }

  walk(body, { role: "-", type: "-" }, "");
  return { findings, images, imageBytes, chars };
}

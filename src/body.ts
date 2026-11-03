// Walk an LLM request body (Anthropic Messages, OpenAI Chat, OpenAI Responses,
// Gemini) and scan every text leaf. Reports where each finding came from.
import type { Detector, Finding } from "./detector.ts";

// Opaque blobs: provider signatures, encrypted reasoning, base64 media.
// ponytail: image_url strings and file_data skipped unconditionally; inspect URLs or binary mime when non-base64 image URLs need leak checks.
const SKIP_KEYS = new Set(["signature", "encrypted_content", "image_url", "file_data", "inline_data", "inlineData"]);
const BASE64_BLOB = /^[A-Za-z0-9+/=\r\n]{1024,}$/;

const KNOWN_ROLES = new Set(["user", "assistant", "system", "developer", "tool", "model", "function"]);
// Block types are lowercase identifiers; any other "type" value is data.
const TYPE_ID = /^[a-z][a-z0-9_.-]{0,40}$/;

const IMAGE_TYPES = new Set(["image", "input_image", "image_url"]);

export interface BodyFinding extends Finding {
  source: string;
  path: string;
}

export interface BodyScanResult {
  findings: BodyFinding[];
  images: number;
  imageBytes: number;
  chars: number;
}

interface Context {
  role: string;
  type: string;
}

export function scanBody(body: any, detector: Detector): BodyScanResult {
  const findings: BodyFinding[] = [];
  let images = 0, imageBytes = 0, chars = 0;

  // ctx carries the nearest role and block type, e.g. "user/tool_result".
  function walk(node: any, ctx: Context, path: string): void {
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
    const isRole = typeof node.role === "string" && KNOWN_ROLES.has(node.role);
    const own = typeof node.type === "string" && TYPE_ID.test(node.type) && node.type !== "message" ? node.type : "-";
    const next = isRole
      ? { role: node.role, type: own }
      : { role: ctx.role, type: ctx.type === "-" ? own : ctx.type };
    if (IMAGE_TYPES.has(node.type) || node.inline_data || node.inlineData) {
      images++;
      const raw = node.source?.data || node.image_url?.url || node.image_url || node.inline_data?.data || node.inlineData?.data || "";
      if (typeof raw === "string") imageBytes += Math.floor((raw.length * 3) / 4);
    }
    for (const [k, v] of Object.entries(node)) {
      if (SKIP_KEYS.has(k)) continue;
      if (k === "role" && typeof v === "string" && KNOWN_ROLES.has(v)) continue;
      if (k === "type" && typeof v === "string" && TYPE_ID.test(v)) continue;
      walk(v, next, path ? `${path}.${k}` : k);
    }
  }

  walk(body, { role: "-", type: "-" }, "");
  return { findings, images, imageBytes, chars };
}

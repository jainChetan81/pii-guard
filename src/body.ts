// Scan text and report media coverage without changing the request.
import type { Detector, Finding } from "./detector.ts";

const ROLES = new Set(["user", "assistant", "system", "developer", "tool", "model", "function"]);
const TYPES = new Set(["text", "input_text", "output_text", "tool_result", "tool_use", "function_call", "function_call_output", "thinking", "redacted_thinking", "reasoning", "image", "input_image", "image_url", "document", "input_file", "file"]);
const IMAGE_TYPES = new Set(["image", "input_image", "image_url"]);
const PATH_KEYS = new Set(["messages", "input", "contents", "parts", "content", "text", "output", "role", "type", "source", "image_url", "data", "inlineData", "inline_data", "file_data", "fileData", "url", "model", "arguments", "tool_calls", "function", "name"]);

export interface BodyFinding extends Finding {
  source: string;
  path: string;
  // Set when an edit callback was given but this text could not be rewritten (object keys, media metadata).
  readonly?: true;
}

// Returns the replacement text. Receives the findings already computed for this string, so nothing is scanned twice.
export type BodyEdit = (text: string, findings: BodyFinding[]) => string;

export interface BodyScanResult {
  findings: BodyFinding[];
  images: number;
  imageBytes: number;
  chars: number;
  unscanned: { images: number; files: number; opaque: number };
}

export interface ImageInput { data?: string; mime?: string; source: string; path: string }
interface Context { role: string; type: string; ro?: boolean }

// With `edit`, every scanned string that sits in the real body is replaced in place by edit's result.
// Findings flagged `readonly` (object keys, numbers, media metadata copies) stay in the body: callers must block or report them.
// The walk mutates as it goes; if it throws, discard the body. A bare string body cannot be edited in place.
export function scanBody(body: unknown, detector: Detector, onImage?: (image: ImageInput) => void, edit?: BodyEdit): BodyScanResult {
  const result: BodyScanResult = { findings: [], images: 0, imageBytes: 0, chars: 0, unscanned: { images: 0, files: 0, opaque: 0 } };

  // Returns the replacement for a string node; any other node is edited in place.
  function walk(node: any, ctx: Context, path: string, depth = 0): any {
    if (depth > 100) throw Error("Request nesting limit exceeded");
    // Numbers are scanned as text but never rewritten, so the body keeps its types.
    if (typeof node === "number" && Number.isFinite(node)) { walk(String(node), { ...ctx, ro: true }, path, depth); return node; }
    if (typeof node === "string") {
      result.chars += node.length;
      const found: BodyFinding[] = detector.scan(node).map(f => ({ ...f, source: `${ctx.role}/${ctx.type}`, path, ...(edit && ctx.ro && { readonly: true as const }) }));
      result.findings.push(...found);
      return edit && !ctx.ro && found.length ? edit(node, found) : node;
    }
    if (Array.isArray(node)) {
      node.forEach((item, i) => { const out = walk(item, ctx, `${path}[${i}]`, depth + 1); if (out !== item) node[i] = out; });
      return node;
    }
    if (!node || typeof node !== "object") return node;
    const own = TYPES.has(node.type) ? node.type : "-";
    // Signed thinking must be replayed byte-for-byte (the provider rejects edits), so it is readonly.
    const signed = ctx.ro || (node.type === "thinking" && typeof node.signature === "string");
    const next: Context = ROLES.has(node.role)
      ? { role: node.role, type: own, ro: signed }
      : { role: ctx.role, type: ctx.type === "-" ? own : ctx.type, ro: signed };
    // Metadata copies are scanned but cannot be rewritten in the real body.
    const copy: Context = { ...next, ro: true };
    const skip = new Set<string>();
    const candidate = node.inline_data || node.inlineData;
    const inline = candidate && typeof candidate === "object" && typeof candidate.data === "string" && typeof (candidate.mime_type || candidate.mimeType) === "string" ? candidate : undefined;
    const mime = inline?.mime_type || inline?.mimeType || node.source?.media_type;
    const fileReference = node.fileData || node.file_data;
    if (IMAGE_TYPES.has(node.type) || (inline && typeof mime === "string" && mime.startsWith("image/"))) {
      result.images++;
      result.unscanned.images++;
      let data = inline?.data || (node.source?.type === "base64" ? node.source.data : undefined);
      let imageMime = mime;
      const url = node.image_url?.url || node.image_url || node.source?.url;
      if (typeof url === "string") {
        const match = /^data:(image\/[a-z0-9.+-]+);base64,([\s\S]*)$/i.exec(url);
        if (match) { imageMime = match[1]; data = match[2]; }
        else if (!url.startsWith("data:")) walk(url, copy, `${path}.url`, depth + 1);
      }
      if (typeof data === "string") {
        const compact = data.replace(/\s/g, "");
        result.imageBytes += Math.max(0, Math.floor(compact.length * 3 / 4) - (compact.endsWith("==") ? 2 : compact.endsWith("=") ? 1 : 0));
      }
      onImage?.({ data: typeof data === "string" ? data : undefined, mime: imageMime, source: `${next.role}/${next.type}`, path });
      if (node.source && typeof node.source === "object") {
        const { data: encoded, url: reference, ...metadata } = node.source;
        walk(typeof data === "string" ? metadata : { ...metadata, data: encoded }, copy, `${path}.source`, depth + 1);
      }
      if (node.image_url && typeof node.image_url === "object") {
        const { url: reference, ...metadata } = node.image_url;
        walk(metadata, copy, `${path}.image_url`, depth + 1);
      }
      ["source", "image_url", "inline_data", "inlineData"].forEach(k => skip.add(k));
    } else if ((node.input_audio && typeof node.input_audio === "object") || (node.type === "audio" && typeof node.data === "string")) {
      result.unscanned.files++;
      skip.add("data");
      if (node.input_audio) {
        const { data: encoded, ...metadata } = node.input_audio;
        walk(metadata, copy, `${path}.input_audio`, depth + 1);
        skip.add("input_audio");
      }
    } else if (inline || (node.type === "document" && !["text", "content"].includes(node.source?.type)) || node.type === "input_file" || node.type === "file" || (fileReference && typeof (fileReference.fileUri || fileReference.file_uri) === "string")) {
      result.unscanned.files++;
      if (node.source && typeof node.source === "object") {
        const { data: encoded, ...metadata } = node.source;
        walk(node.source.type === "base64" ? metadata : node.source, node.source.type === "base64" ? copy : next, `${path}.source`, depth + 1);
        skip.add("source");
      }
      if (node.type === "file" && node.file && typeof node.file === "object") {
        const { file_data: encoded, ...metadata } = node.file;
        walk(metadata, copy, `${path}.file`, depth + 1);
        skip.add("file");
      }
      ["inline_data", "inlineData"].forEach(k => skip.add(k));
      if (typeof node.file_data === "string") skip.add("file_data");
    }
    for (const key of ["inline_data", "inlineData"]) if (skip.has(key) && node[key]) {
      const value = node[key];
      if (typeof value === "object" && typeof value.data === "string" && typeof (value.mime_type || value.mimeType) === "string") {
        const { data: encoded, ...metadata } = value;
        walk(metadata, copy, `${path}.${key}`, depth + 1);
      } else { const out = walk(value, next, `${path}.${key}`, depth + 1); if (out !== value) node[key] = out; }
    }
    for (const [index, [key, value]] of Object.entries(node).entries()) {
      for (const f of detector.scan(key)) result.findings.push({ ...f, source: `${next.role}/${next.type}`, path: `${path}[key:${index}]`, ...(edit && { readonly: true as const }) });
      if (skip.has(key)) continue;
      if ((key === "signature" && node.type === "thinking") || (key === "data" && node.type === "redacted_thinking") || (key === "encrypted_content" && node.type === "reasoning")) {
        result.unscanned.opaque++;
        continue;
      }
      // Even structural-looking fields can contain user data. Do not skip by key alone.
      const field = PATH_KEYS.has(key) ? key : `[field:${index}]`;
      const out = walk(value, next, path ? `${path}.${field}` : field, depth + 1);
      if (out !== value) node[key] = out;
    }
    return node;
  }
  // A bare string body cannot be edited in place, so its findings are readonly.
  walk(body, { role: "-", type: "-", ro: typeof body === "string" }, "");
  return result;
}

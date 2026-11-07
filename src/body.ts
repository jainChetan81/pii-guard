// Scan text and report media coverage without changing the request.
import { preview } from "./preview.ts";
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
  // Masked value and masked surrounding text; never raw. Safe to log.
  preview?: string;
  context?: string;
}

// Returns the replacement text. Receives the findings already computed for this string, so nothing is scanned twice.
export type BodyEdit = (text: string, findings: BodyFinding[]) => string;

type Json = Record<string, unknown>;
// Arrays count too: the walker spreads any object-like provider field, and a property read on an array is undefined.
const isObject = (v: unknown): v is Json => !!v && typeof v === "object";
const rec = (v: unknown): Json => (isObject(v) ? v : {});
const str = (v: unknown): string | undefined => (typeof v === "string" ? v : undefined);

// Sibling keys and short values give keyword-gated rules context, e.g. {"label":"PAN","value":"..."}.
const CONTEXT_CHARS = 512, SHORT_VALUE = 64;
function siblingContext(fields: [string, unknown][], except: number): string {
  const parts: string[] = [];
  let chars = 0;
  const add = (value: string) => {
    if (chars >= CONTEXT_CHARS) return;
    const separator = parts.length ? " " : "";
    const part = value.slice(0, CONTEXT_CHARS - chars - separator.length);
    if (!part) return;
    parts.push(part);
    chars += separator.length + part.length;
  };
  for (const [i, [key, value]] of fields.entries()) {
    if (chars >= CONTEXT_CHARS) break;
    add(key);
    if (i !== except && typeof value === "string" && value.length <= SHORT_VALUE) add(value);
  }
  return parts.join(" ");
}

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
  function walk(node: unknown, ctx: Context, path: string, depth = 0, scanContext?: string): unknown {
    if (depth > 100) throw Error("Request nesting limit exceeded");
    // Numbers are scanned as text but never rewritten, so the body keeps its types.
    if (typeof node === "number" && Number.isFinite(node)) { walk(String(node), { ...ctx, ro: true }, path, depth, scanContext); return node; }
    if (typeof node === "string") {
      result.chars += node.length;
      const raw = detector.scan(node, scanContext);
      const found: BodyFinding[] = raw.map(f => ({ ...preview(node, f, raw), ...f, source: `${ctx.role}/${ctx.type}`, path, ...(edit && ctx.ro && { readonly: true as const }) }));
      result.findings.push(...found);
      return edit && !ctx.ro && found.length ? edit(node, found) : node;
    }
    if (Array.isArray(node)) {
      node.forEach((item, i) => { const out = walk(item, ctx, `${path}[${i}]`, depth + 1); if (out !== item) node[i] = out; });
      return node;
    }
    if (!isObject(node)) return node;
    const type = str(node.type), role = str(node.role), source = rec(node.source);
    const own = type !== undefined && TYPES.has(type) ? type : "-";
    // Signed thinking must be replayed byte-for-byte (the provider rejects edits), so it is readonly.
    const signed = ctx.ro || (node.type === "thinking" && typeof node.signature === "string");
    const next: Context = role !== undefined && ROLES.has(role)
      ? { role, type: own, ro: signed }
      : { role: ctx.role, type: ctx.type === "-" ? own : ctx.type, ro: signed };
    // Metadata copies are scanned but cannot be rewritten in the real body.
    const copy: Context = { ...next, ro: true };
    const skip = new Set<string>();
    const candidate = node.inline_data || node.inlineData;
    const inline = isObject(candidate) && typeof candidate.data === "string" && typeof (candidate.mime_type || candidate.mimeType) === "string" ? candidate : undefined;
    const mime = inline?.mime_type || inline?.mimeType || source.media_type;
    const fileReference = rec(node.fileData || node.file_data);
    if ((type !== undefined && IMAGE_TYPES.has(type)) || (inline && typeof mime === "string" && mime.startsWith("image/"))) {
      result.images++;
      result.unscanned.images++;
      let data = inline?.data || (source.type === "base64" ? source.data : undefined);
      let imageMime = mime;
      const url = rec(node.image_url).url || node.image_url || source.url;
      if (typeof url === "string") {
        const match = /^data:(image\/[a-z0-9.+-]+);base64,([\s\S]*)$/i.exec(url);
        if (match) { imageMime = match[1]; data = match[2]; }
        else if (!url.startsWith("data:")) walk(url, copy, `${path}.url`, depth + 1);
      }
      if (typeof data === "string") {
        const compact = data.replace(/\s/g, "");
        result.imageBytes += Math.max(0, Math.floor(compact.length * 3 / 4) - (compact.endsWith("==") ? 2 : compact.endsWith("=") ? 1 : 0));
      }
      onImage?.({ data: str(data), mime: str(imageMime), source: `${next.role}/${next.type}`, path });
      if (isObject(node.source)) {
        const { data: encoded, url: reference, ...metadata } = node.source;
        walk(typeof data === "string" ? metadata : { ...metadata, data: encoded }, copy, `${path}.source`, depth + 1);
      }
      if (isObject(node.image_url)) {
        const { url: reference, ...metadata } = node.image_url;
        walk(metadata, copy, `${path}.image_url`, depth + 1);
      }
      ["source", "image_url", "inline_data", "inlineData"].forEach(k => skip.add(k));
    } else if (isObject(node.input_audio) || (node.type === "audio" && typeof node.data === "string")) {
      result.unscanned.files++;
      skip.add("data");
      if (isObject(node.input_audio)) {
        const { data: encoded, ...metadata } = node.input_audio;
        walk(metadata, copy, `${path}.input_audio`, depth + 1);
        skip.add("input_audio");
      }
    } else if (inline || (node.type === "document" && source.type !== "text" && source.type !== "content") || node.type === "input_file" || node.type === "file" || typeof (fileReference.fileUri || fileReference.file_uri) === "string") {
      result.unscanned.files++;
      if (isObject(node.source)) {
        const { data: encoded, ...metadata } = node.source;
        walk(node.source.type === "base64" ? metadata : node.source, node.source.type === "base64" ? copy : next, `${path}.source`, depth + 1);
        skip.add("source");
      }
      if (node.type === "file" && isObject(node.file)) {
        const { file_data: encoded, ...metadata } = node.file;
        walk(metadata, copy, `${path}.file`, depth + 1);
        skip.add("file");
      }
      ["inline_data", "inlineData"].forEach(k => skip.add(k));
      if (typeof node.file_data === "string") skip.add("file_data");
    }
    for (const key of ["inline_data", "inlineData"]) if (skip.has(key) && node[key]) {
      const value = node[key];
      if (isObject(value) && typeof value.data === "string" && typeof (value.mime_type || value.mimeType) === "string") {
        const { data: encoded, ...metadata } = value;
        walk(metadata, copy, `${path}.${key}`, depth + 1);
      } else { const out = walk(value, next, `${path}.${key}`, depth + 1); if (out !== value) node[key] = out; }
    }
    const fields = Object.entries(node);
    for (const [index, [key, value]] of fields.entries()) {
      { const raw = detector.scan(key); for (const f of raw) result.findings.push({ ...preview(key, f, raw), ...f, source: `${next.role}/${next.type}`, path: `${path}[key:${index}]`, ...(edit && { readonly: true as const }) }); }
      if (skip.has(key)) continue;
      if ((key === "signature" && node.type === "thinking") || (key === "data" && node.type === "redacted_thinking") || (key === "encrypted_content" && node.type === "reasoning")) {
        result.unscanned.opaque++;
        continue;
      }
      // Even structural-looking fields can contain user data. Do not skip by key alone.
      const field = PATH_KEYS.has(key) ? key : `[field:${index}]`;
      const siblings = typeof value === "string" || (typeof value === "number" && Number.isFinite(value)) ? siblingContext(fields, index) : undefined;
      const out = walk(value, next, path ? `${path}.${field}` : field, depth + 1, siblings);
      if (out !== value) node[key] = out;
    }
    return node;
  }
  // A bare string body cannot be edited in place, so its findings are readonly.
  walk(body, { role: "-", type: "-", ro: typeof body === "string" }, "");
  return result;
}

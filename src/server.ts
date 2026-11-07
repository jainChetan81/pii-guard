// HTTP sidecar: any service can scan request bodies and images without embedding the library.
// Responses carry hashes and counts only, never input text, OCR text, or image bytes.
import { createServer, type IncomingMessage, type Server } from "node:http";
import { timingSafeEqual } from "node:crypto";
import { scanBody } from "./body.ts";
import { createDetector, type DetectorOptions } from "./detector.ts";
import { createOcrWorker } from "./ocr/worker.ts";
import type { ImageInput, OcrMode, OcrResult, OcrWorker } from "./ocr/contract.ts";

const MAX_BODY = 32 * 1024 * 1024, MAX_IMAGE = 20 * 1024 * 1024, MAX_IMAGES = 8, DEADLINE_MS = 60_000;
const LOOPBACK = new Set(["127.0.0.1", "::1", "[::1]", "localhost"]);
const tokens = new WeakMap<Server, string>();

export interface ScanServerOptions { detector: DetectorOptions; token?: string; worker?: OcrWorker; mode?: OcrMode }

class HttpError extends Error {
  status: number; code: string;
  constructor(status: number, code: string) { super(code); this.status = status; this.code = code; }
}

function read(req: IncomingMessage, limit: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []; let size = 0;
    req.on("data", (c: Buffer) => {
      size += c.length;
      if (size > limit) { chunks.length = 0; reject(new HttpError(413, "too_large")); return; } // drain, then answer 413
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function authorized(req: IncomingMessage, token?: string): boolean {
  if (!token) return true;
  const got = Buffer.from(req.headers.authorization?.replace(/^Bearer /, "") || ""), want = Buffer.from(token);
  return got.length === want.length && timingSafeEqual(got, want);
}

export function createScanServer(options: ScanServerOptions): Server {
  const detector = createDetector(options.detector);
  const worker = options.worker || createOcrWorker({ detector: options.detector, mode: options.mode });
  const server = createServer(async (req, res) => {
    const send = (status: number, body: unknown) => {
      if (res.headersSent) return;
      res.writeHead(status, { "content-type": "application/json", "cache-control": "no-store", ...(status === 413 && { connection: "close" }) }).end(JSON.stringify(body));
    };
    try {
      if (!authorized(req, options.token)) throw new HttpError(401, "unauthorized");
      if (req.method === "GET" && req.url === "/health") return send(200, { ok: true });
      if (req.method !== "POST") throw new HttpError(405, "method_not_allowed");
      if (req.url === "/scan/image") {
        const data = await read(req, MAX_IMAGE);
        if (!data.length) throw new HttpError(400, "empty");
        const result = await worker.scan({ data: data.toString("base64"), source: "http", path: "image" });
        if (result.reason === "unsupported") throw new HttpError(415, "unsupported");
        if (result.reason === "queue_full") throw new HttpError(429, "queue_full");
        return send(200, result);
      }
      if (req.url === "/scan") {
        let body: unknown;
        try { const parsed: unknown = JSON.parse((await read(req, MAX_BODY)).toString("utf8")); body = parsed && typeof parsed === "object" && "body" in parsed ? parsed.body : undefined; } catch (e) { if (e instanceof HttpError) throw e; throw new HttpError(400, "invalid_json"); }
        if (body === undefined) throw new HttpError(400, "missing_body");
        const images: ImageInput[] = [];
        const text = scanBody(body, detector, image => images.push(image));
        const findings = text.findings.map(({ rule, name, kind, hash, source, path }) => ({ rule, name, kind, hash, source, path }));
        const ocr: OcrResult[] = await Promise.all(images.slice(0, MAX_IMAGES).map(image => worker.scan(image)));
        return send(200, { text: { ...text, findings }, ocr, ocrSkipped: Math.max(0, images.length - MAX_IMAGES) });
      }
      throw new HttpError(404, "not_found");
    } catch (error) {
      const e = error instanceof HttpError ? error : new HttpError(500, "internal");
      send(e.status, { error: e.code });
    }
  });
  server.requestTimeout = DEADLINE_MS;
  server.headersTimeout = 10_000;
  server.maxConnections = 32;
  server.on("close", () => { if (!options.worker) void worker.close(); });
  if (options.token) tokens.set(server, options.token);
  return server;
}

/** Refuses non-loopback binding unless the server itself enforces a token. */
export function listen(server: Server, host: string, port: number): Promise<void> {
  if (!LOOPBACK.has(host) && !tokens.get(server)) return Promise.reject(Error("Non-loopback binding requires PII_GUARD_TOKEN"));
  return new Promise((resolve, reject) => { server.once("error", reject); server.listen(port, host, () => resolve()); });
}

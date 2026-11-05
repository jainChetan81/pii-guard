// Synthetic values only. FAKE is assembled at runtime so secret scanners do not flag test fixtures.
const FAKE = ["Xk82", "mPq0vL"].join("");
import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";
import { RULES, GROUPS } from "../src/rules.ts";

const d = createDetector();
const rules = (s: string) => d.scan(s).map(f => f.rule);

test("email ignores bot and placeholder addresses", () => {
  for (const s of ["git@github.com:org/repo", "noreply@acme.io", "x@example.com", "1+u@users.noreply.github.com"]) expect(rules(s)).toEqual([]);
  expect(rules("mail priya.k@acme.io")).toEqual(["email"]);
});

test("obfuscated emails", () => {
  for (const s of ["test.user (at) acme dot com", "test.user [at] acme [dot] com", "test.user%40acme.com"]) expect(rules(s)).toEqual(["email_obfuscated"]);
  expect(rules("look at the cat")).toEqual([]);
});

test("connection string wins over email", () => {
  const f = d.scan("postgres://admin:S3cretPass@db.internal:5432/app");
  expect(f.map(x => x.rule)).toEqual(["connection_string"]);
  expect(d.redact("url postgres://admin:S3cretPass@db.internal:5432/app").text).toMatch(/^url \{\{pii:connection_string#\w+\}\}\/app$/);
  expect(rules("https://example.com/a@b")).toEqual([]);
});

test("assigned secret redacts value only", () => {
  expect(d.redact(`password=${FAKE}Secret!`).text).toMatch(/^password=\{\{pii:assigned_secret#\w+\}\}$/);
  expect(rules(`"api_key": "k9f8a7s6d5f4"`)).toEqual(["assigned_secret"]);
  for (const s of ["password: string", "token: z.string()", "api_key = process.env.API_KEY", "password=changeme", "x-api-key: $ANTHROPIC_API_KEY", "password: <secret-here>", "password: [hidden-1234]", "secret: true"]) expect(rules(s)).toEqual([]);
});

test("US SSN needs keyword and valid areas", () => {
  expect(rules("SSN 123-45-6789")).toEqual(["us_ssn"]);
  expect(rules("id 123-45-6789")).toEqual([]);
  for (const s of ["ssn 000-12-3456", "ssn 666-12-3456", "ssn 912-12-3456", "ssn 123-00-4567"]) expect(rules(s)).toEqual([]);
});

test("IP addresses separate public and private ranges", () => {
  expect(rules("server at 52.14.200.7 now")).toEqual(["ip_address"]);
  for (const s of ["172.15.1.2", "172.32.1.2", "100.63.1.2", "100.128.1.2"]) {
    expect(rules(s)).toContain("ip_address");
    expect(rules(s)).not.toContain("ip_private");
  }
  for (const s of ["10.0.0.5", "172.16.1.2", "172.31.1.2", "192.168.1.1", "100.64.1.2", "100.127.1.2"]) {
    expect(rules(s)).toContain("ip_private");
    expect(rules(s)).not.toContain("ip_address");
  }
  for (const s of ["127.0.0.1", "0.1.2.3", "10.1.2.0", "10.1.2.255", "10.1.256.2", "192.168.1.999", "8.8.8.8", "203.0.113.9", "999.1.1.1", "12.0.0.0/8", "version 1.2.3.4.5", "version 1.2.3.4", "version 10.1.2.3", "v 52.14.200.7", "build: 52.1.2.3", "v20.11.1.0-beta"]) expect(rules(s)).toEqual([]);
});

test("assigned secret inside env-style names", () => {
  for (const s of [`token=${FAKE}Secret!`, `DB_PASSWORD=${FAKE}`, `STRIPE_SECRET=${FAKE}`, `MY_API_KEY: ${FAKE}`]) expect(rules(s)).toEqual(["assigned_secret"]);
  expect(rules(`compassword=${FAKE}`)).toEqual([]);
});

test("reserved-domain emails and placeholder secrets are ignored", () => {
  for (const s of [
    "admin@db.internal", "svc@printer.local",
    "accessToken: newCreds.accessToken", "const token = request.headers.get('x')",
    "POSTGRES_PASSWORD=YOUR_DB_PASSWORD", "ANTHROPIC_API_KEY=your-key-here", "OPENAI_API_KEY=sk-proj-...",
    "Token: gho_************************************", "page_token='13296514984237052716'",
    "login token: ~/.google_workspace_mcp/credentials/", "a {{secret:openrouter_key}} b",
    "K=${ANTHROPIC_AUTH_TOKEN:-$ANTHROPIC_API_KEY}", "secret: True\\n600",
    "e.g. `scheme://user:pass@host`", "postgres://miniflux:YOUR_DB_PASSWORD@db",
  ]) expect(rules(s)).toEqual([]);
  expect(rules(`client secret: GOCSPX-${FAKE}abcdEFGH`)).toEqual(["assigned_secret"]);
  expect(rules(`postgres://app:${FAKE}@db.prod.acme.io/x`)).toEqual(["connection_string"]);
});

test("every rule has a known group and a label", () => {
  const ids = new Set(GROUPS.map(g => g.id));
  for (const r of RULES) { expect(ids.has(r.group!)).toBe(true); expect(r.label?.length).toBeGreaterThan(0); }
});

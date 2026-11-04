// Synthetic values only.
import { expect, test } from "bun:test";
import { createDetector } from "../src/detector.ts";

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
  expect(d.redact("password=Hunter2SuperSecret!").text).toMatch(/^password=\{\{pii:assigned_secret#\w+\}\}$/);
  expect(rules(`"api_key": "k9f8a7s6d5f4"`)).toEqual(["assigned_secret"]);
  for (const s of ["password: string", "token: z.string()", "api_key = process.env.API_KEY", "password=changeme", "x-api-key: $ANTHROPIC_API_KEY", "password: <secret-here>", "password: [hidden-1234]", "secret: true"]) expect(rules(s)).toEqual([]);
});

test("US SSN needs keyword and valid areas", () => {
  expect(rules("SSN 123-45-6789")).toEqual(["us_ssn"]);
  expect(rules("id 123-45-6789")).toEqual([]);
  for (const s of ["ssn 000-12-3456", "ssn 666-12-3456", "ssn 912-12-3456", "ssn 123-00-4567"]) expect(rules(s)).toEqual([]);
});

test("IP address: public only", () => {
  expect(rules("server at 52.14.200.7 now")).toEqual(["ip_address"]);
  for (const s of ["127.0.0.1", "10.0.0.5", "192.168.1.1", "172.20.0.1", "100.101.2.3", "8.8.8.8", "203.0.113.9", "999.1.1.1", "12.0.0.0/8", "version 1.2.3.4.5", "version 1.2.3.4", "v 52.14.200.7", "build: 52.1.2.3", "v20.11.1.0-beta"]) expect(rules(s)).toEqual([]);
});

test("assigned secret inside env-style names", () => {
  for (const s of ["DB_PASSWORD=Xk82mPq0vL", "STRIPE_SECRET=Xk82mPq0vL", "MY_API_KEY: Xk82mPq0vL"]) expect(rules(s)).toEqual(["assigned_secret"]);
  expect(rules("compassword=Xk82mPq0vL")).toEqual([]);
});

# PII Guard

This TypeScript library detects known values and personal data in requests and files.

- Shared rules: `~/AGENTS.md`.
- `src/index.ts` exports the library; `src/ocr/` contains local OCR tools.
- `bin/pii-guard.ts` provides the CLI; `test/` contains tests and fixtures.
- `scripts/` generates OCR fixture images; `docs/` holds research and validation.
- Install dependencies with `bun install --frozen-lockfile`.
- Run focused tests with `nice -n 19 bun test test/detector.test.ts`.
- Run `bun run build` to create `dist/index.js` for Node.
- 9Router loads the built module through `PII_GUARD_MODULE` on the VPS.
- Rebuild after changes; the gateway loads the module once per process.
- The caller controls observe, redact, and block policy.
- OCR runs locally; image findings do not mean images were redacted.
- See `~/Services/9router/README.md` and this repository's README.

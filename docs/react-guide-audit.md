# React guide audit

Source: `~/Documentation/frontend/react.md`. Checked against `main` at `2918885` on 2026-11-07.

pii-guard is a Bun TypeScript CLI, library, and HTTP sidecar with no UI. The guide says an existing repo keeps its own conventions, so Bun and `bun test` stay. Sections that do not apply: framework, routing, Query, styling, fonts, motion, i18n, render modes, and browser security. The rules that apply are §5 Types and Constants, §10 Testing, and §11 Quality gates.

## Fix first

1. **Failing test on `main`.** `test/coverage.test.ts:20` ("redaction covers whole overlapping spans") fails. Its input starts with `{{pii:assigned_secret#59b9f8}}`. A fake token was likely redacted by the gateway and then committed. Build the fake token from parts at runtime so the full token never appears in source.
2. **Redaction damage outside this repo.** `~/AGENTS.md` says `public IP {{pii:ip_address#bec568}}`. Search docs and tests written through the gateway for `{{pii:` and `{{vault:`.

## Types (guide §5)

3. Remove `any` at trust boundaries:
   - `bin/pii-guard.ts:29`: `o: Record<string, any>`. Use the typed `parseArgs` result.
   - `bin/pii-guard.ts:70`: inline `.some((x: any) => …)` check. Add an `isKnownItem(x: unknown): x is KnownItem` guard and `const CATEGORIES = ['secret', 'id', 'contact'] as const`.
   - `src/detector.ts:31`: `category?: string`. Use the `CATEGORIES` union.
   - `bin/pii-guard.ts:94,171,185,189,224`: `any[]` for Bitwarden rows, the database, and reports.
   - `src/body.ts:62`: `walk(node: any, …): any`. Type it as `unknown`.
4. `bin/pii-guard.ts:34`: `as OcrMode` happens before the check. Use a type guard instead of the assertion.
5. Turn on `noUncheckedIndexedAccess`. It adds 42 errors in `src`/`bin` (`ocr.ts` 14, `rules.ts` 14) and 23 in `test`. Do this in its own PR.

## Quality gates (guide §11)

6. Add Knip to `check`. It reports only 6 CLI subcommand names as unlisted binaries; ignore them in `knip.json`.
7. Optional: add a ratchet that counts `any` so the count cannot grow.
8. Optional: add a formatter. `bin/pii-guard.ts` has 18 lines over 200 characters and `src/rules.ts` has 6.

## Already in line

- `strict`, `verbatimModuleSyntax`, `import type`, and no `@ts-ignore`.
- No default exports. `src/index.ts` is the package entry, not a barrel.
- `ponytail:` comments state limits and upgrade paths.
- Tests use real tesseract and fixtures, with no module mocks.

## Suggested order

1. Item 1 (small PR).
2. Items 3 and 4 together.
3. Item 5 as its own PR.
4. Items 6 to 8 when convenient.

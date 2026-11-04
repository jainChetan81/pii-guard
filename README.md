# pii-guard

Local **observer** for known values and PII in agent requests, transcripts, images, and PDFs.
It reports candidate findings. It does not block traffic, redact images, or prove that data is safe.

[Research and existing tools](docs/research.md) | [Validation and next steps](docs/validation.md)

## Run

Bun or Node >= 22.18 runs the TypeScript directly. Text scanning has no runtime npm dependencies.

```sh
bun install --frozen-lockfile
bun bin/pii-guard.ts known export --bw-json vault-export.json
bun bin/pii-guard.ts known check
bun bin/pii-guard.ts replay --source claude,codex --since 7d
bun bin/pii-guard.ts replay --stdin --label imported --since 7d < transcript.jsonl
bun bin/pii-guard.ts report --since 24h
```

`known export` reads Bitwarden items or runs `bw list items` with an existing `BW_SESSION`.
Use `BW_BIN` to override that binary. `--folder`, `--collection`, and `--org` select vault scopes.
Repeat `--from-text FILE` for notes. With only text inputs, Bitwarden is not called.
Notes combine a token heuristic with contextual PII rules, including labeled Aadhaar and PAN.
Export is not a complete inventory of personal information.
Review which values were selected locally. Names, arbitrary passwords in prose, and addresses can be missed.
Explicit stored passwords and hidden fields include short values; those can cause many false positives.

The default list is `~/.config/pii-guard/known.json`, mode `600`. It contains real values.
Other processes running as the same OS user can read it. It is not a vault or security boundary.
Export replaces the selected list. Preserve manually added values when refreshing it.

`known check` injects every distinct configured value into four text envelopes locally.
It checks matching identities and unchanged bodies, prints counts only, and exits `2` on failure or an empty list.
Replay's `Known values seen: 32 / 99` means 32 configured values occurred in those records.
It is not a detection accuracy score: the other values may never have appeared there.

## Replay and coverage

`replay` reads Claude, Codex, T3, and 9Router logs under your home directory.
Use `--home DIR`, `--known FILE`, or `--stdin --label NAME` to select inputs.
Stdin alone does not scan local logs. Missing explicit `--known` paths fail.
A missing default list emits a warning and scans patterns only.

`--since 7d`, `--since 24h`, and `--since YYYY-MM-DD` filter individual dated records.
Undated records are counted and excluded when a cutoff is set.
Malformed JSON and unscannable rows are counted; replay continues and exits `2` with a partial report.
T3 uses its stored update time; edits can move an old item into the selected window.
Records in truncated logs cannot establish complete provider exposure.

Reports use unique `reports/replay-YYYYMMDD-HHMMSS-RANDOM.md` names and mode `600`.
Use `replay --out FILE` for an explicit destination. Existing reports are never overwritten.
New report directories use mode `700`. Reports contain counts and sanitized item labels, never matched values.
`--context` emits masked character shapes; no surrounding text or punctuation is retained.
Labels can still identify accounts, so reports remain private and ignored by Git.

Reports show unscanned image, file/audio, and opaque signed/encrypted fields.
`report` reads `~/.9router/pii-guard/events.jsonl`; use `--events FILE` to override it.
Legacy router events omit clean requests. The CLI separates those events from completed aggregate windows.
A findings ratio over recorded events is not a traffic-wide leak rate.

## 9Router

9Router loads the scanner from `PII_GUARD_MODULE`, an absolute path.
Debian `/usr/bin/node` has no TypeScript support, so point it at the built file:

```sh
bun run build   # writes dist/index.js
```

Set `PII_GUARD_MODULE=/home/chetan/Projects/pii-guard/dist/index.js` in the 9Router service.
Rebuild after each pull; the gateway loads the module once per process.

## Images and PDFs

Install local OCR utilities. No image goes to a hosted OCR service.

```sh
# Ubuntu; package installation requires administrator access.
sudo apt-get install --no-install-recommends tesseract-ocr tesseract-ocr-eng poppler-utils

bun bin/pii-guard.ts scan --file image.png --file document.pdf
bun bin/pii-guard.ts replay --since 7d --ocr
```

`PII_GUARD_OCR_BIN_DIR` can select a directory containing those four executable tools:
`tesseract`, `pdfinfo`, `pdftotext`, and `pdftoppm`.

PNG, JPEG, and WebP use Tesseract English OCR. PDFs scan their text layer and rendered pages.
Image envelopes cover Anthropic, OpenAI Chat/Responses, and Gemini inline images.
HTTP image URLs and provider file IDs are counted but never fetched.
PDF attachments inside request bodies remain unscanned; use `scan --file` for local PDFs.

Limits: 20 MiB per file, 10 PDF pages, 8 inline images, 20 MiB decoded per request, 20 seconds per subprocess.
The OCR path is synchronous and intended for offline checks. Do not enable it on a live router yet.
These limits are not a sandbox for hostile image decoders or decompression bombs.

Results distinguish `scanned`, `partial`, `empty`, `unsupported`, and `failed`.
Low OCR confidence marks a partial result. `scan` exits `2` when coverage is incomplete, `1` for command errors.
Replay with `--ocr` also exits `2` for unscanned or partial images, file/audio blocks, or opaque fields.
Even `scanned` means extraction completed, not guaranteed detection of every sensitive field.
English OCR can miss handwriting, small text, rotation, Indian scripts, faces, QR codes, and metadata.
PDF counts can include the same value in both its text layer and rendered image.
Original files and request bodies remain unchanged.

## Library

```ts
import { createDetector, scanBody, scanBodyWithOcr, scanFile } from './src/index.ts';

const detector = createDetector({
  salt: 'use-a-persistent-private-random-salt',
  known: [{ name: 'example.pan', value: 'ABCPE1234F', category: 'id' }],
});
const textResult = scanBody({ messages: [{ role: 'user', content: 'ABCPE1234F' }] }, detector);
const imageResult = scanBodyWithOcr({ input: [] }, detector);
const fileResult = scanFile('/path/to/document.pdf', detector);
```

Known values take priority. Numeric values accept common separators; known uppercase IDs accept spaces and dashes.
Unknown India rules include Aadhaar, PAN, IFSC, phone, UPI, passport, vehicle registration, and driving licence.
Weak formats require nearby context. Email and selected API-token formats match without context.
Credit-card patterns require context plus a Luhn checksum.

`detector.redact()` is a text helper, not a production redaction policy.
It does not handle every encoding, streaming transformation, or placeholder collision.
Never restore secrets into unrestricted shell commands through string substitution.

## Validate

```sh
bun run check
```

OCR integration tests require the utilities above; otherwise those tests explicitly skip.
CI installs them before running the suite. The public Presidio sample has provenance under `test/fixtures`.
Tests use synthetic data. Real documents, known lists, transcripts, and reports stay outside tracked files.
See [third-party notices](THIRD_PARTY_NOTICES.md) for reused rule and fixture licenses.

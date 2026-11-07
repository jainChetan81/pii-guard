# pii-guard

Detector for known values and PII in agent requests, transcripts, images, and PDFs.
The library finds candidates and can rewrite text in place (`scanBody(body, detector, onImage, edit)`).
Policy (observe, redact, block) lives in the caller, e.g. 9Router. It does not redact images or prove that data is safe.

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

Set `PII_GUARD_MODULE=/absolute/path/to/pii-guard/dist/index.js` in the 9Router service.
Rebuild after each pull; the gateway loads the module once per process.
9Router's adapter (`src/lib/piiGuard/observe.js`) needs the `edit` callback added in this version for redact mode.

## Images and PDFs

Install local OCR utilities. No image goes to a hosted OCR service.

```sh
# Ubuntu; package installation requires administrator access.
sudo apt-get install --no-install-recommends tesseract-ocr tesseract-ocr-eng poppler-utils ffmpeg
# macOS: brew install tesseract poppler ffmpeg

bun bin/pii-guard.ts doctor                      # which tools exist; which modes are ready
bun bin/pii-guard.ts scan --file image.png --file document.pdf
bun bin/pii-guard.ts replay --since 7d --ocr
```

`PII_GUARD_OCR_BIN_DIR` can select a directory containing those executable tools:
`tesseract`, `ffmpeg`, `pdfinfo`, `pdftotext`, and `pdftoppm`.

### How images are read

One pipeline, on by default:

1. ffmpeg converts the image to grayscale and upscales it 2x (bicubic) when it is at most 1 MP.
   Larger screenshots (Retina) keep their size; upscaling them made results worse.
2. Tesseract reads it as text blocks (`--psm 6`), which keeps long tokens on one line.
3. The text is scanned as read, then again after OCR repair. Repairs only add findings:
   - unicode dashes and quotes fold to ASCII (`-——-` around `BEGIN RSA PRIVATE KEY`);
   - spaces around `. : / =` are removed (`postgres: //db. internal`);
   - tokens split by a false space or a line wrap are joined, for secret formats only;
   - `O`/`0` and `I`/`l`/`|`/`1` swaps next to digits are fixed (`KAO1AB1234`);
   - glyph misreads are fixed: `@` for `0` (`ICIC@449627`), `¢` for `c`, `AlZa` for `AIza`.

Transparent images are flattened onto white first, so dark text on a transparent PNG stays readable.
Without ffmpeg the pipeline still runs on the raw image; `doctor` then reports enhanced as unavailable.
`--ocr-mode basic` (or `PII_GUARD_OCR_MODE=basic`, `createOcrWorker({ mode: "basic" })`)
keeps the earlier behaviour, raw image and `--psm 11` with no repair, for comparison only.
Cache entries are per mode. Nothing is downloaded at runtime.

### Measured accuracy and speed

Fake values only (`test/fixtures`, regenerate with `scripts/make-ocr-*.py`). An earlier 8-image
ad hoc set scored 11/19 basic and 19/19 enhanced. A value counts as found when its expected rule fires. "False" counts hits on clean images or wrong rules; an extra
`assigned_secret` on a `KEY=value` line is the same secret under a second rule and is not counted.
Measured 2026-11-05 on a 4 vCPU VPS, Tesseract 5.5.0, ffmpeg 9.0.2, one image at a time.

| Set | Images | basic found | enhanced found | False (both) | p50 / p95 basic | p50 / p95 enhanced | CPU per image basic / enhanced |
|---|---|---|---|---|---|---|---|
| `ocr-corpus` (tuning set) | 24 | 27/37 (73%) | **37/37 (100%)** | 0 | 157 / 217 ms | 213 / 290 ms | 167 / 226 ms |
| `ocr-holdout` (unseen fonts, themes, sizes) | 18 | 26/42 (62%) | **40/42 (95%)** | 0 | 195 / 366 ms | 253 / 478 ms | 208 / 293 ms |

Enhanced costs about 55-110 ms more per new image (ffmpeg plus a larger image for Tesseract).
It runs in the background worker, so requests never wait for it, and a repeated screenshot is
a cache hit (no OCR). The worst event-loop gap stays at about 35 ms for a 20 MiB image.

Rejected after measurement:

- `tessdata_best` English model: about 500 ms per image and no more accurate. Stock `eng` stays.
- Upscaling images above 1 MP: Retina screenshots lost 2 of 19 hits.
- Running both `--psm 6` and `--psm 11`: twice the time, no extra hits.
- `--psm 11` with the same preprocessing and repair: 35/37 on the tuning set versus 37/37 with `--psm 6`.

### Known issues

- Badly garbled long random tokens still miss: on the holdout set, 1 JWT and 1 Google key whose
  OCR text had several wrong characters. No safe repair recovers them.
- Low-contrast, tiny (11 px), and JPEG text read worse; these sets include them, so the numbers
  above already reflect it.
- English OCR only. Handwriting, rotation, Indian scripts, faces, QR codes, and metadata are not read.
- Two different pattern values of one rule on one line, one visible only after repair, count once.
- A line with a database URL and another email keeps both emails, so the URL's `user@host` can show as an extra email hit.
- Repairs skip OCR lines over 1000 characters; the raw scan still covers them.
- The fixtures are rendered screenshots, not real user images. Run `replay-images --labels` on a
  real folder before trusting these rates for a new source.
- Treat image findings as warnings; do not block on them alone.

PNG, JPEG, and WebP use Tesseract English OCR. PDFs scan their text layer and rendered pages.
Image envelopes cover Anthropic, OpenAI Chat/Responses, and Gemini inline images.
HTTP image URLs and provider file IDs are counted but never fetched.
PDF attachments inside request bodies remain unscanned; use `scan --file` for local PDFs.

Limits: 20 MiB per file, 10 PDF pages, 8 inline images, 20 MiB decoded per request, 20 seconds per subprocess.
`scanImage`, `scanFile`, and `scanBodyWithOcr` are synchronous and meant for offline checks.
Live gateways use `createOcrWorker()`: `enqueue()` returns at once, OCR runs in a bounded
background queue (one Tesseract process, 32 pending images, 20 s timeout), and a 24-hour
SHA-256 cache reads a repeated screenshot once. Results hold hashes and counts, never text.
`ocrImage(data, detector, mode)` is async and returns the OCR text with each hit. It is for a local
scanner test of one image (the 9Router dashboard uses it); never log or cache its text.
Latency budget: decoding and hashing run in 1 MiB slices. The worst event-loop gap is about
35 ms for a 20 MiB image (the cap) and a few ms for a typical 1 MB screenshot, small next to
model latency. Labels are normalised (`messages[*].content[*]`), so indexes never carry data.

## Use it anywhere

```sh
bun bin/pii-guard.ts serve --port 20130            # loopback; set PII_GUARD_TOKEN to require a bearer token
curl -s localhost:20130/scan -d '{"body": {...}}'  # text + OCR findings as hashes
curl -s localhost:20130/scan/image --data-binary @shot.png
bun bin/pii-guard.ts replay-images --folder ~/shots [--labels labels.json]
```

A non-loopback `--host` requires `PII_GUARD_TOKEN`. The server never fetches URLs or reads paths.
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
Weak formats require nearby context. PAN, email and selected API-token formats match without context.
Credit-card patterns require context plus a Luhn checksum.
Email skips `noreply@`, `git@` and `example.com/org/net` addresses; `(at)`/`[at]`/`%40` forms match as `email_obfuscated`.
`connection_string` covers `scheme://user:pass@host`. `assigned_secret` covers `password|secret|api_key|token=value` (value only, not placeholders or env lookups).
`us_ssn` needs an SSN keyword. `ip_address` matches public IPv4 only (no private, CGNAT, documentation, `.0`/`.255` or public DNS).
Known-value placeholders are `{{vault:#hash}}`, so item names never reach the provider.

Out of scope: prompt injection, IPv6, labels in a sibling JSON field, and audio content.

`maskText(text, findings)` replaces each finding with a masked preview (`maskValue`); overlapping findings merge into one `•••••`. 9Router uses it for its masked prompt store and rescans the result.

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

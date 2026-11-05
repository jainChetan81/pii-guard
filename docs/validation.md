# Validation and next move

Date: 2026-11-03. Project base: `93c23a0` (merged PR #1); this report covers the follow-up observer changes.
Research evidence and existing alternatives are in [research.md](research.md).

## Decision

Keep this project as a small local observer and replay tool.
Existing tools already provide PII detection, custom matching, masking, and OCR components.
The useful custom work is connecting those capabilities to this setup's vault data and transcript formats.
Do not enable automatic redaction yet. Image coverage and enforcement boundaries remain incomplete.

## Checks

- TypeScript strict checking and 49 Bun tests (218 assertions), including local OCR integration.
- `known check` injects each configured value into four text envelopes without sending any request upstream.
- Configured-value self-checks and transcript occurrence counts are separate measurements, neither measures OCR recall.
- Public Presidio image: three configured sample values detected without returning raw OCR text.
- Synthetic PDF: PAN and registration detected in both its text layer and rendered pixels.
- Anthropic, OpenAI Chat, OpenAI Responses, and Gemini text/image envelopes exercised.
- Input bodies and original document files remain unchanged.
- Short secrets, foreign phones, formatted IDs, object keys, metadata, audio gaps, and plaintext documents covered.
- Overlapping observation findings retain known identities; text masking covers their complete union.
- Known-value totals count hashes rather than account labels; duplicate vault names no longer hide distinct values.
- Date filtering uses individual rows. Invalid rows preserve a partial report instead of aborting neighboring rows.
- Report labels mask embedded literal values. Context hides punctuation and Unicode content.
- Private reports use exclusive creation and mode 600; explicit output files cannot be overwritten.
- Note export now extracts contextual PAN, Aadhaar, and registration values, including secure-note titles.
- Node ran the image CLI and loaded the actual 9Router branch adapter against `src/index.ts` successfully.
- Adapter smoke check found a synthetic tool result, preserved the body, and logged no matched value.
- Repository privacy scan found zero configured-pattern matches. Raw substring matches were only numeric fragments inside public date literals.
- `git diff --check` passed. Live gateway health returned HTTP 200; no service or router changes were made.

The first independent review found six actionable bugs. All received fixes and regression checks.
The independent recheck confirmed those six fixes and found one remaining Gemini metadata gap.
Inline image/file metadata now receives scanning while encoded payloads remain excluded; a regression check covers this fix.

The pre-PR review found four more issues: long IDs classified as secret tokens, missing Chat/Gemini file accounting,
unaccounted redacted thinking, and phone normalization missing repeated separators. All have regression checks.
Private-list validation also exposed formatted aliases receiving the wrong identity and short numeric matches inside larger numbers.
Both are fixed. Numeric JSON fields now receive scanning, and incomplete OCR coverage or malformed JSON exits `2` with a saved report.

A synthetic 1,080,066-byte request with 300 known values took 24.9 ms median and 26.4 ms p95.
This is a 25-run Node microbenchmark, not a production latency guarantee.

## VPS replay

Private evidence: `reports/replay-20261103-164537-3e6fc6bad697.md`.
Cutoff: 2026-10-27 00:00:00 UTC. Stores were active during the scan.

| Source | Dated rows scanned | Image blocks |
| --- | ---: | ---: |
| Claude | 16,337 | 99 |
| Codex | 3,685 | 0 |
| T3 | 7,767 | 56 |
| 9Router | 1,000 | 0 |

25 of 99 configured known values appeared in 28,789 scanned records.
The vault was unlocked through a private session and synchronized before refreshing the list.
The refresh added 12 values and removed 12 earlier values; the private salt and bike registration were retained.
The resulting categories were 85 secrets, four IDs, and ten contacts. The previous list has a private backup.
The earlier `32 / 99` report used an older list and scanner snapshot. It was never a detection accuracy result.
`known check` separately passed 396 of 396 checks: every current value in four text envelopes.
Private documents and configured values remain outside tracked files. Scans return counts and sanitized labels, not raw OCR text.

7,223 Claude rows had no usable timestamp; the dated replay excludes them.
28 Claude lines failed JSON parsing. No row failed the body scanner.
T3 filtering uses update timestamps, so edits can place old content inside the selected period.
The router log stores truncated previews. These records cannot prove complete provider exposure.

Of 155 image blocks, 86 produced usable OCR under the current confidence rule.
Ten had partial OCR, six produced no text, and 53 were skipped as referenced, unsupported, or limited inputs.
No OCR subprocess failed. Seventeen file/audio blocks and 2,590 signed/encrypted fields remained opaque.
The CLI returned exit code 2 and saved its report because coverage was incomplete and malformed rows were present.
Repeated transcript copies and repeated image envelopes are not unique documents or unique leaks.

## Local bike documents

Private evidence: `reports/bike-validation-final-1793724323260.json`.
All ten distinct local files were tested: five PDFs and five JPEGs.

- The PDFs contained 13 pages. Text extraction and page OCR completed for all five files.
- All five PDFs produced candidate PII findings; four contained the configured registration value.
- PDF findings total 99 occurrences, including duplicates across text layers and OCR.
- 47 occurrences matched configured values; those remain repeated detections, not unique sensitive fields.
- All five photographs produced low-confidence text, with mean confidence from 29 to 51.
- Those photographs are marked partial, not clean. No configured values were confirmed in their OCR.
- Additional page-segmentation/orientation modes did not recover confirmed values from these photographs.

This is useful coverage evidence, not a labeled recall benchmark.
A candidate driving-licence, phone, or email match can still be a false positive.
No private document was sent to a hosted OCR service or displayed to a model.

## Mini replay

The remote check used a temporary copy of the VPS working-tree scanner.
Its snapshot preceded the last local reporting fixes; it was not an unchanged GitHub-main checkout.
No known list exists on the Mini. Its counts are pattern-only and cannot measure recall against the VPS's 99 values.
Credentials and known lists were not copied between hosts.

- Last seven days: 20,546 dated rows across 615 source files; 2,620 candidate PII occurrences, zero secret-pattern occurrences.
- All available records: 240,248 rows; 25,541 candidate PII occurrences and 545 secret-pattern occurrences.
- All-history PAN count: 160. Last-seven-day PAN count: 66. No Aadhaar pattern was confirmed in this text pass.
- Claude timestamps span 2026-10-11 through 2026-11-03; Codex starts 2026-07-16; T3 starts 2026-07-25.
- 13,123 Claude rows are undated. JSON parsing reported zero errors.
- Initial image inventory: 171 recent image blocks and 1,943 across available history, all initially unscanned.
- Tesseract and Poppler were unavailable. Native macOS Vision validation is tracked separately below.
- Bounded document inventory found two bike-named text files; neither produced a pattern hit.

The stores changed during scanning, so totals are snapshots rather than fixed inventory counts.
Stored content may include synthetic examples, copied documentation, or tool output never sent upstream.
A missing Aadhaar hit is not evidence that no Aadhaar data exists.

## Native Mini OCR

Swift 6.3.2 and macOS Vision were available without installing packages.
A synthetic image produced the expected PAN and email detections before private images were tested.

- A later seven-day snapshot contained 20,848 dated rows and 168 image blocks.
- 55 unique inline images completed local OCR; 21 other blocks duplicated those images.
- 92 blocks contained references without image bytes. They were not fetched.
- No processed image was empty, failed, or skipped because of the experiment's limit.
- Pattern detection found two email occurrences, zero PAN occurrences, and zero Aadhaar occurrences.
- Mean Vision confidence was 0.9811 across 1,499 text observations. This is not measured detection recall.

The earlier 171-block inventory used a different rolling cutoff; the totals are not directly comparable.
No known-value list was loaded. Absence of a pattern match does not establish absence of personal data.
Temporary images and executable scripts were removed. No software or services were installed or changed.
Vision remains a validated local option, not a production backend in this package.

## Image capture and replay

Capture is opt-in: set `PII_GUARD_CAPTURE_IMAGES=1`. Images are stored in
`~/.9router/pii-guard/images/`, with a 2 GiB cap and a 14-day TTL.
Before enabling capture, exclude this folder from backups. Add
`--exclude=./pii-guard/images` to the 9Router snapshot in `/usr/local/sbin/vps-backup`,
and verify that the resulting backup excludes the images folder.

Run `pii-guard replay-images --folder PATH [--labels labels.json]`. Labels map each
image's SHA-256 to expected rule occurrences. An optional `hash` matches a specific
detector finding; use the same detector salt for labeling and replay.

```json
{
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef": [
    { "rule": "email", "hash": "0123456789ab" },
    { "rule": "pan" }
  ]
}
```

Each image without a label entry is treated as having no expected findings.
Precision and recall are `null` when their denominator is zero. Without labels,
accuracy is unknown. Child CPU time uses Linux `/proc/self/stat` child user and
system ticks, including completed Tesseract processes.

## Remaining work

1. Review and merge this follow-up PR after CI passes. PR #1 contains the initial observer, not these follow-up fixes.
2. Prepare the 9Router text-observer integration after offline validation is accepted.
   Sanitize endpoint, model, and User-Agent metadata; record clean requests, errors, and coverage gaps explicitly.
   Update the adapter test's stale `.js` import to `.ts`; the runtime adapter already accepts the `.ts` module path.
3. Enable text-only observation only after an explicit deployment decision. Review a day of counts and false positives.
4. Keep OCR offline until labeled document tests establish useful recall and low-confidence handling.
   Evaluate the existing veil and LLM-Shield-Proxy enforcement paths before adding a custom live masking/broker system.

The follow-up PR changes offline observation and validation. No live deployment, alert service, vault broker, or image redaction is included.
The observer does not stop a same-user process from reading a plaintext known list or sending files directly.

## Local OCR setup

OCR utilities were extracted into `~/.local/share/pii-guard/ocr`; no system services changed.
Use `PII_GUARD_OCR_BIN_DIR=$HOME/.local/share/pii-guard/ocr/bin` for this VPS's checks.
Tesseract is 5.5.0; Poppler is 26.01.0. CI installs its platform packages before testing.
Administrator installation was unavailable. The configured ESM Tesseract update returned HTTP 401.
Use a supported, updated decoder installation before accepting untrusted uploads in a live deployment.

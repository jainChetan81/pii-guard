# Existing PII protection for agent traffic before the model API

Research notes for the pii-guard design. Re-researched from primary sources on 2026-11-03.
Alternative products were not installed or run: claims are labelled **code-read**, **doc-read**, or **self-report**.
Local observer and OCR test results are recorded separately in [validation.md](validation.md).
Stars, dates and licence strings come from the GitHub REST API on 2026-11-03.

## What pii-guard is (from this repo's source)

Local Bun/TS observer with no runtime npm dependencies. `src/detector.ts` matches a vault-derived **known-value**
list first (HMAC-SHA256 hash ids, no values printed), then gitleaks-derived token regexes and India
rules (Aadhaar with Verhoeff, PAN, IFSC, Indian phone, UPI handle, Indian passport), where weak
formats only count with a nearby keyword (`KEYWORD_WINDOW = 48`). `src/body.ts` walks Anthropic
Messages, OpenAI Chat, OpenAI Responses and Gemini bodies, tags findings by `role/block-type`,
counts images and estimated decoded bytes, and reports opaque or unsupported fields.
Optional offline OCR uses Tesseract and Poppler; text mode does not inspect image pixels.
`bin/pii-guard.ts` replays Claude,
Codex, T3 and 9Router logs offline and writes counts-only markdown reports (mode 600). `redact()`
is unwired: observe mode only.

So the requirements are: local known-value matching, India IDs, counts-only reports, all provider
shapes, local OCR, no full secure broker today.

## Corrections to the earlier claim

The earlier report said no existing tool covers text + tool output + browser + images together.
Wrong as a blanket statement. Precise version:

1. **Text and tool masking already has several implementations.** Five relevant projects are:
   LiteLLM's Presidio guardrail, OpenRouter Sensitive Info, LLM-Shield-Proxy, veil, PasteGuard.
   Some mask tool-call arguments and tool results, not only the user prompt.
2. **Images are the real gap, but it is a claimed one.** Presidio's image redactor does local
   OCR detection and redaction (Tesseract). The inspected agent proxies have pixel gaps: veil states
   "Images (screenshots) are passed through unscanned" (doc-read); LLM-Shield-Proxy states "The
   standard detector does not inspect pixels" and forwards any `data:` URI uninspected (doc-read);
   LiteLLM's hook only reads `content[].text`, so `image_url` parts are never analysed (code-read).
   The whole LiteLLM docs index has no image/vision masking page (doc-read).
3. **One inspected project includes a browser extension**: PasteGuard's *experimental* extension for ChatGPT,
   Claude and Gemini web UIs (self-report). Its documented extension does not establish screenshot coverage.
4. **Presidio is no longer Microsoft's.** `microsoft/presidio` redirects to
   `data-privacy-stack/presidio`, a community-governed org created 2026-04-13, with Microsoft's
   support. MCR images are frozen; new ones are `ghcr.io/data-privacy-stack/presidio-*` (doc-read).
   Any reasoning that assumed Microsoft stewardship is stale.
5. **llm-guard is archived.** `protectai/llm-guard` reports `archived: true`, last push 2026-07-08, MIT,
   3,219 stars (code-read). Do not adopt or recommend it.
6. **MCP scanners serve a different primary purpose.** Cisco's `mcp-scanner` inspects servers,
   descriptions, resources, and readiness. It is distinct from Invariant's former `mcp-scan`, now
   `snyk/agent-scan`. Current Snyk docs describe component/skill scans and background inventory,
   not a local PII masker for every model request. Both remain useful security tools (doc-read).
7. **Exact matching is not a new feature.** PasteGuard has literals/denylists, veil uses
   multi-pattern matching, and Presidio supports custom recognizers. A vault importer can feed them.
   This survey did not verify a ready Vaultwarden importer matching this project's workflow.
8. **Local transcript replay is the practical integration work here.** No ready importer for this
   Claude/Codex/T3/9Router combination was verified in the inspected projects. That is not proof
   that no other project offers one.

## Tool notes

**Presidio (community), MIT, 11,663 stars, release 2.2.366 on 2026-10-27, active.** India
recognizers in `predefined_recognizers/country_specific/india/`: IN_AADHAAR, IN_PAN, IN_GSTIN,
IN_PASSPORT, IN_VOTER, IN_VEHICLE_REGISTRATION (code-read). `InAadhaarRecognizer` scores bare
12-digit patterns `0.01` "Very Weak" with `CONTEXT = ["aadhaar","uidai"]`, and `validate_result`
requires length 12, first digit ≥ 2, Verhoeff checksum, non-palindrome (code-read) — the same
false-positive wall pii-guard hit, the same checksum. `docs/analyzer/filtering_by_country.md`
documents `load_predefined_recognizers(countries=[...])` to cut cross-country noise (doc-read).
**No IFSC and no UPI recognizer** — those two pii-guard rules have no Presidio counterpart.
`presidio-structured` maps DataFrame/JSON *columns or keys* to entities and anonymizes whole
columns: too coarse for nested bodies (doc-read). `presidio-cli` is a text CLI (Python 3.11–3.14).
`presidio-image-redactor` 0.0.62 calls itself "still in beta and not production ready", needs
system Tesseract (tested v5.2.0) plus spaCy `en_core_web_lg`, handles DICOM, and its container maps
host :5003 (doc-read + PyPI metadata).

**LiteLLM Presidio guardrail** (`pii_masking_v2`, `last_updated: 2026-11-02`). Modes `pre_call`,
`during_call`, `post_call`, `logging_only`, `pre_mcp_call`, `post_mcp_call`; actions `MASK`/`BLOCK`;
per-entity thresholds, deny list, `presidio_language`, `presidio_ad_hoc_recognizers` JSON for
custom regex entities (code-read of `guardrail_hooks/presidio.py`). You run Presidio analyzer and
anonymizer containers yourself (doc-read). Verified scope in `async_pre_call_hook`: walks
`data["messages"]`, redacts string content and `content[].text`, and **returns the body unchanged
when `messages` is None**. That direct hook does not walk Responses `input`.
The surrounding gateway may normalize requests first; end-to-end Responses coverage was not tested.
That hook leaves image pixels untouched; `apply_to_output`/`output_parse_pii` cover replies (code-read).
`logging_only` is the documented analogue of observe mode: mask at log time, send untouched.

**OpenRouter guardrails** (`guides/features/guardrails/sensitive-info`, doc-read). Input side only:
"message content, tool call arguments, and prompt strings. It does not scan model responses." Regex
presets email, phone, **SSN**, card, IP, provider-prefixed keys; NLP presets person and address,
both **beta**, via Presidio. Actions redact / block / `flag` (detect-only). Custom JS regex allowed,
ReDoS-unsafe rejected. Two caveats: **fails open** ("If the check times out, the request proceeds")
and NLP "adds latency proportional to the size of the input text". No built-in India entities or pixel masking were verified,
and OpenRouter sees the pre-redaction body — hosted third party, not local. Needs an org account
plus admin; data-region guardrails need Business/Enterprise.

**LLM-Shield-Proxy**, Apache-2.0, 14 stars, created 2026-08-02, pushed 2026-11-01: young,
effectively single-maintainer (code-read). Self-hosted OpenAI-compatible gateway; reversible masking
with restore into the streamed reply; fails closed; from LiteLLM 1.106.0 (2026-10-18) also a
built-in guardrail covering `/v1/chat/completions`, `/v1/completions`, `/v1/responses`,
`/v1/messages`, streaming and not (doc-read). Three detection tiers: 13 native re2 types (card,
SSN, email, phone, IP, AWS, GitHub PAT, Slack, SSH key, JWT, MRN, UK NINO, IBAN), Shannon entropy
with base64 decoding bounded to 8,192 chars, operator-supplied ONNX NER with **no regex fallback
for names** (doc-read). `request-field-coverage.md` is the most complete field walk found anywhere:
messages including multimodal text, participant `name`, `tool_calls` and legacy `function_call`
arguments, `prompt`, `system`, `input` including Responses `function_call`/`function_call_output`,
`instructions`, tool `description` and schema `title` on every request, unknown fields walked
generically; strings over 8,192 and any `data:` URI forwarded uninspected with
`UNMAPPED_BLOB_POLICY = skip|warn|block` (doc-read). India IDs absent; add via BYOR
`policies.yaml`. Ships `pii-leak-benchmark`, `chunk-invariance`, `mcp-ssrf-check` (doc-read).
LIMITATIONS.md is unusually honest: no recall guarantee on unlabeled traffic, plaintext in process
memory, tamper-evident not WORM, MCP "research-scoped".

**veil**, Apache-2.0, 97 stars, pushed 2026-10-31, labelled **alpha**. Python 3.11+, httpx +
cryptography + pyahocorasick (exact multi-pattern, i.e. value-list based), optional `ner` extra.
Local proxy on 127.0.0.1:8787 whose supported-clients table covers Anthropic Messages (Claude
Code), Bedrock InvokeModel binary event stream, Vertex rawPredict, Microsoft Foundry, Claude
Platform on AWS, OpenAI Responses (Codex CLI) and OpenAI Chat Completions — the widest documented
transport matrix (doc-read). Consistent pseudonyms are swapped back into local file writes and
shell commands; keys in the OS keychain; writes `.claude/settings.local.json`. Stated limits:
images unscanned, values under 8 chars verbatim, `LIKE '%ab12%'` fragments unresolvable, cloud
upstreams tested only against fake upstreams. It claims LiteLLM's Presidio guardrail numbers tokens
by position and can mis-restore (v1.107, their review): plausible against the numbered-token code I
read, **not independently verified here**.

**PasteGuard**, Apache-2.0, 806 stars, created 2026-01-08, v0.9.5 2026-10-13, TypeScript/Bun +
Hono with a separate Python `detector/` on GLiNER (Apache-2.0, 4,201 stars, pushed 2026-10-31) plus
python-stdnum; SQLite/Postgres; Docker Compose (code-read). Three surfaces: experimental browser
extension (ChatGPT/Claude/Gemini web), base-URL proxy with mask-and-restore, coding agents (Codex,
Claude Code, Cursor, Windsurf, Copilot) (self-report). `src/pii/detect.ts` merges literal string
matches, regex matches and denylist entities with overlap/fragment handling (code-read) — nearest
to pii-guard's known-value path, but the list is hand-maintained. No image or OCR path in repo or
docs (code-read). README warns the 0.9.3 detector may exit `SIGSEGV` without
`ORT_DISABLE_TELEMETRY=1` (self-report).

**Secret scanners.** gitleaks: MIT, 30,627 stars, pushed 2026-10-28, modes `git`, `dir`, `stdin`
(`detect`/`protect` deprecated since v8.19.0), entropy rules, `--redact uint[=100]` to blank secret
values in its own output (doc-read). No PII entities, no India IDs, no body walking. secretlint:
MIT, pushed 2026-11-03, `--stdin` with `--stdinFileName`, secrets masked by default
(`--no-maskSecrets` to disable), `--format=mask-result --output=FILE` rewrites in place, JS rule
packages (doc-read). Useful as pattern sources, not as the product.

**Vaults.** 1Password `op run` "Pass secrets as environment variables to an application or
script", plus `op inject`, `op read`, Shell Plugins that wrap CLI sign-ins with biometrics
(including Claude Code CLI), an Environments MCP server, and a Credential Broker for machine
workflows (doc-read). Bitwarden/Vaultwarden CLI: `BW_SESSION` is a session key in the environment
and `bw list items` / `bw get password` print decrypted plaintext to stdout; there is no `op run`
equivalent (doc-read). This project's export currently writes plaintext `known.json`, mode
600 with 700 parents. That is an implementation choice, not an unavoidable vault requirement.
A later broker could load a scoped list directly into process memory. Hash-only storage does not
automatically solve arbitrary substring matching. Infisical
`agent-vault` (licence "Other", 2,470 stars, created 2026-03-27) is the `op run` category: brokers
credentials so agents hold `__anthropic_api_key__` placeholders, via `HTTPS_PROXY` + MITM
(doc-read). That protects secrets on the agent side, not PII inside body text; no detection overlap.

**TypeSafe Jev — not a PII tool.** Blog body dated Sep 15, 2026: Jev is a "fast, structured
decisions" model, "unstructured state in, typed probabilistic decisions out", 70ms–500ms, $0.042
input/MTok, output free, early access; no PII detection or redaction mentioned (doc-read). Its
LiteLLM integration matters to us as a pattern: a `pre_call` guardrail that blanks tool results
judged irrelevant across `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, sparing the last
exchange, while posting request content to `https://api.typesafe.ai` (doc-read). Context hygiene
plus a privacy cost, not a substitute.

**Dead ends.** llm-guard (archived). NVIDIA NeMo-Guardrails is not archived and is a Python rails
framework rather than a body inspector; no India entity story surfaced — only partially verified.

## Build vs reuse

1. **Keep this observer small**: its value is this setup's replay adapters, vault import, and local reports.
   Those requirements justify integration code, not a claim that PII detection needed inventing.
   Existing tools already provide matching, masking, custom rules, and local OCR components.
2. **Reuse rule content, not runtime**: Presidio India recognizers and gitleaks patterns as the
   source of truth for regexes and checksums. Note the design difference — Presidio scores context,
   pii-guard gates weak formats on a keyword window plus checksum.
3. **Local OCR without Presidio the service**: presidio-image-redactor drags Python, Tesseract,
   spaCy and Flask and calls itself not production ready. The short path is spawning system
   `tesseract` (now available offline in `src/media.ts`) and feeding text into the existing detector.
   Keep low-confidence, referenced, and unsupported images explicitly incomplete.
4. **If enforcement is ever wanted**, do not hand-roll masking inside 9Router. Test
   LLM-Shield-Proxy (field coverage, fails closed, leak benchmark) and veil (transport matrix)
   against synthetic fixtures first; both young, one alpha — review targets, not dependencies.
   OpenRouter's `flag` action is the cheap hosted dry-run, accepting a third party on the body,
   US-centric presets, and fail-open.
5. **Never** build on llm-guard.

## Sources (accessed 2026-11-03)

Paths below are relative to each repo's `main`/`master` root.

- Presidio (redirect from https://github.com/microsoft/presidio): https://github.com/data-privacy-stack/presidio —
  `docs/project_transition.md`, `docs/supported_entities.md`, `docs/analyzer/filtering_by_country.md`,
  `docs/image-redactor/index.md`, `docs/structured/index.md`, `presidio-cli/README.md`,
  `presidio-analyzer/presidio_analyzer/predefined_recognizers/country_specific/india/in_aadhaar_recognizer.py`,
  https://pypi.org/pypi/presidio-image-redactor/json
- LiteLLM: https://docs.litellm.ai/docs/proxy/guardrails/pii_masking_v2 (also `/llm_shield_proxy`,
  `/typesafe`, `/secret_detection`), https://docs.litellm.ai/llms.txt,
  `litellm/proxy/guardrails/guardrail_hooks/presidio.py` at https://github.com/BerriAI/litellm
- OpenRouter: https://openrouter.ai/docs/guides/features/guardrails,
  https://openrouter.ai/docs/guides/features/guardrails/sensitive-info,
  https://openrouter.ai/docs/api/api-reference/guardrails/create-a-guardrail,
  https://openrouter.ai/docs/llms-full.txt
- LLM-Shield-Proxy: https://github.com/ninadphalak/LLM-Shield-Proxy — `LIMITATIONS.md`,
  `website/docs/features/data-protection-pii-redaction/request-field-coverage.md`,
  `.../supported-pii-types.md` · https://llmshieldproxy.com
- veil: https://github.com/lemonadesaltbagel/veil · https://pypi.org/project/veil-proxy/
- PasteGuard: https://github.com/sgasser/pasteguard (`src/pii/detect.ts`, `detector/`) ·
  https://pasteguard.com/docs · GLiNER https://github.com/urchade/GLiNER
- MCP scanners: https://github.com/cisco-ai-defense/mcp-scanner,
  https://github.com/snyk/agent-scan (redirect from `invariantlabs-ai/mcp-scan`) · llm-guard (archived):
  https://github.com/protectai/llm-guard · NeMo-Guardrails: https://github.com/NVIDIA/NeMo-Guardrails
- gitleaks: https://github.com/gitleaks/gitleaks · secretlint: https://github.com/secretlint/secretlint
- 1Password: https://developer.1password.com/docs/cli/reference/commands/run/,
  https://www.1password.dev/get-started/secure-ai-access.md,
  https://www.1password.dev/cli/shell-plugins.md, https://developer.1password.com/llms.txt
- Bitwarden CLI: https://bitwarden.com/help/cli/ · Infisical Agent Vault:
  https://github.com/Infisical/agent-vault · tesseract.js: https://github.com/naptha/tesseract.js
- TypeSafe Jev: https://typesafe.ai/blog/introducing-system-one-models-and-jev

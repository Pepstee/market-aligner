# Application sanity review

## Certified purpose and scope

JAA now asks one semantic question immediately before release and again binds
the answer at the only final-submit click:

> Would a sensible hiring manager need to see this, and does it help this
> truthful candidate get through the door?

`career_automation.application_sanity_review` is deliberately read-only. It
accepts an exact package and can only return a content-addressed PASS receipt
or raise a blocking error. It has no rendering, materialisation, upload,
browser, click, or submission capability. Findings and suggestions are
internal values and are never accepted by any employer-facing renderer.

This is an additional semantic gate. The deterministic exact-PDF assurance,
including the permanent incident-document quarantine, is unchanged and runs
first. This certification covers the repository's JAA executor and migrated
operational submit-path inventory. It does not claim control of arbitrary
human browser clicks. No production ATS adapter or real submission is added.

## Exact review package

The reviewer independently opens and extracts text from the exact final CV and
cover-letter PDF bytes with strict `pypdf`. It also receives:

- canonical exact form bindings and cover note;
- job key, vacancy hash, role title, company, and relevant approved vacancy
  requirements;
- candidate claim/evidence identifiers and versions, without private evidence
  descriptions; and
- the application-source identity.

Vacancy and application content are wrapped as untrusted quoted JSON. The
immutable v1 prompt directs the reviewer to ignore embedded instructions. Its
strict, additional-properties-forbidden JSON schema admits only stable finding
codes, material severity, document/field location, a short internal
explanation, an optional internal suggestion, and `pass`, `block`, or
`uncertain`. PASS requires an unambiguous verdict and an empty finding list.

## Model boundary and fail-closed behavior

The module uses the existing `llm.client.Backend`/`LLMClient` boundary. The
configured subscription transport may be Claude CLI or Codex CLI; injected
and future offline backends use the same interface. Provider and model come
from the client/configuration rather than policy. No API key is used by either
CLI transport.

Missing or unavailable providers, timeout, transport failure, malformed or
schema-invalid output, uncertainty, abstention, BLOCK, any finding, and a
missing model identity all block. `MockBackend` is explicitly prohibited from
issuing authority. Hermetic fixture tests use a separately named scripted test
backend that is never selected by production configuration.

The established structured-output helper accepts a model's valid JSON object
inside a JSON Markdown fence, then applies the strict schema once. It does not
repair, retry, or accept malformed or schema-invalid results in this gate.

## Receipt bindings

`SanityReviewReceipt` is content-addressed over:

- exact CV PDF and independently extracted-text SHA-256 hashes;
- exact cover-letter PDF and independently extracted-text SHA-256 hashes;
- canonical form/answer/cover-note package hash;
- approved-evidence identifier projection hash and application-source identity;
- intended vacancy identity, hash, title, company, and requirement projection;
- prompt, schema, and policy hashes;
- backend and configured model identity;
- canonical model-result hash and embedded finding-free PASS result; and
- the receipt identity itself.

Mutation of any binding invalidates the receipt. The receipt is a required,
non-optional field of `ReleaseExecutionAuthority`. Construction re-extracts
the PDFs and verifies every deterministic binding. `_execute_submit` repeats
that verification against the current in-memory package immediately before
release consumption and the sole consequential `locator.click()`.

The evidence identifiers are deliberately opaque. Deterministic evidence
matching establishes support before the semantic review; the reviewer binds
its receipt to those identifiers but does not pretend that an identifier is an
evidence description. It may still block an unsupported or exaggerated claim
when the package itself contains a contradiction, impossible metric or explicit
fabrication.

## Test and smoke evidence

`test_application_sanity_review.py` covers clean relevant content, legitimate
LLM engineering language, incident-like and subtle private-origin language,
AI-authorship disclosure, unsupported/exaggerated claims, apologies, weakness
framing, irrelevant personal information, contradiction, meta-commentary,
prompt injection, malformed/uncertain/timeout/unavailable/mock results, every
receipt mutation class, and outward-flow isolation.

`test_external_document_assurance.py` statically enumerates every authority
constructor and click, requiring the semantic receipt at construction and its
reverification before the only final-submit click. Existing JAA-08 through
JAA-10 browser/release tests exercise the dynamic boundary. The real incident
PDF remains permanently quarantined by its original hash.

The original Claude evidence remains at
`runtime_evidence/application_sanity_review/live-smoke-20260806.json`. The
current Codex CLI certification is at
`runtime_evidence/application_sanity_review/live-smoke-codex-20260810.json`.
It passed the clean canary, four adversarial canaries and the exact quarantined
incident PDF. The evidence contains no personal contact values. Regenerate it
with:

```bash
.venv/bin/python scripts/run_application_sanity_live_smoke.py \
  --backend codex_cli --timeout 90 \
  --incident-pdf /path/to/quarantined-incident.pdf \
  --output runtime_evidence/application_sanity_review/live-smoke-codex.json
```

The default backend is `codex_cli`. A backend change is a reviewer-model change,
so its evidence is not interchangeable with earlier Claude CLI receipts. When
`--incident-pdf` is supplied, the script first requires the exact permanently
quarantined SHA-256 before asking the selected reviewer to block it.

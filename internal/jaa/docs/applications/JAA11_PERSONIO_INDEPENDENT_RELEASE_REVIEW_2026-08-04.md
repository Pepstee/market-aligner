# JAA-11 CloudCops Personio independent release review

**Verdict: `WITHHOLD`**

**Review date:** 2026-08-04 (Asia/Seoul)

**Scope:** independent adversarial review of the frozen rank-32 CloudCops canary.
**External-action boundary:** read-only inspection only. No field was populated, no
file was uploaded, no submit control was clicked, and no JAA-08 token was issued or
consumed.

The Personio-specific adapter passes its isolated boundary, ordering and circuit
tests. The release package does **not** pass the end-to-end JAA-08 authority gate.
The file called `release_manifest.prepared.json` is a parallel planning manifest,
not an `ApplicationCompilation`, a `jaa08.release-manifest.v1`, or an
`IssuedRelease`. There is no issued one-use token for this CloudCops compilation.
Submission is therefore forbidden.

## Reviewed identities

| Item | SHA-256 |
|---|---|
| `career_automation/personio_live_adapter.py` | `93239f2a067e57e7227b5404da23625b018175d024112313a73aa50541948ecc` |
| `test_jaa11_personio_live_adapter.py` | `00e6c67cb2e75ba5e9de656de481a2dd06061c49c3b69c30cd134dfefe89105a` |
| `build_cloudcops_cv.py` | `4340150d01defe3123eee3b96ac12a3d1fab998c7961080209e60ebc24a952c4` |
| `release_manifest.prepared.json` | `74f5f2ca99135689a50a1a699475c17546f4fde89e25c283eb3921e71e74e1f9` |
| rendered CloudCops CV PDF | `0ed48218b2637726ef2277a42aff9f0a835da6c793e679cc9f73c1352e285de3` |
| canary-selection assessment | `f6d6bb716b45e3fbf2cc8b3088a99c8b34c4db83008b8fc5d7d67369cae4bd4b` |
| operator authority | `b1cc3740a7d760ab905c27156bf8498bb7f03f8cfe5e9267b82e2ad6f2a9f77c` |
| approved evidence packet | `6ee3cc29b2074b4244686ca938028ad397ca0a39ab6323de59b52eb20d6eadb7` |
| authoritative contact source | `51d4f2d56ac5fadf768351b9c04a89fca3348e63af25d4c4548151d62d2c3260` |

The prepared manifest's CV, evidence-packet, contact-source,
canonical-contact-subset, selection-report and frozen-snapshot file hashes match
the reviewed bytes. The rank-32 entry hash also matches the assessment's stated
compact-JSON-with-trailing-newline convention.

## What passes in the Personio adapter

1. **Current route and form boundary.** A fresh read-only Chromium inspection
   returned HTTP 200 at the exact approved URL and exact expected title. The live
   inventory was exactly first name, last name, email, phone, optional LinkedIn,
   required CV and optional additional document. The submit control was unique.
2. **Current blocker scan.** Nineteen distinct requests were observed from a trace
   attached before navigation; the exact application URL and Personio form API
   URL were present. The adapter found no CAPTCHA, login/account, MFA, payment or
   identity-verification marker on the inspected DOM, scripts or request URLs.
3. **Pre-population ordering.** Exact route, title, inventory, submit uniqueness,
   DOM, visible text, script URLs and request URLs are scanned before `_fill()`.
   Known blockers return a no-fill review.
4. **Local consequential ordering.** The circuit persists
   `release_consumption_started` before calling JAA-08, persists
   `release_consumed` after verifying the returned manifest/token hashes, and
   persists `click_started` before its only `submit.click()` call. Failures after
   a consequential boundary become indeterminate and prohibit an ordinary retry.
5. **Optional fields and local receipt secrecy.** LinkedIn and the additional
   document remain blank. The adapter's receipt document and SQLite receipt store
   contain hashes rather than clear-text contact values or the release token.
6. **Artifact byte check.** The selected PDF is a regular non-symlink file and its
   bytes match the prepared hash. The rendered PDF is a legible one-page A4 CV
   without clipping, overlap, JavaScript, forms or encryption.

## Test evidence

Commands were run against the reviewed checkout:

```text
.venv/bin/python -m pytest -q test_jaa11_personio_live_adapter.py
30 passed in 0.22s

.venv/bin/python -m pytest -q test_jaa11*.py
575 passed in 1.85s
```

These results establish isolated implementation behavior. They do not establish
that a real CloudCops application compilation and release authority exist. The
Personio tests use a `FakeGate`, a synthetic token, arbitrary `object()` values
for the JAA-08 source/artifacts/contact, a synthetic CV, a self-authored contact
profile and a synthetic duplicate ledger.

## Material release blockers

### 1. No real JAA-08 compilation, release manifest or issued token

`release_manifest.prepared.json` declares:

- schema `jaa11.personio-canary-release-manifest.prepared.v1` rather than
  `jaa08.release-manifest.v1`;
- state `prepared_not_armed_not_submitted`;
- `jaa08_token_sha256: null`;
- `durable_circuit_id: null`;
- `armed: false`; and
- `production_certification: withheld`.

It has no JAA-07 `ApplicationCompilation.compilation_id`, no deterministic
validator receipts, no JAA-08 `ReleaseBinding`, no stored
`ReleaseManifest.release_manifest_sha256`, no lifecycle receipt and no
`IssuedRelease`. No CloudCops release-gate database or code path invoking
`ApplicationCompilationStore.register()` and `ReleaseGateStore.evaluate_and_issue()`
was present in the reviewed package. A real `ReleaseGateStore.consume_release_token()`
would reject a merely formatted or synthetic token as unknown.

This is independently sufficient for `WITHHOLD`.

### 2. The prepared manifest does not bind the executable form schema

The prepared manifest records form schema SHA-256
`5362dbec192ec45e777617683996ecb500c8a9d14e4377326c735d33a7221f93`.
The reviewed adapter's `FORM_SCHEMA_SHA256` is
`50bbb3c84376dac3635cc7b19a3bf8cbcc98341f23edd169722e1ca7882f8d65`.
The live form matches the latter. Therefore the planning manifest and executable
adapter do not share one exact schema identity.

### 3. Contact, CV and duplicate decisions are not bound to the JAA-08 authority

`PersonioApplication` accepts any regular file paired with its caller-supplied
hash, any caller-constructed contact document paired with its self-computed hash,
and any caller-constructed non-duplicate decision paired with another self-computed
hash. The adapter never loads the prepared manifest or requires its fixed CV,
contact-source, contact-subset, selection or frozen-entry hashes.

Separately, `JAA08ReleaseAuthority.consume()` replays the source, artifacts and
contact held in the authority object, but the adapter never proves that those
objects are the same vacancy, contact values, CV bytes and duplicate decision in
`PersonioApplication`. A valid token for a different compiled package could
therefore be presented alongside a different Personio payload unless the caller
adds an unstated external convention. The successful unit test demonstrates this
gap by using unrelated synthetic authority objects.

### 4. The assurance record is not append-only or independently replayable

The operator authority requires an append-only record of every external request
and state change and hash binding of browser actions. `PersonioNetworkTrace` keeps
only request URLs in memory. The preflight review is returned but not durably
persisted. The circuit overwrites one singleton state row rather than journaling
each transition. The final receipt does not contain the preflight-review hash or
network-trace hash.

The final "official" proof is a client-side success text marker plus disappearance
of the submit button. Only hashes of the success DOM and screenshot are retained;
the DOM bytes, screenshot bytes, POST request/response, response status and any
Personio confirmation identifier are not retained. Those hashes cannot later be
independently inspected. This does not satisfy the authority's official-receipt
and bounded-screenshot retention requirement.

### 5. The CV builder does not deterministically derive claims from approved evidence

The evidence file hash in the prepared manifest is correct, but the builder only
checks that seven evidence IDs exist. It creates an `evidence` mapping and then
does not use the approved statement text when composing the CV. The CV prose is
hard-coded, and several granular claims go beyond the seven cited statements,
including APIs/structured JSON/audit trails, SCAFAD graph analysis/privacy/
adversarial testing/explainability, and specific orchestrator workflow stages.
The reviewed evidence packet may contain related support, but the builder does not
bind those claims to it, require the relevant evidence atoms, or fail when their
text changes. A rebuild also produced different PDF bytes, while the builder and
render environment are not part of the prepared release binding.

### 6. Remaining crash/retry and late-drift weaknesses

- `submit()` calls `prepare_review()` before verifying that the circuit is still
  `ready`. A second call after an indeterminate/succeeded attempt can populate
  fields and bind a local upload before `prepare()` rejects the spent circuit.
- `block()` can overwrite `release_consumption_started` or `release_consumed`
  with `blocked`, weakening the durable distinction between safely blocked and
  consequentially indeterminate.
- After release consumption, the adapter rechecks only submit-control uniqueness
  before clicking. It does not revalidate populated contact values/CV bytes or
  rerun the complete blocker scan at the final click boundary.
- The circuit database path is caller-selected and is not bound to the prepared
  manifest or a globally unique canary identity, so local circuit uniqueness is
  not sufficient by itself to prevent parallel fresh-database attempts.

## Exact work required before a new release review

1. Compile the exact CloudCops source, approved contact, questions and rendered
   artifacts through `ApplicationCompilationStore`; persist and expose its real
   `ApplicationCompilation` identity.
2. Register the exact official route and issue a same-day real
   `jaa08.release-manifest.v1` plus one-use token with
   `ReleaseGateStore.evaluate_and_issue()`. Never copy a token into documentation.
3. Derive the Personio payload from those same compiled objects and make the
   adapter verify that JAA-08's stored job, candidate, artifact set and official
   route equal its own binding before authority consumption.
4. Replace or regenerate the parallel prepared manifest so one canonical schema
   hash, CV hash, contact identity, frozen vacancy and circuit ID are shared by
   documentation, executable code and release-store records.
5. Anchor a single circuit path/ID for this canary and add an immutable transition
   and external-request/response journal. Preserve indeterminate states permanently.
6. Persist the preflight review, redacted network trace, action sequence and actual
   receipt evidence. Bind their hashes into the final receipt while retaining the
   reviewable source bytes under the approved evidence boundary.
7. Make the CV compiler derive every claim from explicit approved evidence atoms,
   bind its implementation/render environment, and remove or separately approve
   claims that are not deterministically supported.
8. Add negative integration tests proving that contact substitution, CV
   substitution, stale/fabricated duplicate decisions, a release for another job,
   a fresh circuit path, late CAPTCHA/schema drift and a post-indeterminate second
   call all fail before population or click as appropriate.
9. Re-run this independent release review against the actual unconsumed
   `IssuedRelease` and durable evidence package.

## Final decision

The current CloudCops route appears clean and the isolated Personio adapter is a
promising fail-closed implementation. It is **not release-authorized**. The real
JAA-07/JAA-08 compilation-to-token chain, cross-object binding and durable official
evidence required by the operator authority are absent. **Do not arm, populate,
upload, consume authority or click. `WITHHOLD`.**

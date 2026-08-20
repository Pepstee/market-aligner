# Gutua application sanity reviewer result — 6 August 2026

## Result

The single-purpose semantic sanity reviewer is mandatory on every currently
enumerated JAA submit path. It cannot edit or materialise application values.
The deterministic exact-PDF gate and permanent quarantine remain intact. No
real application was submitted.

Implementation commit: `c32aad6` (`Add mandatory application sanity review gate`).
The clean starting commit was `83a9d43`.

## Policy and evidence identities

- policy SHA-256: `ffc042623e1b4f503594ffaab05387a62e68f666e7a01608c13ac39e356b3d36`
- prompt SHA-256: `5e9c2b8ddd25cb8e529e6f74077ba28bae12b50779c2950a8cb36fdaa4cf2e41`
- result-schema SHA-256: `4be351798c8a066cdfe55648ac86e8789e4ae39defe8e6f0addd0a1e9219cb52`
- live-evidence file SHA-256: `31d58e0f2c47db0a03f500a36f56accf68805e7542e714f55038e053336e3b50`
- clean live PASS receipt: `11f9fd10e57b0a1e31a424814dc050b82091ba7a23505e57bd926cbf645ab422`

## Live subscription-CLI smoke

Claude CLI 2.1.175, configured model `sonnet`, ran five bounded synthetic
packages. All expectations matched:

- clean, relevant `built an LLM workflow` canary: PASS;
- subtle private traceability/evidence-origin wording: BLOCK,
  `internal.governance_or_audit_disclosure`;
- volunteered AI implementation/application authorship: BLOCK,
  `internal.ai_authorship_disclosure`;
- apology and needless weakness framing: BLOCK, `framing.apology` and
  `framing.needless_weakness`; and
- embedded `ignore previous instructions` request: BLOCK,
  `security.prompt_injection` and `claim.unsupported`.

Evidence records hashes, verdicts, stable codes, provider/model, and timing.
It uses synthetic names and contains no personal contact values.

## Tests

The directly relevant implementation and mutation checks passed 19/19.
The first combined assurance/release/browser run passed 94/95; its one failure
was a legacy newline-normalisation test that deliberately changed cover-note
bytes while reusing authority. The test was corrected to obtain a new scripted
receipt for each changed synthetic package, preserving the original assertion
and proving the new binding.

The complete repository JAA-08, JAA-09, JAA-10, JAA-16, external-document,
and semantic-review selection then produced:

```text
639 passed, 1 failed, 3 errors in 84.63s
```

The four non-passes are honest pre-existing environment/baseline constraints
in `test_jaa10_network_witnessed_fixture.py`:

- three setup errors require exactly one cached pinned Playwright Chromium;
  this host has both `chromium-1228` and `chromium-1234`; and
- one historical integration test demands an exact old Git-diff allowlist,
  which rejects this authorized change and numerous already-present worktree
  files relative to its fixed design base.

No cached browser was deleted and the historical allowlist was not weakened.
All 639 executable checks outside those constraints passed. After the newline
test fix, the focused semantic, exact-PDF, JAA-09 browser/negative/real-vacancy,
JAA-10 full-submit, and JAA-16 certification gate passed `95 passed in 42.30s`.

## Limits

The semantic decision remains model-dependent, so the system treats absence,
uncertainty, malformed output, findings, policy drift, and package drift as
hard failure. A PASS is specific to one exact package and does not assert that
all possible semantic defects are detectable.

The certified scope remains the enumerated JAA executor paths. It does not
control arbitrary human clicks. The production ATS adapter remains a separate
missing boundary, and this work performed no real submission.

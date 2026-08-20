# Gutua JAA assurance, throughput and application handoff

## Frozen objective

Continue the exact Mac checkpoint migrated on 2026-08-05. Do not restart the
solution or discard the partial implementation. Finish it, test it, and keep
all final submissions closed until the new gate is certified.

The incident document is permanently forbidden:

`3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2`

## Non-negotiable assurance contract

1. Inspect text extracted from the exact final PDF bytes, not source text alone.
2. Reject internal governance, audit, model/provenance, prompt leakage,
   unresolved placeholders and self-sabotaging disclaimers.
3. Bind every PASS receipt to the final PDF SHA-256 and exact intended vacancy:
   job key, vacancy SHA-256, role title and company.
4. Require and recompute those receipts immediately before every actual final
   submit click. Cached validation is insufficient.
5. Permanently quarantine the incident hash above before PDF parsing.
6. Prove the boundary with adversarial PDFs, byte mutation, wrong-vacancy,
   missing-receipt and submit-path bypass tests.
7. Never route a final click through raw Playwright or another browser tool to
   evade the gate.

## Partial implementation already present

- `career_automation/external_document_assurance.py`: deterministic PDF text
  extraction, policy rules, immutable incident-hash registry, content-only
  inspection, vacancy-bound PASS receipts and CLI.
- `career_automation/rendering.py`: source-text scan plus exact rendered-PDF
  inspection.
- `career_automation/release_gate.py`: ATS validator now includes the assurance
  policy.
- `career_automation/browser_executor.py`: `ReleaseExecutionAuthority` requires
  CV and cover-letter receipts and `_execute_submit` recomputes assurance at the
  last consequential boundary.
- All three known `ReleaseExecutionAuthority` constructor sites have been
  updated. Syntax compilation passed on the Mac.

This checkpoint is incomplete. It still requires adversarial tests, actual
incident-PDF proof, release regression tests, documentation review, and any
repairs those tests reveal. Inspect the diff before editing.

## Throughput objective

After the assurance gate is certified, profile the application pipeline and
remove avoidable latency without weakening evidence validation, vacancy
binding, duplicate prevention, or final-submit assurance. Prefer reuse of one
warm browser/session, bounded waits, cached immutable vacancy/company data,
and parallel preparation of independent applications. Final clicks remain
serialized and individually verified. Record before/after timings and the
cause of every material improvement.

## Resume-applications boundary

Applications may resume only after:

- the malicious PDF is demonstrably blocked;
- a newly rendered clean PDF passes exact-text inspection;
- adversarial and bypass suites pass;
- the exact clean PDF hash and intended vacancy appear in the final receipt;
- pre-submit evidence shows the clean PDF, not the quarantined hash.

Start with the lowest-priority eligible pending opportunity as a canary. Never
invent a claim or answer. Do not evade CAPTCHA, MFA, consent, rate limits or
site restrictions. A submission is confirmed only by an official ATS receipt
or a matching confirmation email; otherwise record it as indeterminate and do
not resubmit blindly. Continue through the eligible queue after the canary is
verified, and log technical blockers separately.

## Required durable outputs

- tested implementation and Git commits in the isolated Gutua worktree;
- `docs/EXTERNAL_DOCUMENT_ASSURANCE.md`;
- machine-readable PASS/BLOCK test evidence and exact hashes;
- throughput benchmark before/after;
- application ledger entries for every attempted vacancy;
- final handoff recording completed, blocked and operator-gated work.

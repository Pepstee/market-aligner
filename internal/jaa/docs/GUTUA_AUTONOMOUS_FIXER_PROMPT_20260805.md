# Autonomous Gutua JAA fixer work order

You are the sole active writer for this isolated JAA worktree. Work
autonomously until the assurance fix is implemented and proven, then improve
throughput and resume eligible applications through the certified path. Do
not wait for routine operator confirmation. Do not edit any older JAA,
orchestrator, DFI, or giga-user tree.

Read `AGENTS.md` and `docs/GUTUA_ASSURANCE_SPEED_HANDOFF_20260805.md` first.
Inspect the current Git diff/history and continue from commit `50ecb18`; do not
replace the partial implementation with a speculative rewrite.

## Phase 1: finish the non-bypassable assurance gate

Implement the complete contract in the handoff document. In particular:

- exact final-PDF bytes must be parsed and their extracted text inspected;
- internal governance, audit, model/provenance, prompt/control leakage,
  placeholders and self-sabotaging disclaimers must block;
- PASS must be a deterministic receipt bound to final PDF hash and exact
  vacancy identity;
- the incident hash must remain permanently quarantined;
- every actual final-submit boundary must require and recompute the receipts;
- there must be no alternate JAA final-click path that omits the gate.

Add comprehensive tests using generated adversarial PDFs. Include the exact
incident text, homoglyph/whitespace variants where practical, byte mutation,
wrong vacancy, missing receipt, malformed/encrypted/image-only PDF, symlink,
stale policy and bypass-path tests. Run targeted and relevant release/browser
regressions. Test the real quarantined PDF supplied in operational state.
Write machine-readable evidence and `docs/EXTERNAL_DOCUMENT_ASSURANCE.md`.

Do not claim universal control over arbitrary human/browser clicks. Certify
the JAA production submit paths you can actually enumerate and enforce. If an
alternate operational script exists outside this repository, either route its
final click through the gate or disable its submit capability fail-closed.

## Phase 2: produce and inspect a clean canary document

Generate the next CV and cover letter only from the approved evidence packet.
Inspect text extracted from the final PDFs and retain their hashes/receipts.
Confirm the quarantined hash is absent from every upload path. Do not add
authorship disclaimers, internal controls, or unsupported claims.

## Phase 3: optimize speed safely

Measure the current per-application critical path. Optimize proven bottlenecks
without weakening assurance, evidence validation, duplicate prevention or ATS
respect. Prefer a warm reusable browser/session, one-time immutable data
loading, cached employer/vacancy analysis keyed by hash, bounded waits,
parallel preparation of independent jobs, and serialized final submits.
Record before/after timings and add regression tests for changes.

## Phase 4: resume applications

Only after Phase 1 passes, run one low-priority eligible canary through the
new boundary. Verify it using an official ATS receipt or matching confirmation
email if accessible. If email is inaccessible, say so and retain the official
receipt; never fabricate confirmation. Then continue through the eligible
pending queue. Preserve operator facts: UK resident temporarily in Korea,
unrestricted UK work rights, available to start ASAP, degree classification is
a First rather than a cross-university numeric average. Attendance/onsite is a
preference, not an eligibility veto.

Do not evade CAPTCHA, MFA, consent, rate limits or explicit site restrictions.
Place ATS-blocked jobs in the existing blocked queue with technical evidence.
Treat rejection as acceptable; do not suppress truthful applications merely
because fit is imperfect. Never duplicate a confirmed or indeterminate submit.

## Persistence and reporting

Commit coherent checkpoints on this branch. Keep working through test failures
instead of stopping at diagnosis. Write the final status to
`docs/GUTUA_AUTONOMOUS_FIXER_RESULT_20260805.md` and also to the path supplied
by `--output-last-message`. Distinguish verified completion, honest blockers,
and operator-gated actions. Include commit IDs, tests, exact document hashes,
benchmark results, attempted/submitted job IDs, and remaining queue counts.

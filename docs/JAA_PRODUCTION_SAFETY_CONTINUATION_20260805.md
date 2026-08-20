# JAA production safety continuation — 2026-08-05

## Scope and outcome

This slice closes the release-critical findings in the independent audit of
`55fd7a3` and adds an executable Greenhouse queue-to-recorder-to-executor path.
It does not claim that a live application was submitted. No consequential click
was performed during this slice.

The read-only Greenhouse observation is attempt
`jaa-20260805T221502Z-103ee912b1094744`. Its terminal manifest SHA-256 is
`7288c0c9acd00f464f43118c7729cf8c61a1ba8c7d2b1237607f17978550740b` and
its exact provider observation SHA-256 is
`e7786a8d3cd7fcacc7ea494c9de294d97c0e5124964c817bac9a5ffc2a05e988`.
The provider returned HTTP 200. The observation performed zero fills, zero
uploads, and zero submit clicks. It recorded the provider-supplied confirmation
path and positive visible receipt message. CAPTCHA/reCAPTCHA signals caused the
canary to stop and archive a blocked boundary.

## Implemented release boundary

- The executor performs a complete preflight before recording click intent. It
  explicitly verifies both exact-PDF receipts, the semantic-sanity receipt, the
  release archive, current form bytes, approved fields and consents, exact
  browser-resident upload bytes, and the unique submit control.
- The sole click primitive repeats the same authoritative browser validation
  after intent and immediately before its one `locator.click()` call. A known
  in-primitive rejection writes a durable click-cancelled proof and a terminal
  `gate_rejected` outcome with `click_may_have_occurred=false`. An unknown crash
  after intent remains quarantined and is never replayed.
- Upload authority binds each logical role to one exact browser input. It reads
  each selected browser `File`, hashes those bytes outside the page, and rejects
  role swaps, duplicate basenames, same-name/different-byte files, inaccessible
  bytes, missing files, and extra selected inputs.
- Employer-facing fields are bound to canonical approved contact, question,
  answer, and consent values. Undeclared or ambiguous fields fail closed.
- Positive success requires the exact observed confirmation URL and every
  observed visible marker. URL arrival alone is indeterminate.
- Current-batch and historical duplicate checks independently compare job key,
  vacancy hash, and canonical source URL. Any unresolved click intent is a
  duplicate quarantine irrespective of a later crash/timeout label.
- Terminal verification reapplies outcome-specific evidence requirements and
  independently rejects empty HTTP evidence without an explicit availability
  reason.
- Generated final CV source/PDF, cover-letter source/PDF, and answer bytes must
  all exist in the revision inventory before release. Rejected revisions require
  rejection codes and remain append-only archive objects.
- The production runner wires the ascending queue, attempt recorder, release
  archive, release authority, certified executor, terminal checkpoints, and
  provider-boundary continuation. It requires an explicit `--execute-live`
  acknowledgement.

## Adversarial verification

The focused suite passed 164 tests in 32.20 seconds. It includes dynamic tests
for role swaps, duplicate basenames, same-name/different-byte uploads,
inaccessible browser `File` bytes, extra file inputs, wrong answers, preflight
failures before intent, revalidation failures after intent, crash recovery,
URL-only false success, success-observation digest injection, current-batch
equivalence, click-intent quarantine, terminal-role removal, and meaningless
empty network evidence.

A complete dry import of all 88 legacy application records into a disposable
archive also passed: 29 were classified as historical submitted successes and
59 as blocked/gated records. All 88 terminal manifests and the 176-event
checkpoint ledger independently verified. The production import is intentionally
performed only after this code is committed and the clean-source browser fixture
passes.

## Archive and operational limitations

- The Greenhouse observation documents provider behavior but encountered a
  CAPTCHA/reCAPTCHA boundary. That provider state must not be bypassed. Other
  providers or vacancies remain independently actionable.
- No mailbox connector is available in this execution environment. Current
  receipts therefore record email checking as unavailable/unchecked; success is
  never inferred from email. Post-intent recovery uses only exact provider page
  evidence and otherwise records an indeterminate quarantine.
- The production runner deliberately accepts a project-specific preparation
  factory. That factory must supply live vacancy captures, approved documents,
  exact field bindings, the observed success-evidence object and bytes, and a
  complete generated-revision inventory. Missing final-generation bytes fail
  before release.
- The cached `.playwright-cli/` files contain only a failed read-only tool log
  and accessibility snapshot. Inspection found no entered field values, cookies,
  credentials, tokens, passwords, or one-time codes. The directory is ignored
  by Git and its exact files are queued for the local observation archive.

## Exact next resumable action

Commit this safety slice, run the clean-source network-witnessed fixture, import
the 88 legacy records into the production content-addressed archive, archive the
older loose discovery/tool observations, and derive the current live eligible
queue from the durable Market Aligner state. Only then may the weakest-fit
non-duplicate item reach the certified executor.

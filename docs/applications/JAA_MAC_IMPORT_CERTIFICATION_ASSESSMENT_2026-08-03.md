# JAA Mac import certification assessment

Assessment date: 2026-08-04 KST

Imported source: `974b41a566fd3fb95abc12827093ed681d87b31c`
Imported tree: `212fea4b7a4924dbb3f1f7ebc30445953ddf1d51`

## Verdict

The Gutua transfer is authentic and its independent JAA-10 exact-source
certificate is preserved. The current Mac checkout is not yet a final portable
product certificate because it is dirty with the completion work and still
needs final exact manifests and independent receipts for transferred JAA-10
external-control evidence and retained Linux-only evidence.

The controlling JAA-10 raw evidence has SHA-256
`72b27f845cd54b7c9ba2e70485623a3cffbc1cee7636c292fd50e0b0352f2a68` and
contains the terminal ruling
`OPUS_JAA10_EXACT_SOURCE_CERTIFICATION: CERTIFIED`. The local hard-metrics
receipt remains deliberately non-self-certifying; that is separation of duties,
not contradictory evidence.

## Portability work completed

1. Imported the exact 92-file, 34,932,504-byte JAA-09 corpus and selected it
   through `JAA_CERTIFIED_CORPUS_ROOT`.
2. Removed `the implicit home directory` defaults from three tracked shipping modules while
   preserving fail-closed evidence checks.
3. Added an exact certification profile covering 36 named JAA-09/JAA-10 files:
   29 Mac-applicable files and seven Linux-bound suites. Four require the
   private namespace witness, two require Linux `CLOCK_BOOTTIME`, and one
   binds the frozen Linux Chromium rendering identity.
4. The profile rejects broad exclusions, symlinks, dirty source, hash drift,
   missing files and unknown inventory additions.
5. Preserved the Linux namespace proof as retained historical evidence rather
   than pretending Darwin can reproduce `/proc`, `unshare`, `ip`, `setpriv`, a
   private network namespace, `CLOCK_BOOTTIME` or Linux Chromium. The three
   additional Linux-bound suites have no historical-evidence claim and still
   require current-source Linux execution.

## Current verified results

| Scope | Result | Meaning |
|---|---:|---|
| Exact JAA-09 corpus suite | 68 passed | Imported corpus and explicit root are valid. |
| Profile, sealer and runner tests | 24 passed | Exact platform classification and fail-closed execution binding work. |
| Path-free distributable gate | 1 passed | Tracked shipping code no longer embeds the repaired Gutua paths. |
| JAA-08 plus JAA-11 | 637 passed | Release/adapters/bridge remain compatible. |
| JAA-11 through JAA-16 plus profile/sealer/runner | 932 passed | Safe local foundations converge; this is not production promotion. |
| Dirty-tree Mac-applicable JAA-09/JAA-10 diagnostic | 424 passed, 1 expected pre-commit failure | No unexplained Mac failure remains; the last control requires a clean checkout. |

The earlier broad Mac run produced 2,208 passes, 13 skips, 185 failures and 127
errors. It was diagnostic, not a certificate. Its dominant non-passes were old
Gutua topology, external evidence roots and exact Linux-only witness suites.

## Product-boundary result

Production-bounded Recruitee, Ashby and Personio adapters now exist with exact
route/schema/artifact binding, JAA-08 token consumption immediately before the
sole click, durable one-use/indeterminate state and hash-only receipts. Decoded
parks on hCaptcha and Vega parks on reCAPTCHA.

A real CloudCops Personio pipeline bridge now uses the actual JAA-05, JAA-06,
JAA-07 and JAA-08 objects. It correctly withheld release because the approved
evidence packet did not establish several material role requirements. An
independent review also found that the earlier prepared CloudCops manifest was
not an authentic JAA-07/JAA-08 release object and that the earlier CV was not
mechanically derived from the approved ledger. The manifest is now tombstoned.

The bounded candidate search found no release-ready target. A later
evidence-compatible Workable route exposed Cloudflare Turnstile. Consequently
no release token was issued, no applicant data was entered and no submit click
occurred.

## Downstream implementation status

- JAA-12: bounded source-backed status ingestion and follow-up-due ledger.
- JAA-13: source-backed interview preparation, debriefs and non-sendable drafts.
- JAA-14: append-only predictions/outcomes/calibration without policy promotion.
- JAA-15: non-network adapter acquisition registry without activation.
- JAA-16: local supervisor, scheduling, backpressure, budgets, leases, fallback,
  drills, reports and backup/restore metadata without external deployment.

These are executable safe foundations. Promotion requires real upstream events,
locked evaluation evidence, independent certification and, for JAA-16, a
clean-machine distributable release with rollback evidence.

## Remaining Mac certification work

1. Seal exact manifests for transferred JAA-10 external-control evidence.
2. Seal and verify the exact retained Linux evidence package.
3. Run the exact applicable profile from a clean source tree.
4. Obtain an independent receipt for the post-import changes and profiles.
5. Preserve the historical JAA-10 certificate while separately certifying every
   changed source file; do not treat ancestry as certification of new code.

## Final certification gate

Final portable certification may pass only when:

- source and external evidence identities are explicit and immutable;
- every applicable Mac test passes under the exact profile;
- every Linux-bound exclusion is named; historical evidence is attached only
  where it actually exists, and current-source Linux execution remains
  mandatory for all seven;
- tracked distributable code contains no operator-machine path;
- a future JAA-11 canary passes all facts/form/forbidden-interaction gates and
  has an official receipt, or is honestly parked without a success claim;
- downstream slices are promoted only from real dependency evidence; and
- install, upgrade, backup/restore, rollback and uninstall pass independently on
  a clean machine.

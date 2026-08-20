# JAA production certification checkpoint — 2026-08-06

## Outcome

This checkpoint does not claim a live submission. No consequential click was
performed. The certified executor remains fail-closed until an independent
exact-clean-HEAD audit returns PASS and the required external operator contact
authority is enrolled.

The current deterministic candidate authority is
`29fcad97535d25151aa456bb11212b138e3d756723c372ee80d67101aec085d9`.
It is stored both as a content-addressed object and under
`candidate-authorities/` in the production application archive. It contains 21
decisions: 15 eligible, three ineligible, and three unresolved. The concrete
repository production session re-derived this authority from the immutable
discovery, database, evidence, policy, schema, and duplicate snapshot before
accepting it.

## Release-critical boundaries

- Candidate evidence matching requires the same named AWS service and the same
  material deployment action. Parent-platform and service-swap matches fail
  closed; benign terminal punctuation is normalized.
- Contact data requires an enrolled Ed25519 operator key, a content-addressed
  signed authority, and a unique signed registry head. Registry history is
  linear, monotonic, cumulative in revocation, and re-read by the release gate.
  No production key or contact record is embedded in the repository.
- Candidate generation runs in the exact-clean isolated worker, streams every
  revision to the create-only recorder, binds transitive source hashes, and
  reconstructs the returned package only from the archived package object.
- Provider observation authority binds the trusted collector and exact source
  commit. Vacancy identity binds material requirements, not only title, company,
  URL, or token overlap.
- Gmail recovery requires owned transport, a durable query receipt, narrow
  provider/vacancy/time scope, and explicit positive confirmation language.
  It never replays a click.
- Any prior click intent permanently quarantines a vacancy. The label or later
  terminal outcome cannot clear it.
- The sole final-click primitive repeats both exact-PDF receipt checks, semantic
  sanity, current candidate/contact authority, archive truth, form answers,
  consent state, official route, and exact browser-resident upload-byte binding
  immediately after durable intent and before dispatch.

## Exact verification evidence

At clean source commit `e091b3a47082bde56ea2286f2bb2f6723b080ae0`, the
consolidated release-critical suite passed 214 tests in 51.85 seconds. It
covered manifest truth, the application archive, candidate/contact/release
authority, Gmail confirmation, concrete Greenhouse session, legacy import,
production executor, ascending queue, isolated generation runner, and provider
observation capture/authority. The focused candidate/contact/release slice
additionally passed 28 tests, and the executor suite passed 33 tests.

All 131 production terminal attempts independently reverified at that commit:

- 96 `blocked`;
- 29 `historical_submitted_success`;
- four `abandoned`;
- two `crashed`;
- zero release manifests; and
- zero click intents.

The 15 currently eligible Greenhouse vacancies each already have a terminal
blocked attempt containing the provider human-verification boundary, visible
state, screenshot, and network evidence. Each records zero filled fields, zero
uploads, zero click intents, and zero submit clicks. Queue reconstruction
therefore yields zero ready and 15 `prior_blocked` exclusions. These controls
must not be bypassed or silently relabelled.

## Measured time and limitations

No current eligible attempt reached document generation or form filling, so a
truthful end-to-end time per completed application is not available. The 15
archived pre-generation boundary attempts took 22.571 seconds in total: 1.411
seconds minimum, 1.459 seconds median, and 1.807 seconds maximum. These are
boundary-detection times, not application-preparation or submission times.

The production operator key, signed contact record, and signed contact registry
are intentionally absent. Live preparation must continue to fail closed unless
the operator supplies them outside the repository. The current blocked queue
does not require or justify inventing those values.

## Exact next resumable action

Obtain a consolidated independent PASS for the exact clean commit containing
this checkpoint. Only after that PASS, run the required current-HEAD
non-consequential read-only canary. If the provider human-verification boundary
remains, archive it without interaction or submit and preserve the terminal
queue. If a supported form becomes safely reachable, stop before preparation
until the operator enrolls the real signing key, current contact authority, and
registry; then resume from the weakest-fit eligible non-duplicate vacancy. Never
replay a successful, indeterminate, or click-intent attempt.

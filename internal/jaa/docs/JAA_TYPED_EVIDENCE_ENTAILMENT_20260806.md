# JAA typed semantic-evidence entailment — implementation report (2026-08-06)

Read-only, non-release slice closing the mandatory *semantic-entailment contract*
(beyond named-token matching). No network, browser, form, upload, click, email, or
release authority is added or exercised. Operator Ed25519 enrollment remains
absent by design; every consequential action stays gated.

## What changed

`career_automation/candidate_authority.py` replaces the token-set "named material
support" matcher with a typed entailment engine, schema
`jaa.typed-evidence-entailment.v2` (`TYPED_EVIDENCE_SCHEMA`).

- **Explicit hash-bound evidence atlas.** `_APPROVED_EVIDENCE_ATLAS` materializes
  the eighteen approved statements as `(entity, action, modality)` facts, keyed by
  the exact SHA-256 of each statement. It records only what a statement directly
  attests; a clause under negation contributes no positive fact (E-007 "not a B2B
  sales role", E-011 "did not personally hand-write … production code", E-016/E-017
  "not … production …" mint nothing). Production matching is served from the atlas,
  never a token intersection. Any change to the shared candidate source both misses
  the atlas key and fails the pinned-hash gate. Statements outside the atlas (test
  synthetics) are typed by an identical deterministic parser (`_statement_facts`),
  which detects every action a clause coordinates.
- **Typed requirement atoms.** `_requirement_atom` parses a requirement into a
  conjunction of alternative-entity groups (disjunction only for an `or`/`/` clause
  with no `and`), a required action, an optional modality modifier, and numeric
  duration / scale flags.
- **Entailment rules.** A requirement is supported by an evidence item only when
  every conjunct is met by a fact of that same item whose entity matches, whose
  action is entailed by the evidence action (`_ACTION_SATISFIES`: `used`/`studied`
  never imply `built`; `built` never implies `deployed`/`operated`; `experience` is
  entailed by any concrete action but never the reverse), and whose modality is
  compatible (`production` strict; the commercial/professional family accepts any
  real-world tier; `prototype`/`academic`/`personal-project` never satisfy a
  commercial/production modifier). A negated requirement, or a named numeric
  duration/scale the approved evidence never attests, fails closed. Suppressors are
  unchanged and still only remove support, never create it.
- **Schema/hash binding.** `typed_evidence_projection_hash` binds
  `evidence_projection_schema` + `evidence_projection_sha256` into every
  candidate-authority receipt and into the non-Greenhouse projection document.

`career_automation/nongreenhouse_fit_projection.py` binds the same schema/hash
into the Ashby/Lever projection provenance. `fit_from_evidence_matrix`,
`_evidence_matrix` row schema, eligibility, ordering, archive, identity, and
non-release flags are unchanged.

## Tests (`test_candidate_authority.py`)

- Full contract adversarial matrix (16 negatives, 13 positives): numeric shortfall,
  prototype≠production, academic≠commercial, used/experience≠owned/led, AWS
  Lambda≠SageMaker, generic AWS≠exact service, Python≠Django, single-agent≠
  multi-agent, backend≠distributed-backend-at-scale, negation on both sides,
  under-covered conjunction, and a shared entity beside an unattested co-named
  technology (Bazel); positives confirm the exact approved statements still entail
  the exact typed requirements, including disjunction and covered conjunction.
- Retained: the seven prior generic-overlap negatives, named Lambda/SageMaker and
  Python/multi-agent positives.
- New: atlas-covers-exactly-the-eighteen (hashes match the live packet; production
  is served from the atlas, not the parser) and the v2 projection schema/facts
  binding test.

Result: `test_candidate_authority.py` 45 passed; `test_nongreenhouse_fit_projection.py`
and `test_assurance_manifest_truth.py` pass; every test importing the changed
modules passes (216 passed). Ruff lint clean. The `pypdf`/`playwright`-dependent
suites remain red only because those pinned runtimes are absent from this
environment — identical on clean HEAD, unrelated to this slice.

## Fit impact (authoritative Ashby/Lever build, discovery `ebe3b999…`)

15 selected → 7 fit-recomputed, 4 prior-attempt, 4 quarantined. Every recomputed
fit is more conservative than the discarded empty-profile value; every remaining
`matched` row is a genuine attested AI/agent/LLM/AWS fact (E-011/E-012 directed and
owned multi-agent orchestrator/agents; E-016 built an LLM-assisted prototype; E-002
studied AWS in the SCAFAD dissertation). Prior overlap false-positives on the
Greenhouse cohort (Bazel "remote caching" ← E-011 caching; "operate cloud infra on
AWS"/"data pipelines" ← academic E-002; multi-agent RL experiments) are now gaps.
See `JAA_NONGREENHOUSE_FIT_PROJECTION_20260806.md` for the per-row table and the one
deliberately-retained generous match (`anthropic:5198999008` "partner … with …
Sales" ← E-007, real customer-facing sales, internal-only, ordering only).

## Next resumable action

Still read-only and non-release. Remaining safe in-repo work: Ashby-native capture
for the 4 aggregator roles and resolution of the 60 unresolved live sources (both
independently gated). No consequential action before the full signed release
boundary and real operator contact enrollment.

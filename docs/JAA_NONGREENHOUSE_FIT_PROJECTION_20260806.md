# Non-Greenhouse ascending-fit projection (read-only)

Date: 2026-08-06. Branch: `codex/jaa-assurance-gutua-handoff-20260805`.

## Why

The Greenhouse production slice is exhausted: all 15 currently eligible Greenhouse
vacancies carry verified CAPTCHA/reCAPTCHA `prior_blocked` attempts and must not
be replayed. The global objective is not exhausted. The durable multi-provider
discovery (`non-greenhouse-live-below-0143-v2.json`, 307 observations) holds 15
official-authority live opportunities — 12 Ashby and 3 Lever
(`JAA_B891B55_GLOBAL_QUEUE_SCOPE_AUDIT_20260806.md`, next-work item 3).

Those opportunities were discovered with `ranking_candidate_profile: "empty"`, so
their discovery `fit` values are invalid and must not govern order or release
(`JAA_CANDIDATE_AUTHORITY_AUDIT_20260806.md`). This slice recomputes fit from the
exact atomic requirements and orders the resolvable subset weakest-fit-first.

## What was built

`career_automation/nongreenhouse_fit_projection.py` — a read-only,
**non-release** projection. It reuses the audited, provider-agnostic primitives
from `candidate_authority.py` **unchanged** (`_evidence_matrix`,
`fit_from_evidence_matrix`, `_requirements`, `_approved_evidence`, `_projection`,
`_json_bytes`, `_atomic_create_or_verify`). It adds only: opportunity selection,
per-board HTML-body assembly, identity binding, ordering, and non-release framing.
It never invents requirement extraction or fit logic.

### Provider-native body assembly (Lever)

Ashby-style boards emit a single HTML description field, chosen from
`HTML_DESCRIPTION_FIELDS`. Lever does not: its posting body is split across
`description` (the opening), a native `lists` array where each entry pairs a
section `text` heading with a `content` HTML fragment of `<li>` requirement
bullets, and `additional` (benefits). For a Lever-authority opportunity the
projection deterministically reassembles these native fields into one HTML
document — each list heading rendered as `<h2>` immediately before its own
`content` markup, in native order — and feeds **that** to the same audited
`_requirements`/`_evidence_matrix` extractor.

This is pure provider-native field selection and assembly. No requirement is
created, dropped, or classified here — the audited extractor's own heading logic
and benefit filters make every decision (e.g. a `What We Offer` list is excluded
by the audited `_BENEFIT_HEADINGS` filter, not by this module). The reassembly is
recorded for reproducibility: `description_html_field: "lever:native-body"`, the
SHA-256 of the reassembled body, and a `description_reconstruction` list of each
contributing native field with its exact SHA-256. Assembly is Lever-scoped: a
non-Lever posting is never routed through it even if it carries a stray `lists`
field.

Guarantees in every emitted document:

- `release_capable: false`, `authorizes_action: false`, `eligibility_determined: false`.
- Deterministic eligibility is **not** decided; it requires operator-approved
  eligibility policy for these vacancies plus real operator contact enrollment.
  No form fill, upload, click, or email is permitted for any listed opportunity.
- Fit is computed **only** by the audited extractor. Where it cannot
  deterministically derive atomic requirements, the opportunity is quarantined
  with an explicit reason — never scored from an unaudited extractor.
- Binds `discovery_file_sha256`, declared `discovery_snapshot_sha256`,
  `jobs_database_sha256` (+ `jobs_database_approved`), and the audited
  `candidate_projection` identity. The jobs database is read
  `mode=ro&immutable=1` (the same approved immutable DB the release path pins).
- The output object is written create-only and content-addressed under
  `application-artifacts/nongreenhouse-fit-projections/`.

## Result against durable evidence

Current materialized artifact SHA-256:
`e9fbd8513252b2af47d2cc189d42845e8b946efee47bef2cb92cf0e5859f1192`
(`jobs_database_approved: true`, DB SHA
`67dfb680ad422ea7e1fe1e02d2362957ba3493a5eb0cdae17f0949e9ebbc88c3`; discovery file
SHA `ebe3b9992fafd94bc938b20dd98a43c08adaa48b15a7d2ae1160f5642720ff9a`). The prior
8-scored artifact `16d53046…` is preserved create-only in the append-only archive.

15 selected → **11 fit-recomputed, 4 quarantined**. The three Lever roles are
scored via provider-native body assembly (§ above). Fit now comes from the typed
named-material evidence matcher (`candidate_authority.py`, commit `15d2674`): a
requirement is supported only when it names a material capability/entity/service
that the same approved-evidence item explicitly attests, so generic token overlap
(`experience+public`, `architecture+system`, …) no longer inflates fit. This
matches the independent `429ce9e` review, which found only the multi-agent
requirement genuinely supported across the Lever cohort. Fits are accordingly much
more conservative than the earlier overlap heuristic (the AI-Engineer roles fall
from ~0.5 to 0.125; the two Octopus Energy roles and the four SWE roles collapse to
0.0; only the multi-agent-bearing roles retain support):

| rank | fit | empty-profile (discarded) | job_key | body |
|--|--|--|--|--|
| 1 | 0.000000 | 0.1343 | ashby:TRADINGHUB:a145eb8a… (SWE, Market Data) | ashby-desc |
| 2 | 0.000000 | 0.1213 | ashby:edra:142acdd7… (SWE, Back End) | ashby-desc |
| 3 | 0.000000 | 0.1213 | ashby:edra:3e27801a… (SWE, Front End) | ashby-desc |
| 4 | 0.000000 | 0.1046 | ashby:edra:5092d5ac… (SWE, Full Stack) | ashby-desc |
| 5 | 0.000000 | 0.1380 | lever:octoenergy:4f9c5847… (Octopus Energy) | lever-native |
| 6 | 0.000000 | 0.1343 | lever:octoenergy:e1112d35… (Octopus Energy) | lever-native |
| 7 | 0.040000 | 0.1213 | ashby:TRADINGHUB:c6a422ac… (Software Engineer) | ashby-desc |
| 8 | 0.050000 | 0.1413 | lever:electric-twin:830093d0… (Electric Twin) | lever-native |
| 9 | 0.090909 | 0.1320 | ashby:edra:c49b8111… (AI Engineer, London) | ashby-desc |
| 10 | 0.125000 | 0.1320 | ashby:distyl:26cc59d5… (AI Engineer) | ashby-desc |
| 11 | 0.125000 | 0.1320 | ashby:edra:0fef2ffb… (Forward Deployed AI Engineer) | ashby-desc |

Ties break on `job_key`. Every fit remains advisory only: `authoritative` marks the
queue source-bound and read-only, never release-ready, eligibility-determined, or
action-authorized.

Provider-native aliases (4) — `swissaijob:12293` (Mistral AI) and
`developerjobsch:{1e8143c1,36dc393b,dfae4bcc}` (The Flex). These are live
official-authority observations discovered under an aggregator board's own key,
whose apply authority is Ashby. Their durable jobs-DB posting holds only the
aggregator board's own scraped body (no provider-native `id`, no Ashby-native
apply URL), so the role cannot be scored from it. Rather than discard the durable,
allowlisted Ashby apply URL they carry, the projection now binds a
**provider-native alias** (schema `jaa.nongreenhouse-fit-projection.v2`,
`provider_native_aliases` section) to the exact `(provider, company_slug,
native_job_id)` parsed from that URL:

| discovery key | native identity |
|--|--|
| `swissaijob:12293` | `ashby:mistral.ai:8c71b069-0eda-40d1-8cb1-4094fd9c81de` |
| `developerjobsch:1e8143c1…` | `ashby:the-flex:82eafc9b-c4c0-4310-8b9d-9f5410ff0d53` |
| `developerjobsch:36dc393b…` | `ashby:the-flex:51693fcc-7a24-4a4c-9c87-84130b72c751` |
| `developerjobsch:dfae4bcc…` | `ashby:the-flex:806abd84-e07a-4ffc-9823-39fa097896a4` |

The alias is a read-only, durable identity binding only. It never scores or ranks
the role (`fit: null`, `body_identity_verified: false`), never reads the aggregator
body, and never mints or merges a duplicate vacancy: two discovery keys resolving
to one native identity, or an alias colliding with a natively-keyed opportunity,
fail closed (`provider_native_alias_duplicate`); more than one native identity in
the authority URLs fails closed (`provider_native_alias_ambiguous`). Each alias
also inherits any terminal attempt recorded under either its discovery key or its
native identity, so a prior success/blocked/indeterminate outcome bars re-capture.
The provider-native body itself still requires a later, independently gated
network capture (`requires: requires_network_capture`); no opportunity is scored
from an unaudited extractor. The aliases stay inside the official-authority
partition, so `official (15) + unresolved (60) == live (75)` is unchanged.

## Tests

### Provider-native alias adversarial matrix (`test_nongreenhouse_provider_alias.py`)

Fifteen fixtures reproduce every failure the mandatory projection/archive-integrity
addendum enumerates and prove each fails closed: a rich but non-native aggregator
body is never scored (altered-body); two discovery keys to one native identity and
an alias colliding with a native opportunity both quarantine (duplicate-alias /
conflicting vacancy); more than one native identity in the authority URLs
quarantines (ambiguous); `http`, non-allowlisted host, userinfo, and short-path
URLs mint no alias; the `/application` apply suffix is tolerated; a prior
blocked/success/missing-outcome terminal attempt under either the discovery key or
the native identity bars re-capture with the correct retry authority
(forged/missing-outcome/conflicting-attempt); a malformed/unreadable terminal
manifest neither forges a block nor silently clears one; and the live partition
stays exact with an alias present. The existing suite's aggregator test is updated
to the new capture-pending-alias behavior.

### Unresolved-live accounting hardening (`60ddb18` independent audit)

The `unresolved_live_sources` partition and its live-source reconciliation are now
hardened per the independent `60ddb18` audit, entirely read-only:

- **Canonical https host, never `netloc`.** `_final_url_host` now goes through
  `_canonical_host`, which validates an absolute `https` URL, rejects embedded
  credentials/userinfo, an explicit or malformed port, IP literals, scheme-relative
  and non-HTTPS inputs, and any control/format character, then IDNA-encodes the host
  and emits only a canonical lowercase hostname. A netloc bearing userinfo, a port,
  mixed case, or a token can no longer be copied through.
- **Fail-closed allowlist under `python -O`.** The closed-field guard is now an
  explicit `if/raise` (`_enforce_unresolved_allowlist`) that still fires under
  `python -O`, replacing an `assert` that optimized mode would have stripped.
- **Strict typed, bounded public fields.** Every surfaced field is typed and
  bounded: `job_key` fails closed if malformed; `board`/`company`/`role`/`location`/
  `reason` drop to `null` if non-string, oversized, or control/format-bearing;
  `http_status` rejects booleans-as-integers, structured objects, and out-of-range
  values; `discovery_body_sha256` requires canonical lowercase hex. Structured,
  binary, oversized, or nested values can never appear in the projection.
- **Exact set-partition proof.** `live_source_reconciliation.partition_proof` proves
  the live cohort splits into disjoint, duplicate-free official and unresolved sets
  that together reconstitute the exact live identity set, binding sorted identity
  SHA-256 hashes for all three sets — a coincidental count equality is no longer
  sufficient. A live observation without a stable `job_key` now fails closed instead
  of being silently dropped.

`test_nongreenhouse_fit_projection.py` (103 hermetic tests, all pass; ruff clean):
partition/ordering, non-release + no-eligibility invariants, fit matches the
audited primitive, deterministic bytes, identity-mismatch quarantine, non-zero
interaction rejected, wrong-schema rejected, no-official-authority rejected,
create-only + idempotent materialize (+ tamper rejected), and five Lever
provider-native assembly cases: the assembled body is scored solely by the audited
primitive with a fully reproducible `description_reconstruction`; assembly is
deterministic; a benefits-only `lists` mints no requirement; assembly is
Lever-scoped (a stray non-Lever `lists` is ignored); and a Lever posting with no
requirement sections still quarantines. Three later adversarial closures cover the
`429ce9e` escape-to-unescape heading injection (literal split, entity-encoded
split, inverse split) and bind the heading component hash to the exact raw field.

`candidate_authority.py` now carries the typed named-material matcher (commit
`15d2674`) with seven exact negative controls (`experience+public`,
`experience+not`, `evidence+support`, `it+question`, `evidence+it`,
`architecture+system`, `experience+project`), the named Lambda/SageMaker and
Python/multi-agent positive controls, and a projection-binding test; its focused
suite passes. The change is read-only and non-release. The `pypdf`-dependent
release-gate/application-factory suites remain red only because that pinned runtime
is absent from this environment — unrelated to these slices.

## Typed semantic-entailment matching (schema `jaa.typed-evidence-entailment.v2`)

The named-material matcher above shares a *token* between a requirement and an
evidence item. The mandatory semantic-entailment contract requires more: `Python`
matching `Python` cannot by itself prove commercial seniority, production
ownership, deployment, or duration. The matcher is now a typed entailment engine.

**Evidence representation.** The eighteen approved statements are projected into an
explicit, reviewable fact atlas (`_APPROVED_EVIDENCE_ATLAS`) keyed by the exact
SHA-256 of each statement. Each fact is `(entity, action, modality)` and records
only what its statement directly attests; a clause under negation contributes no
positive fact (so E-007 "not a B2B sales role" and E-011 "did not personally
hand-write … production code" mint nothing). Production matching is served from
the atlas, never a token intersection; any change to the shared candidate source
both misses the atlas key and fails the pinned-hash gate. Statements outside the
atlas (test synthetics) are typed by an identical deterministic parser.

**Requirement atoms.** A requirement is parsed into typed constraints on the same
axes: a conjunction of alternative-entity groups (disjunction only for an
`or`/`/` clause with no `and`), a required action, an optional modality modifier,
and numeric duration / scale flags.

**Entailment rules.** A requirement is supported by an evidence item only when
every conjunct is satisfied by a fact of that same item whose (a) entity matches,
(b) action is entailed by the evidence action (`used`/`studied` never imply
`built`; `built` never implies `deployed`/`operated`; `experience` is entailed by
any concrete action but never the reverse), and (c) modality is compatible
(`production` is strict; the commercial/professional family accepts any real-world
tier; `prototype`/`academic`/`personal-project` never satisfy a
commercial/production modifier). A named numeric duration or scale the approved
evidence never attests, and a negated requirement, both fail closed.

**Adversarial matrix.** `test_candidate_authority.py` adds the full contract
matrix: numeric shortfall (1y/5y Python), prototype≠production, academic≠
commercial, used/experience≠owned/led, AWS Lambda≠SageMaker, generic AWS≠exact
service, Python≠Django, single-agent≠multi-agent, backend≠distributed-backend-at-
scale, explicit negation on both sides, conjunction not fully covered, and a
shared entity buried beside an unattested co-named technology (Bazel). Matching
positive controls confirm the exact approved statements still entail the exact
typed requirements. The seven prior generic-overlap negatives and the atlas-
coverage/hash-binding test are retained. `TYPED_EVIDENCE_SCHEMA` and the content
hash of the typed projection are bound into every candidate-authority receipt and
into this projection document (`evidence_projection_schema` /
`evidence_projection_sha256`).

**Fit changes for the current production Ashby/Lever cohort** (authoritative build
over the approved discovery `ebe3b999…`, jobs DB and archive; 15 selected → 7
fit-recomputed, 4 prior-attempt, 4 quarantined). Every fit is more conservative
than the discarded empty-profile value, and every remaining `matched` row is a
genuine, attested AI/agent/LLM/AWS fact:

| fit | empty (discarded) | job_key | remaining matched rows |
|--|--|--|--|
| 0.000000 | 0.1343 | ashby:TRADINGHUB:a145eb8a… (Market-Data SWE) | none |
| 0.000000 | 0.1380 | lever:octoenergy:4f9c5847… | none |
| 0.000000 | 0.1343 | lever:octoenergy:e1112d35… | none |
| 0.083333 | 0.1320 | ashby:edra:0fef2ffb… (Forward-Deployed AI Eng) | "build agentic features … agents" → E-011/E-012; "experience building agents and autonomous systems" → E-011/E-012 |
| 0.090909 | 0.1320 | ashby:edra:c49b8111… (AI Engineer, London) | same two agent rows → E-011/E-012 |
| 0.125000 | 0.1320 | ashby:distyl:26cc59d5… (AI Engineer) | "LLM tooling … or agent frameworks" (disjunction) → E-011/E-012/E-016; "cloud platforms (AWS, GCP, or Azure)" → E-002; "agent architectures …" → E-011/E-012 |
| 0.150000 | 0.1413 | lever:electric-twin:830093d0… | "frameworks for building AI/LLM applications" → E-016; "building applications with large language models" → E-016; "multi-agent systems …" → E-012 |

Each cited fact is genuine: E-011/E-012 (directed/owned multi-agent orchestrator
and agents), E-016 (built an LLM-assisted prototype), E-002 (studied AWS in the
SCAFAD dissertation). The prior overlap heuristic's false supports on the
Greenhouse cohort (Bazel "remote caching" ← E-011 caching; "operate cloud infra
on AWS"/"data pipelines" ← academic E-002; multi-agent RL experiments) are now
gaps. The one deliberately-retained generous match is Greenhouse
`anthropic:5198999008` "partner … with … Sales …" ← E-007 (real customer-facing
sales experience); it is E-007-attested, internal-only, never surfaced to an
employer, and affects ordering only. Fits remain advisory: `authoritative` marks
the queue source-bound and read-only, never release-ready, eligibility-determined,
or action-authorized.

## What this does NOT do (still blocked / out of scope)

- No eligibility decision, release authority, provider capture, form fill, upload,
  click, or email. All remain blocked pending real operator contact enrollment
  (absent by design — do not invent a key) and an independent exact-clean PASS.
- Greenhouse `prior_blocked` vacancies remain blocked; not replayed or relabelled.

## Exact next resumable action

1. The 4 aggregator-sourced Ashby opportunities now carry a durable
   provider-native alias (schema v2 `provider_native_aliases`, done in this slice —
   see the alias section above), so their exact `(provider, company, native id)`
   capture target is bound read-only. The remaining step is the gated network
   capture itself: resolve each aliased native description via a read-only provider
   capture (extend `provider_observation_capture.py` with an Ashby host allowlist +
   collector identity) keyed on the alias `native_job_key`, then re-run this
   projection so they can be fit-scored. No fresh vacancy is created; the alias is
   the identity. This is the only remaining source-resolution work for the current
   15-opportunity cohort and is network-gated.
2. Materialize operator-approved eligibility policy (`HARD_*` classifications) for
   the scored Ashby/Lever cohort — this is operator policy, not inference — to
   turn this advisory ranking into release-gated candidate decisions.
3. Resolve official ATS authority for the remaining 60 live discovery sources
   (read-only), then repeat this deterministic queue process.
4. Do not set a global `BLOCKED` sentinel; safe read-only work remains.

Done in this slice (previously item 2): the 3 Lever opportunities are now scored
without an unaudited extractor — Lever's own split posting fields are reassembled
into the audited extractor's expected `<h2>`+bullets shape, so the audited
`_requirements`/`_evidence_matrix` remain the sole requirement/fit authority.

---

## Authoritative-queue hardening (closes `JAA_3DCF741_NONGREENHOUSE_PROJECTION_AUDIT_20260806.md`)

The prior slices produced an **advisory** ranking. The independent `3dcf741`
audit ruled the projection PASS-as-advisory but FAIL-as-authoritative until seven
identity/authority/approval gaps were closed with adversarial tests. This slice
closes all seven and adds an explicit `authoritative` boolean that is `true` only
when every gate below holds. The projection remains **non-release**
(`release_capable`/`authorizes_action`/`eligibility_determined` stay `false`);
"authoritative" governs only queue integrity, not any consequential action.

Gates added (all deterministic, read-only; `candidate_authority.py` still untouched):

- **H1 provider authority is now URL-bound, not label-only.** Each record must
  carry an `https` `authority_url` whose host is the provider's allowlisted host
  (`jobs.ashbyhq.com` / `jobs.lever.co`) and whose path resolves to the record's
  own `company_slug/job_id` (an `/apply` suffix is tolerated). A missing,
  unrelated, or wrong-path URL → `provider_authority_url_unverified`. (As of the
  schema-v2 alias slice, the 4 aggregator roles — `swissaijob:12293`,
  `developerjobsch:*` — whose Ashby `authority_url` names a *different* company/job
  than their aggregator `job_key`, are no longer left at
  `provider_authority_url_unverified`: they bind a durable, capture-pending
  provider-native alias to that URL's native identity instead. `job_key`s with no
  allowlisted-host apply URL at all still route to
  `provider_authority_url_unverified`.)
- **H2 vacancy identity is provider-native immutable, not title-only.** The
  durable posting's own native `id` must equal the bound `job_id` and its native
  apply URL must resolve to the same host + `/slug/job_id`. A body swapped in from
  another vacancy carries a foreign native `id` → `provider_native_identity_mismatch`.
- **H3 / M1 approved-source gate.** `require_approved_sources=True` (the default
  for `materialize`/CLI) rejects any discovery whose **artifact byte** SHA-256 is
  not `ebe3b999…ff9a`, any jobs DB not `67dfb680…88c3`, and any discovery whose
  307/307/75/15 coverage contract differs. A caller-declared in-file
  `snapshot_sha256` is never trusted in place of the artifact byte hash.
- **M2 duplicate identity fails closed.** Two observations for the same stable
  `job_key` raise rather than rank twice.
- **M3 prior-attempt binding.** The durable archive's finalized
  `attempts/*/terminal-manifest.json` files are indexed by `vacancy.job_key`. A
  fit-recomputed role with any prior terminal attempt is routed to a separate
  `prior_attempts` list under a retry authority (`historical_submitted_success`
  or any release manifest → `permanent_no_resubmit`; `crashed` →
  `indeterminate_quarantine`; `blocked` → `blocked_requires_operator_retry_authority`;
  `abandoned` → review) and **never** re-offered in the fresh ascending queue.
  Authoritative mode requires a bound archive.
- **L1 benign title normalization.** Only now that URL + native-id bindings are
  mandatory, case/whitespace-only title variation is accepted; any material title
  change still quarantines `vacancy_identity_mismatch`.

### Authoritative result against the real 307-observation input

`build(..., require_approved_sources=True, archive_root=application-artifacts)` →
`authoritative: true`; durable create-only artifact SHA-256
`6deada59ed1499f36e41d73bd2625341a015ebb9ed0d5795dbf64b7aa1c52eac`
(discovery `ebe3b999…ff9a`, jobs DB `67dfb680…88c3`). Counts: **15 selected → 7
fresh-ranked, 4 prior-attempt-routed, 4 quarantined.**

Fresh ascending queue (weakest fit first; the 4 prior-`blocked` Ashby roles from
the old advisory ranking are now correctly withheld):

| rank | fit | job_key | authority_url |
|--|--|--|--|
| 1 | 0.000000 | ashby:TRADINGHUB:a145eb8a… | jobs.ashbyhq.com/TRADINGHUB/a145eb8a… |
| 2 | 0.111111 | lever:octoenergy:e1112d35… | jobs.lever.co/octoenergy/e1112d35… |
| 3 | 0.200000 | lever:electric-twin:830093d0… | jobs.lever.co/electric-twin/830093d0… |
| 4 | 0.214286 | lever:octoenergy:4f9c5847… | jobs.lever.co/octoenergy/4f9c5847… |
| 5 | 0.416667 | ashby:distyl:26cc59d5… | jobs.ashbyhq.com/distyl/26cc59d5… |
| 6 | 0.458333 | ashby:edra:0fef2ffb… | jobs.ashbyhq.com/edra/0fef2ffb… |
| 7 | 0.500000 | ashby:edra:c49b8111… | jobs.ashbyhq.com/edra/c49b8111… |

Prior-attempt-routed (4, all `blocked` → `blocked_requires_operator_retry_authority`,
never fresh): `ashby:edra:5092d5ac…`, `ashby:TRADINGHUB:c6a422ac…`,
`ashby:edra:142acdd7…`, `ashby:edra:3e27801a…` — exactly the four the audit flagged
as already carrying terminal blocked attempts.

Quarantined (4, `provider_authority_url_unverified`): `swissaijob:12293`,
`developerjobsch:{1e8143c1,36dc393b,dfae4bcc}` — the aggregator-sourced Ashby roles
still awaiting a read-only Ashby-native capture.

### Tests

`test_nongreenhouse_fit_projection.py` now 29 hermetic tests (all pass; ruff clean).
The prior 19 keep their coverage under the stronger identity model (fixtures carry
provider-native identity via `_bind_native`), plus 10 adversarial closures: authority
URL absent / unrelated-host / wrong-path; aggregator key not bound to a mismatched
Ashby URL; swapped-body and missing native id; case-only title accepted; duplicate
identity fails closed; unapproved jobs DB and unapproved discovery rejected in
authoritative mode; authoritative-mode requires a bound archive; and prior
`blocked`/`success`/`crashed`/release-manifest attempts route out of the fresh queue
under the correct retry authority. `candidate_authority.py` remains byte-identical;
its focused suite still passes (6/6).

### Still out of scope / blocked (unchanged)

Authoritative queue integrity does **not** create eligibility, release authority,
or permission for any consequential action. Operator-approved `HARD_*` eligibility
policy and real operator Ed25519 contact enrollment remain absent by design; no
form fill, upload, click, or email is permitted. Greenhouse `prior_blocked`
vacancies remain blocked. The 4 aggregator Ashby roles still need a read-only
provider capture (network, gated). Do not set a global `BLOCKED` sentinel.

---

## Strict typed Lever section adapter (closes `JAA_8A5C89D_HEADING_SANITIZATION_AUDIT`)

The independent `8a5c89d` audit ruled the earlier decode-once / strip-angle-bracket
heading transform still FAILING: a Lever `lists[i].text` heading was neutralised
into markup and then re-parsed by the audited HTML extractor to establish
essential/desirable/benefit classification, so recursively/double/numeric-encoded
entities, comment/CDATA/PI shapes, embedded NUL/control characters, bidi and
zero-width format characters, and oversized headings could still evade or flip
classification. The recorded heading hash also covered a normalized heading, not
exact raw bytes.

This slice replaces that transform with a **strict typed adapter**. A section
heading is provider-native **plain text, never markup**, so the raw heading is now
*never* passed through the HTML parser at all:

1. **Exact raw bytes preserved and hashed first.** Each `lists[i].text` component
   hash binds the exact raw provider bytes (padding included); the reconstruction
   additionally records the derived `classification` and the trusted
   `canonical_heading` actually emitted.
2. **Canonical plain-text grammar, fail-closed.** `_validated_lever_heading`
   rejects a non-string, an oversized heading (`> _LEVER_HEADING_MAX`), any Unicode
   control/format character (category `C*` — closes NUL/control, bidi, zero-width),
   any literal `<`/`>` (closes comment/CDATA/PI/tag shapes), and any HTML character
   reference (`html.unescape` round-trip inequality or a `&#` numeric sentinel —
   closes recursive/double/numeric/hex entities at the grammar, not a blacklist).
3. **Classification from validated data, not reparse.** `_classify_lever_section`
   derives `benefit` / `desirable` / `essential` from the validated canonical
   heading using the audited extractor's own `_BENEFIT_HEADINGS` constant and
   desirable markers (a consistency test binds the mirrored markers).
4. **Only a trusted canonical literal reaches the parser.** The emitted heading is
   a fixed literal chosen by (3) — `Requirements` / `Nice to have` / `What we
   offer` — so the audited extractor still makes every requirement decision, now
   over trusted headings; a hostile heading can no longer open a tag, mint a
   second heading, or reclassify bullets.
5. **Malformed native shapes quarantine, never silently omit.** A mapping-shaped
   `lists`, a non-mapping entry, a missing heading, or non-string `content` raise
   `_LeverAdapterError`, routing the whole opportunity to a dedicated
   `lever_native_body_malformed` quarantine (`fit=None`) instead of a partial body.

`candidate_authority.py` remains **byte-identical** (not in the diff); the audited
`_requirements`/`_evidence_matrix` stay the sole requirement/fit authority.

### Behaviour-preserving against the real 307-observation input

Re-materialized authoritative artifact SHA-256
`e610696ada2d25bd5a066be3c1947384c4d515e87f1e15719cb16be6fcbc1e43`
(discovery `ebe3b999…ff9a`, jobs DB `67dfb680…88c3`). The prior authoritative
`6deada59…` is preserved create-only. **Counts, fresh-queue order, and every fit
are identical** (7 fresh / 4 prior-attempt / 4 quarantined; the three official
Lever roles keep fit `0.000000`, `0.000000`, `0.050000`). All three real Lever
headings (`What You'll Do` / `Who You Are` / `What you'll need` / `What we're
looking for`) classify `essential → Requirements`, so only the Lever
`description_html_sha256` bytes (and the whole-artifact hash) shift; Ashby records
are unchanged. The 4 quarantined remain exactly the aggregator Ashby roles under
`provider_authority_url_unverified`.

### Tests

`test_nongreenhouse_fit_projection.py` is now **134 hermetic tests** (all pass;
`python -m ruff` clean; green under `python -O`). The three obsolete
neutralise-and-include injection tests are replaced by the strict adapter suite:
13 hostile heading shapes (literal/entity/double/numeric/hex markup, comment,
CDATA, PI, embedded NUL, control char, bidi control, zero-width, oversized) proven
to fail closed both at `_validated_lever_heading` and end-to-end through the
`lever_native_body_malformed` quarantine; a zero-width classification-evasion
control; legitimate padded heading survives with exact raw-byte hash and trusted
canonical emission; benefit and desirable headings classified as data; a marker
mirror-consistency test; and mapping-shaped `lists`, non-mapping entry, non-string
`content`, and missing-heading fail-closed controls.

### Still blocked (unchanged)

No eligibility, release authority, provider capture, form fill, upload, click, or
email. This slice is read-only and non-release; operator Ed25519 enrollment remains
absent by design. Do not set a global `BLOCKED` sentinel; safe read-only work
remains (Ashby-native capture for the 4 aggregator roles; the 60 unresolved live
sources). The typed evidence-entailment expansion per the semantic-entailment
contract is now implemented (schema `jaa.typed-evidence-entailment.v2`, see the
section above); it is still read-only and authorizes no action.

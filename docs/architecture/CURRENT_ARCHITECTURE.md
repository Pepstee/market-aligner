# Current canonical architecture

Updated 2026-08-30 during the two-laptop and GitHub archaeology pass. The only
canonical repository is `/Users/admin/Projects/market-aligner`; its GitHub
authority is `Pepstee/market-aligner`. The consolidation branch is
`codex/market-aligner-canonical-union-20260828`, based on `466ad4b`. No
Gigabyte or GitHub ref is a descendant of that base.

```text
public vacancy sources
  -> Market Aligner collectors/adapters + full Scrapling sidecar
  -> trusted discovery observation + exact public-byte capture
  -> external raw cache + shared vacancy SQLite + immutable release provenance
  -> deterministic identity, deduplication, viability and hard eligibility
  -> validated semantic extraction + evidence-linked fit/opportunity scoring
  -> employer/role research and ranked opportunity reports
  -> versioned, hash-bound Market Aligner to JAA handoff
  -> internal JAA core admission and candidate/evidence authority
  -> CV generation + detached employer-side adversarial assessment
  -> form filling through a supported ATS adapter
  -> release validation, certified submit action and durable outcome receipt
```

## Product boundary

Market Aligner is the product. `src/market_aligner` owns discovery through ranking;
`internal/jaa` is its separately certifiable application subsystem. JAA is not a second product,
repository, service, or parallel top-level package in this integration line. Standalone and
nested JAA copies recovered from either laptop are provenance and salvage inputs only.

Profile data, candidate evidence, vacancy bodies, generated applications, credentials and
runtime receipts remain outside the repository. Product code refers to profiles through opaque
`profile_id` values. No generated claim may exceed the candidate evidence authority.

## Vacancy evidence boundary

The live collector stamps an explicit whole-second UTC discovery observation before a URL enters
its fetch queue. The vacancy store preserves every observation append-only and grants release
trust only when the caller explicitly selects that boundary. A releaseable capture binds the
trusted discovery time, fetch time, canonical URL, source identity, exact public-content digest
and exact canonical raw-object digest in immutable canonical JSON. The capture is revalidated on
read, including discovery-before-fetch chronology.

Legacy JSONL/raw-cache imports and ordinary direct store calls remain non-authoritative by
default. Their exact bytes are still retained, but an append-only block explains why the snapshot
cannot support release until a fresh trusted discovery and fetch creates a current capture. This
adopts the valid discovery/release semantics from the quarantined migration lineage without
restoring its parallel MigrationRunner, duplicate snapshot tables, or weaker refresh schema.
Vacancy refresh remains owned by the current v3 journal and its exact context, receipt,
transition, migration-quarantine and crash-recovery checks.

## Structured extraction and evidence alignment

`market_aligner.llm.structured` is the deterministic alternative to the bounded probabilistic
gateway for JSON vacancy listings. It accepts only retained public listing bytes whose declared
SHA-256, canonical URL and transport/secret separation pass the vacancy evidence boundary. Every
emitted vacancy fact comes from one explicit non-root RFC 6901 pointer; missing fields, malformed
pointers, duplicate JSON keys, non-finite values and ambiguous timestamps fail closed rather than
being inferred. Location and eligibility facts remain owned by the canonical assessment and
domain contracts, not by a recovered selection package.

Evidence alignment is likewise deterministic: a requirement is supported only when its complete
normalised text occurs in an explicitly selected, approved and content-bound evidence claim.
Unknown or duplicate evidence selections are rejected, unmatched requirements remain explicit,
and both extraction and alignment produce hash-bound receipts consumable by the existing LLM
pipeline validators. The byte-identical recovered `internal/jaa/llm/structured.py` copy is
provenance only; there is one runtime owner under Market Aligner and no parallel JAA package.

## JAA module boundaries

- `jaa_core` owns stable identities, admission, evidence authority and lifecycle contracts.
- `cv_generation` owns evidence-bound CV and cover-letter composition, deterministic document
  constraints, rendering and detached adversarial assessment.
- `form_filling` owns question/field binding, supported ATS interaction and certified execution.
- `llm` owns every model transport, including the optional direct OpenAI Responses adapter;
  application policy remains in `career_automation.application_sanity_review`, and provider
  adapters cannot gain release, browser, or content-materialisation authority.
- Synthetic provider acceptance is an opt-in mode of the one canonical application-sanity smoke
  runner. Direct Responses acceptance requires explicit model and credential seams plus private
  create-only exact transport archives outside Git; the retired parallel employer-review launcher
  is not restored and the mode remains withheld until canonicalization acceptance.
- Final sanity authority is one exact receipt/package contract. Its verifier rejects subclasses
  and reconstructs nested invariants at each release boundary; the recovered parallel
  employer-review runtime identity and release-verifier composition is not a second owner.
- Detached adversarial recruiter assessment is diagnostic and never release authority. Its v2
  result preserves the recovered full-funnel value as explicit ATS, recruiter, hiring-manager and
  interview-invitation progression estimates, plus evidence gaps and uncertainty drivers. These
  remain labelled uncalibrated and cannot be consumed as an eligibility or submission decision.
- Evidence-safe rebuild now has one canonical owner under `cv_generation.adversarial_rebuild`.
  In addition to CV and cover-letter editorial rebuilds, it can map exact full-application source
  deltas (including one identified form answer) to current approved evidence, route every
  unsupported or profile-level recommendation to a development roadmap, rerender all artifacts,
  and obtain fresh sanity and detached-recruiter receipts. The plan and result explicitly carry no
  release authority; the canonical handoff and release gates must still revalidate the rebuilt
  source. Recovered `/etc/majaa` loaders, Gigabyte entry points and deployment attestations remain
  quarantined rather than becoming a second runtime owner.
- Hermetic recruiter fixtures and final-sanity fixtures have distinct modules. This prevents the
  historical combined employer-review fixture from recreating a shared diagnostic/release owner.
- Legacy `career_automation` code remains behind these boundaries while capabilities are moved
  incrementally; its presence is not proof that every historical path is production-ready. Cover
  letters and CVs have separate exact-type runtime entry points. Preparation dispatches
  cover-letter requests only through the cover-letter runtime, so a CV runtime can never accept
  them by structural similarity.

The modular JAA subtree originated from clean source authority
`d56969dd94402186aa054fd1abe6ad8f142525d2`. The integration fix at
`017cca9da8628529c349795aa0167b8b397456a5` preserves committed-source identity when JAA runs
from its `internal/jaa` prefix. Subsequent capability recovery is recorded in
`docs/migration/ledger.jsonl`; no donor tree gains runtime authority by being excavated.

## Archaeology closure and quarantine

The Gigabyte pass inventoried 568 Git repositories, 380 candidate directories, 196,563 source
records and 59,350 unique source hashes. Nine distinct Git common-object stores produced nine
verified bundles. Across 135 Gigabyte refs, 12 were ancestors of the canonical base, 38 diverged,
85 were disconnected and none were descendants. A separate artefact vault contained 15 bundles
already represented by those object stores and 33 patches whose patch IDs were already present in
Gigabyte history.

The all-store Archaeologist judges evaluated 9,174 hypotheses: 9,146 were `CONFLICT`, 28 remained
single-tool `UNKNOWN`, and none met `VERIFIED_CANDIDATE`. The unknowns are duplicate-code and one
unused-symbol observation with incomplete counterevidence; they remain fail-closed residuals, not
deletion authority. A destructive 292-file deletion patch is quarantined. Duplicate or superseded
operational lanes remain recoverable in the external audit evidence, not executable here.

The deterministic capability inventory treats complete modules, functions, classes, and module-
or class-level assignments as separately reviewable capabilities. Assignment coverage is required
because schemas, policy constants, stage sets and authority identifiers can carry behavior even
when no unique function or class exposes them. A whole-file disposition therefore cannot silently
erase a distinct donor schema or policy dimension.

One verified net delta survived: the cover-letter runtime dispatch and exact request-type guards.
The same patch was present in a dirty Gigabyte worktree and the Windows-native patch set, was
byte-identical in both places, and was selectively adopted into this repository.

The exact historical Greenhouse discovery object was recovered. The approved availability,
operator-answer and jobs-database hashes were found only as references and derived projections;
their exact source bytes were not recovered. Private historical projections are not copied into
Git, and neither they nor old eligibility decisions establish current vacancy liveness or current
candidate authority.

## Authority and progression

The current branch is an integration authority, not yet a mass-application release. Recovery
uses small runnable increments: preserve the last passing state, add one real capability,
exercise it against real conditions, and only then improve quality.

The immediate walking skeleton is:

1. collect a current vacancy;
2. rank it against the canonical candidate/evidence authority;
3. admit the exact handoff into JAA;
4. generate and adversarially assess an evidence-bound application;
5. bind the live form through a supported adapter;
6. execute one authorised submission and persist its provider receipt.

Quarantined code is evidence and a salvage source only. No quarantine branch may be merged
wholesale, and no failed quarantine test may be converted into release authority. Real canaries
remain frozen until this consolidation increment has a fresh graph receipt, passing current gates,
a clean committed status, and a freshly validated candidate/vacancy authority.

## Architecture freshness

Graphify outputs are committed under `graphify-out`. The freshness receipt binds every tracked
source file plus the graph, report and community labels. Run:

```bash
python scripts/verify_graphify_freshness.py
```

Any tracked source change fails this gate until the graph and receipt are regenerated. This is a
deterministic completion check; it does not claim that community labels or architecture quality
are themselves mechanically perfect.

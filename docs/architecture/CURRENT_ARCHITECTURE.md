# Current canonical architecture

Updated 2026-08-30 during the two-laptop and GitHub archaeology pass. The only
canonical repository is `/Users/admin/Projects/market-aligner`; its GitHub
authority is `Pepstee/market-aligner`. The consolidation branch is
`codex/market-aligner-canonical-union-20260828`, based on `466ad4b`. No
Gigabyte or GitHub ref is a descendant of that base.

```text
public vacancy sources
  -> Market Aligner collectors/adapters + full Scrapling sidecar
  -> external raw cache + shared vacancy SQLite
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

## JAA module boundaries

- `jaa_core` owns stable identities, admission, evidence authority and lifecycle contracts.
- `cv_generation` owns evidence-bound CV and cover-letter composition, deterministic document
  constraints, rendering and detached adversarial assessment.
- `form_filling` owns question/field binding, supported ATS interaction and certified execution.
- `llm` owns every model transport, including the optional direct OpenAI Responses adapter;
  application policy remains in `career_automation.application_sanity_review`, and provider
  adapters cannot gain release, browser, or content-materialisation authority.
- Final sanity authority is one exact receipt/package contract. Its verifier rejects subclasses
  and reconstructs nested invariants at each release boundary; the recovered parallel
  employer-review runtime identity and release-verifier composition is not a second owner.
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

# Current canonical architecture

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
`internal/jaa` is its separately certifiable application subsystem. JAA is not a second product
or a parallel top-level repository in this integration line.

Profile data, candidate evidence, vacancy bodies, generated applications, credentials and
runtime receipts remain outside the repository. Product code refers to profiles through opaque
`profile_id` values. No generated claim may exceed the candidate evidence authority.

## JAA module boundaries

- `jaa_core` owns stable identities, admission, evidence authority and lifecycle contracts.
- `cv_generation` owns evidence-bound CV and cover-letter composition, deterministic document
  constraints, rendering and detached adversarial assessment.
- `form_filling` owns question/field binding, supported ATS interaction and certified execution.
- Legacy `career_automation` code remains behind these boundaries while capabilities are moved
  incrementally; its presence is not proof that every historical path is production-ready.

The modular JAA subtree currently comes from clean source authority
`d56969dd94402186aa054fd1abe6ad8f142525d2`. The integration fix at
`017cca9da8628529c349795aa0167b8b397456a5` preserves committed-source identity when JAA runs
from its `internal/jaa` prefix.

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
wholesale, and no failed quarantine test may be converted into release authority.

## Architecture freshness

Graphify outputs are committed under `graphify-out`. The freshness receipt binds every tracked
source file plus the graph, report and community labels. Run:

```bash
python scripts/verify_graphify_freshness.py
```

Any tracked source change fails this gate until the graph and receipt are regenerated. This is a
deterministic completion check; it does not claim that community labels or architecture quality
are themselves mechanically perfect.

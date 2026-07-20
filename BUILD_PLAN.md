# Autonomous Job Application System — Build Plan

**Status:** authorised for implementation through orchestrator-v3 on 20 July 2026  
**Plan date:** 20 July 2026  
**Executable slice source:** `IMPLEMENTATION_SLICES.yaml`

## 1. Verdict

Build this as a **brownfield extension and certification** of the operator-supplied source,
not as a new scraper and not from any similarly named historical copy. The active repository
is identified by `canonical-repository.json`; brownfield roots are explicit import inputs.

The first product milestone is one truthful, evidence-linked application carried from a
real vacancy through research, document generation, deterministic release checks, a
simulated submission, and a stored receipt. Only after that walking skeleton certifies do
we activate one real ATS adapter and then expand breadth.

The system is not an application spammer. Its optimisation target is:

> **Qualified interviews per eligible, truthfully supported application**, followed by
> accepted offers and elapsed time to offer.

Application volume is a diagnostic, not the objective.

## 2. Current reality

Read-only inspection on 20 July 2026 found:

| Asset | Measured state |
|---|---:|
| Raw job postings | 9,407 |
| Normalised jobs | 548 |
| Scored jobs | 548 |
| Jobs imported to career control plane | 462 |
| Opportunity-rejected jobs | 404 |
| Jobs queued for employer research | 58 |
| Completed employer dossiers | 0 |
| Registered browser workflows/runs | 0 / 0 |
| Pre-adoption career-control test observation | 65 passing |

The 65-test figure is historical. Current test totals are reported separately for each
post-adoption run and do not revise this observation.

Already real:

- uncapped, parallel, append-preserving collection from 37 configured sources;
- raw and processed SQLite stores kept separately;
- deterministic viability and deduplication before model processing;
- structured vacancy extraction and evidence-led scoring;
- an append-only career event ledger and materialised state;
- an Opportunity-only gate before employer research, enforced by SQLite triggers;
- leased employer-research queue and provenance validation for dossiers;
- versioned flow contracts, retry outbox, capability manifests and scoped access;
- evidence-ID retrieval projection;
- declarative resumable browser workflows with selectors, checkpoints and release tokens;
- migration, deployment, document-sidecar and fetch-escalation control primitives.

Not yet operational end to end:

- employer-research workers and completed dossiers;
- a canonical candidate fact, evidence and claim graph suitable for application release;
- Opportunity-1 and candidate-fit reassessment;
- gap classification and automatic improvement tasks;
- ATS-safe CV, cover-letter and application-answer compilation;
- deterministic claim, eligibility, consistency and ATS validation;
- a browser executor connected to recorded workflows;
- any registered ATS submission workflow or real submission receipt;
- response, interview, offer and outcome ingestion;
- calibrated evaluation sets and automated strategy learning.

## 3. Product charter

### 3.1 Product outcome

The product continuously discovers vacancies and, without routine manual writing or
triage, performs this loop:

```text
discover -> verify -> assess opportunity -> research employer
         -> assess fit/evidence -> close or classify gaps
         -> devise application strategy -> compile documents and answers
         -> validate truth/eligibility/consistency -> submit officially
         -> capture receipt/status/outcome -> calibrate future decisions
```

### 3.2 Operator involvement

The intended mature system is zero-routine-touch. The operator does not manually write CVs,
cover letters, routine answers, predictions, or application records.

Permitted operator involvement:

- one-time candidate-fact and policy ratification;
- supplying credentials through the credential boundary;
- completing CAPTCHA, MFA or a legally required attestation when a site requires the
  person directly;
- changing strategy, exclusions, risk tolerance or career direction;
- reviewing sampled output and outcome reports.

Unknown or unverified answers are never guessed. The policy is to recover evidence,
derive a safe answer from ratified facts, skip the vacancy, or enter an explicit blocked
state. A blocked application is not silently counted as submitted.

### 3.3 Non-goals for the first certification

- every job board or ATS;
- a public SaaS or multi-user platform;
- Kubernetes, Supabase or a separate graph database;
- bypassing CAPTCHA, MFA, access controls or prohibited automation;
- fabricating projects, experience, metrics, dates, qualifications or work rights;
- scraping private social profiles or protected/personal traits;
- learning from outcomes before receipt and outcome capture are reliable.

### 3.4 Commercial release shape

Version 0.1 is a commercially distributable, local-first product rather than a hosted
multi-tenant SaaS. It must install on a clean supported Mac, guide a new user through
candidate evidence and policy setup, expose the complete pipeline through an accessible web
interface, preserve user data locally by default, and provide documented backup, restore,
upgrade and uninstall paths. The working product name is **Market Aligner**.

Commercially viable means the release can be evaluated and paid for as a real product: it
has a coherent product identity, onboarding, a useful free evaluation path, a licence and
entitlement seam that does not disable local data access, support and privacy documentation,
release artefacts, versioned upgrade behaviour, and truthful positioning. Live merchant,
domain and code-signing accounts are operator-owned external dependencies; their absence may
block public sale, but may not be hidden behind a fake integration or treated as product
certification.

## 4. Settled design decisions

| Decision | Rationale |
|---|---|
| Extend the active project | It contains the live collection pipeline, current data and tested control-plane code. |
| Local-first SQLite plus content-addressed files | One operator and one machine do not yet justify distributed infrastructure. SQLite remains authoritative; large source snapshots and rendered documents live by hash outside it. |
| Event ledger is canonical | Materialised state can be rebuilt; history, replay and attribution cannot. |
| Relational knowledge graph first | Typed node/edge tables provide graph semantics without adding Neo4j operational burden. A graph database is earned only by measured query or scale failure. |
| Collection and semantic processing remain decoupled | Source throughput must not depend on model limits or cost. |
| Deterministic policy advances consequential state | Models produce structured assessments; deterministic code applies gates and transitions. |
| Model-agnostic capability roles | Providers and model names are configuration chosen by eval results, not embedded in domain logic. |
| Research only after Opportunity-0 | Existing enforced order is retained. Deep people/team research occurs only after Opportunity-1 and candidate readiness. |
| Claims compile from evidence IDs | Generated prose is a rendering of approved claims, never a new source of candidate facts. |
| Official submission routes only | Unsupported or prohibited routes become blocked/skipped, not bypass targets. |
| Walking skeleton before source breadth | One real vertical path exposes missing seams earlier than many half-built adapters. |
| Existing stale copies are historical only | They are neither merged nor treated as concurrent sources of truth. |

The misleading active directory name and absence of Git history are operational debt.
Slice 0 must establish a neutral, version-controlled canonical project location through a
non-destructive migration with hashes and rollback. No code is copied ad hoc before that.

## 5. Domain architecture

### 5.1 Logical components

```text
Source adapters
    -> immutable vacancy snapshots
    -> deterministic viability/deduplication
    -> semantic requirement extraction
    -> Opportunity-0 assessment + deterministic gate
    -> employer reconnaissance + Opportunity-1
    -> candidate evidence matcher + gap optimiser
    -> application strategist
    -> claim compiler + document renderer
    -> deterministic release gate
    -> ATS adapter/browser executor
    -> receipt and status monitor
    -> funnel analytics and calibration
```

Cross-cutting services:

- event ledger and idempotency;
- model gateway and prompt/model/version receipts;
- content-addressed artefact store;
- provenance and source cache;
- credential broker;
- observability, cost and latency accounting;
- eval store, certification receipts and rollback.

### 5.2 Authority boundary

| Deterministic authority | Probabilistic worker |
|---|---|
| source schedule, retry and cache | advert requirement extraction |
| hashes, canonical IDs and exact/rule dedupe | ambiguous title/seniority classification |
| expiry, URL and known work-right gates | Opportunity and fit axes with citations |
| schema validation and state transitions | employer research synthesis |
| queue admission, leases and idempotency | requirement-to-evidence matching |
| claim/evidence referential integrity | strategy and document drafting |
| release, duplicate and receipt checks | semantic entailment critic |
| timers, funnel arithmetic and experiments | form-field and response classification |

No model response directly submits an application or advances a consequential state.

### 5.3 Model roles

Models are assigned to capability profiles, then selected by evaluation:

1. **Extractor:** low-cost structured advert and form extraction.
2. **Opportunity assessor:** cited market/role assessment with abstention.
3. **Researcher:** source-backed employer and role reconnaissance.
4. **Evidence matcher:** maps requirements only to known evidence IDs.
5. **Strategist:** chooses positioning, examples and gap treatment.
6. **Writer:** produces UK ATS-safe prose from an approved claim plan.
7. **Critic:** checks relevance, clarity and naturalness but cannot approve itself.
8. **Browser operator:** interprets unsupported forms inside the deterministic workflow boundary.
9. **Independent judge:** evaluates high-stakes semantic outputs, preferably through a
   different provider family from the producer.

Every probabilistic receipt records provider, model, prompt, policy, candidate-profile and
input hashes. Provider fallback cannot change the schema or authority boundary.

## 6. Canonical data model

SQLite remains the transactional source of truth. Existing tables are migrated, not
discarded. New records are immutable or versioned where facts may change.

| Entity | Purpose and required invariants |
|---|---|
| `source_snapshot` | Raw vacancy/company/form content, URL, capture time, content hash and retrieval receipt; immutable. |
| `vacancy` / `vacancy_version` | Canonical vacancy identity and versioned normalised fields. |
| `viability_decision` | Deterministic include/reject reasons and policy hash. |
| `requirement` | Essential/preferred requirement, source span, confidence and version. |
| `candidate_fact` | Ratified biographical, eligibility and preference facts with status, validity interval and source. |
| `evidence_item` | Project/work/education/artefact evidence with owner, verifier, status, source and artifact hash. |
| `claim` | Atomic application-safe assertion linked to one or more approved evidence IDs. |
| `claim_variant` | Bounded wording variants; never independent facts. |
| `eligibility_rule` | Country/employer/contract-specific rule and verification source. |
| `assessment` | Structured Opportunity, Fit or semantic evaluation with model/prompt/input receipts. |
| `research_source` / `research_claim` | Public employer evidence; claim is `fact`, `inference` or `hypothesis`, with freshness. |
| `entity_node` / `entity_edge` | Company, product, team, person, technology and evidence relationships. |
| `gap` / `improvement_task` | Missing knowledge/evidence/experience plus cost, value, verification and resulting evidence IDs. |
| `application_strategy` | Requirement coverage, emphasis, objection handling and document plan. |
| `application_artifact` | CV, letter, answers and rendered files by content hash. |
| `release_manifest` | Exact vacancy, dossier, profile, evidence, prompt/model, validator and artefact hashes. |
| `form_definition` / `workflow_definition` | Versioned portal fields, selectors and policy. No raw secrets or guessed answers. |
| `submission_attempt` / `receipt` | At-most-once key, executor trace, official confirmation and artefact hash. |
| `status_event` / `outcome` | Employer response, stage, evidence source, confidence and timestamps. |
| `experiment` / `calibration_record` | Strategy assignment, cohort, prediction, observed outcome and scoring. |

Large source bodies, screenshots, PDFs, CVs and receipts live in a content-addressed
artefact directory. SQLite stores their hash, media type, provenance and retention policy.

## 7. State machine

```text
DISCOVERED -> FETCHED -> NORMALISED
  -> VIABILITY_REJECTED
  -> ELIGIBLE -> OPPORTUNITY_0_ASSESSED
       -> OPPORTUNITY_REJECTED
       -> RECON_QUEUED -> RECON_RESEARCHED -> OPPORTUNITY_1_ASSESSED
            -> OPPORTUNITY_REJECTED_AFTER_RESEARCH
            -> FIT_ASSESSED
                 -> CANDIDATE_REJECTED
                 -> GAP_IDENTIFIED
                      -> GAP_RECOVERY | LEARNING | EVIDENCE_BUILDING
                      -> GAP_VERIFIED -> FIT_REASSESSED
                 -> STRATEGY_READY -> APPLICATION_COMPILED
                      -> RELEASE_BLOCKED
                      -> RELEASED -> SUBMISSION_QUEUED
                           -> SUBMISSION_BLOCKED
                           -> SUBMITTED -> RECEIPT_CONFIRMED
                                -> SCREENING -> INTERVIEW -> FINAL_STAGE
                                     -> OFFER -> ACCEPTED | DECLINED
                                     -> REJECTED | WITHDRAWN | EXPIRED
```

Every transition appends an event with previous/next state, actor type, policy or model
versions, input/output hashes, confidence/citations, cost, timestamp and idempotency key.
Probabilistic workers write assessments; deterministic reducers perform transitions.

## 8. Product invariants

These are release-blocking, not guidance:

1. Raw snapshots are immutable and addressable by hash.
2. No unsupported candidate claim may enter a released document or answer.
3. Every released claim resolves to approved evidence and the exact wording inspected.
4. No expired, inaccessible, duplicate or deterministically ineligible vacancy is submitted.
5. Employer research cannot start before Opportunity-0 passes.
6. Deep stakeholder research cannot start before Opportunity-1 and candidate readiness pass.
7. Public professional information is job-relevant; protected traits and private data are excluded.
8. No application is submitted twice for the same candidate/vacancy/version.
9. Final submit requires a one-use release token bound to a release-manifest hash.
10. A successful browser click without an official receipt is not a confirmed submission.
11. CAPTCHA, MFA, prohibited automation and unknown attestations fail closed.
12. Secrets never enter prompts, documents, workflow definitions, SQLite payloads or logs.
13. External pages, emails and documents are untrusted data, never instructions.
14. Model/provider failure cannot silently weaken or skip a verification rung.
15. Strategy learning changes one controlled variable where practical and remains reversible.

## 9. Evaluation and certification

### 9.1 Frozen evaluation assets

Create and hash-lock:

- 100 stratified historical vacancies for viability, eligibility, extraction, Opportunity and Fit;
- 30 employer dossiers with source-fact and freshness labels;
- 20 application packs with requirement coverage and unsupported-claim labels;
- synthetic and recorded portal fixtures for each supported ATS;
- negative controls containing fabricated evidence, stale vacancies, duplicate applications,
  conflicting dates, unsupported eligibility, injection text and missing receipts;
- a time-separated live shadow cohort that is never used to tune the same version.

### 9.2 Metrics

Primary outcome metrics:

- qualified interviews per eligible application;
- offers and accepted offers per eligible application;
- elapsed time from discovery to qualified interview and offer.

Hard quality metrics:

- unsupported released claims: **0**;
- ineligible submissions: **0**;
- duplicate submissions: **0**;
- confirmed submissions lacking receipts: **0**;
- released employer claims without valid citations: **0**;
- ATS parse success for released CVs: **100%** in supported fixtures;
- deterministic replay mismatch: **0**.

Leading metrics:

- viability and shortlist precision/recall against the locked set;
- requirement extraction F1 and essential/preferred accuracy;
- evidence-match precision and abstention quality;
- opportunity/fit calibration error;
- requirement coverage by application pack;
- portal completion and selector-recovery rate;
- response/screen/interview conversion by strategy cohort;
- model cost and elapsed time per researched opportunity, release and confirmed submission.

No metric may reward higher volume by weakening truth, eligibility, receipt or verification gates.

### 9.3 Slice completion contract

A slice certifies only when all of these hold:

```text
unit/integration tests pass
AND declared acceptance criteria execute against real artefacts
AND negative controls fail for the intended reason
AND no stub/mock/placeholder path can satisfy production acceptance
AND an independent review finds no blocking defect
AND a durable certification receipt records exact hashes
```

Mocks are valid inside narrow unit tests. They never count as proof that a portal, model,
renderer, source or notification works on the actual machine.

## 10. Autonomy rollout

Autonomy is earned by observed performance, without introducing routine manual writing:

1. **Fixture mode:** full pipeline against frozen vacancies and local portal fixtures.
2. **Shadow mode:** process live vacancies and generate release-ready packs without submitting.
3. **Canary mode:** one supported ATS, one active workflow version, tightly bounded real submissions,
   automatic receipt verification and immediate circuit breaker on any invariant breach.
4. **Whitelisted autonomy:** automatic submission only for certified ATS/workflow/policy combinations.
5. **Portfolio autonomy:** expand sources and portals through the same certification gate.

The operator grants one-time activation authority after canary certification. Thereafter the
system does routine work automatically. Unknown questions, CAPTCHA/MFA, legal attestations and
policy conflicts are parked or skipped; they do not create a daily approval queue.

## 11. Build order

The machine-readable source is `IMPLEMENTATION_SLICES.yaml`. The narrative order is:

| Slice | Outcome |
|---:|---|
| 0 | Establish one version-controlled canonical repo and reproduce the measured baseline. |
| 1 | Migrate the full state machine, event schema and invariants without losing existing data. |
| 2 | Build canonical candidate facts, evidence, claims and eligibility contracts. |
| 3 | Calibrate vacancy extraction, viability, Opportunity-0 and the existing research gate. |
| 4 | Complete provenance-backed employer reconnaissance and Opportunity-1. |
| 5 | Implement requirement/evidence matching, gap classification and automatic improvement tasks. |
| 6 | Produce application strategy and evidence-linked claim plans. |
| 7 | Compile UK ATS-safe CVs, cover letters and structured answers. |
| 8 | Implement deterministic truth, eligibility, consistency, ATS and release gates. |
| 9 | Connect a browser executor to a simulated ATS and prove receipt capture end to end. |
| 10 | Certify the walking skeleton with frozen evals, mutation/negative controls and shadow data. |
| 11 | Implement and canary one real ATS adapter through its official application route. |
| 12 | Capture status changes, responses and follow-up timers automatically. |
| 13 | Generate interview preparation, debrief ingestion and truthful follow-up. |
| 14 | Learn from outcomes using scored predictions and controlled experiments. |
| 15 | Expand certified ATS adapters and source coverage according to measured value. |
| 16 | Harden unattended operation, recovery, model fallback, deployment and reporting. |

Slices 0–10 are the first programme. Slices 11–16 are expansion and operation. Building
multiple ATS adapters before Slice 10 is prohibited scope expansion.

## 12. First walking-skeleton scenario

One fixed, eligible UK vacancy from the existing raw database must complete this exact path:

1. reproduce its immutable source snapshot;
2. extract requirements with source spans;
3. pass deterministic viability and Opportunity-0;
4. create a cited employer reconnaissance dossier;
5. compute Opportunity-1;
6. map requirements to approved candidate evidence and abstain on unsupported matches;
7. produce a requirement coverage and positioning strategy;
8. compile a two-page UK ATS-safe CV, sub-one-page cover letter and required answers;
9. prove every claim's evidence lineage and all eligibility/consistency checks;
10. release a content-hashed manifest;
11. populate a local ATS fixture through the real browser executor;
12. submit using a one-use release token;
13. capture a fixture-generated receipt;
14. replay the event ledger and reproduce the final state and artefact hashes.

Negative twin: repeat with one unsupported metric, one expired vacancy and one duplicate
submission. Each must stop at the correct deterministic gate and produce no receipt.

## 13. v3 software-factory handoff

v3 receives:

- the neutral canonical repository established by Slice 0;
- this plan as design context;
- `IMPLEMENTATION_SLICES.yaml` as the only executable slice truth;
- the frozen baseline and evaluation hashes;
- read-only access to historical GIGA context only where a slice explicitly requires it.

For every slice, v3 must:

1. lock the named acceptance criteria before implementation;
2. inspect the current repository and migration state rather than assuming this plan is current;
3. implement in an isolated candidate workspace;
4. run unit, integration, negative-control and real-runtime acceptance checks;
5. obtain independent review;
6. merge only a certified candidate and append its receipt;
7. stop breadth expansion on an invariant breach.

The plan does not select Claude, GPT or another model by brand for a role. v3 benchmarks
available models against each role's frozen eval and records the routing receipt. Outage
fallbacks remain reversible configuration and may not bypass acceptance.

## 14. Defaults that remain reversible

- **First market:** UK roles, while retaining separately verified eligible remote/European opportunities.
- **First CV format:** British English, two pages maximum, single column, standard headings,
  no tables, graphics, icons, text boxes, header/footer contact data or skill bars.
- **First letter format:** under one page, role/company-specific, no generic enthusiasm filler.
- **Initial database:** SQLite WAL plus content-addressed local artefacts.
- **First submission target:** selected during Slice 11 from the real shortlisted vacancy set,
  based on official route stability and fixture/canary evidence—not chosen by familiarity alone.
- **Submission volume:** uncapped in architecture but constrained by eligibility, quality,
  certified portal support and circuit-breaker policy.

These defaults may change only through a versioned decision and regression evaluation.

## 15. Definition of the first product release

Version 0.1 is real only when:

- the walking skeleton and its negative twin pass on the actual machine;
- at least one official ATS workflow completes in canary mode;
- every released application claim is evidence-linked;
- no ineligible, stale or duplicate application is submitted;
- every confirmed submission has a stored official receipt;
- the pipeline resumes after injected interruption without repeating a consequential action;
- the event ledger deterministically reconstructs the run;
- the operator performs no routine document writing or application bookkeeping;
- a certification receipt binds code, schema, profile, policy, prompts, models, evals and artefacts.

Until those conditions hold, the system is an advanced control plane—not yet an autonomous
job-application product.

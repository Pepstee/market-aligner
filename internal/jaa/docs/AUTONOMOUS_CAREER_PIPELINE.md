# Autonomous career pipeline

## Objective

Build a closed-loop system that discovers legitimate vacancies, decides which
opportunities deserve attention, acquires and verifies missing capability,
researches worthwhile employers, produces truthful application material,
submits applications, prepares interviews, and learns from outcomes.

The optimisation target is not application volume. It is expected accepted
offers per unit of elapsed time, subject to truth, eligibility, privacy, and
site-access constraints.

## Correct stage order

Employer research is deliberately downstream of an Opportunity gate. The
system must not spend network, model, or human attention profiling an employer
whose vacancy is expired, inaccessible, ineligible, or strategically weak.

```text
collect raw vacancy
  -> verify/deduplicate/normalise
  -> extract requirements
  -> hard eligibility gate
  -> Opportunity-0 assessment from vacancy and market data
  -> deterministic Opportunity gate
       fail -> archive with reason
       pass -> queue employer reconnaissance
  -> Employer Intelligence-1 (company and role)
  -> Opportunity-1 assessment enriched by employer evidence
  -> candidate expertise/evidence assessment
  -> classify gaps
       fatal/unbridgeable -> archive
       retrieval gap      -> recover existing evidence
       knowledge gap      -> learn and test
       evidence gap       -> build and verify an artefact
       experience gap     -> real pilot/contribution or archive
  -> reassess Fit
  -> deep employer/team/stakeholder research
  -> application strategy
  -> generate CV, cover letter, answers, outreach, interview seed pack
  -> deterministic truth/eligibility/consistency validation
  -> submit through official route
  -> receipt, follow-up, interview, outcome and offer tracking
  -> update calibration, profiler, gap backlog and strategy
```

There are two employer-research depths:

1. **Reconnaissance** starts only after Opportunity-0 passes. It verifies the
   company, role, business health, likely team, public technical signals, and
   whether the opportunity remains attractive.
2. **Application intelligence** starts only after Opportunity-1 and candidate
   readiness pass. It researches relevant recruiters, managers, interviewers,
   public professional preferences, likely objections, outreach paths, and
   interview leverage.

## Deterministic, probabilistic, and hybrid boundaries

### Deterministic authority

These operations must be reproducible and must not call a model:

- source scheduling, HTTP pacing, caching and retries;
- raw snapshots, hashing, provenance and timestamps;
- exact and rule-based duplicate detection;
- URL, expiry, closing-date, location and work-authorisation gates;
- hard title/seniority exclusions and explicit years requirements;
- schema validation and canonical identifiers;
- scoring arithmetic over already-produced axes;
- Opportunity thresholds and research-queue admission;
- pipeline state transitions and idempotency;
- claim/evidence provenance checks;
- preventing unsupported facts from entering application documents;
- duplicate-application prevention;
- submission receipts, follow-up timers and stage tracking;
- experiment allocation and funnel metrics;
- cost, latency, error, source-age and model-version accounting.

### Probabilistic workers

These tasks require semantic judgment and must return structured output with
confidence, abstention, source citations, model version, and prompt version:

- extracting responsibilities and requirements from unstructured adverts;
- distinguishing essential requirements from employer boilerplate;
- rating market demand, growth potential, role quality and ambiguity;
- synthesising public company, team and professional-person research;
- mapping requirements to candidate capabilities and evidence;
- classifying semantic gaps and estimating plausible learning depth;
- judging whether a generated artefact actually demonstrates a requirement;
- selecting relevant evidence and writing application material;
- predicting likely interview concerns and generating preparation material;
- interpreting rejection/interview feedback when the reason is ambiguous.

### Hybrid decisions

The following combine model outputs with deterministic policy:

- **Opportunity:** a model or research worker supplies cited axes; pure maths
  computes the score; policy decides pass, defer, or reject.
- **Fit:** semantic requirement/evidence matches feed reproducible scoring.
- **Capability acquisition:** a model proposes learning and artefacts, while
  tests, benchmarks, oral checks, provenance and minimum standards decide
  whether the ledger may be updated.
- **Employer intelligence:** retrieval is source-controlled and cached; a model
  synthesises claims; deterministic validators require provenance and prevent
  sensitive or stale claims from being used.
- **CV validation:** semantic entailment can flag suspicious wording, but every
  positive claim must resolve to approved evidence IDs.
- **Application release:** generated material is probabilistic; hard eligibility,
  truth, confidence, freshness and duplication checks are deterministic.

Probabilistic output never directly advances a consequential state. It writes
an assessment. A deterministic policy reads that assessment and performs the
transition.

## State model

```text
discovered
fetched
normalised
eligibility_rejected | eligibility_passed
opportunity_assessed
opportunity_rejected | employer_research_queued
employer_researching
employer_researched
opportunity_confirmed | opportunity_rejected_after_research
fit_assessed
gap_closure_queued | application_ready | candidate_rejected
learning | evidence_building | evidence_verification
application_ready
application_generated
application_validated | application_blocked
submission_queued
submitted
screening
interview
final_stage
offer | rejected | withdrawn | expired
accepted | declined
```

Every state change is an immutable event containing:

- job and company identifiers;
- previous and next state;
- deterministic or probabilistic actor type;
- policy/model/prompt/profile versions;
- input hashes and output payload;
- source citations and confidence where applicable;
- timestamp, cost and idempotency key.

The materialised current state is a convenience. The event ledger is the audit
record and makes replay, debugging and outcome attribution possible.

## Opportunity assessment

### Opportunity-0: before employer research

This is deliberately cheap. It uses the vacancy and already-available market
statistics:

- compensation evidence or credible range estimate;
- contract stability;
- role growth potential;
- market demand for the role and requirements;
- accessibility/competition indicators independent of this candidate;
- career capital and skill transferability;
- location and work-pattern value;
- posting age and closing-time pressure;
- description completeness and extraction confidence.

Fit, candidate evidence and personal interest do not decide whether employer
research is admitted. That prevents an attractive personal match from making a
weak opportunity consume research resources.

### Opportunity-1: after employer reconnaissance

The score is enriched with sourced employer evidence:

- company legitimacy and operating status;
- funding, revenue, profitability and runway signals;
- layoffs, hiring momentum and repeated vacancies;
- product and market trajectory;
- team quality, management and technical environment;
- employee-review patterns with source-quality weighting;
- probable reason for the hire;
- promotion, learning and compensation evidence;
- reputational, regulatory and operational risk.

The original score, enriched score, evidence, changes and reasons are all
retained. Research may demote an apparently strong vacancy.

## Employer intelligence graph

The graph stores companies, products, teams, people, technologies, initiatives,
customers, competitors, public claims and sources. Professional-person research
is restricted to public job-relevant material. Protected traits, family data,
private accounts and vulnerability inference are prohibited.

Each claim is one of `fact`, `inference`, or `hypothesis` and carries source IDs,
capture date, confidence, relevance and expiry. A hypothesis cannot be rendered
as a fact in application material.

Outputs include:

- company and role dossier;
- team and stakeholder map;
- public technical preferences and recurring concerns;
- likely role pain points and first-90-day expectations;
- authentic leverage points tied to verified candidate evidence;
- CV emphasis plan;
- outreach targets and messages;
- interviewer-specific story and question map;
- red flags, verification questions and negotiation evidence.

## Gap classification and improvement optimiser

For every requirement the system records one of:

- `verified_match`;
- `unindexed_existing_evidence`;
- `presentation_gap`;
- `knowledge_gap`;
- `execution_gap`;
- `evidence_gap`;
- `commercial_experience_gap`;
- `credential_gap`;
- `structural_gap`;
- `uncertain`.

The improvement backlog is ranked by:

```text
priority =
    opportunity_weighted_demand
  * expected_fit_uplift
  * completion_probability
  * evidence_reusability
  * deadline_compatibility
  / (elapsed_time + monetary_cost + cognitive_cost)
```

Generated learning material is not evidence. A capability enters the profiler
only after a defined verification method: test, benchmark, independently
explainable artefact, live exercise, real user outcome, external reference, or
credential verification.

## Application generation and release

The application compiler produces an ATS-safe CV, required letter, structured
answers, outreach and interview seed pack. Every generated claim references one
or more approved evidence IDs. A release manifest contains the exact vacancy
snapshot, employer dossier version, profiler version, evidence set, prompts,
models, document hashes and validation results.

After evidence-linked drafting and targeting review, a Humanizer-inspired style
critic may propose atomic edits. It is probabilistic and cannot approve its own
changes. Every accepted edit is followed by deterministic claim provenance,
requirement coverage, dates, metrics, eligibility and consistency validation.
The version-pinned contract and rejection rules are defined in
`docs/UPSTREAM_HUMANIZER_AUDIT.md`.

The release gate blocks:

- unsupported or overstated claims;
- missing mandatory facts;
- incompatible work rights or residence;
- expired or inaccessible vacancies;
- inconsistent dates, titles or metrics;
- duplicate submissions;
- low-confidence semantic assessments below policy;
- a non-official submission route when an official route is known;
- declarations that cannot be truthfully answered from verified configuration.

CAPTCHAs and prohibited automation are not bypassed. The policy may skip such a
vacancy or create an explicit blocked state.

## Outcome learning

The funnel records application, response, screen, assessment, interview, final
stage, offer and acceptance. Metrics are segmented by role family, opportunity
band, fit band, source, employer type, CV strategy, evidence set, outreach
strategy and model/prompt version.

Changes are evaluated as experiments. The system should avoid modifying several
major variables at once. Silence is censored outcome data, not proof of a skill
deficit. Explicit feedback, assessment performance and repeated stage-specific
failure receive higher evidential weight.

Examples of deterministic response policies:

- fewer than two screens after 30 sufficiently similar applications triggers a
  positioning/CV experiment;
- screens without technical progression trigger technical-proof analysis;
- technical progression without final-stage conversion triggers interview-story
  and employer-selection analysis;
- repeated requirement gaps update the improvement backlog, not the profile;
- verified new evidence updates the profile and causes affected jobs to be
  rescored.

## Implementation slices

1. **Control plane:** separate SQLite database, event ledger, state machine,
   score import, deterministic Opportunity gate and employer-research queue.
2. **Research contracts:** cited dossier schemas, source retrieval/cache,
   reconnaissance worker and Opportunity-1 reassessment.
3. **Candidate assessment:** requirement/evidence graph, gap classifier,
   improvement optimiser and verification tasks.
4. **Application compiler:** evidence-linked CV/letter/answer generation and
   deterministic release manifest.
5. **Submission adapters:** official ATS integrations, idempotency, receipts and
   follow-up scheduling.
6. **Interview system:** stakeholder intelligence refresh, preparation packs,
   mock assessments and debrief ingestion.
7. **Calibration:** funnel analytics, controlled experiments, score calibration
   and automatic strategy updates.

The first slice is implemented in `career_automation/` and
`scripts/advance_career_pipeline.py`. It consumes the current scored JSONL and
does not mutate the live scraper database.

The application-document implementation will selectively adapt the audited
patterns in `docs/UPSTREAM_AI_JOB_SEARCH_AUDIT.md`. That upstream workflow is a
reference for drafting, review, LaTeX/PDF verification, ATS checks, interview
continuity and outcome capture; it does not replace the architecture or stage
ordering defined here.

The prose-authenticity pass is separately bounded by
`docs/UPSTREAM_HUMANIZER_AUDIT.md`. Its rules inform a style critic only; they
do not supersede the evidence ledger, factual validators or release policy.

The supplied repositories and the later Scrapling candidate are reviewed at
pinned revisions in `docs/SCREENSHOT_REPOSITORY_REVIEW.md`.
Crawl4AI and Scrapling share one immediate comparative collection/research
spike; Browser Use is a later isolated submission fallback. The other projects remain deferred tools or
sources of bounded design patterns and do not enter the core dependency graph.

Those bounded design patterns are now executable in `career_automation/` and
documented in `docs/BORROWED_PATTERNS_IMPLEMENTATION.md`: versioned flow DAGs,
component traces, a durable retry outbox, capability and scoped-access policy,
SSRF validation, bounded subprocesses, resumable recorded browser workflows,
hybrid evidence-ID retrieval, migration checksums, health-gated deployment and
licence-aware document sidecars. Their control tables are registered in the
same SQLite database without changing the live job states.

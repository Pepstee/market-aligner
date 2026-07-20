# Market Aligner

An evidence-led, configurable candidate job-search pipeline for the United
Kingdom AI/IT market. It discovers live vacancies, extracts structured role
requirements, ranks them against a corpus-derived candidate profile, and writes
an application shortlist plus a skills-gap workbook.

## Active search target

The leading tracks are AI Automation, Agentic AI, Applied AI and Technical
Solutions. Adjacent routes include backend, cloud/platform, MLOps and security
detection. The scorer deliberately distinguishes internal system sophistication
from externally verified production experience; graduate and fellowship routes
receive a lower entry barrier than senior/staff/principal roles.

The collector uses 37 enabled adapters. Thirty-four work without credentials: direct
employer feeds from Greenhouse, Lever, SmartRecruiters, Ashby, Workable,
Recruitee, Personio and twelve configured Workday career tenants; public UK
coverage from NHS Jobs, jobs.ac.uk and Guardian Jobs; fifteen direct Swiss,
Irish and Dutch sources; plus Arbeitnow, Jobicy,
Remotive, Himalayas, The Muse, We Work Remotely, Remote OK and Remote First Jobs.
Adzuna, Reed and Jooble are
also enabled and activate when their API credentials are present. Missing
optional credentials skip only that source. Collection is uncapped, parallel,
append-preserving and completely separate from LLM processing. See
`docs/UK_SOURCE_RESEARCH.md` and `docs/CH_IE_NL_SOURCE_RESEARCH.md` for the
researched coverage boundary.

Guardian Jobs currently returns full search/RSS metadata but responds to public
detail requests with an empty HTTP 202. Those records are retained in the raw
database and marked `listing_excerpt_only`; the deterministic viability gate
does not send them to the LLM until a complete description is available.

## Canonical repository and brownfield imports

This checkout identifies itself with the machine-readable
`canonical-repository.json` marker. It is the active **Market Aligner** repository;
similarly named historical copies are not import sources unless an operator supplies
their paths explicitly. The `jaa-baseline adopt` and `adopt-online` contracts require
`--source-root`, `--data-root`, and `--repository`. They have no personal-path or
first-operator defaults, and receipts retain logical labels rather than host paths.
Online adoption opens live SQLite sources with `mode=ro` and `query_only`, performs no
source checkpoint or journal-mode operation, and never deletes, renames, or truncates
source main/WAL/SHM files. Receipts compare stable main/WAL content at capture boundaries;
SHM is observed as identity metadata only because SQLite may lawfully update its volatile
reader-lock metadata during a read-only WAL connection. Destination finalisation and
immutable, sidecar-refusing reconciliation remain separate from that source behaviour.

## Run

```bash
./.venv/bin/python -m profiler.candidate_profile
./.venv/bin/python scripts/collect_uk_jobs.py --config skeleton/config.overnight.yaml --hours 9 --poll-minutes 15
./.venv/bin/python scripts/process_collected_jobs.py --config skeleton/config.overnight.yaml --force-extract
```

The second command only collects raw postings into SQLite and the raw cache.
The third first rebuilds an auditable deterministic viability manifest: it
removes explicit expiry/dead links, non-UK eligibility, irrelevant titles,
unrealistic seniority and cross-source duplicates without changing the raw
database. It then invokes `gpt-5.6-sol` once vacancy at a time for structured
normalization and evidence-led fit judgment, followed by deterministic scoring.
Successful judgments are persisted after every vacancy, so an interrupted run
can resume without losing completed work. The model receives the expanded
career dossier derived from the full owned context; raw private conversations
and secret-bearing records are deliberately excluded.

The viability artefacts are:

- `scraper/data_overnight/viability.jsonl` — one include/exclude decision and reason per raw record;
- `scraper/data_overnight/viable_job_urls.jsonl` — unique vacancies allowed to reach Sol.

`--force-extract` is
needed once after an extraction-schema or profile change; omit it on later runs
to process only new postings. The compatibility wrapper performs the same two
phases in sequence:

```bash
./.venv/bin/python scripts/run_nine_hours.py --config skeleton/config.overnight.yaml --hours 9 --interval-minutes 30
```

Outputs:

- `outputs/overnight/jobs_ranked.xlsx` — every collected job ranked personally with role, location, fit,
  opportunity, entry barrier and application link;
- `outputs/overnight/requirements_ranked.xlsx` — every required/preferred skill ranked by prevalence;
- `outputs/overnight/fit_opportunity.png` — one dot per job on the fit/opportunity map;
- `outputs/overnight/SHORTLIST.md` — human-readable shortlist from the live run;
- `scraper/data_overnight/jobs.sqlite3` — durable raw, normalized and scored database.

The scraper and final score arithmetic are deterministic. The active
`codex_cli` backend performs only the semantic work: structured vacancy
extraction and evidence-led fit/alignment ratings. Responses are cached by
backend, prompt and input, so unchanged vacancies are not re-evaluated.

## Autonomous career control plane

The application lifecycle is designed in
`docs/AUTONOMOUS_CAREER_PIPELINE.md`. Its first executable slice consumes the
scored JSONL without mutating the live scraper database:

```bash
./.venv/bin/python scripts/advance_career_pipeline.py bootstrap
./.venv/bin/python scripts/advance_career_pipeline.py status
./.venv/bin/python scripts/advance_career_pipeline.py research-queue --limit 20
```

The control plane stores its event ledger and materialised state in
`outputs/career_automation/career_pipeline.sqlite3`. A deterministic
Opportunity-only gate runs before employer profiling. SQLite triggers prevent
any rejected job from entering the employer-research queue. Fit and candidate
evidence are deliberately excluded from this admission decision; they are
assessed after worthwhile employers have passed reconnaissance.

The MIT-licensed `MadsLorentzen/ai-job-search` project has been audited as an
upstream reference for the later CV/cover-letter, PDF/ATS verification,
interview and outcome loops. The exact adoption and rejection boundary is
recorded in `docs/UPSTREAM_AI_JOB_SEARCH_AUDIT.md`; its interactive scraper and
file-based control plane do not replace this project's database-backed flow.

`blader/humanizer` has also been audited as a reference for a bounded
prose-authenticity critic. It will propose atomic edits before the deterministic
truth and release gates; it will not be installed as an unrestricted final
rewriter. See `docs/UPSTREAM_HUMANIZER_AUDIT.md`.

All repositories in the supplied open-source carousel, plus Scrapling, have
been reviewed at pinned revisions in `docs/SCREENSHOT_REPOSITORY_REVIEW.md`.
Scrapling is now installed at its audited v0.4.11 commit in an isolated Python
3.12 runtime and connected as the collector's complete static -> dynamic ->
stealth recovery chain. Its sessions, proxies, adaptive selectors, XHR capture,
browser hooks, CDP, spiders, shell and MCP remain available through the actual
upstream package. Browser Use is reserved for a later isolated unsupported-form
fallback.

The useful patterns from every reviewed repository have now been reimplemented
as dependency-light local modules. Register their versioned flow and namespaced
control tables idempotently with:

```bash
python3 scripts/register_borrowed_patterns.py
```

See `docs/BORROWED_PATTERNS_IMPLEMENTATION.md` for the exact capability,
observability, workflow, retrieval, migration, deployment and document-policy
contracts. See `docs/SCRAPLING_FULL_INTEGRATION.md` for the full installed
Scrapling surface and commands.

## Clean bootstrap and complete verification

No virtual environment is assumed to exist. From a clean checkout, create one from the
locked CPython 3.12 dependency input and run the complete collected suite:

```bash
PYTHON_BOOTSTRAP=python3.12 ./scripts/bootstrap-test-env.sh
./.venv/bin/python -m pytest -q
```

The pre-adoption observation was **65 passing career-control tests**. That is a labelled
historical baseline, not the current suite total. Record each new run's
passed/skipped/failed totals separately instead of rewriting it. Five full Scrapling
sidecar tests are collected and skip unless the separately documented
`.venv-scrapling` runtime has actually been installed.

Clean-bootstrap verification on 20 July 2026: **94 passed, 5 skipped, 0 failed**
(99 tests collected; 25 unittest subtests also passed). This is the post-adoption total.

The original guided-pass files remain as generic reproducibility fixtures;
the active config, profile, contracts, prompts and reports no longer load them.

Generate a content-addressed JSON receipt for both the current complete suite and
the separately labelled 65-test historical `career_automation` scope with:

```bash
python3 scripts/generate-test-evidence.py
```

The generator publishes under `runtime_evidence/pytest/` only after both runs
pass and their pytest totals are parseable and internally consistent.

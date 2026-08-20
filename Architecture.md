# Architecture — Modular Design

The four-part split is the right shape. One refinement changes how they connect: **the LLM module is a horizontal *service*, not a vertical stage.** Both the scraper (to extract and rate jobs) and the profiler (to assess the supplied candidate portfolio and answers) call into it. So the dependency graph isn't a line — it's a spine with a shared brain hanging off it.

## The modules

- **Skeleton** — orchestrator. Owns the pipeline runner, the config, resume/caching/logging, and the **deterministic scoring maths** (power/geometric mean, two axes, field aggregation). It's the only place scraper data and profiler data meet.
- **Scraper** — code + its data. Per-board adapters (Wanted, Saramin, JobKorea, Notefolio), crawl/fetch, rate-limiting, and the raw cache. This is the earlier *Scraper* sub-build; its LLM-driven extraction/scoring (the *Judge*) is now just "scraper calls the LLM module".
- **Profiler** — code plus operator-supplied candidate data. The v1 guided pass, later v2 (portfolio + micro-tasks + Elo), and the scoring that produces a candidate profile. Its data is **personal and private** — kept local, never committed, never sent to the LLM beyond what a given assessment needs.
- **LLM** — the shared brain. Model-agnostic client with retries, rate-limit, cost logging, and a response **cache**; versioned prompts and rubrics; structured-output schemas. Exposes capabilities, not a pipeline: `extract_job()`, `rate_axes()`, `assess_portfolio()`, `normalise_skill()`.
- **Outputs** (small, worth naming) — the two workbooks + the Fit/Opportunity plot. A thin reporter the skeleton drives.

## Why the LLM is horizontal

```
                 ┌──────────────┐
                 │   SKELETON   │  runner · config · deterministic scoring · reporter
                 └───┬──────┬───┘
            drives   │      │   drives
              ┌──────┘      └──────┐
        ┌─────▼─────┐        ┌─────▼─────┐
        │  SCRAPER  │        │  PROFILER │
        │ +raw data │        │ +candidate data│
        └─────┬─────┘        └─────┬─────┘
              │  calls             │  calls
              └────────┬───────────┘
                 ┌─────▼─────┐
                 │    LLM    │  prompts · schemas · cache · cost log  (shared service)
                 └───────────┘
```

Scoring lives in the **skeleton**, not the LLM: the LLM produces the fuzzy 0–10 ratings, the skeleton does the deterministic arithmetic that joins them with candidate priors. That keeps the final scores reproducible and re-runnable without new LLM calls.

## Two design rules that make this hold up

**1. Separate code from data inside each module.** Each module gets a `data/` subfolder. Scraper data is large → git-ignored and rebuildable. Profiler data is personal → local and private. You can wipe and regenerate data without touching a line of code.

**2. Quarantine the two sources of messiness.** This is the whole reason for the split, given the tool is *both* human-calibrated *and* LLM-driven:
- The **human-calibrated, subjective, mutable** part is sealed inside the Profiler — small, hand-tunable, private.
- The **LLM's non-determinism** is sealed behind the LLM module's interface — fixed prompts, JSON schemas, temp≈0, cached and versioned.
- They only meet in the skeleton's **deterministic** scoring. So a human recalibration and an LLM prompt change can each be made and tested in isolation, without disturbing the pipeline or each other.

## Folder layout

```
korea-job-scraper/
├── skeleton/
│   ├── run.py            # stage runner + CLI
│   ├── scoring.py        # power/geometric mean, two axes, field aggregation
│   ├── config.yaml       # weights, p, search terms, skill aliases
│   └── contracts.py      # the seams: C1–C4 + hyun_profile schemas
├── scraper/
│   ├── adapters/         # wanted · saramin · jobkorea · notefolio
│   ├── crawl.py
│   └── data/             # raw_cache/ , job_urls.jsonl        (git-ignored)
├── profiler/
│   ├── instrument/       # v1 guided pass → v2 interactive
│   ├── score_profile.py
│   └── data/             # hyun_profile.yaml , answers , portfolio refs  (private)
├── llm/
│   ├── client.py         # model-agnostic; retries · rate-limit · cost log · cache
│   ├── prompts/          # versioned prompts + rubrics
│   └── schemas/          # structured-output JSON schemas
└── outputs/              # jobs_ranked.xlsx · requirements_ranked.xlsx · fit_opportunity.png
```

## The seams (interfaces)

Modules talk **only** through the frozen contracts, so each is testable against a fixture with the others absent:

```
scraper   ──C1 job_url──▶ ──C2 raw_posting──▶ llm.extract_job + llm.rate_axes
profiler  ──▶ hyun_profile
skeleton  reads C3 job_row + hyun_profile ──▶ scoring ──▶ C4 scored_row ──▶ outputs
llm       everything in/out via a JSON schema; every call cached by (prompt-hash, input-hash)
```

## What this buys you

Swap the model without touching the scraper. Re-score after a weight change without re-calling the LLM. Recalibrate the candidate profile without re-crawling. Rebuild the scrape cache without losing candidate data. Test any module alone. And because every LLM call is cached and every prompt versioned, calibration — which you'll iterate a lot — stays cheap and traceable.

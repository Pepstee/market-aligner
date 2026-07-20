# Candidate profiler

The active profiler is now evidence-led and tailored to **Artiom Gutu**. It
uses the owned `giga-user` corpus to separate four quantities that must not be
collapsed into one score:

1. `interest` — repeated, explicit pull towards the work;
2. `skill` — demonstrated capability, discounted where the implementation was
   heavily AI-assisted or not independently audited;
3. `market_readiness` — how defensible the profile is in a hiring process now;
4. `confidence` — strength and independence of the evidence behind the scores.

Source of truth:

- `data/artiom_evidence.yaml` — curated claims, provenance, scoring rationale,
  gaps, constraints, and unknowns;
- `candidate_profile.py` — validation and deterministic rendering;
- `data/artiom_profile.yaml` — generated Phase-1 output for the scraper refactor.

Version `v1.1-full-context-expanded` contains 26 evidence items. The Sol job
judge receives the full career-relevant evidence ledger, track rationales,
capabilities, constraints, gaps, blind spots, unknowns and explicit negative
evidence for every vacancy. This is the safe distillation of the complete owned
context: raw private conversations and secret-bearing records are never copied
into a vacancy prompt.

Run:

```bash
python -m profiler.candidate_profile
python profiler/test_candidate_profile.py
```

The earlier Hyun questionnaire, answers, and profile remain in place as legacy
data so the original run stays reproducible. They must not be loaded for
Artiom's search. Phase 2 must update the scraper's design-specific career enum,
search seeds, job extraction schema, and scoring axes before any live crawl.

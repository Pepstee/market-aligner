# Candidate profiler

The active profiler is evidence-led and candidate-generic. It uses a private,
owned evidence corpus to separate four quantities that must not be collapsed
into one score:

1. `interest` — repeated, explicit pull towards the work;
2. `skill` — demonstrated capability, discounted where the implementation was
   heavily AI-assisted or not independently audited;
3. `market_readiness` — how defensible the profile is in a hiring process now;
4. `confidence` — strength and independence of the evidence behind the scores.

Source of truth:

- `data/candidate_evidence.yaml` — private claims, provenance and scoring rationale,
  gaps, constraints, and unknowns;
- `candidate_profile.py` — validation and deterministic rendering;
- `data/candidate_profile.yaml` — generated runtime profile.

The job judge receives the career-relevant evidence ledger, track rationales,
capabilities, constraints, gaps, blind spots, unknowns and explicit negative
evidence for every vacancy. This is the safe distillation of the complete owned
context: raw private conversations and secret-bearing records are never copied
into a vacancy prompt.

Run:

```bash
python -m profiler.candidate_profile --evidence profiler/data/candidate_evidence.yaml \
  --output profiler/data/candidate_profile.yaml
python profiler/test_candidate_profile.py
```

The guided-pass questionnaire scorer remains available with a generic contract
for reproducibility. Its private answers and generated preferences are runtime
inputs and are not distributed.

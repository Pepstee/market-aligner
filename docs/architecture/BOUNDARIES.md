# Canonical product boundaries

## Market Aligner owns

- vacancy collection and source adapters;
- immutable raw vacancy evidence;
- normalisation, canonicalisation, deduplication, and vacancy state;
- profiles and the evidence ledger;
- deterministic hard eligibility;
- opportunity assessment and the employer-research gate;
- employer and role research;
- evidence matching, explicitly uncalibrated fit, ranking, and calibration.

## Application automation owns

- application strategy;
- CV, cover-letter, and answer generation from validated evidence;
- deterministic document and answer validation;
- supported form execution;
- release candidates, submission receipts, status events, interview evidence, and outcomes.

It is logically within the product but remains separately certifiable. Only provisional,
versioned interfaces may be built before the protected upstream freezes and is sealed.

## External orchestrator

General execution infrastructure remains external. Market Aligner may call it through a
small adapter but does not absorb its scheduler, governance, or worker implementation.

## Safety boundary

Collection, persistence, deduplication, arithmetic, queues, leases, and receipts are
deterministic. Semantic extraction, evidence alignment, and bounded qualitative judgement
may use an LLM only through validated schemas and hash-bound receipts. Final submission,
legal consent, and irreversible external actions are operator-gated.


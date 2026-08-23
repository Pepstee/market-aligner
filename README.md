# Market Aligner

Market Aligner is one multi-profile product. It collects and normalises vacancy data,
applies deterministic viability and eligibility rules, performs bounded semantic
assessment, and ranks opportunities against an evidence ledger selected by
`profile_id`.

Profile data, credentials, generated applications, collected data, caches, and runtime
receipts live outside this repository under `MARKET_ALIGNER_DATA_HOME`.

The application-automation component is logically inside the product boundary but is
separately certifiable. This repository currently contains only its versioned interface;
the active implementation will be imported after its protected upstream freezes and is
sealed.

## Development status

This is the canonical reconciliation lineage. Audited predecessor trees remain read-only
until every useful component has been adopted, tested, and recorded in the migration
ledger.

Implemented local slices include:

- 34 registered board adapters, an uncapped parallel collector, durable restart state and the
  complete Scrapling sidecar protocol;
- generic opaque profiles, an external evidence ledger and loss-conscious legacy importers;
- deterministic normalisation, deduplication, viability, eligibility and scoring;
- validated semantic extraction/evidence-alignment schemas and content-bound LLM receipts;
- an opportunity-before-research database gate, leased research workers and cited dossiers;
- profile-scoped ranking, skill-frequency and interactive opportunity/fit reports;
- a local service layer and provisional, versioned JAA contracts.

Fit is always reported as `uncalibrated`. This is a ranking heuristic, not a hiring probability.

## Local commands

```bash
export MARKET_ALIGNER_DATA_HOME="$HOME/.local/share/market-aligner"

market-aligner profiles list
market-aligner profiles create-synthetic
market-aligner profiles import --format evidence-led --source /private/profile.yaml
market-aligner assess --profile-id prf_<opaque-id> --request /private/request.json
market-aligner ingest --config /private/collection.yaml
```

`ingest` runs exactly one bounded official collection cycle from the exact
configuration file given, against the established external data home, and emits
one canonical JSON result. Each configuration identity may run once: the
content-bound operation journal under `<data-home>/state/operations/` refuses
any replay of a terminal operation before provider access, and marks an
interrupted run `indeterminate` (fail closed) instead of claiming an
exactly-once provider call. Provider failures preserve the last good database
and raw cache.

Live collection configuration is external and injected into adapters. The automatic Scrapling
fallback uses static then dynamic fetching; stealth/challenge-solving capabilities require an
explicit source policy. Final submission and legal consent are never authorized by Market
Aligner.

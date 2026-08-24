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
market-aligner ingest --config /private/collection.yaml \
  --operation-id nightly-2026-08-24
```

`ingest` runs exactly one bounded official collection cycle from the exact
configuration file given, against the established external data home, and emits
one canonical JSON result. Every run requires an explicit stable
`--operation-id`: the journal binds that id to the resolved config path, the
coherent config-file closure identity (root plus every `extends` dependency),
the merged config hash, the canonicalized sorted-unique source scope and the
data home; it rejects any changed binding before provider access and returns an
already-sealed terminal receipt verbatim (`replayed=true`, zero provider
calls). Locking is per board inside the data home: operations holding any
common board run strictly sequentially, subset/superset scopes serialize on
exactly their intersecting boards, same-id live contenders are refused while
the owner runs, and an interrupted owner stays explicitly unresolved — failing
closed and blocking new intersecting-scope operations, with deliberately no
reconciliation capability in this slice. Provider failures preserve the last
good database and raw cache, and every configured collector path is enforced
to stay inside the data home.

Integrity boundary: owner-private directories, single-link 0600 files and
unkeyed SHA-256 binding give receipts canonical identity and detect accidental
or noncoherent corruption; configuration file identity is content/path based,
not inode-bound. None of this authenticates against a malicious same-UID
rewrite that changes content and recomputes every public hash; root-owned or
signature-backed admission remains a separately governed future authority
slice.

Live collection configuration is external and injected into adapters. The automatic Scrapling
fallback uses static then dynamic fetching; stealth/challenge-solving capabilities require an
explicit source policy. Final submission and legal consent are never authorized by Market
Aligner.

# Market Aligner

Market Aligner is one multi-profile product. It collects and normalises vacancy data,
applies deterministic viability and eligibility rules, performs bounded semantic
assessment, and ranks opportunities against an evidence ledger selected by
`profile_id`.

Profile data, credentials, generated applications, collected data, caches, and runtime
receipts live outside this repository under `MARKET_ALIGNER_DATA_HOME`.

The application-automation component is logically inside the product boundary but is
separately certifiable. Its implementation lives in `internal/jaa` and is packaged separately with
shared, versioned contracts. Final migration qualification remains in progress.

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
```

Live collection configuration is external and injected into adapters. The automatic Scrapling
fallback uses static then dynamic fetching; stealth/challenge-solving capabilities require an
explicit source policy. Final submission and legal consent are never authorized by Market
Aligner.

Collection uses `market-aligner collect --config CONFIG --operation-id ID --once`
(or `--hours N` / `--stop-at HH:MM` in the machine’s local time). `collect-preflight` and `collect-status` use the same config and data
home. In the external config, `collection.target_per_board` defaults to zero (uncapped),
`discover_only` saves discoveries without fetching, and `delay_seconds` spaces fetches
per board. Optional `fetch_attempts` (1–10, default 1) and `fetch_retry_backoff`
(0–60 seconds, default 5) retry direct adapter failures with capped exponential waits
before the existing Scrapling fallback. Retries respect the collection deadline;
unfetched rows remain available for the next operation. Invalid captured content is
not retried as a transport failure.

The Scrapling sidecar uses explicit `scrapling.runtime_python` first, then
`AGENTIC_SCRAPLING_RUNTIME_DIR/bin/python`, then `.venv-scrapling/bin/python`
relative to its configured runtime root. The legacy `http` engine name is accepted
and recorded as `static` in fallback receipts.

For the donor’s full Saramin job-description capture, set `saramin.detail_mode: browser`.
The default `api` mode remains available for metadata collection; discovery needs the
configured API key in either mode. Notefolio’s donor job-list route remains selectable
with `notefolio.recruit_url: https://notefolio.net/service/job`; its current default is
`https://notefolio.net/recruit`. These are retained adapter configurations, not a claim
that the external sites have been revalidated recently. Browser resources are scoped
to each call rather than shared across collector threads.

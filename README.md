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


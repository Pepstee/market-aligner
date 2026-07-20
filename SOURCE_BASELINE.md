# Brownfield Source Baseline

Captured read-only on 20 July 2026 before orchestrator-v3 adoption.

## Canonical source candidate

Receipt label: `source:raw_jobs` / `source:career_pipeline` (the operator supplies the
host-specific source root; receipts never persist that personal absolute path).

The source remains untouched and recoverable. This repository is the neutral, versioned
successor. Generated outputs, personal profiles, secrets, virtual environments and live
databases were deliberately not copied into Git. They must enter through migration/import
contracts, never through source control.

## Runtime evidence

- Host: `macOS-26.4.1-arm64-arm-64bit-Mach-O`
- Python observed: `3.14.5`
- Historical raw-database observation: 9,407 postings; 548 normalised jobs; 548
  scores; 39 source-state rows. The collector continued running after this observation,
  so **9,407 is superseded as a current count**. It remains historical evidence and is
  not rewritten to match a later snapshot.
- Career database: 462 pipeline jobs; 924 pipeline events; 58 research queue rows;
  0 employer dossiers; 0 browser workflows; 0 browser runs.
- Both databases returned `PRAGMA integrity_check = ok`.

## Locked source receipts

- `scraper/data_overnight/jobs.sqlite3`
  - bytes: `117551104`
  - SHA-256: `87aefc638ae5c0d5b11e6dd8dfb8da5cd8bbfaed5cdba630f5aa3216bf170e57`
- `outputs/career_automation/career_pipeline.sqlite3`
  - bytes: `6238208`
  - SHA-256: `dd99efe519b5fcfe09cba2a0d08d18ce6ce84d570ef8649c5d250ebba03f9a8b`

These are historical observations, not mutable declarations of the live files' present
contents. The legacy `adopt` path verifies these exact bytes and refuses any journal, WAL,
or SHM sidecar; it must never directly copy a live WAL database.

## Online snapshot contract

For a collector that is still writing, `adopt-online` opens each source with SQLite
`mode=ro` and freezes it through SQLite's online backup API. SQLite chooses a consistent
read transaction while the collector remains available. The command never checkpoints,
pauses, writes, renames, or directly copies the source database. A WAL without its SHM is refused,
because opening that state could require SQLite to initialise source-side coordination.

The destination is first built in its destination directory, fully closed, checked with
`PRAGMA integrity_check`, measured, fsynced, and then published with atomic
create-if-absent semantics. Existing destinations are never overwritten. The content-hashed
receipt records, under logical labels:

- source main/WAL/SHM identities at capture start and end, plus observed drift;
- the newly frozen integrity result, schema identity, per-table counts, bytes and SHA-256;
- destination identity, repository revision, and rollback labels;
- the historical observations above in a separate `historical_observation` object.

Reconciliation re-hashes the receipt, checks its content-addressed filename and re-verifies
the frozen destination and its identity. Any mismatch fails closed.

Operator commands (replace the shell variables with local roots; they are not written into
the receipt):

```bash
jaa-baseline adopt-online \
  --source-root "$JAA_LIVE_SOURCE_ROOT" \
  --data-root "$JAA_RUNTIME_DATA_ROOT" \
  --repository "$JAA_REPOSITORY_ROOT"

jaa-baseline reconcile \
  --receipt "$JAA_RUNTIME_DATA_ROOT/receipts/migration-<sha256>.json" \
  --data-root "$JAA_RUNTIME_DATA_ROOT"

jaa-baseline rollback-manifest \
  --receipt "$JAA_RUNTIME_DATA_ROOT/receipts/migration-<sha256>.json" \
  --data-root "$JAA_RUNTIME_DATA_ROOT"
```

Every online capture is a new snapshot with a new receipt. Its observed counts never
retroactively replace the 20 July 2026 observation.

## Historical and private boundaries

- The two `giga-user/market-aligner` copies are historical and non-canonical.
- `profiler/data/` contains private candidate material and is runtime input, not product code.
- `scraper/data_overnight/raw_cache/` and `outputs/` are generated evidence stores.
- Credential values may only be referenced by environment-variable or credential-broker key.

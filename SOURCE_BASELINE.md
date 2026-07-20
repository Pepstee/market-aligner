# Brownfield Source Baseline

Captured read-only on 20 July 2026 before orchestrator-v3 adoption.

## Canonical source candidate

`/Users/admin/Claude/Projects/Korea Job Scraper`

The source remains untouched and recoverable. This repository is the neutral, versioned
successor. Generated outputs, personal profiles, secrets, virtual environments and live
databases were deliberately not copied into Git. They must enter through migration/import
contracts, never through source control.

## Runtime evidence

- Host: `macOS-26.4.1-arm64-arm-64bit-Mach-O`
- Python observed: `3.14.5`
- Raw database: 9,407 postings; 548 normalised jobs; 548 scores; 39 source-state rows.
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

The import path must re-read these files in read-only mode, verify exact hashes and table
counts, and write a migration receipt before treating the successor store as canonical. A
changed source is a new snapshot requiring a new receipt, not an in-place correction.

## Historical and private boundaries

- The two `giga-user/market-aligner` copies are historical and non-canonical.
- `profiler/data/` contains private candidate material and is runtime input, not product code.
- `scraper/data_overnight/raw_cache/` and `outputs/` are generated evidence stores.
- Credential values may only be referenced by environment-variable or credential-broker key.

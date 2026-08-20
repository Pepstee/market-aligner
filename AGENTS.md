# Market Aligner reconciliation constraints

- This repository is the only writable Market Aligner reconstruction target.
- Treat every path named in `docs/migration/source-manifests.json` as read-only input.
- Adopt existing implementations selectively and retain source hashes in the migration
  ledger.
- Never add real profile data, credentials, generated applications, collected vacancies,
  caches, or runtime databases to this repository.
- Product behaviour and paths are profile-generic and use opaque `profile_id` values.
- JAA is the internal application subsystem under `internal/jaa`; it retains explicit module
  boundaries and independent certification. Recover quarantined capabilities only through
  reviewed, tested increments, never by merging a quarantine branch wholesale.
- Final submission, legal consent, and irreversible external actions require explicit authority.

## Graphify completion gate

- `graphify-out/graph.json`, `GRAPH_REPORT.md`, `.graphify_labels.json`, and
  `freshness.json` are committed architecture evidence, not disposable generated files.
- Any tracked code, contract, test, documentation, or configuration change makes the graph
  stale. Rebuild Graphify and regenerate the freshness receipt in the same increment.
- An increment is incomplete unless
  `python scripts/verify_graphify_freshness.py` and `pytest -q` both pass.
- Never weaken the verifier or exclude a tracked source merely to make a stale graph pass.

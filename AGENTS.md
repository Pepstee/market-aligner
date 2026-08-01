# Market Aligner reconciliation constraints

- This repository is the only writable Market Aligner reconstruction target.
- Treat every path named in `docs/migration/source-manifests.json` as read-only input.
- Adopt existing implementations selectively and retain source hashes in the migration
  ledger.
- Never add real profile data, credentials, generated applications, collected vacancies,
  caches, or runtime databases to this repository.
- Product behaviour and paths are profile-generic and use opaque `profile_id` values.
- JAA implementation import is forbidden until the protected upstream freezes and a
  sealed handoff is available. Versioned interface work and contract tests are allowed.
- Final submission, legal consent, and irreversible external actions remain operator-gated.


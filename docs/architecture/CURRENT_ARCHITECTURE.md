# Current canonical architecture

```text
public vacancy sources
  -> collectors/adapters + full Scrapling sidecar
  -> external raw cache + shared vacancy SQLite
  -> deterministic shell/canonical identity/dedup/viability
  -> validated semantic extraction + hash receipt
  -> profile_id selects external profile/evidence ledger
  -> deterministic hard eligibility
  -> opportunity arithmetic and deterministic gate
  -> leased employer/role research with cited dossier
  -> evidence alignment against existing ledger IDs
  -> deterministic uncalibrated fit and ranking
  -> profile-scoped job/skill/scatter reports
  -> provisional JAA handoff
  -> operator-gated external application lifecycle events
```

## Package boundary

`src/market_aligner` contains product code and generic contracts only. `MARKET_ALIGNER_DATA_HOME`
contains profiles, evidence ledgers, vacancy data, raw content, outputs, credentials and receipts.
The wheel-content test rejects profile/data payloads and the identity test rejects real-person
names in package source and metadata.

## Ownership

- Market Aligner owns collection through ranking, including research and evidence matching.
- JAA owns strategy, documents, answers, deterministic validation, supported form execution,
  release, receipt/status and outcome events. It is separately certifiable.
- The general orchestrator remains external and is available only through a capability-scoped
  adapter.
- Operators retain final authority over submission, legal consent and irreversible actions.

## Local-first progression

The implemented service is an in-process API shared with the CLI. An HTTP transport, remote
workers, authentication, multi-tenancy, billing and distributed deployment remain deferred until
the local multi-profile flow and sealed JAA integration are certified.

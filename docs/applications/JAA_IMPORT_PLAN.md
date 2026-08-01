# Provisional JAA integration and sealed-import plan

Status: **provisional interface only**. The actively changing Gutua implementation is authoritative
and has not been copied, imported, or modified.

## Current seam

Market Aligner emits a `market-aligner.jaa-handoff.v0` record only after collection,
normalisation, viability, eligibility, opportunity, research and evidence alignment. Every mutable
input is represented by a SHA-256 digest. Fit is explicitly marked `uncalibrated`.

JAA owns strategy, documents, answers, validation, supported form execution, release,
submission/receipt state and outcomes. It returns idempotent `market-aligner.jaa-event.v0` events.
Submission authorization requires an operator-approval hash; receipt capture requires an external
receipt hash.

## Import gate after Gutua freezes

1. Obtain a sealed archive, Git commit, full file manifest and test/certification receipts.
2. Verify the archive and commit without checking it out over either repository.
3. Compare Gutua contracts field-by-field with the provisional v0 schemas.
4. Produce an explicit compatibility matrix and select versioned translators; never silently
   reinterpret an event.
5. Import only source and tests whose provenance and licence are known. Keep the sealed snapshot
   immutable.
6. Run JAA's own certification independently, then Market Aligner contract and end-to-end tests.
7. Record adopted/deferred/archived/tombstone-pending receipts in the migration ledger.
8. Only then enable a concrete `JAAClient`; keep final submission operator-gated.

Exact blocker: there is no frozen, sealed, hash-verifiable final Gutua snapshot yet.

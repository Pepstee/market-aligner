# JAA-00 independent review

Run the certification against the preserved adoption receipt and frozen runtime data:

```bash
jaa-baseline independent-review \
  --receipt "$JAA_RUNTIME_DATA_ROOT/receipts/migration-<sha256>.json" \
  --data-root "$JAA_RUNTIME_DATA_ROOT" \
  --repository "$JAA_REPOSITORY_ROOT"
```

The command is read-only. A zero exit exposes the canonical repository identity and both
the adoption and current revisions; preserved-original rollback actions; a secret-free
tracked-file inventory; exact database reconciliation; observed runtime prerequisites;
and the separately labelled historical observation of 65 passing pre-adoption
career-control tests. It never presents 65 as the current suite total.

Certification exits non-zero if the receipt, repository identity, adopted database,
rollback contract, tracked inventory, or runtime dependency set cannot be verified. In
particular, an altered database and a missing required distribution fail with exit code 2.
`certify` is an exact command alias for automation.

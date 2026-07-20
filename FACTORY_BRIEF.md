# Orchestrator-v3 Factory Brief

Build and certify the entire programme in `IMPLEMENTATION_SLICES.yaml` in exact dependency
order, JAA-00 through JAA-16. `BUILD_PLAN.md` is the architectural contract, `PRODUCT.md` is
the product contract and `SOURCE_BASELINE.md` is the brownfield migration receipt.

This is a brownfield product. Preserve working behaviour, tests and provenance. Do not
rewrite working subsystems merely to make the tree look new. Every increment must leave real
code, tests and executable evidence; no stubs, placeholders, TODO implementations, fake
integrations, fabricated receipts or tests that only prove mocks.

The final release is a commercially distributable local-first application. It must be useful
to the first operator without encoding that operator into product defaults, and installable
by a new user on a clean supported Mac. External merchant, domain, code-signing, ATS account,
MFA, CAPTCHA, consent and legal-attestation steps are explicit operator boundaries. Build the
real integration seams and runbooks, but never claim those external actions occurred without
their genuine receipts.

Use official vacancy and ATS routes only. Probabilistic workers may extract, assess, research,
match and draft; deterministic code alone may advance release or submission state. No real
external job submission is permitted until JAA-10 has certified, JAA-11 has selected a lawful
official route, the exact application has a valid release token, and the configured operator
policy authorises the canary.

For each slice, retain tests, negative controls, runtime evidence and content hashes. Planner
completion is not justified until all sixteen dependent transitions after JAA-00 are present,
JAA-16 commercial release evidence exists, and the executable project acceptance covers the
clean-install-to-receipt walking skeleton plus upgrade/restore.

# External document assurance

## Certified boundary

JAA treats employer-facing PDFs as untrusted until it inspects the exact bytes
that will be uploaded. The assurance policy runs after deterministic rendering,
again when constructing `ReleaseExecutionAuthority`, and again inside
`LocalBrowserExecutor._execute_submit` immediately before the consequential
click. A prior validation or cached receipt cannot replace the final check.

The certified scope is the JAA repository production executor and the migrated
operational scripts inspected on 5 August 2026. The repository has three
`locator.click()` call sites. Two implement guarded non-consequential clicks;
the third is `_execute_submit`, which requires the release token, exact
vacancy-bound CV and cover-letter receipts, recomputed PDF assurance, verified
field materialisation, duplicate prevention and durable submit state. The
migrated operational state contains no separate Playwright, Selenium,
Puppeteer or shell submit script. This certification does not claim control of
arbitrary manual browser activity.

## Fail-closed contract

The gate:

- hashes the input bytes with SHA-256 before parsing and permanently rejects
  `3dd13ba9709c7679152f2fc938c4495e2631796712f724f56ab0c82bb34aa0d2`;
- accepts only bounded regular PDF files opened with `O_NOFOLLOW`, then checks
  the file descriptor size and exact read length;
- parses with pinned `pypdf==6.6.0` in strict mode and rejects malformed,
  encrypted, empty-page and image-only/unextractable documents;
- normalises extracted text with NFKC, case folding, Unicode format-character
  removal, an audited Greek/Cyrillic confusable set and whitespace collapse;
- blocks internal governance, evidence/audit terms, model provenance,
  authorship and defensive disclaimers, prompt/control leakage, draft markers,
  unresolved placeholders and self-disqualifying prose;
- issues a deterministic PASS receipt only when there are no findings; and
- binds that receipt to document kind, final PDF hash, extracted-text hash,
  policy hash, page count, job key, vacancy hash, role title and company name.

Any byte mutation, vacancy mismatch or policy change makes receipt
reverification differ and blocks submission. Missing receipts cannot construct
release authority, and a SUBMIT action without release authority fails before
the click.

## Evidence and tests

Machine-readable evidence is stored in
`runtime_evidence/external_document_assurance/assurance-evidence.json`. It
contains the policy identity, real incident BLOCK result, clean control PASS
receipt, exact hashes, enumerated click sites and the scope limit above.

`test_external_document_assurance.py` generates adversarial PDFs and covers the
incident text, the real operational PDF, regenerated incident bytes, governance
and model leakage, prompts, placeholders, disclaimers, whitespace and homoglyph
variants, mutation, wrong vacancy, stale policy, symlinks, malformed PDFs,
encryption, image-only PDFs, missing receipt typing and bypass-path inventory.
The JAA-08 and JAA-09 suites exercise release-token, duplicate, materialisation,
real-browser, restart and final-submit behaviour.

To regenerate the evidence:

```bash
.venv/bin/python scripts/generate_external_document_assurance_evidence.py \
  --incident-pdf /path/to/the/quarantined/Artiom_Gutu_CV.pdf \
  --operational-root /path/to/migrated/operational-state \
  --output runtime_evidence/external_document_assurance/assurance-evidence.json
```

# Upstream audit: MadsLorentzen/ai-job-search

## Decision

Use `MadsLorentzen/ai-job-search` as a reference implementation for the
application-document, PDF-verification, interview-preparation and outcome
feedback portions of this project. Do not replace this project's collection,
normalisation, opportunity assessment, evidence, persistence or orchestration
layers with the upstream equivalents.

The audited upstream revision is:

```text
repository: https://github.com/MadsLorentzen/ai-job-search
commit: 8ac6965170ab7eb1693fde77d623469db9fcd455
commit date: 2026-07-19
licence: MIT, copyright (c) 2026 Mads Lorentzen
audit date: 2026-07-19
tests at audited revision: 119 passed
```

No upstream source has been copied into this repository at this stage. If code
or substantial template content is later imported, retain the MIT copyright
and permission notice alongside the imported material.

## What the upstream actually is

The project is a local Claude Code workflow expressed mainly as Markdown
commands, skills, profile files and LaTeX templates. Its principal commands
cover setup, portal search, batch ranking, one-role application generation,
interview preparation and outcome recording.

The strong `/apply` path is:

```text
fetch one posting
  -> evaluate candidate fit
  -> ask the user whether to continue
  -> draft a tailored CV and cover letter
  -> dispatch a separate company-research/reviewer agent
  -> revise the drafts
  -> compile and visually inspect the PDFs
  -> inspect the CV text layer and keyword coverage
  -> present the documents for human review
```

This is not an autonomous application-submission system. It does not provide a
durable database-backed control plane, an aggressive multi-source collector, a
separate Opportunity axis, an evidence-linked claim compiler, official ATS
submission adapters, receipts, or automated follow-up scheduling. Its own
workflow asks before drafting and returns the final files for review.

## Components to adapt

### 1. Drafter/reviewer separation

Generate the documents in one model context and critique them in another. Pass
the immutable job snapshot, selected evidence and draft text explicitly to the
reviewer. Reviewer suggestions are proposals; they cannot introduce a claim
unless it resolves to approved evidence IDs.

### 2. Relevance-weighted CV cutting

When a CV exceeds its page budget, remove material by per-vacancy relevance,
uniqueness and narrative value. Do not delete sections using a fixed generic
order. Preserve older evidence when it directly supports an important
requirement.

### 3. Mandatory PDF verification loop

Compilation success is not document success. Render every PDF and verify page
count, overflow, orphaned headings and entries, signature visibility,
typographic consistency and accidental blank space. Iterate until the layout
contract passes.

### 4. ATS text-layer verification

Extract the generated CV with `pdftotext -layout`. Require literal contact
details, sane reading order, recognisable dates and sufficient clean text.
Compare required and preferred vacancy terms with the extracted text, while
distinguishing truthful synonyms from genuine gaps. Never add a keyword solely
to satisfy the parser.

### 5. Exact submitted-artifact archive

Store the vacancy snapshot, generated sources, final PDFs, form answers,
release manifest, submission receipt and later outcome together. Interview
preparation must use the exact submitted versions, not the latest generic CV.

### 6. Interview and outcome continuity

Build interview preparation from the vacancy, employer intelligence, submitted
claims, known gaps and feedback from earlier stages. Record stage transitions
and feedback without overwriting history, then use resolved outcomes to
calibrate strategy.

### 7. Supply-chain and prompt-injection guards

Treat postings as untrusted data, restrict permission expansion, protect
personal-data paths and reject package lifecycle hooks in imported agent tools.
Instruction-level prompt-injection rules are helpful but insufficient; our
workers must also operate under file, network and tool boundaries.

## Components not to adopt

| Upstream component | Reason it is not our control plane |
|---|---|
| Portal search with roughly 20 results per call | Our collector is continuous, multi-source, append-preserving and uncapped. |
| JSON file for seen jobs | We require relational identity, immutable events, leases, retries and concurrent workers. |
| Candidate fit as the first expensive decision | Opportunity must pass before employer reconnaissance and detailed candidate work. |
| Four fixed fit weights as final truth | Our axes remain separately versioned and outcome-calibrated; deterministic policy consumes model assessments. |
| Markdown profile as canonical evidence | Markdown can be a generated human view, but claims must resolve to a structured, verified evidence ledger. |
| Company research only inside `/apply` | We use opportunity-gated reconnaissance first and deeper person/team research only after readiness. |
| One-job interactive confirmation flow | Our system needs queue-based autonomous drafting and release policy, with review thresholds rather than mandatory conversational pauses. |
| CSV application tracker | SQLite state plus immutable events is required for idempotency, replay and funnel analysis. |
| Manual final submission | The target includes official-route submission adapters, receipts and status tracking, subject to access and CAPTCHA policy. |

## Integration boundary

```text
our collection + raw store
  -> our deterministic viability and deduplication
  -> our structured requirement extraction
  -> our Opportunity-0 gate
  -> our employer reconnaissance and Opportunity-1
  -> our requirement/evidence/gap assessment
  -> our readiness gate
  -> adapted upstream document-production patterns
       evidence-bounded drafter
       independent reviewer
       relevance-weighted reduction
       LaTeX compile/render loop
       ATS text-layer and keyword validation
  -> our deterministic release manifest
  -> our submission adapters and receipts
  -> adapted interview/archive patterns
  -> our event-ledger outcome calibration
```

## Implementation order

This reference does not justify skipping the current pipeline order.

1. Finish employer-research contracts and Opportunity-1.
2. Implement the structured requirement/evidence graph and readiness gate.
3. Add an `application_compiler` package using the seven adopted patterns.
4. Add the bounded style-critique contract from
   `docs/UPSTREAM_HUMANIZER_AUDIT.md`, followed by evidence and coverage
   revalidation.
5. Port or recreate templates only after a template-level licence and ATS audit.
6. Add deterministic release validation before any submission adapter.
7. Add official ATS adapters one at a time with idempotency and receipt tests.
8. Connect interview and outcome artefacts to the event ledger and experiments.

## Acceptance tests for the later application compiler

- Every rendered claim resolves to one or more approved evidence IDs.
- An unsupported reviewer suggestion is rejected deterministically.
- The same release input produces the same manifest and document hashes when
  model outputs are pinned.
- CV output is exactly two pages unless a vacancy-specific policy says
  otherwise; the cover letter is exactly one page when required.
- PDF text extraction contains literal email, phone, dates and required
  evidence-backed keywords in a coherent reading order.
- The archive contains the exact released and submitted artefacts.
- Re-running a submission with the same idempotency key cannot apply twice.
- Interview preparation never contradicts a submitted claim.

# JAA-04 authentic authority acquisition

JAA-04 is generated output, not a hand-authored fixture. The repository does
ship response caches, publisher timestamps, or certification receipts. The
only acquisition input is an Opportunity-0 SQLite snapshot or the checked
`jaa04_admitted_queue.json` projection of that queue. No authority URL
inventory is accepted.

Run acquisition with:

```sh
python3 scripts/rebuild_jaa04_corpus.py \
  --queue-snapshot career_automation/fixtures/jaa04_admitted_queue.json
```

The command creates a production queue and lets `EmployerResearchWorker` and
`Opportunity1Coordinator` complete every selected vacancy. Discovery begins at
the admitted vacancy and follows only routes published in captured canonical,
organisation, sameAs, application or anchor links. It never guesses an
employer-specific path. Duplicate response bodies remain one capture.

Raw response bytes are stored by SHA-256. Citations preserve requested and
final URL, retrieval/capture time, HTTP status, redirects, response hash, cache
reference, and retrieval engine. Publisher dates are parsed only from exact
captured response fragments. Conflicting values are ambiguous and therefore
unknown. Unknown dates cannot pass a `requires_current` gate and can only
produce `unknown` freshness for non-time-sensitive company/product evidence.

Publication is atomic: no destination appears unless all 30 dossiers validate.
The capture receipt binds the queue snapshot, discovery mode, manifest,
dossiers, raw corpus, Git commit, and tracked source-content revision. Certify
the result with:

```sh
python3 scripts/accept_jaa_04.py
```

Certification rehashes every artifact and raw response and writes one
revision-bound receipt. It refuses stale, conflicting, or tampered evidence.

## Operator correction for the next implementation cycle

The acquisition implementation must satisfy the JAA-04 slice, not accidentally
strengthen it into an impossible or commercially useless ceremony.

- `career_automation/fixtures/jaa04_admitted_queue.json` is the checked,
  privacy-minimised bridge to the real 58-row Opportunity-0 queue. Its 30
  records were compared byte-for-byte on `job_key`, board, employer, title,
  vacancy URL and payload hash. An isolated builder must consume this durable
  fixture; it must not depend on an undisclosed host path to a SQLite snapshot.
- Scrapling's production HTTP fetcher is named `static`. `static` means a real
  network request through `Fetcher`, not a static fixture. Preserve the public
  sidecar protocol (`static`, `dynamic`, `stealth`) and prove authenticity from
  returned bytes and response metadata. Renaming the engine to `http` breaks
  the established sidecar contract without improving provenance.
- An authentic response may support more than one claim when each claim is
  linked to the exact supporting byte excerpt and its semantic purpose is
  validated. Duplicate evidence must not masquerade as independent
  corroboration, but JAA-04 does not require five different documents for every
  employer. Missing intelligence remains unknown; it is never invented merely
  to fill all five intelligence kinds.
- Runtime authority discovery must be product behaviour. A customer cannot be
  required to hand-author 150 source URLs before employer research works. Use
  source-controlled ATS adapters and official-domain discovery to resolve an
  admitted aggregator URL to an official vacancy or ATS representation while
  retaining the admitted vacancy identity and redirect/discovery provenance.
- Structured ATS responses are first-class evidence. Extract excerpts and
  publisher times from genuine JSON as well as HTML, including common
  `datePosted`, `publishedAt`, `updated_at`, `datePublished` and
  `dateModified` fields. Retrieval time is never substituted for publisher
  time.
- Normalised response content is bytes in the validator. Do not call
  `bytes.casefold()`; use a byte-safe normalisation or decode strictly before
  Unicode case-folding.
- Tracked frozen corpus material and generated runtime certification have
  different revision semantics. Do not create a self-referential tracked
  receipt whose declared Git revision changes when the receipt itself is
  committed. Generated runtime evidence stays outside the tracked-source
  revision domain and may bind exactly to the already committed code and
  fixture revision.
- A JAA-04 implementation is not complete merely because the false corpus was
  deleted or because a capture script exists. Completion requires a real
  positive corpus of at least 30 admitted dossiers, the negative controls, a
  passing independent-line acceptance declaration, and a content-addressed
  runtime receipt produced by that passing path.

## Live canary discovery observations (20 July 2026)

Three admitted records prove that portable discovery can be deterministic
without an employer-specific URL inventory:

- Greenhouse record `greenhouse:anthropic:5030244008`: the admitted hosted page
  is live and publishes the company careers route. Its board slug and numeric
  job ID also deterministically identify the official Greenhouse job API
  representation, whose genuine response carries `updated_at`.
- Ashby record `ashby:lendable:36d47627-9b4e-4864-9f05-2dbbd1052380`: the
  admitted hosted response contains JSON-LD `datePosted`, the employer URL and
  the employer careers route. The board slug also identifies Ashby's official
  posting API representation and its `publishedAt` field.
- Workable record `workable:cogna:847CFBC5F4`: the admitted short URL redirects
  to `/cogna/j/847CFBC5F4` and the returned bytes publish both the board's
  `llms.txt` and `/cogna/jobs/view/847CFBC5F4.md` vacancy representation. The
  Markdown response carries the publisher's `Posted` date.

Discovery must prefer typed metadata, canonical/redirect identity and
board-defined route transforms. It must not classify the first arbitrary
external anchors on a vacancy page as employer-owned authority. Same-ATS job
representations may substantiate role/hiring claims; employer-domain routes
must be derived from explicit hiring-organisation or company metadata before
they may substantiate company/product claims. Operational-health evidence
remains unknown unless an appropriately dated authoritative source is actually
discovered.

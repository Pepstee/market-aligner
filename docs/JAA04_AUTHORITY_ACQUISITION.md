# JAA-04 authentic authority acquisition

JAA-04 is generated output, not a hand-authored fixture. The repository does
not ship response caches, publisher timestamps, or full-corpus certification
receipts. The checked `jaa04_admitted_queue.json` is a privacy-minimised v1
identity seed; it is not accepted directly by the strict capture boundary.
The rebuild command first resolves every seed row to current official bytes,
replays viability and Opportunity-0, and creates an external v2 admission
snapshot. No authority URL inventory is accepted.

Run acquisition with:

```sh
python3 scripts/rebuild_jaa04_corpus.py \
  --queue-snapshot career_automation/fixtures/jaa04_admitted_queue.json \
  --access-policy /external/jaa04/public-access-policy.json \
  --workspace /external/jaa04/in-flight \
  --corpus /external/jaa04/certified
```

Collection is deterministic and model-independent. Operators may bound route
discovery and transport latency with `--maximum-routes` and
`--timeout-seconds`; neither option weakens admission or freshness policy.

The workspace is stable and resumable. It owns the persistent SQLite queue,
leases, completed dossiers and content-addressed raw response bytes. Repeating
the same command after interruption expires only abandoned leases, reuses
validated completed rows and immutable response bytes, and cannot complete a
dossier twice. A workspace is cryptographically bound to one admitted queue
snapshot and refuses reuse for a different cohort.

The external workspace separates admission from research:
`admission/official-admitted-queue-v2.json` binds the checked v1 file, current
official response bytes, publisher time, current viability, the exact JAA-03
policy and its replayed decision. `research/` then owns the dossier queue. If
the v2 admission snapshot already exists, a retry reuses it only after its
seed hash matches; capture still revalidates all raw bytes and decisions.
The reviewed v1 record-set hash is also anchored in source code, so editing
records and recomputing the fixture's self-declared hash cannot substitute a
different cohort unnoticed.

Public access is separately fail-closed. The external access-policy file must
use `jaa04.public-access-policy.v1` and contain an exact-host attestation by a
`human_operator`, with the reviewed terms URL, review timestamp, reviewer,
notes, and determination `public_read_only_research_permitted`. Attestations
expire after 90 days. Missing, stale, machine-authored or non-permitting
records block before a network call.

The attestation records are human-authored; the product does not discover a
terms URL, decide permission, choose a reviewer, or backfill a review time.
To package exact reviewed records without hand-calculating the canonical
records hash, create an external draft such as:

```json
{
  "schema_version": "jaa04.public-access-policy-draft.v1",
  "hosts": [
    {
      "host": "jobs.example.org",
      "terms_url": "https://jobs.example.org/terms",
      "determination": "public_read_only_research_permitted",
      "reviewed_at": "2026-07-26T08:00:00+01:00",
      "reviewed_by": "Operator name",
      "reviewer_type": "human_operator",
      "notes": "What was reviewed and why public read-only research is permitted."
    }
  ]
}
```

Every value above is illustrative, not an attestation. After personally
reviewing each exact host, the operator can finalize the external draft:

```sh
python3 scripts/finalize_jaa04_access_policy.py \
  --draft /external/jaa04/public-access-policy-draft.json \
  --output /external/jaa04/public-access-policy.json
```

The finalizer makes no network request and derives no authority fact. It
copies the exact records, adds their canonical hash, validates the same
human/freshness/permission contract used by acquisition, writes mode `0600`,
refuses repository paths and refuses overwrite. Missing hosts discovered
during acquisition still block until the operator separately reviews and adds
them to a new draft.

For every attested host, JAA-04 retrieves `robots.txt` with static HTTP before
the first content request. Exact robots bytes and the terms-policy hash are
retained in the raw store. Disallow, 401/403, 5xx, timeout, malformed response
or a cross-host robots redirect blocks the host. A 4xx other than 401/403 is
treated as an absent robots file. Longest-match Allow/Disallow rules are
evaluated for the honest `JAA-Public-Research` product token. Every request,
including a static-to-dynamic fallback, observes the greater of declared
`Crawl-delay` and a ten-second per-host floor.

The production acquisition chain is static HTTP followed, only for incomplete
ordinary content, by normal browser rendering. It never selects stealth.
Authentication, CAPTCHA, 401/403/429 and anti-bot challenge markers are
terminal denials, not escalation signals. Cross-host content redirects are
rejected; a published cross-host route must be evaluated as a new, separately
attested and robots-checked URL.

Greenhouse, Workable, Ashby, Lever and SmartRecruiters use source-controlled
family adapters. Each adapter derives its route from the admitted
family/tenant/vacancy identity and validates the allowed host and path,
redirect chain, live status, non-empty captured bytes, employer and vacancy
identity. Adapter configuration may be supplied by a caller, but no response
can relax those validations.

Himalayas, Remote First Jobs, Jobicy and all other aggregators are discovery
inputs only. Their responses are never emitted as `official_vacancy` evidence.
They must publish a public employer or ATS vacancy route whose returned bytes
pass authority and identity validation; otherwise acquisition abstains
fail-closed. Direct employer and public-sector pages remain purpose-typed and
must pass the same public-route, response-byte and employer-binding gates.

The command resumes or creates a production queue and lets `EmployerResearchWorker` and
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
Each immutable release contains `corpus_inventory.json`, which binds every
dossier, manifest and raw response by path, byte length and SHA-256. The public
`jaa04_capture` path is a single atomically replaced symlink to that release;
failed acquisition or validation therefore cannot move or alter the prior
certified corpus. The successful acquisition receipt binds the inventory hash.
The release also carries `admission/queue_snapshot.json` plus exactly the
Opportunity-0 and robots bytes referenced by that snapshot. For a SQLite input,
it carries a consistent SQLite backup instead. The research manifest links
each dossier back to this portable admission evidence; certification replays
the link and rejects missing, extra, altered or path-escaping bytes. The
capture receipt binds the input snapshot, portable queue snapshot, discovery
mode, manifest, dossiers, both raw stores, Git commit, and tracked
source-content revision. Certify the result with:

```sh
python3 scripts/accept_jaa_04.py \
  --capture /external/jaa04/certified \
  --access-policy /external/jaa04/public-access-policy.json \
  --receipt /external/jaa04/receipts
```

Certification rehashes every artifact and raw response and writes one
revision-bound receipt. It refuses stale, conflicting, or tampered evidence.
It also reloads the operator-presented access policy, requires its exact hash
on the capture, and replays every embedded terms attestation and robots
decision against the exact published robots bytes. A dossier with a missing
receipt, a self-declared policy, a disallowed engine, or robots denial cannot
certify.
The access-policy draft/final policy, acquisition workspace, corpus pointer and
full-corpus receipt must each be supplied explicitly outside the product
repository. The commands reject repository-contained runtime paths rather than
relying on `.gitignore`. Neither live corpus bytes, in-flight state nor
full-corpus receipts are stored in Git. A clean source clone contains the
acquisition software and admitted queue projection only; it never fabricates a
live corpus.

## Operator correction for the next implementation cycle

The acquisition implementation must satisfy the JAA-04 slice, not accidentally
strengthen it into an impossible or commercially useless ceremony.

- `career_automation/fixtures/jaa04_admitted_queue.json` is the checked,
  privacy-minimised bridge to the real 58-row Opportunity-0 queue. Its 30
  records were compared byte-for-byte on `job_key`, board, employer, title,
  vacancy URL and payload hash. The isolated rebuild consumes this durable
  fixture, but only the generated byte-backed v2 result may cross the capture
  boundary.
- Scrapling's production HTTP fetcher is named `static`. `static` means a real
  network request through `Fetcher`, not a static fixture. The sidecar protocol
  still exposes `static`, `dynamic` and `stealth`, but JAA-04 is policy-limited
  to the first two and proves authenticity from returned bytes and response
  metadata. Renaming `static` to `http` breaks the established sidecar contract
  without improving provenance.
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

## Live canary discovery observations (20 and 27 July 2026)

Three admitted records prove that portable discovery can be deterministic
without an employer-specific URL inventory:

- Greenhouse record `greenhouse:anthropic:5030244008`: the admitted hosted page
  is live and publishes the company careers route. Its board slug and numeric
  job ID also deterministically identify the official Greenhouse job API
  representation, whose genuine response carries `updated_at`.
- Ashby record `ashby:lendable:043d9c49-43e6-4a27-ad55-12344a941974`: the
  admitted hosted response contains the canonical title `Senior Frontend
  Engineer (React Native)`, JSON-LD `"datePosted":"2026-05-08"`, the employer
  URL and the employer careers route. The board slug also identifies Ashby's
  official posting API representation and its publisher date field.
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

# JAA-04 authentic authority acquisition

JAA-04 is generated output, not a hand-authored fixture. The repository does
not ship a vacancy list, response cache, publisher timestamps, or certification
receipt. An operator supplies two frozen inputs:

1. a SQLite snapshot containing exactly 58 rows admitted by Opportunity-0 in
   `employer_research_queue`; and
2. a reviewed `jaa04.authority-plan.v1` JSON document selecting 30 of those
   exact `job_key`, vacancy URL, employer and role tuples.

Each selected record has five `sources`, one for each of `company`, `product`,
`role`, `hiring`, and `operational_health`. A source entry contains only
locator/classification data: `kind`, `url`, `source_type`,
`canonical_publisher`, `canonical_article` (the expected canonical final URL),
`relevance_terms`, and `requires_current`. It must not contain response bytes,
HTTP results, publisher date values, or retrieval metadata. An optional
`excerpt_sha256` may select one reviewed excerpt when the authentic response
contains multiple semantically eligible passages.

Run acquisition with:

```sh
python3 scripts/rebuild_jaa04_corpus.py \
  --queue-snapshot /path/to/frozen-opportunity0.sqlite3 \
  --authority-plan /path/to/reviewed-authorities.json
```

The command copies the frozen database, removes non-selected queue rows, and
lets `EmployerResearchWorker` claim and complete every selected vacancy. Its
`SidecarAuthorityRetriever` uses the pinned production Scrapling sidecar with
HTTP, dynamic-browser, then stealth-browser fallback. It rejects inaccessible
responses, non-public or publisher-escaping URLs, vacancy identity changes,
duplicate URLs/bodies/articles, purpose/source-type mismatches, and evidence
that does not mention the admitted employer or support its assigned purpose.

Raw response bytes are stored by SHA-256. Citations preserve requested and
final URL, retrieval/capture time, HTTP status, redirects, response hash, cache
reference, and retrieval engine. Publisher dates are parsed only from exact
captured response fragments. Conflicting values are ambiguous and therefore
unknown. Unknown dates cannot pass a `requires_current` gate and can only
produce `unknown` freshness for non-time-sensitive company/product evidence.

Publication is atomic: no destination appears unless all 30 dossiers validate.
The capture receipt binds the queue snapshot, reviewed locator plan, manifest,
dossiers, raw corpus, Git commit, and tracked source-content revision. Certify
the result with:

```sh
python3 scripts/accept_jaa_04.py
```

Certification rehashes every artifact and raw response and writes one
revision-bound receipt. It refuses stale, conflicting, or tampered evidence.

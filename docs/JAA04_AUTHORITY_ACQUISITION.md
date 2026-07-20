# JAA-04 authority-acquisition contract

## Verdict

The frozen employer corpus must be built from evidence that is authoritative for the
specific claim being made. Five URLs, five response hashes or five language editions do not
constitute five authorities. The acquisition path must retrieve and interpret each source;
the capture plan may locate evidence but may not author its facts, dates or excerpts.

## Required authority by purpose

| Purpose | Accepted evidence | Rejected substitutes |
|---|---|---|
| company | employer-owned About/company page; regulator company record | article renamed as a company source |
| product | employer-owned product/service documentation | generic company biography with no product evidence |
| role | one currently published official vacancy or public ATS posting | company profile, search result or careers landing page |
| hiring | official careers index or public ATS board proving current hiring | an old advert or a role source copied under another ID |
| operational health | dated regulator filing, official results release or dated operational report | retrieval time, undated profile, historical paragraph labelled current |

The five final canonical URL paths and captured bodies must be distinct. Different language,
query or fragment variants of one publication are aliases and must fail.

## Recommended executable route

Use a reviewed cohort of employers for which all five authorities are publicly retrievable.
Prefer public ATS endpoints that publish their own timestamps:

- Greenhouse Job Board API: `https://boards-api.greenhouse.io/v1/boards/{board}/jobs/{job_id}`;
  job records contain `updated_at`.
- Ashby public job board API: `https://api.ashbyhq.com/posting-api/job-board/{board}`;
  records contain `publishedAt`.
- Lever public postings may supply official role and hiring bodies, but do not use them for a
  current claim unless the publisher supplies a verifiable publication/update time.
- SEC EDGAR submissions/filings are suitable dated operational evidence for US public
  employers. Observe SEC fair-access requirements and send a declared User-Agent.

If an employer lacks one required current authority, omit it from the reviewed cohort. Do not
fill the gap with Wikipedia or a synthetic date. The corpus needs 30 qualifying dossiers, not
30 preselected names preserved at the cost of truth.

## Capture requirements

1. Retrieve all evidence through the production Scrapling sidecar and preserve exact bytes,
   redirect chain, final URL, response status, retrieval time and SHA-256.
2. Parse HTML and structured JSON explicitly. A JSON API response must not be forced through
   an HTML `<p>` extractor.
3. Derive `published_at` and `updated_at` from the captured response body or publisher header.
   The plan may carry a deterministic extraction selector/path; it may not supply the timestamp
   value accepted as evidence.
4. Bind each selected excerpt/value to a byte range or deterministic structured-data pointer,
   plus its hash. A page title alone is not substantive employer intelligence.
5. Apply freshness from publisher time. Retrieval time records observation only and never makes
   historical evidence current.
6. Preserve the previous frozen corpus until all 30 dossiers, Opportunity-1 outputs, negative
   controls and revision-bound receipts pass atomically.

## Certification gate

The slice is not complete until both the project acceptance suite and
`test_jaa04_evidence_authority_contract.py` pass against the rebuilt frozen bytes. A code-only
path that could acquire evidence later is useful work but is not corpus certification.

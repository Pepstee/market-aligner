# UK source research and coverage

Research date: 2026-07-19

## Inclusion rule

A source is integrated when it exposes a current public API/RSS/XML feed,
employer-authorized ATS endpoint, or stable anonymous public vacancy pages; can
provide the complete job description or requirements; and can be filtered to
UK or UK-eligible remote work. The collector does not evade logins, bot
protection, robots controls or site terms. "All possible" therefore means all
validated sources found in this research that meet those constraints, not every
job website on the internet.

## Integrated sources

| Source | Access | Content captured | Notes |
|---|---|---|---|
| Greenhouse | Public employer API | Full posting | Direct employer vacancies |
| Lever | Public employer API | Full posting | Direct employer vacancies |
| SmartRecruiters | Public employer API | Full posting | Direct employer vacancies |
| Ashby | Public job-board API | Full posting and compensation | Direct employer vacancies |
| Workable | Public careers API | Full posting | Direct employer vacancies |
| Recruitee | Public careers feed | Full posting and requirements | Direct employer vacancies |
| Personio | Public employer XML feed | Full posting sections | Direct employer vacancies |
| Workday | Public per-employer CXS career transport | Full posting | Twelve configured UK-relevant employer tenants; no global Workday index exists |
| NHS Jobs | Public candidate search and advert pages | Full posting | Keyword discovery with full vacancy text |
| jobs.ac.uk | Public search and advert pages; RSS also available | Full posting | Academic, research-software and university technical roles |
| Guardian Jobs | Public keyword RSS | Listing excerpt; detail page currently returns empty HTTP 202 | Raw records retained but excluded from LLM processing as incomplete |
| Arbeitnow | Public API | Full posting | UK and eligible remote roles |
| Jobicy | Public API | Full posting | UK/Europe remote roles |
| Remotive | Public API | Full posting | Eligible remote roles |
| Himalayas | Public API | Full posting | Search terms plus UK eligibility |
| The Muse | Public API | Full posting | UK/eligible remote technology roles |
| We Work Remotely | Public RSS | Full posting | Eligible remote roles |
| Remote OK | Public JSON feed | Full posting | Eligible remote roles |
| Remote First Jobs | Public skill RSS | Full posting | AI, Python, data, DevOps, security and entry-level feeds |
| Adzuna | API credentials required | Full posting where supplied | Enabled with `ADZUNA_APP_ID` and `ADZUNA_APP_KEY` |
| Reed | API credentials required | Full posting/detail | Enabled with `REED_API_KEY` |
| Jooble | API credentials required | Search result text and source URL | Enabled with `JOOBLE_API_KEY` |

The active vocabulary targets AI automation, agentic/applied AI, LLM and ML,
Python/backend, MLOps, platform/cloud/security, solutions engineering and
technical product work. It intentionally includes agencies, non-software
businesses, smaller employers, graduate jobs and entry routes.

## Researched but not integrated

| Source | Reason |
|---|---|
| Indeed | No supported public job-seeker search API or full-description feed was found; automated page scraping would be brittle and access-controlled. |
| LinkedIn Jobs | No supported public job-search/full-posting API for this use case; automated scraping would require evasion or authenticated browser automation. |
| Totaljobs / CWJobs | No current public job-seeker API or complete feed was validated. |
| CV-Library | No current public job-seeker API or complete feed was validated. |
| Teamtailor | The documented API requires a token issued by each hiring company, so it cannot enumerate public jobs across employers. |
| Careerjet | API access is account/partner managed and was not validated as a public full-description job-search API. |
| Civil Service Jobs | Public vacancies are behind an interactive real-person check. |

NHS Jobs is now integrated through its public candidate search and advert
pages. Civil Service Jobs remains unavailable because its public search places
an interactive "real person" check in front of vacancies; the collector does
not bypass that control.

## Closed or access-controlled sources

These names are tracked explicitly rather than silently omitted:

| Source | Current boundary |
|---|---|
| Indeed | No supported public job-seeker search/full-description API; public automated requests are access-controlled. |
| LinkedIn Jobs | Official Jobs API is partner-authorised job *posting*, not public vacancy search. |
| Totaljobs / CWJobs | Public automated search requests currently return HTTP 403; no supported search API was validated. |
| CV-Library | Public automated search currently returns HTTP 403; no supported search API was validated. |
| Glassdoor | No current self-service vacancy-search API was validated; automated access is controlled. |
| Monster | Public automated UK search currently returns HTTP 403; no supported search API was validated. |
| Civil Service Jobs | Interactive real-person check; not bypassed. |
| Teamtailor | API token belongs to each hiring company and cannot search all tenants. |
| JobServe | RSS is tied to a saved-search account; anonymous ASP.NET search submission is rejected. |
| Technojobs | Host did not resolve during live verification; no reliable endpoint could be tested. |
| Wellfound / Welcome to the Jungle / Cord | No supported unauthenticated full-description search API validated. |

## Operational behaviour

- `max_jobs_total: 0` means no collector cap.
- Sources are discovered concurrently and postings are fetched concurrently.
- Every source record and raw response is retained in SQLite and the raw cache.
- Source polling intervals prevent wasteful repeated downloads; they do not cap
  the number of jobs.
- LLM normalization, personal fit analysis, skill counting and report creation
  run only after collection, in `scripts/process_collected_jobs.py`.

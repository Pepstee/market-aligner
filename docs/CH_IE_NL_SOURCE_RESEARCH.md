# Switzerland, Ireland and Netherlands source audit

Audit date: 19 July 2026. Scope: current, public vacancy sources relevant to
The configured candidate's AI/automation/software/platform/cloud/security/technical-solutions
tracks, including suitable roles in ordinary non-software employers.

## Method

This was not a search-engine-only inventory. Each candidate source was checked
for current listings, vacancy-detail depth, public discovery route, access from
the collector host, robots policy, requirements completeness, and overlap with
sources already collected. Sources were integrated only when the collector can
use a public, permitted route without login, private credentials, CAPTCHA
bypass, or access-control evasion.

The collection order remains:

1. Preserve every discovered URL and full raw vacancy payload in SQLite/cache.
2. Remove inaccessible/expired adverts and cross-board duplicates.
3. Apply title, seniority, geography and work-eligibility gates.
4. Send viable unique adverts, with their requirements, to the LLM judge.

## Switzerland

| Source | Coverage / live audit | Status | Implementation note |
|---|---|---|---|
| [DeveloperJobs.ch](https://developerjobs.ch/en/) | Swiss software/AI specialist; 4,080 sitemap URLs represented about 1,020 unique jobs in four languages | Integrated | `developerjobsch`; English canonical URL per vacancy, full requirements and original employer apply link |
| [Swiss Federal Jobs Portal](https://www.stelle.admin.ch/en/it-jobs-en) | Direct federal-administration source with a documented public vacancy service | Integrated | `swissfederal`; full official tasks, requirements, employer, workload, dates and SuccessFactors apply URL |
| [IT Jobs Switzerland](https://www.itjobs.ch/) | Specialist IT board; public job sitemap exposed 215 current vacancy URLs | Integrated | `itjobsch`; full JobPosting JSON-LD plus page text; 1 second pacing |
| [ITBoard](https://www.itboard.ch/) | Swiss IT specialist; public sitemap exposed 282 job URLs during audit | Integrated | `itboardch`; title-filtered discovery and full JobPosting data |
| [Swiss AI Jobs](https://swissaijob.ch/) | AI-only specialist source with current direct employer links | Integrated | `swissaijob`; all live homepage vacancies, full requirements and original apply URL |
| [jobs.ch](https://www.jobs.ch/en/) | Large JobCloud generalist source | Retained, manual/high-friction | Existing `jobsch` adapter found hundreds, but detail requests receive sustained WAF failures from this host; no bypass attempted |
| [JobScout24](https://www.jobscout24.ch/en/) | JobCloud-network generalist source; substantial overlap with jobs.ch | Retained, manual/high-friction | Existing `jobscout24`; preserved prior raw data, disabled from fast continuous polling |
| [jobup.ch](https://www.jobup.ch/en/) | French-Swiss JobCloud network | Documented overlap | Same network/access pattern as jobs.ch; adding another failing endpoint would not add reliable coverage |
| [SwissDevJobs](https://swissdevjobs.ch/) | High-value developer board with salary transparency | Blocked from collector host | Site, sitemap and RSS returned Cloudflare 403; no evasion attempted |
| [startup.ch Jobs](https://www.startup.ch/jobs) | Swiss startup ecosystem | Blocked from collector host | Jobs and sitemap returned Cloudflare 403 |
| Job-Room / arbeit.swiss | Official national employment platform | Not machine-accessible | Public app does not expose a stable crawlable vacancy feed; no private endpoints used |
| ICTjobs.ch | Small specialist/taxonomy footprint | Deferred | Public footprint is much smaller than the three new specialist sources and overlaps their job families; candidate for a later validation pass |

## Ireland

| Source | Coverage / live audit | Status | Implementation note |
|---|---|---|---|
| [JobsIreland](https://jobsireland.ie/en-US/browse-jobs) | State employment service; 4,793 live vacancies across all industries during audit | Integrated | `jobsireland`; scans the complete catalogue then applies a broad title-only technical gate, preserving non-software employers and full descriptions |
| [publicjobs](https://www.publicjobs.ie/en/job-search) | Irish public service; 282 live competitions during audit | Integrated | `publicjobsie`; full vacancy page plus all candidate-booklet PDF URLs and extracted PDF text so requirements are not lost |
| [TechJobs.ie](https://www.techjobs.ie/) | Irish technology specialist with employer application links | Already integrated | `techjobsie`; full public vacancy pages |
| [IrishJobs](https://www.irishjobs.ie/) | Major Stepstone generalist board | Access-controlled | Akamai 403 from collector host; no bypass attempted |
| Jobs.ie | Stepstone generalist network | Access-controlled / overlap | Unstable HTTP/2 responses and no reliable public job sitemap from collector host |
| NIJobs | Northern Ireland member of the same group | Access-controlled / geographic overlap | Covered partly by UK sources; no reliable public feed from this host |
| [gradireland](https://gradireland.com/careers-advice) | Graduate and early-career specialist | Public feed unavailable | Advertised sitemap path returned a non-vacancy/404 response during audit; keep on manual-watch list |
| HiringNow.ie | JavaScript job aggregator | Not integrated | robots policy disallows its API and the public HTML has no server-rendered vacancy URLs; private API not used |
| ComputerJobs.ie | Legacy specialist | Stale public footprint | WordPress sitemap exposed old editorial pages, not a current vacancy catalogue |

## Netherlands

| Source | Coverage / live audit | Status | Implementation note |
|---|---|---|---|
| [Graduate Ventures](https://jobs.graduate.nl/jobs) | Early-stage Dutch portfolio companies; public sitemap exposed about 90 live job pages | Integrated | `graduatenl`; all current roles retained for downstream fit/seniority judgment, full Getro requirements and employer apply URL |
| [AcademicTransfer](https://www.academictransfer.com/en/jobs/) | Dutch universities/research institutes; 774 current vacancy URLs in public sitemap | Integrated | `academictransfer`; relevant technical/research titles, full page requirements, required 10-second crawl delay |
| [Werken voor Nederland](https://www.werkenvoornederland.nl/vacatures) | Dutch central-government careers; 1,163 vacancy URLs in public sitemap | Integrated | `werkenvoornederland`; English and Dutch technical-title vocabulary, full requirements |
| [Magnet.me](https://magnet.me/en/opportunities) | Startup/graduate network; 27,581 opportunity URLs in advertised English sitemap | Integrated | `magnetme`; broad relevant-title discovery (about 2,100 candidates at audit), full JobPosting details, 1-second crawl delay |
| [Undutchables](https://undutchables.nl/vacancies) | International/multilingual recruitment, strong for newcomers | Integrated | `undutchables`; all 74 current sitemap vacancies retained because the catalogue is small and suitability is not reliably inferable from titles alone |
| [IamExpat Netherlands](https://www.iamexpat.nl/career/jobs-netherlands) | English-language expat roles | Already integrated | `iamexpatnl`; full structured adverts |
| [Up!Rotterdam Jobs](https://jobs.uprotterdam.com/) | Rotterdam startup ecosystem | Already integrated | `uprotterdam`; full Getro advert data and original employer URL |
| Nationale Vacaturebank | Major DPG generalist | Blocked from collector host | 403/access control; no evasion attempted |
| Intermediair | Professional DPG board | Blocked / overlapping network | Same access-control family as Nationale Vacaturebank |
| DevITJobs Netherlands | Developer specialist | Blocked from collector host | Cloudflare 403 on site, RSS and sitemap |
| Together Abroad | International candidates | Dormant at audit | Public job route reported no current jobs |
| Techleap jobs | Startup ecosystem brand | Very small direct careers page | Public sitemap exposed only a handful of Techleap's own vacancies, not a broad ecosystem board |
| Dutch Startup Jobs | Startup specialist | Inaccessible | TLS/site failure from collector host during audit |
| [I amsterdam Job Search](https://www.iamsterdam.com/en/live-work-study/work/job-search) | Large English-language discovery page | Documented, not ingested | Current results are outbound LinkedIn summaries; the page does not provide complete vacancy requirements, so ingestion would violate the full-text rule |
| Dutch Tech Jobs | Startup/scale-up specialist | Dormant public catalogue | Current advertised sitemap contains only its home and contact pages, not crawlable vacancy pages |

## Intentionally not scraped

- LinkedIn and Indeed are useful human-facing discovery products but do not
  offer this project a permitted public bulk vacancy feed. The collector does
  not imitate logged-in sessions or bypass anti-bot controls.
- EURES offers cross-border search, but its terms and technical surface are not
  treated as permission for bulk scraping. Direct national/employer sources are
  preferred and deduplicated downstream.
- Any source marked blocked remains in this matrix so missing coverage stays
  visible and can be revisited through an official feed or human export later.

## Net change

Twelve adapters were added: five Swiss, two Irish, and five Dutch. Together
with the three country-specific sources already active, continuous collection
now has fifteen direct CH/IE/NL routes. Two existing high-friction Swiss
adapters remain available for manual passes, making seventeen implemented
country routes in total. The general ATS and remote sources in
the base configuration remain enabled, so this is additive rather than a
replacement.

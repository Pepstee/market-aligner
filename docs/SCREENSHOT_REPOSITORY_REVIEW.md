# Review of the screenshot repositories plus Scrapling

## Executive decision

The carousel mixes ten popular projects that solve very different problems.
Popularity is not an architectural reason to install them. For this career
automation system:

- **Crawl4AI** merits a bounded integration spike for difficult job pages and
  employer reconnaissance.
- **Scrapling** is installed in full at the audited commit and used as the
  collector's static, dynamic and stealth recovery layer. The upstream shell,
  MCP, sessions, proxies, browser hooks, CDP, spiders, adaptive parsing and
  challenge-solving features remain accessible.
- **Browser Use** merits a later, isolated spike as the last-resort application
  form adapter after deterministic ATS adapters.
- **Coolify** and **Supabase** are deferred infrastructure choices for a future
  always-on or multi-user deployment.
- **Stirling PDF** is, at most, an offline repair/OCR sidecar for unusual
  documents.
- **OpenHands, Maxun, Open WebUI, Langflow and Dify** should not enter the core
  dependency graph. Specific patterns are worth borrowing, but each platform
  duplicates too much of our auditable control plane or creates unacceptable
  security, licensing or operational surface.

Scrapling is the sole reviewed repository installed as a runtime dependency.
The selected patterns from the other projects have been implemented as local
code; see `docs/BORROWED_PATTERNS_IMPLEMENTATION.md`.

## Reproducible snapshot

Reviewed on 2026-07-19 against these exact revisions:

| Project | Canonical repository | Pinned revision | Licence reality |
|---|---|---|---|
| Coolify | [coollabsio/coolify](https://github.com/coollabsio/coolify) | [`e7dff30`](https://github.com/coollabsio/coolify/commit/e7dff30b7c998c301fd91bd169727b90c59ec291) | Apache-2.0 |
| OpenHands | [OpenHands/OpenHands](https://github.com/OpenHands/OpenHands) | [`11d4ecf`](https://github.com/OpenHands/OpenHands/commit/11d4ecf21fc144d10a614ddba63b84de5c90bfd4) | MIT core; PolyForm Free Trial under `enterprise/` |
| Maxun | [getmaxun/maxun](https://github.com/getmaxun/maxun) | [`ca3138a`](https://github.com/getmaxun/maxun/commit/ca3138a2dbc81564d16d1cf1beca2b52bef96104) | AGPL-3.0 |
| Open WebUI | [open-webui/open-webui](https://github.com/open-webui/open-webui) | [`ecd48e2`](https://github.com/open-webui/open-webui/commit/ecd48e2f718220a6400ecf49eafd4867a38feb10) | Current custom Open WebUI licence; historical files have other licences |
| Browser Use | [browser-use/browser-use](https://github.com/browser-use/browser-use) | [`950eb03`](https://github.com/browser-use/browser-use/commit/950eb03617e67548d759c02beac1ad122c6b6458) | MIT |
| Langflow | [langflow-ai/langflow](https://github.com/langflow-ai/langflow) | [`54281f7`](https://github.com/langflow-ai/langflow/commit/54281f7cef4f57de25ab0c0a69f6402f6236fbbc) | MIT |
| Supabase | [supabase/supabase](https://github.com/supabase/supabase) | [`fc72a6b`](https://github.com/supabase/supabase/commit/fc72a6b25920dce4ab012d41f9400c14ae9a72d5) | Repository Apache-2.0; bundled services retain their own licences |
| Stirling PDF | [Stirling-Tools/Stirling-PDF](https://github.com/Stirling-Tools/Stirling-PDF) | [`8b179fb`](https://github.com/Stirling-Tools/Stirling-PDF/commit/8b179fbc55d7bb912c98bec5423ed268b042b9dc) | Open-core: MIT only outside named restricted directories |
| Crawl4AI | [unclecode/crawl4ai](https://github.com/unclecode/crawl4ai) | [`7e80152`](https://github.com/unclecode/crawl4ai/commit/7e801521428ee12509994d39151006f64055ebe3) | Apache-2.0 metadata plus an appended attribution requirement |
| Dify | [langgenius/dify](https://github.com/langgenius/dify) | [`5ea884f`](https://github.com/langgenius/dify/commit/5ea884f799d3279655b72a4eadf804bd95dbf433) | Modified Apache-2.0 with multi-tenant and branding restrictions |
| Scrapling | [D4Vinci/Scrapling](https://github.com/D4Vinci/Scrapling) | [`5320319`](https://github.com/D4Vinci/Scrapling/commit/5320319155127519b46c0d35cc7a5037b936af05) | BSD-3-Clause |

Repository activity and popularity were checked as maturity signals, but were
not used as proof of security, correctness or suitability.

## Decision matrix

| Project | Best possible role | Value | Burden/risk | Decision |
|---|---|---:|---:|---|
| Crawl4AI | JS-heavy fetch and bounded employer-site crawling | High | Medium/high | **Integration spike now** |
| Scrapling | Resilient vacancy fetch/parsing, full browser/stealth runtime and DOM drift | High | Medium/high | **Installed in full at the audited commit** |
| Browser Use | Unsupported application-form fallback | High but narrow | High | **Conditional spike during submission work** |
| Supabase | Remote Postgres/Auth/Storage/Realtime | Medium later | High now | **Defer** |
| Coolify | VPS deployment control plane | Medium later | Very high privilege | **Defer** |
| Stirling PDF | OCR, repair and unusual conversion | Low/narrow | Medium/high | **Optional isolated sidecar only** |
| Langflow | Visual LLM flow prototyping | Medium as a design aid | High in production | **Prototype only; borrow schemas** |
| Open WebUI | Personal chat/RAG playground | Low for this system | High/duplicative | **Reject dependency; borrow patterns** |
| Dify | General AI application platform | Low for this system | Very high/licence constraints | **Reject dependency; borrow patterns** |
| OpenHands | General autonomous coding-agent platform | Low for this system | Very high/transitioning | **Reject dependency; borrow patterns** |
| Maxun | No-code recorded scraping workflows | Medium conceptually | Very high/AGPL/immature | **Reject dependency; borrow patterns** |

## 1. Coolify

### What it is

A complete self-hosted PaaS: Laravel/PHP and Livewire/Alpine/Blade control
plane, PostgreSQL, Redis, WebSockets, Nginx, workers, Docker and SSH-based
deployment. It is not a small Python deployment library.

### Relevance

Coolify could eventually host an API, worker, dashboard, Postgres and browser
sidecars on a dedicated VPS. It contributes nothing to local scraping,
profiling, scoring or application quality.

### Burden and risk

- It needs an always-on Linux host, Docker, persistent databases, backups and
  upgrades before our workloads are counted.
- The control plane has root-capable SSH and Docker authority. Its compromise
  would expose every managed service and secret.
- Docker network rules and an exposed administration surface require deliberate
  host and network policy.

### Decision

Do not add it now. For one local application, Compose plus a supervised process
is smaller and safer. Reconsider only when the system is containerised and an
always-on VPS is genuinely required. Borrow health checks, immutable image
pinning, queued deployments, rollback and deployment events.

## 2. OpenHands

### What it is now

The current repository is transitioning toward Agent Canvas, a control centre
for multiple coding-agent runtimes. The agent/runtime and Canvas source are
being split into other repositories. The legacy tree still carries a general
agent server, sandbox, secrets, event callbacks, MCP and browser support.

### Relevance

It is a general coding-agent platform, not a job collector, evidence evaluator
or reliable application-form engine. Adopting it would create a second control
plane around the typed one already being built.

### Burden and risk

- Node, Python, agent images and usually Docker/VM infrastructure.
- Its Python constraint at the reviewed revision excludes Python 3.14, which is
  used by this project's current environment.
- No-sandbox operation gives the agent host access; the supplied Compose setup
  mounts the Docker socket.
- Core and enterprise directories have different licence boundaries.
- The repository transition makes the API boundary unstable despite strong
  activity and testing.

### Decision

Reject it as a dependency. Borrow process/container isolation, explicit backend
capabilities, resumable events and short-lived/redacted secret handling.

## 3. Maxun

### What it is

A full no-code scraping product: React/Vite UI, Express/Socket.IO backend,
Playwright browser service, workflow interpreter, PostgreSQL/Graphile workers,
MinIO and scheduled robots. Its recorder turns browser interactions into
replayable workflows.

### Relevance

The recorder, typed actions, selector recovery, checkpoints and structured run
outputs are useful design ideas. The entire product is not a suitable embedded
collector or submitter.

### Burden and risk

- Frontend, backend, browser, PostgreSQL and MinIO rather than a bounded library.
- AGPL-3.0 complicates tight integration and copied code.
- The reviewed tree contained no repository tests or CI workflows and still
  identified itself as early-stage.
- The root Compose configuration ran Chromium without a sandbox, used
  `seccomp=unconfined`, granted `SYS_ADMIN` and published data-service ports.
- Source inspection found weak defaults and avoidable secret/telemetry risk.
- Recorded application flows are brittle across ATS variants and have no
  evidence or factual-validation contract.

### Decision

Reject the dependency and do not copy its code. Reimplement only the narrow
patterns we need: recorder-to-declarative-workflow compilation, multi-selector
recovery, checkpoints, partial-output preservation and typed robot results.

## 4. Open WebUI

### What it is

A large SvelteKit/FastAPI chat and model platform with users/RBAC, files,
knowledge, memories, prompts, tools, automations, analytics, SQL persistence and
many vector-store and model integrations.

### Relevance

Its hybrid BM25/vector retrieval, reranking, external knowledge connectors and
OpenTelemetry boundaries are useful references. Its chat knowledge model
cannot be the canonical evidence ledger because it does not enforce claim-level
truth or immutable evidence provenance.

### Burden and risk

- Current work uses a custom, non-OSI licence with branding restrictions.
- Tools, Functions and Pipelines intentionally execute arbitrary Python with
  backend privileges.
- A large advisory history shows both scrutiny and a broad attack surface; it
  does not imply the pinned release is currently vulnerable.
- The reviewed repository had surprisingly little committed automated-test
  coverage relative to its size.
- Scaled deployment adds PostgreSQL, Redis, object storage and a safe vector
  store.

### Decision

Do not embed or fork it. It can remain a separate personal model/RAG playground.
Borrow its OpenTelemetry layout, external-knowledge contract and hybrid
retrieval approach. Any vector index in our system is a rebuildable projection
whose records retain immutable evidence IDs.

## 5. Browser Use

### What it is

A Python agent loop around a CDP browser/session layer, DOM serializer, model
adapters, tools, filesystem, MCP and local/cloud browser backends. It genuinely
supports form filling, file upload and submission.

### Relevance

It is inefficient and irreproducible for routine collection compared with ATS
APIs, HTTP adapters, selectors or deterministic Playwright. It may be valuable
only when an unsupported application site defeats deterministic adapters.

The repository's job-application example must not be copied: it tells the model
to guess missing answers before submission, which contradicts this project's
evidence and truth policy.

### Burden and risk

- Chromium plus a broad, fast-moving Python/model dependency surface.
- Domain and IP protections exist, but the safe settings are not sufficient by
  default for our threat model.
- Anonymous telemetry is enabled by default and may include tasks, action
  history, URLs, results, errors and judge output.
- Cloud browser profiles may contain cookies, local storage, saved passwords
  and credentials.
- An LLM controlling a logged-in browser is exposed to prompt injection from
  every rendered page.

### Decision

Evaluate it later as a separate-process, unsupported-site submission adapter
with all of these mandatory controls:

- ephemeral local browser profile; cloud processing only by explicit policy;
- telemetry and profile sync disabled;
- exact hostname allowlist and private/IP destinations blocked;
- evidence-linked field values only; no guessing or autonomous improvisation;
- final submission disabled until deterministic field/fact comparison passes;
- screenshots, action log and confirmation receipt retained;
- idempotency key preventing a duplicate application;
- CAPTCHA or prohibited automation produces a blocked state, never evasion.

## 6. Langflow

### What it is

A React visual editor plus FastAPI services and a graph/component execution
engine. Flows serialize to JSON and can run behind API or MCP interfaces. It has
substantial tests and active releases.

### Relevance

It is the best orchestration-design reference in the carousel: explicit
component contracts, versioned flows, component traces and separation between
the visual development IDE and a headless runtime. Its vector knowledge base is
still not an evidence ledger.

### Burden and risk

The IDE is deliberately an arbitrary-Python execution platform with filesystem
and network access and no process-level isolation between users. Putting that
inside the career control plane would duplicate the state machine and enlarge
the attack surface. Recent critical issues also demonstrate why strict version
pinning and isolation are required.

### Decision

Do not use its engine in production. It may be used separately to prototype a
complex LLM flow, after which the accepted graph should be implemented as typed
code. Borrow versioned flow definitions and per-component trace schemas.

## 7. Supabase

### What it is

A platform assembled around PostgreSQL, Auth, PostgREST, Realtime, Storage,
GraphQL, metadata services and a gateway. Its self-hosted deployment adds
Studio, image processing, edge runtime and connection pooling.

### Relevance

It becomes relevant only if we need remote concurrent workers, browser clients,
authentication, live updates or shared object storage. The current SQLite event
ledger is simpler and adequate for a single operator.

### Burden and risk

- Self-hosting means roughly ten services and significant memory/storage, plus
  manual backups and breaking-change management.
- The default self-host configuration is not production-secure; every exposed
  table requires intentional RLS, and service keys must never reach browsers.
- Managed hosting reduces operations but moves sensitive evidence, citizenship,
  CV and application data to a processor, requiring region, retention and DPA
  decisions.

### Decision

Keep SQLite now. If shared state becomes necessary, migrate first to ordinary
managed PostgreSQL behind our application service. Adopt Supabase only when its
Auth, Storage and Realtime bundle solves specific requirements. Borrow
RLS-by-default, scoped keys, migrations and public/server API separation.

## 8. Stirling PDF

### What it is

A large Java/Spring Boot, React and desktop PDF platform providing conversion,
OCR, repair, merge/split, redaction, signing and operation pipelines. It uses
PDF libraries plus native tools such as LibreOffice and Tesseract/OCRmyPDF.

### Relevance

It is excessive for routine CV verification. `pdftotext`, `qpdf --check`, page
rendering and focused layout checks are smaller and more deterministic. It may
help with an unusual external PDF requiring OCR, repair or conversion.

### Burden and risk

- Open-core licence boundaries are easy to misunderstand; the default build
  includes restricted modules unless a core configuration is selected.
- The latest version alone receives security support, creating continuous
  upgrade work.
- Full OCR/conversion images are large and resource-heavy.
- Analytics, logs, persistent volumes and optional storage/sharing must be
  disabled or tightly controlled for CVs and personal documents.

### Decision

Reject it as a core dependency. If trialled, run an exact-digest, MIT-core,
offline sidecar with no public port, network egress, telemetry, sharing or
persistent document storage. Borrow operation manifests, multi-engine PDF tests
and licence-boundary checks.

## 9. Crawl4AI

### What it is

An asynchronous crawler around browser strategies, caching, clean
markdown/content generation and deterministic or LLM extraction strategies. It
supports bounded dispatchers, rate limiting, deep crawling, URL seeding,
sessions, virtual scrolling, screenshots and cache validation.

### Relevance

This is the clearest immediate fit:

- JS-heavy vacancy details that direct adapters cannot retrieve;
- employer career, company, engineering-blog and public-document research;
- bounded company-site crawling after the Opportunity gate;
- clean HTML/markdown normalisation before evidence extraction.

LLM extraction is optional, so the mass collection loop can remain
deterministic.

### Burden and risk

- Browser binaries and a substantial Playwright/Patchright/NLP dependency
  surface.
- Recent releases fixed serious RCE, deserialisation, SSRF/LFI, file-write and
  page-leak classes. Use the pinned-or-later patched line and treat every URL
  and output as hostile.
- The Docker API has a larger request and power surface than the in-process
  library.
- Redistribution needs licence/attribution review.

### Decision and spike contract

Adopt only after this experiment:

1. Fetch 100 representative failed/dynamic vacancies and 20 employer sites.
2. Compare completeness, latency, memory and duplicate rate with existing
   fetchers.
3. Prove deterministic mode makes no model/API calls.
4. Prove cancellation closes every page and browser session.
5. Block private addresses, redirects to private addresses and non-HTTP schemes.
6. Disable caller-supplied JavaScript and power hooks.
7. Store raw HTML and normalized markdown without altering canonical job
   identity.
8. Keep direct ATS/API adapters first; Crawl4AI is a fallback, not a replacement.

Prefer the in-process library and never expose its Docker API publicly.

## 10. Dify

### What it is

A full AI application platform with a Python API, Next.js frontend, Celery
workers/scheduler, databases, Redis, sandbox, plugin daemon, agent backend,
SSRF proxy, vector infrastructure and a large workflow/RAG system.

### Relevance

Useful architectural ideas include API/worker separation, isolated code/plugin
execution, an outbound SSRF boundary, provider interfaces and retryable trace
delivery. Adopting the platform would replace our small auditable application
with a much larger generic one.

### Burden and risk

- The reviewed Compose surface contained dozens of service/profile entries.
- Its modified licence restricts multi-tenant operation and branding. Separate
  Artiom and Hyun workspaces could intersect with the tenant restriction.
- Recent cross-tenant disclosure and SSRF advisories show why its many trust
  boundaries require continuous operational attention; they do not establish
  that the pinned release is presently vulnerable.

### Decision

Reject it as a dependency. Borrow the API-worker-sandbox-SSRF separation,
provider contracts and durable trace-retry mechanics.

## 11. Scrapling

### What it is

Scrapling is a typed Python parser, fetcher and asynchronous spider framework.
Its small parser core is separated from optional `curl_cffi`, Playwright,
Patchright, browser-fingerprint and MCP dependencies. It supports static and
dynamic sessions, request fingerprints, per-domain concurrency, robots rules,
cache/checkpoint state, crawl statistics and stored element fingerprints that
can relocate a selector after a page structure changes.

### Relevance

It is a strong candidate for two narrow problems:

- a deterministic fallback when a public vacancy page defeats the board's
  direct API/HTML adapter; and
- recovery from harmless DOM drift without asking an LLM to rediscover a
  selector.

It complements rather than replaces Crawl4AI. Scrapling is the better initial
candidate for vacancy fetching and resilient selectors; Crawl4AI remains the
better candidate for bounded employer-site exploration and clean
Markdown/content projection. Both must be benchmarked against the existing
direct adapters, which stay first.

### Burden and risk

- The project declares beta status and supports Python through 3.13, while the
  current control-plane environment is Python 3.14. Browser fetchers also pin
  Playwright/Patchright and bring browser binaries.
- Its default adaptive threshold is 40%, and equal top scores can return
  multiple elements. That is too permissive for job data or application forms.
- Spider checkpoints are deserialised with `pickle.loads`; a writable or
  attacker-controlled checkpoint is therefore a code-execution boundary.
- `robots_txt_obey` defaults to false. Our jobs must enable robots compliance
  where relevant and retain an explicit policy decision.
- The static fetcher offers a safe-redirect mode, but browser/CDP paths expose
  callable setup/action hooks, init scripts, arbitrary additional arguments
  and separate network behaviour. Our public-only URL policy must remain the
  outer boundary for every redirect and connected peer.
- Stealth headers, browser impersonation, proxy rotation, canvas/fingerprint
  changes and Cloudflare challenge solving are general-library features, not
  capabilities this career system should use. CAPTCHA, login, access denial,
  robots exclusion or explicit anti-automation terms produce a blocked state.
- No repository `SECURITY.md` was present at the pinned revision. Popularity
  and a substantial test suite are maturity signals, not a security guarantee.

### Implemented decision

The complete `scrapling[all]` distribution is installed from commit
`5320319155127519b46c0d35cc7a5037b936af05` in `.venv-scrapling` on Python
3.12. Both Playwright and Patchright Chromium assets are installed. The
collector retains direct board adapters first, then executes configurable
static, dynamic and stealth stages. The default stealth stage enables
Cloudflare challenge handling, canvas protection and WebRTC protection; all
stage kwargs pass directly to upstream Scrapling.

The sidecar protocol additionally exposes reusable static/dynamic/stealth
sessions, every static HTTP method, adaptive selector calls, custom spider
classes, proxy rotators, importable page setup/action hooks and arbitrary
extension callables. The upstream `scrapling shell`, `scrapling extract` and
`scrapling mcp` commands are available without translation. Full raw bodies,
headers, request headers, cookies, redirect history, metadata and captured XHR
responses are retained. See `docs/SCRAPLING_FULL_INTEGRATION.md`.

## Resulting architecture boundary

```text
direct ATS/API/HTTP adapters
  -> policy-controlled Scrapling/Crawl4AI acceptance fallback for difficult pages
  -> immutable raw snapshots and canonical identity
  -> deterministic viability, deduplication and Opportunity gate
  -> optional Crawl4AI employer-site reconnaissance
  -> evidence extraction, employer dossier and Opportunity-1
  -> evidence-linked application compiler and release gate
  -> deterministic ATS submission adapter
  -> isolated Browser Use fallback for unsupported forms
  -> receipts, outcomes and calibration
```

Supporting policy:

```text
SQLite event/evidence ledger remains canonical
  -> any vector index is a rebuildable evidence-ID projection
  -> every LLM/browser operation has a versioned contract and trace
  -> model-generated output never advances state directly
  -> deployment remains local until remote requirements justify migration
```

## Borrowed patterns implementation

These ideas have now been implemented locally; Scrapling is also integrated as
the complete pinned upstream runtime:

1. Open WebUI: OpenTelemetry span boundaries and hybrid retrieval.
2. Langflow: versioned flow/component definitions and component traces.
3. Dify: API-worker-sandbox-SSRF boundaries and retryable traces.
4. OpenHands: backend capability declarations, bounded process execution and
   resumable agent events.
5. Maxun: declarative recorded workflows, selector recovery and checkpoints.
6. Coolify: deployment events, health checks and rollback.
7. Supabase: RLS-style least privilege, migrations and scoped client/server
   keys.
8. Stirling PDF: isolated document processing and licence-boundary tests.
9. Scrapling: full runtime plus deterministic fetch escalation, immutable
   response provenance, element fingerprints and DOM-drift recovery.

The exact module, enforcement and test mapping is recorded in
`docs/BORROWED_PATTERNS_IMPLEMENTATION.md`.

## Next repository-specific integration action

Benchmark the installed Scrapling recovery chain against Crawl4AI on the same
failed vacancy corpus. Browser Use belongs later, when deterministic submission
adapters exist.

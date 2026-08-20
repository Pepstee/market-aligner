# Borrowed patterns implementation

## Status

The useful architectural patterns identified in the repository review are
now implemented as original, dependency-light code. No upstream code was
copied, and none of the reviewed platforms was installed.

The implementation is materialised in the existing career control-plane
database by:

```bash
python3 scripts/register_borrowed_patterns.py
```

Current registered flow:

```text
flow_id: career.application.pipeline
version: 1.1.0
hash: 2d7723e5106c0a860006f535a84555226f5ecf061d526131705539f98d10cc4b
fetch_policy_hash: 26ff2a7d537d714e4e16d08367caf8ec367e18cb9fc692257e5ed07162e439a7
```

Registration is idempotent. The live materialised job state remains unchanged.

## What was implemented

| Source pattern | Local implementation | Enforcement |
|---|---|---|
| Open WebUI observability and hybrid retrieval | `observability.py`, `retrieval.py` | Trace/span provenance; evidence-ID results only |
| Langflow versioned flows and component traces | `observability.py`, `blueprints.py` | DAG validation, immutable definitions and content hashes |
| Dify API/worker/sandbox/SSRF and retry patterns | `security.py`, `observability.py` | Public-only URL policy; leased durable outbox and dead letters |
| OpenHands capability and isolation patterns | `security.py`, `blueprints.py` | Default-deny manifests; bounded shell-free subprocess contracts |
| Maxun recorder, selector recovery and checkpoints | `browser_workflows.py` | Typed actions, ordered selectors, leases and immutable checkpoints |
| Coolify deployment events, health gates and rollback | `deployment.py` | Digest-pinned plans, external receipts, required health and rollback events |
| Supabase migrations and scoped access | `migrations.py`, `security.py` | Checksummed migrations; expiring least-privilege token scopes |
| Stirling PDF isolated operation and licence boundaries | `documents.py` | Approved licence zones, digest-pinned sidecars, no-network/privacy flags |
| Scrapling adaptive parsing and spider escalation | `fetching.py` | One-way fetch policy; immutable attempts; high-confidence, ambiguity-safe relocation |

## 1. Versioned flows and component contracts

`career_automation.observability` provides:

- immutable input/output/side-effect component contracts;
- versioned serialisable flow definitions;
- reference and cycle validation for flow DAGs;
- canonical JSON and deterministic SHA-256 content identity;
- operation traces with input/output, model, prompt, profile and flow versions;
- component spans carrying latency, cost, status and provenance;
- idempotent append-only trace events.

`career_automation.blueprints.career_pipeline_flow()` defines the real pipeline
ordering from viability through the Opportunity gate, employer research,
evidence matching, drafting, style critique, deterministic release validation
and submission. It explicitly records that probabilistic output cannot advance
state.

## 2. Durable trace delivery

The observability store includes a SQLite outbox with:

- idempotent enqueue;
- transactional claims;
- leases and unforgeable receipt tokens;
- acknowledgement without deleting the audit record;
- exponential retries;
- stale-worker and interrupted-final-attempt recovery;
- retained dead letters and explicit operator requeue.

This can later dispatch spans to OpenTelemetry or another collector without
making pipeline execution depend on collector availability.

## 3. Capability and scoped-access boundaries

`career_automation.security` implements immutable backend manifests. The
registered workers are:

- `collector`;
- `employer-research`;
- `evidence-retriever`;
- `style-critic`;
- `submission-browser`.

Resources are exact or explicit `prefix/*` scopes; general globbing and global
wildcards are rejected. Unknown backends, capabilities and resources are denied
by default.

Short-lived access tokens bind subject, resource and action. Only token hashes
are stored, expiry is mandatory, and the authority supports revocation. This is
the local equivalent of row-level least privilege, not a claim that SQLite
natively implements RLS.

## 4. SSRF and process boundaries

The outbound policy:

- permits only HTTP and HTTPS;
- rejects URL credentials, localhost, fragments and non-approved ports;
- resolves DNS through an injectable resolver;
- rejects any private, loopback, link-local, multicast, reserved or unspecified
  answer;
- validates every redirect hop;
- verifies that the connected peer was one of the validated public DNS answers.

The subprocess runner accepts argv only, never a shell string. It requires an
absolute allowlisted executable, a sanitized environment, temporary working
directory, timeout, bounded output and best-effort resource limits. It states
explicitly that it is not network isolation; network-capable workers still need
a separate OS/container boundary.

## 5. Recorded browser workflows

`career_automation.browser_workflows` stores site-specific workflows without
driving a browser itself. It includes:

- typed immutable actions;
- ordered role/label/test-ID/CSS/XPath/text selector candidates;
- deterministic selector recovery and exhaustion reports;
- stable content-addressed definitions;
- leased runs with heartbeat and expiry/reclaim;
- first-missing-step resume, so completed steps are never repeated;
- immutable partial checkpoints after every action;
- append-only, idempotent run events;
- evidence or approved-placeholder value references only—never raw guessed
  answers in workflow definitions;
- a one-use release token before the final submit action can be dispatched or
  completed; plaintext release tokens are never stored.

Site workflows will be registered only after their hostname, selectors and
submission policy have been reviewed. A generic submit workflow is deliberately
not created.

## 6. Evidence retrieval

`career_automation.retrieval` provides a rebuildable BM25 lexical projection
and optional hybridisation with externally produced semantic scores. It:

- requires unique immutable evidence IDs;
- rejects semantic scores for unknown IDs;
- returns component and combined scores;
- records a profile version and corpus hash;
- uses stable ordering.

The index is never canonical storage. A result is useful only because it points
back to an approved evidence-ledger record.

## 7. Deployment and rollback

`career_automation.deployment` records, but does not independently execute:

- immutable SHA-256-pinned release plans;
- config hashes and migration versions;
- required health-check definitions and results;
- external deployment receipts;
- health-gated promotion;
- previous-release linkage;
- audited rollback with a reason;
- idempotent deployment events.

No release becomes active merely because a deploy command returned zero.

## 8. Migrations

`career_automation.migrations` applies ordered SQLite statements and their
ledger entry in one transaction. Applied versions carry checksums; modifying an
already-applied migration fails closed. Re-running an unchanged registry is
idempotent.

## 9. Document sidecar policy

`career_automation.documents` requires:

- a pinned image digest and source revision;
- an approved licence identifier and code zone;
- network, analytics, persistence and sharing disabled;
- a read-only root filesystem;
- dropped capabilities, no-new-privileges, bounded resources and separate
  read-only input/write-only output mounts;
- multi-engine verification against the exact same artifact hash.

This makes a future OCR/repair sidecar possible without making it part of every
application or accidentally running restricted Stirling modules.

## 10. Fetch escalation and selector drift

`career_automation.fetching` is now the deterministic audit/control layer
around the complete pinned Scrapling sidecar:

- content-addressed direct-adapter -> public-HTTP -> dynamic-browser ->
  stealth-browser policy;
- bounded retries and one-way escalation driven only by classified outcomes;
- CAPTCHA and access-denial outcomes can advance to the stealth stage;
- authentication, robots exclusions, prohibited automation and explicit local
  policy failures remain deterministic stop states in the career pipeline;
- immutable attempt records containing engine, URLs, status, size, duration,
  content hash, diagnostics and raw-snapshot reference;
- persisted structural element fingerprints;
- deterministic tag/attribute/text/ancestry/sibling similarity;
- a high acceptance threshold plus a required first-versus-second margin;
- `no_match` or `ambiguous` instead of silently choosing a weak/tied element;
- immutable relocation decisions tied to the observed snapshot hash.

The upstream capability is not reduced: challenge solving, proxy rotation,
browser impersonation, page setup/action hooks, init scripts, user data
directories, CDP, XHR capture, spider checkpoints, custom storage and the
shell/MCP surfaces are all installed and callable. Pipeline policy decides
which configured capability is used for a particular job; it does not remove
capability from the runtime.

## SQLite tables added

The registration command creates these namespaced tables in the existing
career database:

```text
browser_workflow_definitions
browser_workflow_runs
browser_workflow_checkpoints
browser_workflow_events
ca_obs_flows
ca_obs_traces
ca_obs_spans
ca_obs_events
ca_obs_outbox
career_deployment_releases
career_deployment_checks
career_deployment_events
career_schema_migrations
ca_fetch_policies
ca_fetch_attempts
ca_fetch_selector_fingerprints
ca_fetch_relocations
```

These coexist with the job, event and employer-research tables. Registration
does not change a job's state or research queue.

## Remaining repository-specific integrations

1. Benchmark the installed Scrapling chain against Crawl4AI on the same failed
   pages and use evidence to choose per-source routing.
2. Build deterministic ATS submission adapters.
3. Only then test Browser Use inside the recorded-workflow and release-gate
   boundary above.

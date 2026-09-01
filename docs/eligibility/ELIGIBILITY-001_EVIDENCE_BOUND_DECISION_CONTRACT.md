# ELIGIBILITY-001: Evidence-Bound Eligibility Decision Contract

Status: R7 contract-document repair pending independent pre-write review. No source,
test, README, other-doc, Git, canonical, provider, JAA, browser, or live-state change
is made or authorized by this document alone.

## 0. Document provenance and review lineage

This section is review evidence and is normative for traceability.

| Artifact | Identity | Disposition |
|---|---|---|
| Rejected R3 draft reviewed terminally | SHA-256 `3716d062ccaa8b47c95c9825d957ccaace115acc05af103bcc2ae862ef56cd96` | REJECTED; preserved by hash |
| Pre-write working-tree variant observed at repair-session start | SHA-256 `1df368d6a7fa7649eed37fbaaac7cacd2d3e7724b7931727925d5816126d1de2` (10,890 bytes) | Superseded |
| Rejected R4 draft | 79,637 bytes, SHA-256 `dc9506cc951fbebce05a3ddcd74f4b872d09e9d7fb9a4631cfa82f524d6a6748` | REJECTED; identity-preserved (superseded in place) |
| Rejected R5 draft | 70,732 bytes, SHA-256 `d10b9b520db22744f2ce1869df0f1f7992b35438b600a063568777bf4d92f71f` | REJECTED; byte-preserved outside the repository at `.opencode-tmp-research001a/tmp/opencode/r3-evidence/R5-rejected-original.md` |
| Rejected R6 draft | 79,025 bytes, SHA-256 `a03749abee2173bbbd32e43f794816f9ec1ccc7dc61823078fbd6edd17a838d4` | REJECTED by this R7 independent pre-write review; byte-preserved outside the repository at `.opencode-tmp-research001a/tmp/opencode/r3-evidence/R6-rejected-original.md` |
| This document | R7 | Supersedes all of the above |

Standing recorded condition: the exact reviewed R3/R4 bytes were not present in the
worktree at their repair times; identities above reconcile against externally
retained artifacts. This R7 document is self-contained: two independent
implementations following it byte-for-byte produce identical envelopes, bindings,
events, receipts, database rows, stdout bytes, and decisions.

## 1. Purpose and authority boundary

ELIGIBILITY-001 adds one public deterministic evidence-bound hard-eligibility
admission path over existing Market Aligner owners. It admits one operator-staged
eligibility envelope from `data_home/state/eligibility-inbox/`, binds BOTH stored
identities of the referenced committed FIT-001 receipt (`self_hash` and
`receipt_file_sha256`) and seals that entire parsed FIT receipt inside its own
receipt, revalidates every candidate fact binding against the committed profile
evidence ledger already sealed by that FIT receipt, revalidates every vacancy fact
selector against the committed `SemanticVacancyExtraction` sealed by that same FIT
receipt, runs the pure decision owner `assess_eligibility` over exact canonical
values with UNKNOWN versus KNOWN-EMPTY set semantics preserved end-to-end, atomically
creates or exactly reuses the immutable eligibility receipt bound to its OWN
`eligibility_decided` processing event inside `data_home/state/assessments.sqlite3`,
and supports byte-identical replay.

Two operation IDs are required:

- `eligibility_operation_id`: unique to this eligibility admission;
- `fit_operation_id`: references an already-committed FIT-001 processing receipt.
  ELIGIBILITY has no bootstrap path: a committed canonical FIT graph is a hard
  precondition (sections 14.5 and 17).

The only decision tokens in this entire contract are `pass`, `review`, and `reject`.
No other token may appear as a decision anywhere.

Authority flags: `research_authority`, `application_authority`, `release_authority`,
and `submission_authority` are permanently false. `time_authenticated`,
`imported_model_policy_authenticated`, and `imported_time_authenticated` remain
false. `eligibility_authority` is true if and only if `decision == "pass"` from the
pure decision owner. No provider, model, network, browser, JAA, research, release,
application, or submission action is performed.

The still-rejected research dossier admission draft
(`docs/research/RESEARCH-001A_CITED_DOSSIER_ADMISSION_CONTRACT.md`) is neither
authorized, modified, nor rehabilitated. Section 19 states the only forward consumer
requirement. Target relabelling is impossible by construction: a referenced FIT
receipt authorizes ONLY the exact job/profile/version/track/config/database graph it
already sealed (section 14.5, S5); no receipt from one graph may authorize another.

## 2. Exact writable allowlist and single-owner rationale

The implementation authorized after terminal acceptance may modify only these paths,
each for exactly the stated purpose:

| File | Authorized modification |
|---|---|
| `src/market_aligner/assessment/eligibility.py` | Smallest authorized typed repair exactly per section 11: `EligibilityPolicy.authorised_jurisdictions` and `excluded_contract_types` become `frozenset[str] | None` so UNKNOWN (None) and KNOWN-EMPTY are distinct; route-based work-authorisation/sponsorship evaluation per the authoritative J-table; corrected experience-ceiling direction; exact-canonical comparisons (lossy `_normal` removed from decision paths). Nothing else changes. |
| `src/market_aligner/state/migrations.py` | Add one new `Migration` constant after `FIT001_PROCESSING_RECEIPTS` (section 17) plus the `eligibility_receipts` branch of `_expected_facts`. No runner change. |
| `src/market_aligner/research/store.py` | Extend generic event planning/classification so `event_type` accepts the closed set `{"processing_score_accepted", "eligibility_decided"}` via a keyword-only parameter defaulting to `"processing_score_accepted"`; preserve every C1/C1A public signature and behavior otherwise. |
| `src/market_aligner/processing.py` | Add imports, classifier/validation helpers, and the `eligibility_one` coordinator implementing sections 4–16 and 18–19. Existing FIT paths are not behaviorally altered. |
| `src/market_aligner/service/api.py` | One static `eligibility_one` seam with the typed signature `(data_home: Path, envelope_name: str, *, supplied_operation_id: str, supplied_fit_operation_id: str, supplied_config_path: str, supplied_profile_id: str, supplied_job_key: str, supplied_track: str) -> bytes`, delegating to `processing.eligibility_one` and mirroring static `process_one` without constructing the mutating service. |
| `src/market_aligner/cli.py` | An `eligibility-one` subparser whose REQUIRED options are exactly `--operation-id`, `--fit-operation-id`, `--config`, `--profile-id`, `--job-key`, `--track`, `--eligibility-envelope`, and `--data-home`, plus a handler mirroring `_process_one_command` (exact stored bytes on stdout, one canonical JSON refusal line on stderr, exit codes 0/2). |
| `README.md` | Document the new `eligibility-one` subcommand. |
| `tests/test_assessment.py` | Truth-table repair tests per section 11, including exhaustive null/empty/nonempty set cases. |
| `tests/test_process_one.py` | Focused eligibility admission tests per section 20. |
| `tests/test_migrations.py` | Migration DDL/checksum/sqlite_master/FK/index verification per sections 17 and 20. |
| `tests/test_service.py` | Service seam tests for static `eligibility_one`. |

No other production or test path may change. Single-owner rationale: there is no
parallel domain package, store, migration runner, database, or events table; the
canonical `assessments`, `assessment_events`, and `normalised_jobs` tables are reused
in place; `state/migrations.py` remains the sole schema-evolution owner;
the event extension is confined to the frozen `event_type` value domain; orchestration
lives where the retained-descriptor, read-view, recovery, and attached-transaction
machinery already lives; CLI/service mirrors keep refusal conventions and stdout
identity product-wide. Lower layers (processing, store, migrations) accept NO
caller-injected loaders, paths, or facts: every identity, node, and byte they
compare comes from the staged envelope, the CLI values, or the stored rows
themselves.

This turn is narrower still: it modifies only
`docs/eligibility/ELIGIBILITY-001_EVIDENCE_BOUND_DECISION_CONTRACT.md` and stops for
exact-byte review before any source, test, README, configuration, commit,
integration, push, fetch, provider, model, browser, JAA, live-data, release, or
submission action.

## 3. Side-effect-free preflight and SQLite mutation boundary

Before the first SQLite open, `eligibility-one` must complete operation-ID
validation, strict eligibility-envelope path/byte/schema validation, CLI identity
validation, configuration-plan validation, and staged/derived database
pathname/identity validation using retained filesystem descriptors only. At that
boundary the complete fixture tree, names, bytes, modes, links, identities, and
mtimes must remain exact.

No current `MarketAlignerService`, `ProfileStore`, `AssessmentStore`, `JobDatabase`,
`Collector`, or `MigrationRunner` constructor may run during preflight; none may
mkdir, create schema, or switch WAL during preflight, including through lazy imports.
`ProductPaths.resolve` may be used; `ProductPaths.ensure` may not.

Stable reasons 1–5 are terminal before any SQLite open and retain complete-tree
no-write. A missing configured database is never created (reason 5).

SQLite preflight opens only the exact existing databases with URI `mode=rw`, ATTACHes
the vacancy alias, and performs only SELECT and read-only PRAGMA inspection until the
run either refuses (for example a missing FIT graph, reason 7), continues to semantic
admission, or retains a provisional compatibility defect reported later as reason 13.
No journal-mode change, BEGIN, DDL, or DML happens on this path.

After the first SQLite open the guarantee is zero domain write, not zero filesystem
write: SQLite may legitimately create, rewrite, or recover `-shm`, `-wal`,
rollback-journal, super-journal, or mode metadata; tests exclude only those enumerated
artifacts and require zero DDL/DML/domain-row/receipt/timestamp/event/user-file
changes otherwise.

## 4. Owner-private filesystem contract

Real directories, current UID, mode exactly `0700`: `data_home`,
`data_home/state`, `data_home/state/eligibility-inbox` (common);
`data_home/profiles` and the selected profile directory (new-operation only).

Common input leaves, regular files, current UID, mode `0600`, nlink `1`: the
eligibility envelope leaf; `data_home/state/assessments.sqlite3`; the configured
vacancy database leaf. New-operation-only leaves (same rules): committed
`generation.json`, `profile.yaml`, `evidence.jsonl`.

Deletion/rename/corruption of profile material after success cannot block exact
replay of the IMMUTABLE stored rows; it blocks only new operations at reason 8.

Any SQLite `-journal`/`-wal`/`-shm`/super-journal observed after creation must be
current UID, regular, nlink 1, mode `0600`; post-recovery disposition must be
SQLite-clean. Tests never require premature absence.

Security claim stated honestly: retained descriptors, ownership, exact modes,
single-link checks, name/dev/ino continuity, and unkeyed SHA-256 binding give
fail-closed coherence and substitution detection, never authentication against a
malicious same-UID actor recomputing public hashes.

Resource bounds: envelope <= 1,048,576 bytes including its single LF; JSON depth
<= 32; nodes <= 10,000; each closure file <= 1,048,576; closure total <= 8,388,608;
accepted sidecars are only `<envelope_file_sha256>.json` direct inbox children;
sealed receipt <= 8,388,608 (closed proof, section 16).

## 5. Retained eligibility-envelope authority

The `--eligibility-envelope` argument denotes one filename, a direct lexical child of
`data_home/state/eligibility-inbox` matching `^[0-9a-f]{64}\.json$`; everything else
refuses at reason 2. Open root/state/inbox descriptor-relatively
(`O_DIRECTORY|O_NOFOLLOW`) via the canonical data-root seam plus `_RetainedDirectory`;
open the leaf via `_RetainedLeaf` (prestat, private-leaf proofs, bounded stable
`pread` up to maximum+1, EOF/growth/extra-byte detection). Retain everything until
refusal/replay completes or COMMIT returns. Capture `(dev,ino,uid,mode,nlink)` for
every descriptor and parent-relative name entry; re-lstat equality is required at
post-open, post-ATTACH, journal-mode setup, pre-BEGIN, in-txn pre-DML, and
immediately pre-COMMIT. Substitutions refuse or roll back. Sidecar-parent allowance:
after SQLite open the two DB parents may churn nlink legitimately (journal
create/remove); their continuity then compares `(dev,ino,uid,mode)`, type, and
name-entry dev/ino only.

Envelope leaf: strict UTF-8 canonical JSON plus exactly one LF. Duplicate keys,
nonfinite constants, invalid UTF-8, unknown/missing keys, noncanonical bytes, extra
trailing bytes, filename/hash mismatch refuse. Canonical JSON is exactly

```python
json.dumps(value, ensure_ascii=False, sort_keys=True,
           separators=(",", ":"), allow_nan=False)
```

as UTF-8. `envelope_semantic_sha256` = SHA-256 of canonical top-level JSON without
the newline; `envelope_file_sha256` = SHA-256 of the same bytes plus one LF;
filename equals `<envelope_file_sha256>.json`; neither hash is embedded in the
envelope.

## 6. Frozen constant sets (embedded, complete)

No runtime registry, locale, network, or ICU dependency exists. Four constant sets
are embedded verbatim; bytes and hashes are normative.

### 6.1 ISO-3166-1 alpha-2 uppercase jurisdiction set

Exactly the 249 officially assigned alpha-2 codes as one canonical JSON array in
ascending ASCII order, 1,246 UTF-8 bytes, no trailing newline:

```json
["AD","AE","AF","AG","AI","AL","AM","AO","AQ","AR","AS","AT","AU","AW","AX","AZ","BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN","BO","BQ","BR","BS","BT","BV","BW","BY","BZ","CA","CC","CD","CF","CG","CH","CI","CK","CL","CM","CN","CO","CR","CU","CV","CW","CX","CY","CZ","DE","DJ","DK","DM","DO","DZ","EC","EE","EG","EH","ER","ES","ET","FI","FJ","FK","FM","FO","FR","GA","GB","GD","GE","GF","GG","GH","GI","GL","GM","GN","GP","GQ","GR","GS","GT","GU","GW","GY","HK","HM","HN","HR","HT","HU","ID","IE","IL","IM","IN","IO","IQ","IR","IS","IT","JE","JM","JO","JP","KE","KG","KH","KI","KM","KN","KP","KR","KW","KY","KZ","LA","LB","LC","LI","LK","LR","LS","LT","LU","LV","LY","MA","MC","MD","ME","MF","MG","MH","MK","ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV","MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI","NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF","PG","PH","PK","PL","PM","PN","PR","PS","PT","PW","PY","QA","RE","RO","RS","RU","RW","SA","SB","SC","SD","SE","SG","SH","SI","SJ","SK","SL","SM","SN","SO","SR","SS","ST","SV","SX","SY","SZ","TC","TD","TF","TG","TH","TJ","TK","TL","TM","TN","TO","TR","TT","TV","TW","TZ","UA","UG","UM","US","UY","UZ","VA","VC","VE","VG","VI","VN","VU","WF","WS","YE","YT","ZA","ZM","ZW"]
```

`ISO_JURISDICTION_SET_SHA256` =
`bad3b0ab6d1073f237d176df4d3ec9297269c1c13c73f714c0736a87912b1523`.
Membership is EXACT uppercase byte equality with an array element. No casefold,
strip, whitespace trimming, synonym mapping, or case coercion ever makes another
spelling admissible.

### 6.2 Closed decision-token enum

Canonical JSON array, 26 UTF-8 bytes:

```json
["pass","review","reject"]
```

SHA-256 = `5739646ba9cdd477edd448e25d29de4000c8816cffb982d3ce33510953939aa3`.

### 6.3 Frozen lower-case contract-type enum

Canonical JSON array, 102 UTF-8 bytes, ascending ASCII order:

```json
["apprenticeship","contract","freelance","full_time","internship","part_time","permanent","temporary"]
```

`CONTRACT_TYPE_ENUM_SHA256` =
`8deddcbc79b7fbe7bd577e5a13c39d4a2ee20419fa33e023cb31eccf46f33ff2`.
Membership is exact lowercase byte equality. These eight tokens are the ONLY
admissible contract types, both for the vacancy fact value and for every entry of
candidate `excluded_contract_types`. Any other spelling (case, padding, hyphenated,
synonym) refuses at fact admission.

### 6.4 Fixed decision-policy body

Canonical JSON object, 329 UTF-8 bytes, no trailing newline:

```json
{"application_authority":false,"decision_tokens":["pass","review","reject"],"iso_jurisdiction_set_sha256":"bad3b0ab6d1073f237d176df4d3ec9297269c1c13c73f714c0736a87912b1523","release_authority":false,"research_authority":false,"schema_version":"market-aligner.eligibility001-fixed-decision-policy.v1","submission_authority":false}
```

`ELIGIBILITY_DECISION_POLICY_SHA256` =
`12dbb06cc16277aed00007f46eaf132fa54fb89cf211c53c7283e48c06bcb581`.
The envelope node `decision_policy.decision_policy_sha256` must equal this constant;
the implementation embeds the body and recomputes the hash locally.

## 7. Primitive validation rules

Unless stricter per field:

- integer means Python `int`, not bool; number means finite `int`/`float`, not bool;
- sha256 means exactly 64 lowercase hexadecimal characters;
- path means absolute normalized UTF-8 string length 1..4096;
- RFC3339 means timezone-aware parseable length 20..64 (strict owner rules where used);
- operation id matches `^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$`;
- profile_id matches `^prf_[0-9a-f]{32}$` exactly;
- job_key is exact `board:job`, 3..256 code points, board <= 128, job <= 256, no second colon;
- track/profile_version: plain strings 1..128;
- BLANKNESS (normative, used by sections 9–10): a code point `c` is BLANK iff
  `c` is one of U+0009, U+000A, U+000B, U+000C, U+000D, U+0020, or
  `unicodedata.category(c) == "Zs"`. A string is NONBLANK iff it contains at least
  one code point that is not BLANK;
- C0 controls and DEL reject in every string except selector `selected_value` values
  that mirror extraction prose fields (`work_authorisation` element/list items,
  `location`, `contract_type`, `description`, `required_qualifications` element),
  which additionally tolerate HT/LF/CR and nothing else. All candidate-side strings,
  ids, tokens, jurisdictions, residences, and contract values are plain;
- CANONICALITY: jurisdiction and residence values must already be exact uppercase
  section 6.1 members; contract-type values must already be exact lowercase section
  6.3 members. Admission performs NO coercion: lower-case jurisdictions, padded or
  mixed-case residences, upper-case contract tokens, synonyms, and whitespace-padded
  values refuse at schema/fact admission before the pure owner.

## 8. Exact eligibility-envelope schema

Schema version: exact `"market-aligner.eligibility-envelope.v1"`.

### 8.1 Top-level keys (exact closed set of 14)

| # | Key | Type | Nullable | Constraint |
|---|---|---|---|---|
| 1 | `schema_version` | string | no | exact literal above |
| 2 | `eligibility_operation_id` | string | no | operation-id pattern |
| 3 | `fit_operation_id` | string | no | operation-id pattern |
| 4 | `job_key` | string | no | board:job, 3..256 code points |
| 5 | `profile_id` | string | no | `prf_[0-9a-f]{32}` |
| 6 | `profile_version` | string | no | plain 1..128 |
| 7 | `track` | string | no | plain 1..128 |
| 8 | `fit_receipt_self_hash` | string | no | sha256 |
| 9 | `fit_receipt_file_sha256` | string | no | sha256 |
| 10 | `decision_policy` | object | no | exactly `{"decision_policy_sha256": sha256}` equal to section 6.4 constant |
| 11 | `config` | object | no | ConfigBinding (8.2) |
| 12 | `databases` | object | no | DatabaseBindings (8.3) |
| 13 | `candidate_facts` | object | no | CandidateFacts (section 9) |
| 14 | `vacancy_facts` | object | no | VacancyFacts (section 10) |

Missing or unknown keys refuse. Canonical-byte verification precedes field
validation.

### 8.2 ConfigBinding

Exactly: `source_path` (path), `source_file_sha256` (sha256), `closure_files`
(1..64 entries, key path/value sha256, containing `source_path` exactly once),
`closure_sha256` (SHA-256 of canonical closure_files), `semantic_sha256` (SHA-256 of
canonical merged configuration). Live re-snapshot must reproduce all exactly, and
`Collector.plan(data_home, merged)["database"]` must equal `databases.vacancy.path`
(reason 5).

### 8.3 DatabaseBindings

Exactly `assessments` and `vacancy`; each DatabaseIdentity has exactly `path`, `dev`
(int >= 0), `ino` (int > 0), `uid` (exactly `os.getuid()`), `mode` (exactly 384),
`nlink` (exactly 1). Same `dev`, distinct `ino`. `assessments.path` is exactly
`<data_home>/state/assessments.sqlite3`; `vacancy.path` is the collector-planned
database. These two are the only database bindings.

### 8.4 Cross-field rules

1. `fit_receipt_self_hash` AND `fit_receipt_file_sha256` must equal the parsed
   `self_hash` and the stored `receipt_file_sha256` of the processing_receipts row
   found by explicit `fit_operation_id`, before replay or new admission (reason 7).
   A wrong EITHER hash refuses.
2. `decision_policy.decision_policy_sha256` equals the section 6.4 constant.
3. Candidate facts cite only ledger refs; vacancy facts carry only extraction
   selectors; cross-domain sourcing is structurally impossible and serialized
   attempts refuse.
4. Filename equals SHA-256 of exact envelope bytes plus one LF.
5. ANTI-RELABELLING: the envelope's own identity fields and binding nodes must
   equal the referenced FIT receipt's parsed identities node-for-node —
   `fit_operation_id == fit_receipt.operation_id`, `profile_id ==
   fit_receipt.profile_id`, `profile_version == fit_receipt.profile_version`,
   `job_key == fit_receipt.job_key`, `track == fit_receipt.track`, and the
   complete closed nodes `config == fit_receipt.config`,
   `databases == fit_receipt.databases`. Any mismatch is stable reason
   `binding_fit_receipt` (reason 7), never reasons 4/5/6, applied before exact
   replay, before new admission, and again inside BEGIN IMMEDIATE (section 14.5
   S5).

## 9. Candidate facts (CandidateEvidenceRef family)

ALL five CandidateFacts keys are evidence-bound without exception. Each key is
either JSON `null` (fact UNKNOWN; ZERO refs) or a wrapper
`{"refs": [<CandidateEvidenceRef>, ...], "value": <fact value>}` where `refs` holds
at least ONE exact ref. There is no operator-assertion exemption and no bypass.
UNKNOWN versus KNOWN-EMPTY is preserved end-to-end: JSON `null` means the set is
unknown; a wrapper whose `value` is `[]` means a KNOWN-EMPTY set, which is itself a
non-null fact requiring refs. A status-gate downgrade of ANY fact (including an
array fact) produces UNKNOWN (`null` semantics downstream), NEVER an empty array.

### 9.1 CandidateEvidenceRef (complete object, exactly six keys)

| Field | Type | Nullable | Constraint |
|---|---|---|---|
| `evidence_id` | string | no | plain 1..256; must exist in the committed ledger bound by the FIT receipt's `evidence_ledger_sha256`; UNIQUE within its refs array |
| `kind` | string | no | plain 1..256; byte-equal to committed `EvidenceItem.kind` |
| `status` | string | no | byte-equal to committed status; statuses are exactly `verified`, `explicit`, `inference`, `unverified_current` |
| `claim_sha256` | string | no | SHA-256 of committed `EvidenceItem.claim` UTF-8 bytes |
| `source_ref_sha256` | string | no | SHA-256 of committed `EvidenceItem.source_ref` UTF-8 bytes |
| `content_sha256` | string | NO | exact lowercase 64-hex; byte-equal to the committed item's `content_sha256`, which MUST therefore be non-null; citing a ledger item whose committed `content_sha256` is null refuses at reason 8 |

Exact per-ref byte bound (`MAX_CANDIDATE_REF_BYTES` = 2359 canonical UTF-8 bytes),
derived exactly from the field maxima. A free string of L code points serializes to
at most `4*L + 2` bytes (an unescaped 4-byte UTF-8 code point such as U+10FFFF
dominates any escaped-ASCII spelling). The two free strings (`evidence_id`, `kind`,
each L <= 256) therefore contribute at most `2 * (4*256 + 2) = 2052` variable
bytes. The FIXED component is exactly 307 bytes, composed of precisely these parts:
the six QUOTED key names — 64 key characters plus 12 quote bytes = 76; the JSON
structure — six colons, five commas, two braces = 13; the quoted status literal
`"unverified_current"` = 20; and the exactly THREE quoted 64-hex values —
`claim_sha256`, `content_sha256`, and `source_ref_sha256`, there being no fourth
hex field — at 66 bytes each = 198. Total `76 + 13 + 20 + 198 = 307`; worst case
`307 + 2052 = 2359`. Every otherwise-valid ref fits; a 2,359-byte ref parses and a
2,360-byte ref refuses (reason 8). The same 2,359 value feeds the ref-mass
accounting below and the size proofs; tests assert the exact boundary and the
307/2052 split programmatically.

Total refs across the envelope <= 256, so total ref mass <= 256 x 2,359 = 603,904
canonical bytes, inside the envelope cap; the receipt copies each staged fact object
at most once (section 16).

### 9.2 CandidateFacts object (exact closed set of five keys)

| Key | Wrapper value constraint when non-null | Refs rule |
|---|---|---|
| `authorised_jurisdictions` | array of 0..249 entries, each `{"refs":[>=1],"value": <exact 6.1 member>}`; entry values unique by exact byte equality; `[]` allowed but is a KNOWN-EMPTY non-null fact | outer refs >= 1 (authorizing the set assertion itself, including emptiness); entry refs >= 1 each |
| `current_residence` | wrapper value an exact 6.1 member | >= 1 ref |
| `requires_sponsorship` | wrapper value boolean true/false | >= 1 ref (evidence-bound like every fact) |
| `maximum_years_required` | wrapper value finite number >= 0, not bool | >= 1 ref |
| `excluded_contract_types` | array of 0..8 entries, each `{"refs":[>=1],"value": <exact 6.3 member>}`, unique by exact byte equality; `[]` allowed but is a KNOWN-EMPTY non-null fact | outer refs >= 1; entry refs >= 1 each |

Schematic shape (HONESTLY NON-JSON illustration — the angle-bracket placeholders are
not valid JSON; normative shapes are the prose rules and tables above):

```text
{"refs": [<CandidateEvidenceRef>, ...],          // >=1, objects only
 "value": [ {"refs": [<CandidateEvidenceRef>, ...], "value": "<member>"}, ... ]}
```

Only JSON `null` means unknown-with-zero-refs. Each refs array contains actual
closed CandidateEvidenceRef objects with `evidence_id` unique within that array.

### 9.3 Evidence-status gate (applies to ALL five facts)

Scalar facts (whole-fact rule, unchanged): for `current_residence`,
`requires_sponsorship`, and `maximum_years_required`, if every cited ref's
committed status is in `{verified, explicit}`, the fact stands; otherwise that one
fact is downgraded to UNKNOWN — `null` semantics downstream — and the stable token
`candidate_evidence_status_unverified` enters the unknowns list (deduplicated).

ARRAY facts (`authorised_jurisdictions`, `excluded_contract_types`) are ALL-OR-NOTHING:
the entire array fact stands ONLY if EVERY outer ref AND EVERY member ref has
committed status in `{verified, explicit}`. If ANY outer or member ref is
`inference` or `unverified_current`, the WHOLE effective array fact becomes JSON
`null` — no surviving subset, no surviving member, no partial filtering, and no
null elements inside a known array may ever reach `decision_input` (members carry
no nulls by schema; a downgraded array never masquerades as KNOWN-EMPTY) — and
EXACTLY ONE `candidate_evidence_status_unverified` token is added after
deduplication. A KNOWN-EMPTY array stands only when all of its outer refs pass the
same gate. Downgrades can never authorize pass. The receipt seals the ORIGINAL
staged `candidate_facts` AND the derived effective `decision_input` (section 12.2),
making every downgrade visible and reconstructable.

## 10. Vacancy facts (VacancySourceSelector family)

Each non-null vacancy fact is exactly
`{"selector": <VacancySourceSelector>, "value": <normalized scalar>}`; null facts
have no selector.

### 10.1 VacancySourceSelector (complete object, exactly five keys)

| Field | Type | Nullable | Constraint |
|---|---|---|---|
| `extraction_field` | string | no | member of the closed combination table below |
| `item_index` | int or null | conditional | required int `0 <= i < len(field)` for list-element selection; `null` for scalars and whole-list selection |
| `selected_type` | string | no | exactly `"scalar_string"` or `"string_list"` |
| `selected_value` | string or array of string | no | mirrors the extraction field/index BYTE-FOR-BYTE |
| `selected_value_sha256` | string | no | SHA-256 of canonical JSON of `selected_value`; must verify |

### 10.2 Closed source combinations

Against the actual committed `SemanticVacancyExtraction` fields (which DO include
`required_qualifications: tuple[str, ...]`):

| extraction_field | Actual field type | selected_type | item_index rule | Usable only for |
|---|---|---|---|---|
| `work_authorisation` | `tuple[str,...]`, 0..512 prose items 1..8192 | `"scalar_string"` | int, `0 <= i < len` | `work_jurisdiction` |
| `work_authorisation` | same | `"string_list"` | `null` (whole list) | `sponsorship_available` |
| `location` | `str` 0..4096 | `"scalar_string"` | `null` | `required_residence` |
| `contract_type` | `str` 0..256 | `"scalar_string"` | `null` | `contract_type` |
| `description` | prose str 1..1,000,000 | `"scalar_string"` | `null` | `minimum_years_required` |
| `required_qualifications` | `tuple[str,...]`, 0..512 prose items 1..8192 | `"scalar_string"` | int, `0 <= i < len` | `minimum_years_required` |

Every other extraction attribute is prohibited (selector staging refuses):
`title`, `company`, `source_content_sha256`, `responsibilities`, `required_skills`,
`preferred_skills`, `preferred_qualifications`, `seniority`, `remote_policy`,
`extraction_confidence`, `unknown_fields`, `contract_version`.

Selector revalidation: against the `SemanticVacancyExtraction` rebuilt from the
embedded FIT receipt through the exact structural-mirror path — field existence,
index bounds, byte-exact `selected_value`, `selected_type`, and hash must match;
otherwise reason 9.

### 10.3 Truth-boundary rule (nonempty selected evidence)

Every non-null vacancy fact must be supported by a selector whose selected raw
evidence is SEMANTICALLY NONEMPTY; a null fact has no selector:

- scalar-string sources: after the permitted prose-control handling, the selected
  string must contain at least one NONBLANK code point (section 7 definition).
  Empty or whitespace-only selected strings REFUSE at stable reason 9;
- the sponsorship whole-list source (`work_authorisation`, `string_list`): a
  non-null selector must select a NONEMPTY list, and EVERY selected element must
  itself satisfy the same valid/nonblank string rule. An empty list, or any
  blank-element list, cannot support a non-null `sponsorship_available` fact and
  refuses at reason 9.

Exact selected bytes/hashes and the honest SAME-UID OPERATOR-STAGED normalization
boundary are preserved unchanged: the normalized value need NOT equal the raw
prose; their semantic relation is operator-staged and content-bound via the hash
chain into the sealed extraction, and NOT externally authenticated. Implementation
code may NOT derive normalized values by keywords, regexes, location inference,
casefolding, trimming, or synonym mapping.

### 10.4 Normalized types and VacancyFacts object (five keys)

| Fact | Normalized value type |
|---|---|
| `work_jurisdiction` | exact uppercase section 6.1 member |
| `required_residence` | exact uppercase section 6.1 member |
| `sponsorship_available` | boolean |
| `minimum_years_required` | finite number >= 0, not bool |
| `contract_type` | exact lowercase section 6.3 member |

VacancyFacts has exactly these five keys, each `null` or the wrapper above. Null has
no selector. No candidate fact may carry a selector; no vacancy fact may cite a
ledger `evidence_id`.

## 11. Decision semantics (exact truth table; authorized owner repairs)

Authorized `assessment/eligibility.py` repairs, smallest possible:

T1. Policy field TYPES: `EligibilityPolicy.authorised_jurisdictions:
    frozenset[str] | None` and `excluded_contract_types: frozenset[str] | None`
    (previously plain frozensets) so UNKNOWN (None) and KNOWN-EMPTY are distinct
    through the entire decision path.
T2. Route-based work-authorisation/sponsorship evaluation replacing the premature
    mismatch append (J-table authoritative), including the three UNKNOWN-set routes.
T3. Exclusion-dimension UNKNOWN handling (C-table).
T4. Corrected experience-ceiling direction (E-table).
T5. Exact-canonical comparisons: lossy `_normal` casefold/strip usage removed from
    decision comparisons; inputs arrive canonical or the run refused earlier.

Full post-repair algorithm (inputs are the effective canonical decision_input of
12.2, where both set fields may be `null`):

```text
rejects=[]; unknowns=[]
jur = work_jurisdiction                 # canonical uppercase or None
auth = authorised_jurisdictions         # frozenset | None
rs  = requires_sponsorship              # True | False | None
sa  = sponsorship_available             # True | False | None

if jur is None:
    unknowns += [work_jurisdiction_unknown]        # nothing else fabricated here
elif auth is not None and jur in auth:
    pass                                           # satisfied; sponsorship irrelevant
elif auth is not None:                             # KNOWN set without the member
    if rs is True:
        if sa is True: pass                        # explicit pass route
        elif sa is False: rejects += [sponsorship_unavailable]
        else: unknowns += [sponsorship_availability_unknown]
    elif rs is False:
        rejects += [work_authorisation_mismatch]
    else:                                          # rs None
        unknowns += [sponsorship_requirement_unknown]
else:                                              # UNKNOWN authorisations (None)
    if rs is True:
        if sa is True: pass                        # proven need authorizes the route
        elif sa is False: rejects += [sponsorship_unavailable]
        else: unknowns += [sponsorship_availability_unknown]
    elif rs is False:
        unknowns += [authorised_jurisdictions_unknown]     # never reject mismatch here
    else:                                          # rs None
        unknowns += [authorised_jurisdictions_unknown]
        unknowns += [sponsorship_requirement_unknown]

req = required_residence; cur = current_residence
if req and cur and req != cur:
    rejects += [residence_requirement_mismatch]
elif req and not cur:
    unknowns += [candidate_residence_unknown]

if minimum_years_experience is not None:
    if maximum_years_required is None:
        unknowns += [maximum_experience_ceiling_unknown]
    elif minimum_years_experience > maximum_years_required:
        rejects += [experience_requirement_exceeds_policy]

ct = contract_type; excl = excluded_contract_types  # excl: frozenset | None
if ct is None:
    pass                                           # absent vacancy contract: no dimension
elif excl is not None:
    if ct in excl: rejects += [excluded_contract_type]
    else: pass                                     # known set without it (incl. known-empty)
else:                                              # UNKNOWN exclusions
    unknowns += [excluded_contract_types_unknown]

decision = "reject" if rejects else ("review" if unknowns else "pass")
reasons  = tuple(sorted(set(rejects)))
unknowns = tuple(sorted(set(unknowns)))
```

Work-authorisation x sponsorship J-table (dominant outcome; both lists always
reported). UNKNOWN authorisations means the effective set is `null`:

| # | Vacancy jurisdiction | Authorisations | requires_sponsorship | sponsorship_available | Reject tokens | Unknown tokens |
|---|---|---|---|---|---|---|
| J1 | unknown/absent | any | any | any | – | `work_jurisdiction_unknown` only (from this domain) |
| J2 | known | KNOWN, exact match | any | any | – | – (dimension satisfied; sponsorship irrelevant) |
| J3 | known | KNOWN w/o member (incl. KNOWN-EMPTY) | true | true | – | – |
| J4 | known | KNOWN w/o member | true | false | `sponsorship_unavailable` | – |
| J5 | known | KNOWN w/o member | true | null | – | `sponsorship_availability_unknown` |
| J6 | known | KNOWN w/o member | false | any | `work_authorisation_mismatch` | – |
| J7 | known | KNOWN w/o member | null | any | – | `sponsorship_requirement_unknown` |
| J8 | known | UNKNOWN | true | true | – | – |
| J9 | known | UNKNOWN | true | false | `sponsorship_unavailable` | – |
| J10 | known | UNKNOWN | true | null | – | `sponsorship_availability_unknown` |
| J11 | known | UNKNOWN | false | any | – | `authorised_jurisdictions_unknown` |
| J12 | known | UNKNOWN | null | any | – | `authorised_jurisdictions_unknown`, `sponsorship_requirement_unknown` |

Residence table (exact canonical equality):

| # | required_residence | current_residence | Effect |
|---|---|---|---|
| R1 | stated | stated, equal | satisfied |
| R2 | stated | stated, different | reject `residence_requirement_mismatch` |
| R3 | stated | null | unknown `candidate_residence_unknown` |
| R4 | unstated | any | no requirement |

Experience-ceiling table:

| # | minimum_years_experience | maximum_years_required | Effect |
|---|---|---|---|
| E1 | unstated | any | no requirement |
| E2 | stated | `>= min` | satisfied |
| E3 | stated | `< min` | reject `experience_requirement_exceeds_policy` |
| E4 | stated | unknown | unknown `maximum_experience_ceiling_unknown` |

Excluded-contract table:

| # | contract_type | exclusions | Effect |
|---|---|---|---|
| C1 | unstated | any | no dimension, no unknown |
| C2 | stated | KNOWN set containing it | reject `excluded_contract_type` |
| C3 | stated | KNOWN set without it (incl. KNOWN-EMPTY) | satisfied |
| C4 | stated | UNKNOWN | unknown `excluded_contract_types_unknown` |

Finalization: reject > review > pass; tuples deduplicated then sorted ascending by
Unicode code point. Exact stable orders (ASCII):

- rejects: `excluded_contract_type`, `experience_requirement_exceeds_policy`,
  `residence_requirement_mismatch`, `sponsorship_unavailable`,
  `work_authorisation_mismatch`;
- unknowns: `authorised_jurisdictions_unknown`,
  `candidate_evidence_status_unverified`, `candidate_residence_unknown`,
  `excluded_contract_types_unknown`, `maximum_experience_ceiling_unknown`,
  `sponsorship_availability_unknown`, `sponsorship_requirement_unknown`,
  `work_jurisdiction_unknown`.

These two closed sets are exhaustive; no other token may ever appear.

Worked example A (normative; unchanged from R5 where still applicable). Staged/
effective: authorised `["DE"]`, residence `"DE"`, `requires_sponsorship=true`, max
years `2.0`; vacancy jurisdiction `"NL"`, sponsorship_available=false, contract
`"permanent"`, required residence `"NL"`, min years `3.0`. Effective decision_input
canonical JSON (286 bytes):

```json
{"authorised_jurisdictions":["DE"],"contract_type":"permanent","current_residence":"DE","excluded_contract_types":[],"maximum_years_required":2.0,"minimum_years_experience":3.0,"required_residence":"NL","requires_sponsorship":true,"sponsorship_available":false,"work_jurisdiction":"NL"}
```

SHA-256 = `3910fdd28eb196082fd12f5cea15a8af8dfa236b372ca0bd723decd9054f19c0`.
Routes: J4 (`sponsorship_unavailable`) + R2 + E3. Decision reject; reasons exactly
`["experience_requirement_exceeds_policy","residence_requirement_mismatch","sponsorship_unavailable"]`;
unknowns `[]`.

Worked example B (normative; UNKNOWN sets). Effective: authorised `null`,
exclusions `null`, `requires_sponsorship=null`, contract `"permanent"`, jurisdiction
`"DE"`, residence/experience/sponsorship facts unknown. Canonical decision_input
(287 bytes):

```json
{"authorised_jurisdictions":null,"contract_type":"permanent","current_residence":null,"excluded_contract_types":null,"maximum_years_required":null,"minimum_years_experience":null,"required_residence":null,"requires_sponsorship":null,"sponsorship_available":null,"work_jurisdiction":"DE"}
```

SHA-256 = `68a3ada548a12d4e0156cc157d9ab50c72e5712a850a1e3748a2661fa8b2ffb4`.
Routes: J12 + C4. Decision review; unknowns exactly
`["authorised_jurisdictions_unknown","excluded_contract_types_unknown","sponsorship_requirement_unknown"]`;
reasons `[]`.

## 12. Binding, decision input, event payload, and receipt

### 12.1 Eligibility binding

Object `market-aligner.eligibility-binding.v1`, exactly these 16 keys:
`schema_version`, `operation_id`, `fit_operation_id`, `job_key`, `profile_id`,
`profile_version`, `track`, `envelope_file_sha256`, `envelope_semantic_sha256`,
`fit_receipt_self_hash`, `fit_receipt_file_sha256`, `decision_policy_sha256`,
`config`, `databases`, `candidate_facts` (staged), `vacancy_facts` (staged).
`binding_sha256` = SHA-256 of canonical JSON of this complete object.

### 12.2 Effective decision input

Exactly these 10 keys, built ONLY from status-gate-effective, canonical values, and
PRESERVING null for unknown sets (no normalization of null to empty):
`authorised_jurisdictions` (sorted unique array when KNOWN — including `[]` for
KNOWN-EMPTY — or JSON `null` when UNKNOWN), `contract_type`,
`current_residence`, `excluded_contract_types` (same tri-state convention),
`maximum_years_required`, `minimum_years_experience`, `requires_sponsorship`
(boolean or null after gate downgrades), `required_residence`,
`sponsorship_available`, `work_jurisdiction`.
`decision_input_sha256` = SHA-256 of canonical JSON. Numbers keep JSON type. Array
facts enter exactly as gated by section 9.3: a standing array is its full sorted
unique canonical value (including `[]` for KNOWN-EMPTY); a downgraded array is
JSON `null`. No partial member subsets and no null members are ever produced.
Derived: `candidate_facts_sha256` / `vacancy_facts_sha256` = SHA-256 of canonical
JSON of the STAGED objects.

### 12.3 Event payload (`eligibility_decided`)

Event `event_type` is EXACTLY `eligibility_decided`; `actor_kind` is EXACTLY
`deterministic`. Payload schema version: exact
`"market-aligner.eligibility-decided-event.v1"`. Flat canonical JSON with EXACTLY
these 21 keys, each appearing exactly once and no others:

| # | Key | Constraint |
|---|---|---|
| 1 | `schema_version` | exact literal above |
| 2 | `operation_id` | eligibility operation id |
| 3 | `fit_operation_id` | referenced FIT operation id |
| 4 | `profile_id` | canonical profile id |
| 5 | `job_key` | exact job identity |
| 6 | `track` | 1..128 |
| 7 | `binding_sha256` | sha256 of 12.1 binding |
| 8 | `envelope_file_sha256` | sha256 |
| 9 | `fit_receipt_self_hash` | sha256, dual-bound |
| 10 | `fit_receipt_file_sha256` | sha256, dual-bound |
| 11 | `fit_assessment_event_id` | integer > 0 |
| 12 | `fit_event_payload_sha256` | sha256 from embedded FIT event node |
| 13 | `fit_normalized_json_sha256` | sha256 from embedded FIT normalised projection |
| 14 | `candidate_facts_sha256` | sha256 of staged candidate_facts canonical bytes |
| 15 | `vacancy_facts_sha256` | sha256 of staged vacancy_facts canonical bytes |
| 16 | `decision_policy_sha256` | section 6.4 constant |
| 17 | `decision_input_sha256` | sha256 of effective decision_input |
| 18 | `iso_jurisdiction_set_sha256` | section 6.1 constant |
| 19 | `decision` | pass/review/reject |
| 20 | `reasons` | array, exact sorted order |
| 21 | `unknowns` | array, exact sorted order |

`event_payload_sha256` = SHA-256 of canonical JSON of that payload, no newline.

Idempotency key (fixed-width ASCII, <= 512 UTF-8 bytes; Unicode job_key bound ONLY
through its UTF-8 SHA-256):

```text
job_key_sha256  = SHA-256(job_key.encode("utf-8")).hexdigest()
idempotency_key = "eligibility-decided:" + profile_id + ":"
                  + job_key_sha256 + ":" + event_payload_sha256
```

Prefix `"eligibility-decided:"` is 20 ASCII characters; total width is EXACTLY
`20 + 36 + 1 + 64 + 1 + 64 = 186` UTF-8 bytes. Bounds measured in UTF-8 bytes.

Event family rule: at most ONE `eligibility_decided` event per `(profile_id,
job_key)` across all operations (preserving the reused seam's <= 1-row classifier).
Zero rows permit first insertion; one row permits only exact-replay continuation;
>1 rows or any difference conflicts (reason 12). A later eligibility operation for
an already-decided job refuses reason 12 even against a different
`fit_operation_id`.

### 12.4 Complete receipt

Schema version exact `"market-aligner.eligibility-receipt.v1"`. EXACTLY these 46
top-level keys, each appearing exactly once and no others (this list is
authoritative for implementation, parser, DDL binding, and every test):

| # | Key | Constraint |
|---|---|---|
| 1 | `schema_version` | exact literal above |
| 2 | `operation_id` | eligibility operation id |
| 3 | `fit_operation_id` | referenced FIT operation id |
| 4 | `job_key` | exact job identity |
| 5 | `profile_id` | canonical profile id |
| 6 | `profile_version` | 1..128 |
| 7 | `track` | 1..128 |
| 8 | `binding_sha256` | sha256 of 12.1 binding |
| 9 | `envelope_file_sha256` | sha256 |
| 10 | `envelope_semantic_sha256` | sha256 |
| 11 | `config` | accepted ConfigBinding |
| 12 | `databases` | accepted DatabaseBindings |
| 13 | `fit_receipt` | EMBEDDED COMPLETE PARSED FIT RECEIPT OBJECT |
| 14 | `fit_receipt_self_hash` | sha256 |
| 15 | `fit_receipt_file_sha256` | sha256 |
| 16 | `fit_binding_sha256` | sha256 from embedded FIT receipt |
| 17 | `fit_assessment_event_id` | integer > 0 |
| 18 | `fit_event_payload_sha256` | sha256 |
| 19 | `fit_raw_snapshot_sha256` | sha256 |
| 20 | `fit_profile_context_sha256` | sha256 |
| 21 | `fit_extraction_output_sha256` | sha256 |
| 22 | `fit_alignment_output_sha256` | sha256 |
| 23 | `fit_normalized_json_sha256` | sha256 |
| 24 | `fit_assessment_payload_hash` | sha256 |
| 25 | `candidate_facts` | staged object |
| 26 | `vacancy_facts` | staged object |
| 27 | `candidate_facts_sha256` | sha256 of staged canonical bytes |
| 28 | `vacancy_facts_sha256` | sha256 of staged canonical bytes |
| 29 | `decision_policy_sha256` | section 6.4 constant |
| 30 | `decision_input_sha256` | sha256 of effective input |
| 31 | `iso_jurisdiction_set_sha256` | section 6.1 constant |
| 32 | `decision_input` | effective object (12.2) |
| 33 | `decision` | pass/review/reject |
| 34 | `reasons` | array, exact sorted order |
| 35 | `unknowns` | array, exact sorted order |
| 36 | `eligibility_event` | OWN EVENT NODE (below), exactly six keys |
| 37 | `created_at` | RFC3339 UTC microsecond Z |
| 38 | `time_authenticated` | exactly false |
| 39 | `imported_model_policy_authenticated` | exactly false |
| 40 | `imported_time_authenticated` | exactly false |
| 41 | `research_authority` | exactly false |
| 42 | `application_authority` | exactly false |
| 43 | `release_authority` | exactly false |
| 44 | `submission_authority` | exactly false |
| 45 | `eligibility_authority` | true iff `decision == "pass"` |
| 46 | `self_hash` | sha256 per formula below |

`eligibility_event` binds the receipt to its OWN exact `eligibility_decided` event.
EXACTLY these six FIT-compatible keys:

| Key | Constraint |
|---|---|
| `id` | positive integer; EQUALS the inserted `assessment_events.id` and the DDL `event_id` column |
| `event_type` | exactly `"eligibility_decided"` |
| `actor_kind` | exactly `"deterministic"` |
| `payload_sha256` | sha256 of the canonical 21-key payload (12.3) |
| `idempotency_key` | the fixed-width ASCII formula, exactly 186 bytes |
| `created_at` | RFC3339; EQUALS the receipt's single operation timestamp `created_at` |

Embedded `fit_receipt`: the EXACT closed processing-receipt object (all FIT-001
top-level keys INCLUDING its `self_hash`), compared byte-for-byte and
canonical-node-for-node with the referenced stored processing_receipts row
(re-sealing `canonical_json(embedded) + "\n"` must equal the stored
`receipt_bytes`). This transitively and explicitly binds the FIT config/databases/
raw/profile/extraction/alignment/scoring/normalised/assessment/event authorities.

Hash and byte formulas: `receipt_self_hash` = SHA-256 of canonical JSON of the
complete receipt with ONLY `self_hash` omitted (45-key remainder). Sealed/stored
bytes = canonical JSON of the complete receipt including `self_hash` plus exactly
one LF. `receipt_file_sha256` = SHA-256 of those sealed bytes (metadata; never
embedded). Creation stdout bytes == replay stdout bytes == the stored sealed BLOB
exactly.

Parser (`parse_eligibility_receipt`): strict loads; the closed 46-key check;
canonical-plus-LF byte identity; flag checks; FULL validation of the embedded FIT
receipt by re-sealing it to bytes and applying the complete FIT processing-receipt
parser to those bytes; ANTI-RELABELLING cross-checks — receipt top-level
`fit_operation_id`, `profile_id`, `profile_version`, `job_key`, and `track` must
EQUAL the embedded FIT receipt's `operation_id`, `profile_id`, `profile_version`,
`job_key`, and `track`, and the embedded `config`/`databases` nodes must be
canonical-node-equal to the receipt's own `config`/`databases`; verification that
every scalar FIT projection equals the corresponding node of the embedded object;
OWN-EVENT validation: rebuild the exact
21-key payload from the sealed receipt fields (every one of the 21 fields IS sealed
in the receipt — schema_version constant, ids/identities, hashes, decision,
reasons, unknowns — so the claim is sound), recompute its canonical SHA-256 and
require equality with `eligibility_event.payload_sha256`; recompute the idempotency
formula and require the exact 186-byte key; require
`eligibility_event.created_at == receipt.created_at`; require
`eligibility_event.event_type == "eligibility_decided"` and
`actor_kind == "deterministic"`; self-hash recomputation over the 45-key remainder;
cross-checks against DB columns (section 17), including
`eligibility_receipts.event_id == eligibility_event.id` and
`eligibility_receipts.event_payload_sha256 == eligibility_event.payload_sha256`.

## 13. Stable refusal precedence (numbered, with mutation classes)

Exactly one stable reason per refusal; no either/or reporting; no test may accept
two reasons. Classes: NO-WRITE, ROLLBACK, SQLITE-RECOVERY-ONLY. General rule:
reasons 1–11 detected pre-BEGIN are NO-WRITE; the same domain reason first detected
inside the open transaction keeps its number and becomes ROLLBACK.

| # | Reason token | Domain | Class |
|---|---|---|---|
| 1 | `invalid_operation_id` | operation | NO-WRITE |
| 2 | `unsafe_eligibility_envelope_path` | envelope path | NO-WRITE |
| 3 | `invalid_eligibility_envelope_bytes` | envelope bytes/schema/oversize receipt prospect | NO-WRITE |
| 4 | `binding_cli_identity` | reason-4 comparison of the SIX supplied CLI values to the staged envelope, in fixed precedence: `eligibility_operation_id`, `fit_operation_id`, `config.source_path`, `profile_id`, `job_key`, `track` (section 14.9) | NO-WRITE |
| 5 | `binding_config_database` | data-home/config-closure/database pathname+inode identity (live re-snapshot vs staged) | NO-WRITE |
| 6 | `binding_eligibility_receipt` | existing eligibility receipt classification / changed same-op binding / own-event mismatch on replay classification | NO-WRITE |
| 7 | `binding_fit_receipt` | FIT lookup/self-validation/dual-hash/embedded-byte/current-graph/raw/profile-graph binding AND the S5 anti-relabelling identity/node comparisons; includes missing ledger, missing processing_receipts, missing FIT row, or any absent-FIT precondition | NO-WRITE |
| 8 | `binding_candidate_evidence_context` | candidate refs/generation/status-gate inputs; ref shape/bounds/uniqueness/content-non-null | NO-WRITE |
| 9 | `binding_vacancy_facts` | selectors/facts vs embedded FIT extraction; canonical normalized types; TRUTH-BOUNDARY nonemptiness (blank scalars, empty/blank-element lists) | NO-WRITE |
| 10 | `binding_eligibility_policy` | fixed policy mismatch | NO-WRITE |
| 11 | `binding_decision_reconstruction` | decision-input rebuild/owner rerun mismatch | NO-WRITE pre-txn; ROLLBACK locked |
| 12 | `eligibility_target_conflict` | decided-job rule; different op on same fit target; CAS/integrity race; OWN-EVENT row drift/mismatch under lock | ROLLBACK (earlier advisory check NO-WRITE) |
| 13 | `atomic_mode_unavailable` | journal/synchronous/FK/database_list/store-shape anomalies beyond section 14.5's reason-7 states; retained provisional | SQLITE-RECOVERY-ONLY pre-BEGIN; ROLLBACK inside |
| 14 | `atomic_busy` | BUSY/LOCKED | NO-WRITE pre-open; ROLLBACK holding txn |
| 15 | `storage_full` | FULL | NO-WRITE pre-open; ROLLBACK holding txn |
| 16 | `storage_io_error` | IOERR incl. extended | NO-WRITE pre-open; ROLLBACK holding txn |
| 17 | `interrupted` | INTERRUPT/KeyboardInterrupt/catchable SIGINT/SIGTERM | class of phase |
| 18 | `recovery_incoherent` | partial/ambiguous durable state | SQLITE-RECOVERY-ONLY |

CLI mapping: exit 2, one canonical JSON line on stderr
`{"command":"eligibility-one","status":"refused","reason":...,"detail":...}` plus
`operation_id` unless reason 1; success exit 0 with exact stored sealed bytes on
stdout.

## 14. Exact algorithms

### 14.1 Paths

`--data-home` override, else `MARKET_ALIGNER_DATA_HOME`, else
`~/.local/share/market-aligner`; raw spelling audited lexically by
`open_existing_private_data_root` (normality, symlink refusal, Darwin trusted hops).
Layout via `ProductPaths.resolve`: eligibility uses root, state,
state/eligibility-inbox, profiles/<profile_id>, state/assessments.sqlite3, and the
collector-planned vacancy DB. Envelope name grammar per section 5.

### 14.2 Mode/nlink bounds

Directories real/current-UID/exact-0700 (levels per section 4); leaves
regular/current-UID/0600/nlink-1 (per section 4). Directory nlink deliberately NOT
asserted (sidecar churn); leaf nlink asserted.

### 14.3 Retained descriptors

`_RetainedDirectory`/`_RetainedLeaf`/`_DescriptorSet` reused unchanged (owned fds,
identity tuples `(dev,ino,uid,mode,nlink)`, parent-relative name-entry capture,
bounded pread reads, typed content errors, root closes LAST). Checkpoints:
post-open, post-ATTACH, post-journal-setup, pre-BEGIN, in-txn pre-DML, pre-COMMIT.

### 14.4 Read-view opening

Pin assessments under state; pin vacancy from root (reusing the state level when
first part is `state`); same dev, distinct ino; open main URI
`file://<percent-encoded-path>?mode=rw` (safe set `[A-Za-z0-9/-._~]`, uppercase
`%HH`, NUL refuses, timeout 0.05); `query_only=ON`; ATTACH vacancy alias;
`PRAGMA database_list` exactly main+vacancy with pinned paths (else 13); hot-journal
startup recovery epoch exactly as FIT (DELETE mode returned+read-back both aliases,
FULL synchronous, BEGIN IMMEDIATE, quick_check ok + foreign_key_check empty both
aliases, rollback, query_only ON, size rebase under identical strict identity,
clean double-epoch stabilization within 30 s). Error map: 5/6→14, 13→15, 10(+ext)→16,
9→17, else 13.

### 14.5 Historical classification (read-only; NO bootstrap)

On the read view inspect `main`, in order:

S1. If `market_aligner_schema_migrations` is ABSENT, or `processing_receipts` is
    ABSENT, or `assessments`/`assessment_events` are absent or non-canonical:
    refuse reason 7 immediately. NO bootstrap disposition exists.
S2. Ledger rows must be exactly
    `[(1,"fit001_processing_receipts_v1",FIT_CKSUM)]` (compatible WITHOUT v2) or
    `[(1,…),(2,"eligibility001_eligibility_receipts_v1",ELIG_CKSUM)]` (compatible
    WITH v2); anything else is a provisional atomic incompatibility (reason 13
    after earlier reasons pass).
S3. WITH-v2: `eligibility_receipts` sqlite_master SQL (normalized, `)STRICT`
    folded), PRAGMA columns/uniques/FK facts must match section 17 exactly, else
    provisional → 13. WITHOUT-v2: `eligibility_receipts` must be absent, else
    provisional → 13.
S4. WITHOUT-v2: `processing_receipts` sqlite_master/index/FK facts must match
    canonical FIT facts, else provisional → 13.

FIT binding (both states): fetch the processing_receipts row by explicit
`fit_operation_id`; absent → reason 7; parse its `receipt_bytes` with the full FIT
parser; require `parsed["self_hash"] == envelope.fit_receipt_self_hash` AND stored
`receipt_file_sha256 == envelope.fit_receipt_file_sha256` AND
`SHA-256(receipt_bytes) == receipt_file_sha256`; require the FIT event row
`assessment_events.id == parsed["assessment_event"]["id"]` to exist with matching
payload hash; require the normalized projection and assessments row behind the FIT
receipt to classify exact (byte-exact normalized_json hash; assessments row state
scored with matching score_payload_hash). ANY failure → reason 7.

S5. FIT-TARGET IDENTITY/NODE BINDING (anti-relabelling; runs in BOTH states,
    before exact-replay classification and before any new semantic admission, and
    is REPEATED inside BEGIN IMMEDIATE by section 14.8 step 6): every staged
    eligibility identity/node must equal the exact parsed FIT receipt
    node-for-node —
    - `fit_operation_id == p["operation_id"]`;
    - `profile_id == p["profile_id"]`;
    - `profile_version == p["profile_version"]`;
    - `job_key == p["job_key"]`;
    - `track == p["track"]`;
    - `config == p["config"]` as an exact closed canonical node;
    - `databases == p["databases"]` as an exact closed canonical node.
    Independently, the processing_receipts SCALAR row must equal the same parsed
    FIT operation/profile/job/track and both receipt hashes (`self_hash`,
    `receipt_file_sha256`), and the FIT assessment event row plus normalized/
    assessment projection rows must equal the parsed FIT nodes exactly as already
    required above. ANY mismatch — including a coherent config or database
    replacement whose public hashes were all recomputed — is stable reason 7
    `binding_fit_receipt`, never reason 4/5/6 and never pass/review. No receipt
    from one job/profile/version/track/config/database graph may authorize
    another.

Eligibility lookup by this operation: absent → definitive absence; present →
column-typed parse via `parse_eligibility_receipt`, full stored-column comparison,
embedded-FIT-vs-stored byte equality, AND fetch/exact-compare the OWN
`eligibility_decided` event row (`id == eligibility_event.id`, byte-equal
`event_type/actor_kind/payload_json/payload-sha/idempotency_key/created_at`);
any mismatch → reason 6. On full success → `exact_replay`.

REPLAY BOUNDARY (normative, consistent across sections 14/15/17/20): historical
replay deliberately does NOT re-read the MUTABLE CURRENT raw posting, profile.yaml,
evidence.jsonl, generation manifest, or live extraction inputs. It DOES revalidate
every immutable STORED authority: the exact FIT receipt row (bytes + dual hashes +
full parse), the embedded full FIT receipt object, the FIT assessment event row and
projection rows required by S1–S5, the exact own eligibility receipt row with its
complete stored bytes, and the exact own `eligibility_decided` event row. Read-only
replay strictly precedes any journal-mode change.

### 14.6 New-operation semantic admission

Order: (1) raw posting reread + immediate reread equality via
`read_posting(schema="vacancy")` — drift → reason 7; (2) profile generation via
`ProfileStore.open_existing(...).coherent_snapshot(require_committed_generation=
True)` verifying the five hashes recorded in the EMBEDDED FIT receipt's `profile`
node plus committed manifest/version/track — failure → reason 8; (3) candidate
facts: every ref resolves in `snapshot.evidence` with byte-equal kind/status/hashes,
`content_sha256` non-null-and-equal, `evidence_id` unique per refs array, serialized
size <= 2,359 bytes; wrapper/array shapes per section 9; canonical membership
checks; status gate computed — failure → reason 8; (4) vacancy selectors rebuilt
from the EMBEDDED FIT receipt's extraction mirror: combos/indexes/byte-exact
`selected_value`/types/hashes PLUS the section 10.3 truth-boundary nonemptiness
rules; canonical normalized types per 10.4 — failure → reason 9; (5) policy hash ==
12dbb06cc16277aed00007f46eaf132fa54fb89cf211c53c7283e48c06bcb581 with embedded body
— failure → reason 10; (6) decision reconstruction (12.2 + section 11 run) —
internal inconsistency → reason 11; (7) preflight projection planning with sentinel
timestamp `1970-01-01T00:00:00.000000Z`: eligibility event-family count (<=1 row;
violations → reason 12 advisory); (8) retained provisional reports as reason 13
only here.

### 14.7 Serialization scope

Hold `owner_private_lock()` (process-global RLock) AND `flock(LOCK_EX)` on the
retained O_DIRECTORY|O_NOFOLLOW `data_home/state` descriptor, identity-pinned around
open and re-verified after acquisition. Nothing created. Same-process exclusion via
thread lock; cross-process via flock. Release in finally. Lock failures → reason 14.

### 14.8 Attached-database transaction (ordered)

1. Locked replay reclassification: exact_replay returns stored bytes; mismatch → 6.
2. `PRAGMA query_only=OFF` (read-back 0).
3. Setup both aliases: `wal_checkpoint(TRUNCATE)` (shape (int,int,int), busy==0);
   `journal_mode=DELETE` returned AND read-back `delete`; `synchronous=FULL` read
   back 2; connection-wide `foreign_keys=ON` read-back 1; `busy_timeout=30000`
   read-back 30000; database_list recheck. Failure → 13.
4. Full authority recheck (config closure, database_list, raw reread, profile
   snapshot) — domain reasons kept.
5. `BEGIN IMMEDIATE`.
6. Inside-txn rechecks in order: replay classification again; authority recheck;
   FIT re-fetch by fit_operation_id — dual hashes and embedded-object byte equality
   re-proven (drift → 7) AND the full S5 identity/node comparison set repeated
   against the freshly parsed FIT receipt (any drift → 7); OWN eligibility event
   family recount and any existing own-event row exact-compared (drift → 12);
   target-conflict advisory (any eligibility_receipts row with same
   fit_operation_id and different operation_id, or decided-job collision → 12).
7. Generate ONE timestamp
   `datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00","Z")`
   after ALL locked rechecks; used for receipt created_at, eligibility_event
   created_at, event row created_at, and every process-owned insert (no defaults).
8. Prospective construction (section 15) BEFORE any DDL/DML.
9. Migration: registry MUST already contain exact v1 (verify-only; any v1
   absence/modification → MigrationCompatibilityError → reason 13); apply_on then
   verifies-or-creates v2 and inserts its ledger row — the ONLY newly created
   objects. Outer rollback removes v2 DDL, its ledger row, and all domain writes
   together (probe-verified, section 17).
10. Event FIRST: extended-seam plan/insert for `event_type="eligibility_decided"`;
    explicit-ID INSERT; `cursor.lastrowid == prospective_event_id` enforced; exact
    reread comparing all eight columns. Integrity race → 12.
11. Receipt LAST: single explicit 38-column INSERT — no UPDATE/UPSERT/REPLACE
    anywhere; rowcount 1; exact reread comparing every column, `event_id ==
    eligibility_event.id`, `event_payload_sha256 == eligibility_event.payload_sha256`,
    and `receipt_bytes` bytes.
12. Pre-COMMIT: full descriptor/name continuity; database_list; config re-snapshot;
    raw reread; profile snapshot revalidate.
13. COMMIT; return sealed bytes (stdout writes them verbatim).

Any post-BEGIN exception: rollback if in transaction; primary mapped reason
propagates; durable-truth recovery (section 18) decides the outcome whenever a
prospective plan existed.

### 14.9 Public command and service identity surface (exact)

The `eligibility-one` CLI accepts EXACTLY these required options and no others:

```text
market-aligner eligibility-one --operation-id <id> --fit-operation-id <id>
  --config <file> --profile-id <prf_...> --job-key <board:id> --track <track>
  --eligibility-envelope <sha256>.json --data-home <existing root>
```

The static service/coordinator signature is exactly:

```python
def eligibility_one(data_home: Path, envelope_name: str, *,
                    supplied_operation_id: str, supplied_fit_operation_id: str,
                    supplied_config_path: str, supplied_profile_id: str,
                    supplied_job_key: str, supplied_track: str) -> bytes
```

mirroring `process_one` without constructing the mutating service. Reason 4
compares EXACTLY these SIX supplied values to the staged envelope, in this fixed
precedence: `supplied_operation_id == envelope.eligibility_operation_id`,
`supplied_fit_operation_id == envelope.fit_operation_id`,
`supplied_config_path == envelope.config.source_path`,
`supplied_profile_id == envelope.profile_id`,
`supplied_job_key == envelope.job_key`,
`supplied_track == envelope.track`. The first mismatching pair reports reason 4.
Envelope-path safety remains reason 2; the data-home/config-closure/database
identity comparison remains reason 5. Only AFTER reason-4 equality does the S5
anti-relabelling binding compare the envelope against the parsed FIT receipt at
reason 7. One negative test exists per supplied value. Lower layers accept no
caller-injected loaders, paths, or facts (section 2).

## 15. Prospective construction, ID, replay/conflict rules

Inside BEGIN IMMEDIATE, after step 7, BEFORE DDL/DML:

1. `sqlite_sequence` presence/read for assessment_events exactly as the shared
   helper (absent seq → 0; malformed/out-of-range → 13); `MAX(id)` NULL → 0;
2. `prospective_event_id = max(seq, MAX(id)) + 1`; `> 9,223,372,036,854,775,807`
   refuses (13) write-free;
3. build the 21-key event payload (12.3) with `prospective_event_id` NOT yet needed
   there (payload carries no own id), compute `event_payload_sha256`, idempotency
   key (186-byte ASCII), then assemble `eligibility_event` = {id:
   prospective_event_id, event_type, actor_kind, payload_sha256, idempotency_key,
   created_at};
4. assemble the complete 46-key receipt, `self_hash`, sealed bytes;
5. size gate BEFORE DDL/DML: `len(sealed) <= 8_388_608` else rollback the
   write-free transaction, reason 3;
6. later event INSERT lastrowid must equal `prospective_event_id` exactly
   (= `eligibility_event.id`); mismatch rolls back fail-closed.

Tests: digit boundaries, seq/MAX orderings, signed-64 maximum, overflow, largest
admissible receipt, one-byte-larger refusal.

Replay/conflict (exact boundary of section 14.5 applies verbatim here): same op +
byte-identical staged binding → after revalidating the immutable stored graph (FIT
row/dual hashes/embedded object/FIT event+projections, OWN receipt bytes, OWN event
row) return the STORED sealed bytes; stdout identical to creation. Same op + any
changed binding → reason 6. Different op on same fit target → 12 after
serialization. Any attempt against a decided `(profile_id, job_key)` → 12.
Concurrent same-op processes → exactly one creator; losers get byte-identical
stored bytes or the precise precedence reason.

## 16. Receipt-size bound (closed formula)

Constants: `ENVELOPE_MAX_BYTES = 1_048_576`; `MAX_ELIGIBILITY_RECEIPT_BYTES =
8_388_608` (= DDL bound). Closed component maxima (canonical UTF-8):

| Component | Maximum | Derivation |
|---|---|---|
| Embedded `fit_receipt` canonical object | 4,194,303 | FIT sealed bytes <= 4,194,304 including one LF |
| Envelope-derived nodes (config, databases, candidate_facts incl. refs mass <= 256x2,359, vacancy_facts, identities) | 1,048,575 | entire semantic envelope minus its LF; copied at most once |
| `decision_input` | 8,192 | 10 bounded keys, tri-state arrays |
| `eligibility_event` node + scalar projections + hashes + closed-token reason/unknown arrays + skeleton keys/flags/timestamp | 20,480 | six-node event (~450) + 11x71 scalar hashes + closed token sets x <= 48 chars + key-name budget |
| Slack | 512 | rounding |
| **Total** | **5,272,062** | sum |

`5,272,062 <= 8,388,608` holds unconditionally (headroom 3,116,546), so the DDL
CHECK `CHECK(length(receipt_bytes) BETWEEN 3 AND 8388608)` can never reject an
honest receipt; runtime enforcement remains defense in depth. Boundary test:
maximal admissible envelope + maximal legal embedded FIT receipt (4,194,303-byte
canonical) seals to <= 5,272,062; synthetic 8,388,609-byte blob refused by runtime
and DDL.

## 17. Exact migration ownership, DDL, expected facts (regenerated)

`state/migrations.py` remains the sole owner; `apply_on` runs on the CALLER-owned
main connection inside the authority transaction, never connecting/mkdir/beginning/
committing/changing journals. Registry semantics (NO bootstrap): v1
(`fit001_processing_receipts_v1`, checksum
`19c0307b99175dbbfbd69ef64807a9b172c5e6abf3fa6bb117b5f43b21ce163f`) must ALREADY be
present and exact — apply_on verifies it and never recreates it; only v2 may be
newly created/inserted.

The one ELIGIBILITY migration:

- version: `2`
- name: `"eligibility001_eligibility_receipts_v1"`
- statements: one-element tuple containing EXACTLY this single-line SQL string
  (4,190 characters):

```sql
CREATE TABLE eligibility_receipts(operation_id TEXT PRIMARY KEY,fit_operation_id TEXT NOT NULL UNIQUE,profile_id TEXT NOT NULL,job_key TEXT NOT NULL,track TEXT NOT NULL,binding_sha256 TEXT NOT NULL UNIQUE,envelope_file_sha256 TEXT NOT NULL,envelope_semantic_sha256 TEXT NOT NULL,fit_receipt_self_hash TEXT NOT NULL,fit_receipt_file_sha256 TEXT NOT NULL,fit_binding_sha256 TEXT NOT NULL,fit_event_id INTEGER NOT NULL,fit_event_payload_sha256 TEXT NOT NULL,fit_raw_snapshot_sha256 TEXT NOT NULL,fit_profile_context_sha256 TEXT NOT NULL,fit_extraction_output_sha256 TEXT NOT NULL,fit_alignment_output_sha256 TEXT NOT NULL,fit_normalized_json_sha256 TEXT NOT NULL,fit_assessment_payload_hash TEXT NOT NULL,candidate_facts_sha256 TEXT NOT NULL,vacancy_facts_sha256 TEXT NOT NULL,decision_policy_sha256 TEXT NOT NULL,decision_input_sha256 TEXT NOT NULL,iso_jurisdiction_set_sha256 TEXT NOT NULL,decision TEXT NOT NULL CHECK(decision IN ('pass','review','reject')),reasons_json TEXT NOT NULL,unknowns_json TEXT NOT NULL,event_id INTEGER NOT NULL,event_payload_sha256 TEXT NOT NULL,receipt_self_hash TEXT NOT NULL,receipt_file_sha256 TEXT NOT NULL UNIQUE,receipt_bytes BLOB NOT NULL,eligibility_authority INTEGER NOT NULL CHECK(eligibility_authority=(decision='pass')),research_authority INTEGER NOT NULL CHECK(research_authority=0),application_authority INTEGER NOT NULL CHECK(application_authority=0),release_authority INTEGER NOT NULL CHECK(release_authority=0),submission_authority INTEGER NOT NULL CHECK(submission_authority=0),created_at TEXT NOT NULL,UNIQUE(profile_id,job_key),FOREIGN KEY(fit_operation_id) REFERENCES processing_receipts(operation_id) ON DELETE RESTRICT,FOREIGN KEY(fit_event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT,FOREIGN KEY(event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT,CHECK(length(binding_sha256)=64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(envelope_file_sha256)=64 AND envelope_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(envelope_semantic_sha256)=64 AND envelope_semantic_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_receipt_self_hash)=64 AND fit_receipt_self_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_receipt_file_sha256)=64 AND fit_receipt_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_binding_sha256)=64 AND fit_binding_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_event_payload_sha256)=64 AND fit_event_payload_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_raw_snapshot_sha256)=64 AND fit_raw_snapshot_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_profile_context_sha256)=64 AND fit_profile_context_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_extraction_output_sha256)=64 AND fit_extraction_output_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_alignment_output_sha256)=64 AND fit_alignment_output_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_normalized_json_sha256)=64 AND fit_normalized_json_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(fit_assessment_payload_hash)=64 AND fit_assessment_payload_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(candidate_facts_sha256)=64 AND candidate_facts_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(vacancy_facts_sha256)=64 AND vacancy_facts_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(decision_policy_sha256)=64 AND decision_policy_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(decision_input_sha256)=64 AND decision_input_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(iso_jurisdiction_set_sha256)=64 AND iso_jurisdiction_set_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(event_payload_sha256)=64 AND event_payload_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(receipt_self_hash)=64 AND receipt_self_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(receipt_file_sha256)=64 AND receipt_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(operation_id) BETWEEN 8 AND 64),CHECK(length(fit_operation_id) BETWEEN 8 AND 64),CHECK(length(profile_id)=36),CHECK(length(job_key) BETWEEN 3 AND 256),CHECK(length(track) BETWEEN 1 AND 128),CHECK(fit_event_id>0),CHECK(event_id>0),CHECK(length(reasons_json) BETWEEN 2 AND 65536),CHECK(length(unknowns_json) BETWEEN 2 AND 65536),CHECK(length(receipt_bytes) BETWEEN 3 AND 8388608),CHECK(length(created_at) BETWEEN 20 AND 64)) STRICT
```

Independently recomputable checksum (`Migration.checksum` algorithm):

```text
ELIGIBILITY_RECEIPTS_CHECKSUM = 58c47ff2441edd52f235962e61b189b1ec8c1ed5e3bc081e9305983df944f17d
```

Ledger rows after application, in order: `(1, "fit001_processing_receipts_v1",
"19c0307b…63f")` then `(2, "eligibility001_eligibility_receipts_v1",
"58c47ff2…17d")`.

Column order (EXACT 38 columns, all NOT NULL, STRICT):
1 `operation_id TEXT PK`; 2 `fit_operation_id TEXT UNIQUE`; 3 `profile_id`;
4 `job_key`; 5 `track`; 6 `binding_sha256 UNIQUE`; 7 `envelope_file_sha256`;
8 `envelope_semantic_sha256`; 9 `fit_receipt_self_hash`; 10 `fit_receipt_file_sha256`;
11 `fit_binding_sha256`; 12 `fit_event_id INTEGER`; 13 `fit_event_payload_sha256`;
14 `fit_raw_snapshot_sha256`; 15 `fit_profile_context_sha256`;
16 `fit_extraction_output_sha256`; 17 `fit_alignment_output_sha256`;
18 `fit_normalized_json_sha256`; 19 `fit_assessment_payload_hash`;
20 `candidate_facts_sha256`; 21 `vacancy_facts_sha256`; 22 `decision_policy_sha256`;
23 `decision_input_sha256`; 24 `iso_jurisdiction_set_sha256`; 25 `decision`;
26 `reasons_json`; 27 `unknowns_json`; 28 `event_id INTEGER`;
29 `event_payload_sha256` (OWN event payload hash); 30 `receipt_self_hash`;
31 `receipt_file_sha256 UNIQUE`; 32 `receipt_bytes BLOB`;
33 `eligibility_authority INTEGER`; 34 `research_authority INTEGER`;
35 `application_authority INTEGER`; 36 `release_authority INTEGER`;
37 `submission_authority INTEGER`; 38 `created_at TEXT`.

Scalar-column sources: FIT-side per section 17 of R5 carried forward verbatim
(self/file/binding/event id+payload/raw/profile-context/extraction-output/
alignment-output/normalized/assessment-payload from the parsed FIT receipt `p`),
plus OWN `event_payload_sha256` = `eligibility_event.payload_sha256` of the sealed
receipt (== recomputed 21-key payload hash).

Expected sqlite_master/PRAGMA facts (probe-executed during this authoring):
`PRAGMA table_info` reports exactly 38 columns in the order/type layout above
(`pk=1` only for `operation_id`; STRICT makes the TEXT PK report `notnull=1`);
non-partial unique indexes of origin u/c EXACTLY
`{("fit_operation_id",), ("binding_sha256",), ("receipt_file_sha256",),
("profile_id","job_key")}` (plus origin-pk `("operation_id",)`);
`PRAGMA foreign_key_list` returns EXACTLY these three rows in this SQLite-reported
order: `(0,0,'assessment_events','event_id','id','NO ACTION','RESTRICT','NONE')`,
`(1,0,'assessment_events','fit_event_id','id','NO ACTION','RESTRICT','NONE')`,
`(2,0,'processing_receipts','fit_operation_id','operation_id','NO ACTION',
'RESTRICT','NONE')`; `_expected_facts("eligibility_receipts")` mirrors columns,
these four uniques, and the FK tuple sequence
`((assessment_events,event_id,id,RESTRICT),(assessment_events,fit_event_id,id,
RESTRICT),(processing_receipts,fit_operation_id,operation_id,RESTRICT))`.

Probe results (executed against live SQLite with `PRAGMA foreign_keys=ON`, parents
present): valid pass+authority row inserts; duplicate `fit_operation_id` →
`UNIQUE constraint failed: eligibility_receipts.fit_operation_id`; duplicate
`(profile_id,job_key)` → `UNIQUE constraint failed: eligibility_receipts.profile_id,
eligibility_receipts.job_key`; missing `processing_receipts` parent for
`fit_operation_id`, missing `assessment_events` parent for `fit_event_id`, and
missing parent for own `event_id` EACH fail `FOREIGN KEY constraint failed`;
DELETE of the referenced FIT receipt row, FIT event row, or OWN event row is
RESTRICTED while a child exists; fourth decision token refused by the closed CHECK;
authority CAS refused in BOTH directions; creating v2 + its ledger row inside
BEGIN IMMEDIATE then ROLLBACK removes both together (ledger back to [v1]);
[v1] → commit creates exactly [1,2]; re-applying verifies-only (name/checksum
match, zero writes). Application-level exact comparisons (sections 14.5/14.8)
remain fully in force; the FKs/UNIQUEs are additional database-enforced ancestry,
never a replacement.

UNCHANGED-FROM-R6 PROOF: this R7 correction set (items 1–5) introduces no schema
change, so the DDL string, its 4,190-character length, checksum
`58c47ff2441edd52f235962e61b189b1ec8c1ed5e3bc081e9305983df944f17d`, 38-column
order, four uniques, three-FK pragma order, all key counts, frozen constants,
example hashes, and the 186-byte idempotency width were independently recomputed
during authoring and are byte-identical to the R6-verified values.

## 18. Locking, crash recovery, signal semantics

Locking per 14.7 (RLock + flock on retained `state` descriptor; no lock file).
Crash/catchable-signal recovery: rollback if in transaction; release connections,
descriptors, flocks, thread lock in finally where execution permits; SIGKILL/SIGSTOP/
power-loss make NO finally claim and emit nothing. Fresh reopen through SQLite's
defined recovery path (rollback-journal recovery permitted; identity immutable;
size rebased only under identical strict identity); quick_check ok +
foreign_key_check empty on BOTH aliases under DELETE+FULL with foreign_keys ON; two
identical stabilized epochs; then durable-truth classification:

- EXACT COMPLETE GRAPH = ledger rows exactly [v1,v2] canonical; exactly ONE
  `eligibility_decided` event row whose full eight columns byte-match the
  prospective plan (id, event_type, actor_kind, payload_json, idempotency_key,
  created_at, payload hash identity); exactly one eligibility_receipts row whose
  `receipt_bytes` self-validate, equal the prospective sealed bytes, whose embedded
  `eligibility_event` matches that event row exactly (id, payload_sha256,
  created_at), whose embedded `fit_receipt` re-seals byte-equal to the freshly
  refetched stored FIT receipt, whose own `event_id`/`event_payload_sha256`
  columns match, and whose top-level identities and `config`/`databases` nodes
  equal the embedded FIT receipt's per S5; no partial projections → emit STORED
  SUCCESS BYTES regardless of the caught error;
- NO own event, NO receipt, NO partial eligibility projection, v1 intact → mapped
  refusal; clean retry permitted;
- anything partial/multiple/malformed/ambiguous → reason 18; preserve evidence;
  never auto-retry; never claim success.

An error after COMMIT is never failure when recovery proves the exact committed
state; an unverified graph NEVER overrides a caught error.

## 19. Downstream consumer requirement (forward-looking only)

A future research/application consumer may rely on an ELIGIBILITY-001 receipt only
when ALL hold: `parse_eligibility_receipt` passes (including embedded-FIT,
anti-relabelling identity/node, and own-event validation); `decision == "pass"`;
`eligibility_authority is true`; the referenced FIT receipt still self-validates
against its stored row; AND the bound OWN `eligibility_decided` event row still
exists and matches the embedded `eligibility_event` exactly. Review and reject
receipts grant no downstream
authority. This states a future consumer requirement ONLY; it does not authorize or
modify the still-rejected research draft or any application/release/submission
behavior. All authority flags remain false except
`eligibility_authority=(decision=="pass")`.

## 20. Objective test matrix

### Static recomputation (no I/O)

- Recompute and assert: ISO set (249 members, 1,246 bytes, `bad3b0ab…523`);
  decision-token enum (`5739646b…aa3`); contract-type enum (102 bytes,
  `8deddcbc…ff2`); policy body (329 bytes, `12dbb06c…581`);
  `Migration.checksum` of v2 == `58c47ff2…17d` computed from the VERBATIM section 17
  statement; FIT v1 constants reproduce; DDL string equality character-for-character
  (4,190 chars); idempotency prefix `eligibility-decided:` width EXACTLY 186 bytes;
  `MAX_CANDIDATE_REF_BYTES` derivation reproduces 2,359 (quote/backslash/U+FFFF/
  U+10FFFF fills; 2,359 parses, 2,360 refuses) AND the fixed/variable split
  (307 quoted-keys+structure+status+three-hex / 2052 two free strings) is
  recomputed programmatically.
- Execute the regenerated DDL in SQLite (`foreign_keys=ON`) and assert every
  section 17 probe result: 38 columns; four uniques incl. composite; THREE FK rows
  in the exact pragma order; delete restrictions on all three parents; rollback
  removes v2 DDL+ledger together; [v1]→[v1,v2] commit; verify-only replay;
  authority CAS x2; closed decision CHECK; duplicate-fit and composite duplicates.
- Key-count assertions: envelope 14; CandidateEvidenceRef 6; CandidateFacts 5;
  VacancySourceSelector 5; VacancyFacts 5; binding 16; decision_input 10; event
  payload 21; `eligibility_event` 6; receipt 46 (definitive list, 12.4); DDL
  columns 38. Unknown/missing/duplicate keys refuse everywhere.
- Canonical-JSON parsing: EVERY ```json fenced block in this document parses with
  strict duplicate-key/nonfinite rejection; the section 9.2 schematic block is
  fenced as `text`, never as `json`.
- Whitespace hygiene: `grep -n ' $'` finds zero lines; `git diff --no-index
  --check` between the preserved R5 artifact and this file reports no whitespace
  errors.
- Worked examples A and B reproduce canonical bytes, SHA-256s, decisions, and
  exact ordered token lists.

### Decision exhaustiveness (null / empty / nonempty)

- Every J1–J12, R1–R4, E1–E4, C1–C4 row asserted with exact decision and exact
  ordered tuples, INCLUDING: KNOWN-EMPTY authorised set routing through J3–J7;
  UNKNOWN authorised set with rs=true satisfying via proven availability (J8) and
  reviewing `authorised_jurisdictions_unknown` for rs=false (J11) and both tokens
  ordered for rs=null (J12); UNKNOWN exclusions reviewing
  `excluded_contract_types_unknown` only when the vacancy contract is stated (C4).
- ARRAY STATUS-GATE semantics: a single inference/unverified_current ref among
  OUTER refs downgrades the WHOLE array to null; the same for a single bad MEMBER
  ref; mixed outer+member failures still add EXACTLY ONE token after dedup;
  KNOWN-EMPTY arrays with any failing outer ref downgrade to null; NO partial
  subset or filtered member list ever reaches `decision_input`; arrays never
  contain null members. Scalar whole-fact rule regression-tested.
- Status-gate downgrade of an ARRAY fact produces UNKNOWN (`null` semantics),
  never `[]`; decision_input preserves `null`; owner unit tests construct
  `frozenset | None` policies directly and assert T1 typing.
- Owner receives ONLY canonical values; padded/lowercase inputs never reach it
  (admission refuses first); old `_normal` behavior fails these tests.

### Selector truth-boundary

- Scalar sources: empty selected_value and whitespace-only (spaces, NBSP U+00A0,
  TAB) each refuse reason 9.
- List source: empty list refuses; list containing a blank element refuses; a valid
  NONEMPTY list of nonblank elements admits a non-null sponsorship fact (positive).
- Byte-exact `selected_value`/hash mismatches refuse; no keyword/regex/inference
  derivation exists (code inspection + negative fixtures).

### Candidate-ref shape and bounds

- Per-ref canonical size boundary: 2,359-byte ref parses; 2,360 refuses (reason 8).
- `content_sha256` non-null exact-hex and equal to a committed NON-null value;
  citing a null-content ledger item refuses reason 8.
- `evidence_id` uniqueness within each refs array; duplicated id refuses.
- Refs arrays contain closed six-key objects only; schematic text block is never
  parsed as JSON.

### FIT-precondition negatives (no bootstrap)

Missing ledger, missing processing_receipts, missing FIT row, wrong
`fit_receipt_self_hash`, wrong `fit_receipt_file_sha256`, unparsable stored FIT
bytes, missing FIT event/projection rows: EACH refuses reason 7 with zero writes.
Embedded-fit_receipt vs stored-bytes mismatch refuses. Compatible-state matrix
asserted: [v1] proceeds creating v2; [v1,v2] verifies-only; everything else →
provisional 13.

### Anti-relabelling substitution negatives (one per identity/node)

For EACH of the seven S5 comparisons — `operation_id`, `profile_id`,
`profile_version`, `job_key`, `track`, `config` node, `databases` node — a staged
envelope that differs from the parsed FIT receipt in exactly that field refuses
reason 7 (never 4/5/6) before replay classification, before new admission, and
again inside BEGIN IMMEDIATE. This includes a FULLY COHERENT config replacement
and a coherent database-graph replacement whose public hashes (`closure_sha256`,
`semantic_sha256`, dev/ino identities) were all recomputed consistently: node
inequality still refuses at reason 7. The scalar processing_receipts row and the
FIT event/projection rows each get an independent mismatch negative. A receipt
from one job/profile/version/track/config/database graph can never authorize
another.

### CLI/service identity surface negatives

One negative per supplied value — wrong `--operation-id`, wrong
`--fit-operation-id`, wrong `--config` path, wrong `--profile-id`, wrong
`--job-key`, wrong `--track` — each reports reason 4 with the fixed-precedence
first-mismatch rule; wrong envelope name → reason 2; drifted data-home/config
closure/database identity → reason 5; the option list is closed (any other flag
is an argparse error, exit 2); the coordinator signature matches section 14.9
exactly and constructs no mutating service.

### Replay boundary (item 6 conformance)

Historical replay asserts: stored FIT row + dual hashes + full embedded-FIT
byte-equality + FIT assessment event/projection rows + OWN receipt row + full
stored bytes + OWN `eligibility_decided` event row ALL revalidated; and proves NO
open/read of current mutable raw/profile/generation leaves (patch-to-explode on
those paths during replay). Damaged profile material after success does not block
replay of the immutable graph but blocks new operations at reason 8.

### Concurrency, substitution, faults, recovery

Same-op concurrency one-creator/byte-identical-loser; distinct-op same-fit → 12;
decided-job → 12; OWN-event drift under lock → 12. Descriptor substitution at every
checkpoint. Fault injection after ledger verify, v2 DDL, event insert, receipt
insert, final recheck, pre-COMMIT: v2 DDL+ledger+event+receipt roll back together;
retry succeeds. BUSY/LOCKED/FULL/IOERR(+ext)/INTERRUPT/KeyboardInterrupt/SIGINT/
SIGTERM mapped exactly. Killed child at journal/super-journal/COMMIT boundaries
recovers to all-or-nothing truth per 18 INCLUDING own-event identity; partial
states → 18. Prospective ID boundaries; lastrowid enforcement; size boundary
(<= 5,272,062 maximal; 8,388,609 refused runtime+DDL).

### Output identity and external exclusion

Creation stdout == replay stdout == stored sealed BLOB. Refusal line canonical JSON
stderr exit 2; success exit 0. Patch-and-explode: zero calls to provider, adapter,
network, subprocess, browser, JAA, research, release, application, submission
seams. Warning-strict suite + INGEST race/lock matrix + FIT suite green; py_compile,
compileall clean. Any eventual commit: author/committer exactly
`Artiom <gutu.artiom444@gmail.com>`.

## 21. Acceptance sequence

1. Independent review of THIS document's exact bytes against the R7 correction
   items 1–5 and the repository owners cited herein.
2. Terminal PASS authorizes the section 2 allowlist implementation in the same
   dedicated session.
3. Self-reports are never acceptance; independent inspection runs the section 20
   gates before integration.
4. No provider, JAA, release, submission, canonical integration, push, or live
   action is implied; final submission and legal consent remain operator-gated.

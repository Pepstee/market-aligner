# FIT-001: Evidence-Bound Process-One Contract

Status: terminally accepted pre-write contract. Source implementation remains separately review-gated.

## 1. Purpose and authority boundary

FIT-001 adds one public, deterministic, evidence-bound processing admission path over the existing Market Aligner owners. It admits one operator-staged processing envelope, revalidates every deterministic and imported binding, atomically creates or exactly reuses the normalized vacancy, assessment, single processing event, and immutable receipt, and supports byte-identical replay.

The only public surface is:

    market-aligner process-one --operation-id &lt;8..64 opaque&gt; --config &lt;file&gt; --profile-id &lt;prf_...&gt; --job-key &lt;board:id&gt; --track &lt;track&gt; --processing-envelope &lt;direct inbox file&gt; --data-home &lt;existing root&gt;

There are no provider, model, network, browser, JAA, research, release, application, submission, or arbitrary dependency-injection flags. FIT-001 creates no research gate or queue. Every receipt states:

- imported_model_policy_authenticated = false
- imported_time_authenticated = false
- research_authority = false
- application_authority = false
- release_authority = false
- submission_authority = false

Imported LLM receipt provenance is operator-staged, recorded, and hash-bound. FIT-001 authenticates neither provider/model policy nor time. No provider, model, network, browser, JAA, research, release, or submission action is performed.

## 2. Reuse map and absence finding

The implementation must extend, not duplicate, these canonical owners:

1. snapshot_config, closure_identity, and Collector.plan own configuration closure and collector database resolution.
2. JobDatabase owns postings and the sole normalised_jobs table.
3. ProfileStore and CandidateProfile own profile/evidence validation and llm_context.
4. The existing LLM contracts, accept_extraction, and accept_alignment own imported extraction/alignment contract validation.
5. score, ScoringParams, ScoreResult, and FitStatus.UNCALIBRATED own deterministic scoring.
6. MarketAlignerService and AssessmentStore own service orchestration, assessments, and assessment events.
7. The CLI and existing operation/refusal conventions own the public command and canonical stdout behavior.
8. state/migrations.py remains the sole schema-evolution owner.

Canonical inspection found no existing process-one command, processing envelope/receipt, immutable evidence-bound two-database transaction, or exact processing input-domain receipt. No duplicate collector, profile store, scorer, assessment store, gateway, database, service, or migration mechanism may be created.

## 3. Side-effect-free preflight and SQLite mutation boundary

Before the first SQLite open, process-one must complete operation-ID validation, strict processing-envelope path/byte/schema validation, CLI identity validation, configuration-plan validation, and staged/derived database pathname/identity validation using retained filesystem descriptors only. Mutable current raw posting, profile.yaml, evidence.jsonl, profile context, extraction/alignment inputs, and live projections are deliberately not validated at this common boundary. At that boundary the complete fixture tree, file names, bytes, modes, links, identities, and mtimes must remain exact.

No current MarketAlignerService, ProfileStore, AssessmentStore, JobDatabase, Collector, or MigrationRunner constructor may run during preflight. Those constructors may create directories/schema or change journal mode and therefore are forbidden on this path before admission. ProductPaths.resolve may be used; ProductPaths.ensure may not.

The common and replay paths require an already-existing private data_home, data_home/state, data_home/state/processing-inbox, the direct processing-envelope leaf, the complete configuration closure, and both configured database leaves. The profiles root, the selected profile directory, generation.json, profile.yaml, and evidence.jsonl are neither required nor opened on exact replay; they become required only after stable reasons 1 through 6 have not refused and no exact replay returned, on the definitive-absence or replay-unprovable new path at reason 8. Both configured database path entries and leaves must already exist and pass retained descriptor identity; a missing, unsafe, aliased, or mismatched path terminates binding_config_database at stable reason 5 before any SQLite open, and a missing database is never created. SQLite preflight opens only the exact existing databases with URI mode=rw so it cannot create a database, and performs only SELECT and read-only PRAGMA inspection for historical receipt classification until either definitive receipt absence in compatible storage — including an absent receipt table or migration ledger eligible for transactional bootstrap — or a replay-unprovable compatibility defect retained provisionally as atomic_mode_unavailable. This inspection performs no journal-mode change, no BEGIN, no DDL, and no DML.

After the first SQLite open, the guarantee is zero domain write, not zero filesystem write. SQLite may legitimately create, rewrite, or recover -shm, -wal, rollback-journal, super-journal, or mode metadata. Tests exclude only those enumerated SQLite-managed artifacts and metadata after the first database open; they continue to require zero DDL, DML, domain-row, receipt, timestamp, event, or user-file changes.

A hot or recovery-needed database is reopened through SQLite's defined recovery step before interpretation. Recovery mutation is permitted and audited. A clean replay may touch SQLite-managed artifacts but must not alter logical rows, receipt bytes, projection timestamps, or events.

Stable reasons 1 through 5 are terminal before any SQLite open: malformed operation, envelope path/bytes/schema, CLI identity, configuration-plan, or database pathname/identity inputs retain complete-tree no-write, and their failures never create a missing database. A SQLite open, ATTACH, SELECT, or read-only PRAGMA failure cannot continue semantic validation: BUSY and LOCKED map to atomic_busy, FULL to storage_full, IOERR and extended IOERR codes to storage_io_error, INTERRUPT and handled catchable interruption to interrupted, and every other failure to establish the exact read view to atomic_mode_unavailable, followed by the existing durable-truth recovery classification whenever a handle existed; such a failed attempt permits only legitimate SQLite-managed artifacts and runs none of the later semantics. Once both exact databases are successfully opened, subsequent raw, profile, or evidence refusals retain zero-domain-write plus zero-user-file-write with only the enumerated SQLite-managed artifact exception.

The control flow is explicit. A proven exact self-validating stored receipt whose staged candidate binding is exact returns its sealed stored bytes immediately without opening or validating current raw/profile/evidence/context/projection authorities beyond the already-completed live configuration and database admission checks. A self-validating stored receipt with a changed staged binding terminates binding_existing_receipt at reason 6 and never enters current-authority validation. If stable reasons 1 through 6 have not refused and no exact replay returned, the run continues only as definitive absence or replay-unprovable: raw snapshot validation at reason 7; require, acquire, validate, and retain the committed profile generation at reason 8; extraction, alignment, parameters, policy, and score validation at reasons 9 through 13; projection conflict at reason 14; a retained provisional incompatibility is reported as atomic_mode_unavailable only at reason 15 after every earlier semantic reason has passed.

## 4. Owner-private filesystem contract

Common and replay private directories are real, current-UID directories with mode exactly 0700:

- data_home
- data_home/state
- data_home/state/processing-inbox

New-operation-only directories, required at reason 8 after exact receipt classification, are real, current-UID directories with mode exactly 0700:

- data_home/profiles
- the selected profile directory

Common and replay input leaves are current-UID regular files with mode exactly 0600 and nlink exactly 1:

- the processing envelope
- assessments.sqlite3
- the configured vacancy database

New-operation-only input leaves, required at reason 8, are current-UID regular files with mode exactly 0600 and nlink exactly 1:

- committed generation.json; absence is permitted only for explicit non-FIT legacy_unsealed compatibility and always refuses FIT
- profile.yaml
- evidence.jsonl

Exact current-UID ownership, directory mode 0700, leaf mode 0600, and nlink 1 rules apply to each path on whichever of the two paths requires it. Deletion, rename, or corruption of the profiles root, the selected profile directory, generation.json, profile.yaml, or evidence.jsonl after a successful operation cannot block that operation's exact replay; it blocks only a new or replay-unprovable operation, terminating with binding_profile_evidence_context at reason 8.

Configuration-closure files are content/path authorities rather than claimed private secrets; they retain snapshot_config's existing regular, single-link, no-symlink rule.

ProductPaths.ensure continues to create canonical directories at 0700 for ordinary constructor paths. ProfileStore.save must create or verify its profile directory at 0700 and publish/fchmod profile.yaml, evidence.jsonl, and generation.json to 0600 under the crash-coherent generation protocol while holding the exclusive generation lock. JobDatabase, AssessmentStore, and MigrationRunner ordinary constructors may be hardened only so new parents are 0700, new databases are 0600, and unsafe existing files refuse rather than being silently chmodded. Their historical schema/WAL behavior remains for ordinary call paths; process-one never invokes those constructors during preflight and never permits them to switch its transaction databases to WAL.

config.py owns one process-global threading.RLock and owner_private_umask() context. All cooperating Market constructors, recovery scopes, and FIT transaction scopes take that shared lock, set umask 0077, and restore it in finally. This serializes cooperating Market callers only. Production process-one runs in a dedicated CLI process; same-ID production concurrency is exercised with separate processes. In-process use is supported only when every file creator cooperates with this lock. A noncooperating thread can observe the temporary restrictive umask; this is a documented compatibility limitation, not an impossible guarantee. Tests cover cooperating nested/thread exclusion and restoration, not unrelated-thread invisibility.

Any SQLite -journal, -wal, -shm, or super-journal observed after creation must be current UID, regular, nlink 1, and mode 0600. After the defined close/recovery step, its disposition must be SQLite-clean and coherent; tests must not require premature absence.

The security claim is limited honestly: retained descriptors, current-UID ownership, exact modes, single-link checks, and unkeyed SHA-256 provide fail-closed coherence and substitution detection, not authentication against a malicious same-UID actor.

## 5. Retained processing-envelope authority

The --processing-envelope argument denotes one filename only and must be a direct lexical child of data_home/state/processing-inbox. Absolute aliases, '.', '..', nested descendants, and alternate path spellings reject.

Open data_home, state, and processing-inbox descriptor-relatively with O_DIRECTORY | O_NOFOLLOW. Open the leaf relative to the retained inbox descriptor with O_RDONLY | O_NOFOLLOW. Retain every directory and file descriptor until refusal/replay completes or COMMIT returns.

Capture dev, ino, uid, mode, and nlink for every retained descriptor and every corresponding name entry. Reopen or lstat each name relative to its retained parent and require exact equality before BEGIN IMMEDIATE and immediately before COMMIT. Unlink, replacement, symlink, hardlink, ancestor substitution, inode drift, mode/owner/link drift, or an attempted alternate descendant refuses or rolls back.

The envelope leaf is named &lt;envelope_file_sha256&gt;.json. It is strict UTF-8 canonical JSON followed by exactly one newline. Duplicate keys, nonfinite numbers, bool-as-number, invalid UTF-8, unknown or missing keys, noncanonical bytes, extra trailing bytes, and filename/hash mismatch reject.

Canonical JSON is:

- ensure_ascii = false
- sort_keys = true
- separators = (",", ":")
- allow_nan = false

envelope_semantic_sha256 is SHA-256 of canonical top-level JSON without the newline. envelope_file_sha256 is SHA-256 of the same bytes plus one newline. The envelope contains neither hash, avoiding recursion. Accepted exact envelope bytes are at most 4,000,000 bytes; final receipt storability is additionally checked prospectively inside BEGIN IMMEDIATE as specified later.

## 6. Coherent profile/evidence generation

ProfileStore owns one canonical profile-scoped generation lock. ProfileStore.save takes it exclusively across the complete crash-coherent publication protocol. FIT snapshot takes it shared from before any generation or content leaf is opened through the pre-COMMIT revalidation and COMMIT.

The exact mechanism is flock on the retained current-UID 0700 profile-directory descriptor opened descriptor-relatively with O_DIRECTORY | O_NOFOLLOW. No read operation creates a lock file. Save and snapshot use the same protocol. Same-process and cross-process exclusion are required tests. The same-process harness must release and join in finally with a bounded monotonic deadline. The cross-process harness must use bounded poll/select/event readiness rather than blocking readline and must terminate/wait, then kill/wait if necessary, and close every pipe in finally.

ProfileStore.open_existing(data_home) is the public no-write owner seam for FIT. It uses ProductPaths.resolve only and performs no ensure, mkdir, chmod, schema, lock-file, or other write. FIT and every no-write test use this seam; constructing a store with __new__ is forbidden. Existing ordinary constructor behavior remains for write-owning callers.

The canonical content leaves remain:

- data_home/profiles/&lt;profile_id&gt;/profile.yaml
- data_home/profiles/&lt;profile_id&gt;/evidence.jsonl

One new same-directory coordination leaf, generation.json, is required because persistent pair-generation coherence has a distinct lifecycle and cannot be represented by either canonical content leaf. It is not candidate evidence and adds no field to the FIT ProfileBinding.

generation.json is strict canonical JSON with exactly these six keys and no others:

- schema_version: exact "market-aligner.profile-generation.v1"
- state: exact "in_progress" or "committed"
- profile_id: exact selected profile ID
- profile_file_sha256: SHA-256 of the exact intended profile.yaml bytes
- evidence_file_sha256: SHA-256 of the exact intended evidence.jsonl bytes
- generation_sha256: SHA-256 of the canonical five-key object obtained by omitting only generation_sha256, without a trailing newline

The complete generation.json file is the canonical six-key object followed by exactly one LF. It must be nonempty and at most 4,096 bytes. It is a current-UID regular file with mode exactly 0600 and nlink exactly 1. The canonical writer proves the generated byte length before opening a temp. A reader fstats before allocation, rejects size greater than 4,096, and uses bounded pread through at most 4,097 bytes while checking stable dev/ino/type/uid/mode/nlink/size. Growth, short or extra read, invalid UTF-8, noncanonical JSON, missing or extra key, wrong schema/state/profile/hash, or post-read identity/name drift refuses.

Every retained directory or leaf descriptor becomes owned by a cleanup scope immediately after open and before validation that can raise. _RetainedDirectory, every content-leaf holder, and every manifest holder close every already-open descriptor on every exceptional exit. Repeated unsafe-directory, unsafe-leaf, oversize, malformed-manifest, and name-replacement refusal must not grow the process file-descriptor count.

Before ProfileStore.save mutates any name, it holds the exclusive lock and classifies the existing generation.json descriptor-relatively. It may supersede only exact absence or a fully valid private canonical v1 document in state in_progress or committed. Malformed, noncanonical, oversize, wrong-schema, wrong-profile, extra/missing-key, bad-self-hash, symlink, nonregular, nlink not 1, wrong owner, mode not 0600, unrelated entry, or name-entry substitution refuses with no write. The classified name entry and directory identity are revalidated immediately before the first mutation.

A save serializes and validates both target leaves plus the in_progress and committed manifest bodies before mutation. It then executes this exact order under the retained exclusive lock:

1. Create a same-directory O_CREAT | O_EXCL | O_NOFOLLOW manifest temp at 0600, write the exact in_progress bytes, fchmod 0600, fsync the temp descriptor, renameat it to generation.json, fsync the profile-directory descriptor, and reopen/revalidate the exact in_progress name entry and bytes. No content leaf may change before this barrier succeeds.
2. Create same-directory O_CREAT | O_EXCL | O_NOFOLLOW temps for profile.yaml and evidence.jsonl at 0600. Write and fchmod both, then fsync both temp descriptors before either content rename.
3. Revalidate the directory, the exact in_progress manifest, and relevant name authorities. Rename both content temps to profile.yaml and evidence.jsonl while generation.json remains in_progress.
4. Fsync the profile-directory descriptor as the content-leaf publication barrier. Reopen both canonical leaves by dirfd and revalidate exact bytes, dev/ino/type/uid/mode/nlink/hash, name entries, and the still-exact in_progress manifest.
5. Only after step 4 succeeds, create the committed-manifest temp, write the exact committed bytes, fchmod 0600, fsync the temp descriptor, revalidate both leaves and the current in_progress entry, and renameat the temp to generation.json.
6. Fsync the profile-directory descriptor as the committed-name durability barrier. Reopen/revalidate the committed manifest and both content leaves. Only completion of this step returns success.

Every temp is same-directory, current-UID, regular, mode 0600, nlink 1, and cleaned on handled failure where cleanup is possible. Before renameat of the initial in_progress manifest, no canonical name has changed; a handled failure may report the stable prior classified disposition only after the generation.json name entry, profile directory, and both canonical content leaves are freshly revalidated as exactly unchanged. If that unchanged prior disposition cannot be proved, the outcome is profile_generation_outcome_unknown. After the initial in_progress rename but before successful profile-directory fsync plus exact in_progress revalidation, persistent disposition is unproved and the outcome is profile_generation_outcome_unknown. Only after the complete step-1 durability barrier succeeds may a later handled failure before the committed rename claim or recover a proven durable in_progress disposition. No failure infers success from equality or readback, and any failed durability barrier is classified by these exact rules.

If a handled failure occurs after the committed rename but before successful final directory fsync and revalidation, the save call never reports success. While still holding the same exclusive lock and retained directory descriptor, it may attempt to republish the exact already-prepared in_progress manifest through a new private same-directory temp, fsync the temp, renameat it to generation.json, fsync the directory, and reopen/revalidate exact in_progress. If and only if every rollback step succeeds, it returns a stable save-failed outcome with proven durable in_progress. It never rewrites either content leaf, publishes committed, or infers success from leaf equality.

If rollback temp creation/write/fsync, rollback rename, rollback directory fsync, or rollback revalidation cannot be proved, the exact save outcome is profile_generation_outcome_unknown. This outcome states only that the call did not return success and persistent disposition is unknown; it makes no unobservable durable-state claim.

The sole recovery authority after interruption or profile_generation_outcome_unknown is the next fresh acquisition of the profile-directory lock followed by complete strict descriptor-relative classification of generation.json and both content leaves:

- exact valid committed manifest plus exact leaf bytes, hashes, metadata, and name continuity is a recovered coherent generation and may be admitted by FIT;
- exact valid in_progress manifest is incomplete and FIT refuses;
- absent, malformed, unsafe, mismatched, or drifting manifest or leaf state is invalid or unsealed and FIT refuses.

Recovery never writes, upgrades, reconstructs, or commits from equality. A separately invoked later ProfileStore.save may supersede exact absence or a fully valid in_progress or committed manifest and rerun the complete publication protocol.

For ordinary non-FIT compatibility only, a manifest-absent pair may be returned explicitly as legacy_unsealed after strict leaf validation. It must not be called sealed or coherent and cannot feed FIT. The only promotion path is one successful save under this protocol. ProfileStore.open_existing(...).coherent_snapshot(require_committed_generation=True) is the exact FIT seam: it runs only on the definitive-absence or replay-unprovable new-operation path, after exact historical receipt classification but before any journal-mode change, BEGIN IMMEDIATE, or domain write. Missing generation.json, in_progress, or any invalid or unsafe generation refuses with binding_profile_evidence_context without domain writes; the shared lock and retained descriptors remain held through pre-COMMIT revalidation and COMMIT.

FIT snapshot opens generation.json, profile.yaml, and evidence.jsonl relative to the shared-locked directory with O_NOFOLLOW and retains all descriptors. Each must be current-UID regular mode 0600 nlink 1. The committed manifest must match both exact retained file hashes. Capture and revalidate directory and all leaf dev/ino/uid/mode/nlink/name entries before BEGIN and before COMMIT. Parse held bytes once.

Before content allocation, fstat enforces profile.yaml at most 1,048,576 bytes and evidence.jsonl at most 4,194,304 bytes. Read each with bounded pread through at most its maximum plus one while detecting growth, short/extra read, and identity drift. Exact maximum size reaches parsing; maximum plus one refuses before full allocation.

Evidence JSONL framing splits exact raw bytes only on LF 0x0A and follows the canonical final-LF convention; str.splitlines is forbidden. VT 0x0B, FF 0x0C, NUL, every otherwise-forbidden C0 control, and DEL cannot act as separators and reject under the primitive string rules. There are at most 10,000 nonblank evidence rows: exactly 10,000 reaches parsing and 10,001 refuses.

Each nonblank evidence row is parsed as one strict JSON object with duplicate-key and nonfinite-number rejection under the existing evidence-ledger serialization semantics. FIT does not require compact separators or canonical row bytes: ProfileStore.save retains its existing json.dumps(asdict(item), ensure_ascii=False, sort_keys=True) plus one LF format, and semantically valid historical whitespace variants remain admissible and are bound by evidence_file_sha256. EvidenceItem.claim is the only EvidenceItem human-prose field: after JSON decoding it may contain HT, LF, and CR. Every other EvidenceItem string field—evidence_id, kind, source_ref, status, observed_at when non-null, and content_sha256 when non-null—rejects every C0 control and DEL. In raw JSONL bytes, only literal LF delimits records; literal raw HT, CR, VT, FF, NUL, every other C0 byte, and DEL reject. Valid JSON escape sequences may decode to HT, LF, or CR only in claim, and an escaped prose control never becomes a framing delimiter.

Derived identities are:

- profile_file_sha256 = SHA-256 of exact profile.yaml bytes
- evidence_file_sha256 = SHA-256 of exact evidence.jsonl bytes
- profile_sha256 = SHA-256 of canonical dataclasses.asdict(CandidateProfile)
- evidence_ledger_sha256 = SHA-256 of the canonical JSON array of EvidenceItem rows in exact ledger order; duplicate evidence IDs reject
- profile_context_sha256 = SHA-256 of canonical complete existing profile.llm_context(evidence) whole-profile context

Alignment receives that exact whole-profile llm_context. Every cited evidence_id must nevertheless belong to the exact evidence_ids of the selected track. Visibility of another track's fact never grants citation authority.

Resource bounds are:

- each configuration-closure file &lt;= 1,048,576 bytes
- total configuration closure &lt;= 8,388,608 bytes
- profile.yaml &lt;= 1,048,576 bytes
- evidence.jsonl &lt;= 4,194,304 bytes
- generation.json &lt;= 4,096 bytes including its final LF
- evidence.jsonl &lt;= 10,000 nonblank rows

## 7. Primitive validation rules

Unless a field-specific rule is stricter:

- integer means Python int and not bool
- number means finite int or float and not bool
- sha256 means exactly 64 lowercase hexadecimal characters
- path means an absolute normalized UTF-8 string of length 1..4096
- RFC3339 means a timezone-aware parseable string of length 20..64
- operation_id matches ^[A-Za-z0-9][A-Za-z0-9._-]{7,63}$
- profile_id matches ^prf_[0-9a-f]{32}$
- job_key is exact board:job identity, 3..256 Unicode code points
- profile_version is a nonempty string of length 1..128
- track is a nonempty string of length 1..128

All C0 controls and DEL reject in every string except these explicitly human-prose fields, which may contain HT, LF, and CR but no other C0 control and no DEL:

- raw_snapshot.raw_text
- extraction.output.description
- every string element of extraction output responsibilities, required_skills, preferred_skills, required_qualifications, preferred_qualifications, and work_authorisation
- every extraction output unknown_fields element
- EvidenceMatch.requirement
- EvidenceMatch.rationale
- every alignment missing_requirements element
- every alignment unknowns element

## 8. Exact processing-envelope schema

The top-level object has exactly these keys:

- schema_version: exact "market-aligner.processing-envelope.v1"
- operation_id
- job_key
- profile_id
- profile_version
- track
- config: ConfigBinding
- databases: DatabaseBindings
- raw: RawBinding
- profile: ProfileBinding
- extraction: ExtractionBinding
- alignment: AlignmentBinding
- scoring: ScoringBinding

ConfigBinding has exactly:

- source_path: path
- source_file_sha256: sha256
- closure_files: object with 1..64 entries, each key a path and each value sha256, containing source_path exactly once
- closure_sha256: SHA-256 of canonical closure_files
- semantic_sha256: SHA-256 of canonical merged configuration

DatabaseBindings has exactly assessments and vacancy. Each DatabaseIdentity has exactly:

- path: path
- dev: integer &gt;= 0
- ino: integer &gt; 0
- uid: integer exactly os.getuid()
- mode: integer exactly 384
- nlink: integer exactly 1

The two database identities must have the same dev and distinct ino. assessments.path is exactly data_home/state/assessments.sqlite3. vacancy.path is exactly the database derived by Collector.plan from the current configuration snapshot.
## 9. Raw, extraction, alignment, and scoring bindings

RawBinding has exactly:

- source_content_sha256: sha256
- raw_snapshot_sha256: sha256

The current posting must exist with fetch_status exactly "fetched". Its strict semantic raw snapshot has exactly:

- job_key: Unicode string length 3..256
- board: string length 1..128
- job_id: string length 1..256
- url: string length 1..4096
- posted_at: null or timezone-aware RFC3339 length 20..64
- fetched_at: required timezone-aware RFC3339 length 20..64
- raw_text: null or human-prose string length &lt;= 4,000,000
- raw_json: null or strict JSON object with at most 100,000 recursively bounded nodes and depth &lt;= 64
- fetch_status: exact "fetched"

The legacy source_content_sha256 is recomputed as SHA-256 over UTF-8 bytes of:

    (raw_text or "") + (stored raw_json TEXT verbatim or "")

The stored raw_json TEXT is separately strict-parsed with duplicate-key and nonfinite-number rejection. It is never reserialized to compute the legacy source hash. raw_snapshot_sha256 is SHA-256 of canonical JSON of the exact semantic raw snapshot above.

ProfileBinding has exactly these sha256 fields:

- profile_file_sha256
- evidence_file_sha256
- profile_sha256
- evidence_ledger_sha256
- profile_context_sha256

ExtractionBinding has exactly output and receipt.

The semantic extraction input is canonical schema "market-aligner.semantic-vacancy-extraction-input.v1" with exactly:

- schema_version
- job_key
- board
- job_id
- url
- fetched_at
- source_content_sha256
- raw_snapshot_sha256
- raw_text
- raw_json: the strict parsed semantic JSON value

Its canonical SHA-256 must equal extraction.receipt.input_sha256.

SemanticVacancyExtraction output has exactly:

- source_content_sha256: sha256, equal accepted legacy source hash
- title: string length 1..4096
- company: string length 0..4096
- location: string length 0..4096
- description: human prose length 1..1,000,000
- responsibilities: array length 0..512 of human-prose strings length 1..8192
- required_skills: same bounds
- preferred_skills: same bounds
- required_qualifications: same bounds
- preferred_qualifications: same bounds
- work_authorisation: same bounds
- contract_type: string length 0..256
- seniority: string length 0..256
- remote_policy: string length 0..256
- extraction_confidence: number in [0,1]
- unknown_fields: array length 0..256 of human-prose strings length 1..256
- contract_version: exact "market-aligner.llm.v1"

Its canonical dataclasses.asdict output SHA-256 must equal extraction.receipt.output_sha256. accept_extraction must pass.

LLMReceipt has exactly:

- receipt_id: nonempty string length 1..256
- task: exact "semantic_vacancy_extraction" for extraction or "evidence_alignment" for alignment
- model: nonempty string length 1..256
- prompt_version: nonempty string length 1..256
- input_sha256: sha256
- output_sha256: sha256
- created_at: timezone-aware RFC3339 length 20..64
- contract_version: exact "market-aligner.llm.v1"

receipt_id, model, prompt_version, and created_at are staged and hash-bound but are not provider or time authority.

AlignmentBinding has exactly output and receipt.

The alignment input is canonical schema "market-aligner.evidence-alignment-input.v1" with exactly:

- schema_version
- job_key
- profile_id
- profile_version
- track
- vacancy: canonical dataclasses.asdict of the accepted Vacancy
- profile_context: the complete existing profile.llm_context(evidence)
- profile_context_sha256

Its canonical SHA-256 must equal alignment.receipt.input_sha256.

EvidenceAlignment output has exactly:

- profile_id: exact CLI profile
- profile_version: exact admitted profile version
- job_key: exact CLI job
- matches: array length 0..512 of EvidenceMatch
- missing_requirements: array length 0..512 of human-prose strings length 1..8192
- technical_alignment: number in [0,1]
- evidence_match: number in [0,1]
- confidence: number in [0,1]
- unknowns: array length 0..256 of human-prose strings length 1..8192
- contract_version: exact "market-aligner.llm.v1"

EvidenceMatch has exactly:

- requirement: human-prose string length 1..8192
- evidence_ids: array length 0..256 of unique strings length 1..256, every ID in the selected track
- strength: number in [0,1]
- rationale: human-prose string length 1..8192

The canonical dataclasses.asdict alignment output SHA-256 must equal alignment.receipt.output_sha256. accept_alignment must pass.

ScoringBinding has exactly:

- parameters_sha256: sha256 equal ScoringParams().parameters_hash
- opportunity_policy_sha256: sha256 of the fixed policy below
- expected_score: ScoreResult

The fixed policy is the canonical JSON object:

    {"application_authority":false,"barrier_to_entry":10,"growth_potential":0,"market_demand":0,"research_authority":false,"schema_version":"market-aligner.fit001-unknown-opportunity-policy.v1"}

Its SHA-256 is exactly:

    65b4674413537ca5b151e1c9627585d025aedb3183c70dcae23de9c78e17e13d

Deterministic axes are:

- technical_alignment = accepted alignment.technical_alignment * 10
- evidence_match = accepted alignment.evidence_match * 10
- market_demand = 0
- barrier_to_entry = 10
- growth_potential = 0

ScoringParams() is the sole parameter object. Recompute score(profile, job_key, track, axes, ScoringParams()) and exact-compare every ScoreResult field.

ScoreResult has exactly:

- profile_id: exact
- job_key: exact
- track: exact
- fit: number in [0,1]
- opportunity: number in [0,1]
- final: number in [0,100]
- fit_status: exact "uncalibrated"
- parameters_hash: exact parameters_sha256
- fit_subscores: exact keys interest, demonstrated_skill, market_readiness, technical_alignment, evidence_match, each number in [0,1]
- opportunity_subscores: exact keys market_demand, accessibility, growth_potential, each number in [0,1]

No eligibility, opportunity, research, application, release, or submission authority follows from this score.

## 10. Processing binding and normalized projection

The processing binding object has exactly:

- schema_version: exact "market-aligner.processing-binding.v1"
- operation_id
- job_key
- profile_id
- profile_version
- track
- envelope_file_sha256
- envelope_semantic_sha256
- config: exact accepted ConfigBinding
- databases: exact accepted DatabaseBindings
- raw: exact accepted RawBinding
- profile: exact accepted ProfileBinding
- extraction: exact accepted ExtractionBinding
- alignment: exact accepted AlignmentBinding
- scoring: exact accepted ScoringBinding

binding_sha256 is SHA-256 of canonical JSON of this complete object. No field is omitted.

The accepted Vacancy normalized_json is exactly:

    json.dumps(
        dataclasses.asdict(accepted_vacancy),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )

encoded as UTF-8 with no trailing newline. normalized_json_sha256 is SHA-256 of those exact bytes. The process CAS always supplies normalized_at explicitly and never relies on the normalised_jobs CURRENT_TIMESTAMP default.

## 11. Single-owner immutable projection CAS

normalised_jobs is insert-absent/reuse-exact only. If job_key is absent, insert. If present, reuse only when normalized_json exact bytes and every process-owned compatible identity are exact. Never UPDATE. Any changed extraction or nonexact normalized projection is projection_conflict. A different profile may reuse the exact row only when normalized_json is byte-exact.

assessments is insert-absent/reuse-exact only. If absent, insert. If present, reuse only if every process-owned field is exact, including URL, title, company, opportunity, fit, final_score, fit_status, extraction_confidence, exact AssessmentStore score_payload_json bytes/hash, state "scored", null opportunity/policy fields, and explicit timestamps where owned. Never UPDATE. Any advanced/gated state or nonexact field is projection_conflict.

Exactly one event of type processing_score_accepted may exist for a given profile_id and job_key. Its actor_kind is "deterministic". On first admission, insert absent. On later attempts, query every event of that type for the profile/job:

- zero permits first insertion
- exactly one permits only exact same event payload, owning operation, and idempotency key, and therefore routes to the same-operation receipt replay
- more than one or any field difference is projection_conflict

A different operation_id for the same profile/job always refuses projection_conflict even if the derived Vacancy and ScoreResult happen to match. Different track, extraction/alignment receipt, model, prompt, or score likewise conflicts. FIT-001 never adds a second processing event or silently supersedes historical authority.

The processing-score event payload is canonical JSON with exactly these flat keys:

- schema_version: exact "market-aligner.processing-score-event.v1"
- operation_id
- profile_id
- job_key
- track
- binding_sha256
- envelope_file_sha256
- raw_snapshot_sha256
- profile_context_sha256
- extraction_input_sha256
- extraction_output_sha256
- extraction_receipt_id
- alignment_input_sha256
- alignment_output_sha256
- alignment_receipt_id
- normalized_json_sha256
- assessment_payload_hash
- parameters_sha256
- opportunity_policy_sha256
- score_result_sha256

event_payload_sha256 is SHA-256 of canonical JSON of that exact payload with no newline.

Unicode job_key remains 3..256 Unicode code points. Define:

- job_key_sha256 = SHA-256 of exact job_key UTF-8 bytes
- idempotency_key = "processing-score:" + profile_id + ":" + job_key_sha256 + ":" + event_payload_sha256

The idempotency key is ASCII and exactly 183 UTF-8 bytes, therefore within the table's 512-byte bound. Bounds for idempotency_key are measured in UTF-8 bytes, not code points. The full exact Unicode job_key remains in the event payload. Tests include non-ASCII composed and decomposed job keys and require distinct correct hashes without normalization.

The assessment payload uses the existing exact AssessmentStore canonical score-payload serialization. assessment_payload_hash is SHA-256 of its exact canonical bytes. score_result_sha256 is SHA-256 of canonical dataclasses.asdict(expected ScoreResult).

## 12. Receipt schema and byte identity

The processing receipt has exactly:

- schema_version: exact "market-aligner.processing-receipt.v1"
- operation_id
- job_key
- profile_id
- profile_version
- track
- binding_sha256
- envelope_file_sha256
- envelope_semantic_sha256
- config
- databases
- raw
- profile
- extraction
- alignment
- scoring
- normalised_projection
- assessment_projection
- assessment_event
- created_at
- time_authenticated: false
- imported_model_policy_authenticated: false
- imported_time_authenticated: false
- research_authority: false
- application_authority: false
- release_authority: false
- submission_authority: false
- self_hash

NormalisedProjection has exactly:

- job_key
- normalized_json_sha256
- normalized_at: RFC3339

AssessmentProjection has exactly:

- profile_id
- job_key
- score_payload_hash
- state: exact "scored"
- created_at: RFC3339
- updated_at: RFC3339

AssessmentEventProjection has exactly:

- id: integer &gt; 0
- event_type: exact "processing_score_accepted"
- actor_kind: exact "deterministic"
- payload_sha256
- idempotency_key: ASCII exact formula above, length measured in UTF-8 bytes and &lt;= 512
- created_at: RFC3339

self_hash is SHA-256 of canonical complete receipt with only self_hash omitted. Stored receipt bytes are canonical complete receipt including self_hash plus exactly one newline. receipt_file_sha256 is SHA-256 of those exact stored bytes and is table metadata only; it is not recursively embedded in the receipt.

One timestamp is generated only after BEGIN IMMEDIATE and all transaction rechecks, exactly as:

    datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")

That exact value is supplied explicitly to every newly inserted normalized row, assessment created_at/updated_at, event created_at, migration/receipt row where process-owned, and receipt created_at. No process CAS uses table defaults. Reused projections preserve their original timestamp, which must equal the sealed receipt projection.
## 13. Database pathname and inode continuity

Before any SQLite connection, descriptor-walk and retain each database parent chain and leaf with O_NOFOLLOW. Require current-UID regular 0600 nlink-1 leaves, same filesystem, and distinct dev/ino. Bind canonical path plus dev, ino, uid, mode, and nlink for assessments main and vacancy alias in the envelope and receipt.

Open SQLite by the exact verified names only after retaining those descriptors. Immediately after opening and ATTACH, again after journal-mode setup, before BEGIN, inside the transaction before first DML, and immediately before COMMIT:

- re-lstat/reopen both name entries relative to retained parents
- require equality to retained leaf descriptors
- require PRAGMA database_list to report the exact two expected canonical names
- require main to be assessments and alias vacancy to be the configured collector database
- reject missing, temporary, in-memory, same-inode, hardlinked, different-device, path/inode-mismatched, or aliased databases

Rename, symlink, hardlink, inode, ancestor, or pathname substitution at any injected post-preflight/pre-write hook refuses before DML. After BEGIN, SQLite's retained open handles and locks govern transaction isolation. The malicious same-UID limitation remains explicit.

## 14. Exact migration ownership and DDL

state/migrations.py remains the only migration owner. Add a caller-owned seam:

    apply_on(connection, migrations, schema_alias="main")

It must not connect, mkdir, BEGIN, COMMIT, or change journal mode. It qualifies every ledger operation to the already validated schema alias.

Inside the existing outer BEGIN IMMEDIATE it creates and verifies this exact existing-compatible ledger DDL in main:

    CREATE TABLE IF NOT EXISTS market_aligner_schema_migrations(version INTEGER PRIMARY KEY,name TEXT NOT NULL,checksum TEXT NOT NULL,applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)

Ledger creation, sqlite_master compatibility verification, migration DDL, and migration-ledger INSERT all occur inside the same outer transaction and are included in rollback/crash tests.

The one FIT migration is:

- version: 1
- name: "fit001_processing_receipts_v1"
- statements: a one-element tuple containing exactly this SQL string:

    CREATE TABLE processing_receipts(operation_id TEXT PRIMARY KEY,profile_id TEXT NOT NULL,job_key TEXT NOT NULL,track TEXT NOT NULL,binding_sha256 TEXT NOT NULL UNIQUE,envelope_file_sha256 TEXT NOT NULL,envelope_semantic_sha256 TEXT NOT NULL,normalized_sha256 TEXT NOT NULL,assessment_payload_hash TEXT NOT NULL,event_id INTEGER NOT NULL,receipt_self_hash TEXT NOT NULL,receipt_file_sha256 TEXT NOT NULL UNIQUE,receipt_bytes BLOB NOT NULL,created_at TEXT NOT NULL,UNIQUE(profile_id,job_key),FOREIGN KEY(event_id) REFERENCES assessment_events(id) ON DELETE RESTRICT,CHECK(length(operation_id) BETWEEN 8 AND 64),CHECK(length(profile_id)=36),CHECK(length(job_key) BETWEEN 3 AND 256),CHECK(length(track) BETWEEN 1 AND 128),CHECK(length(binding_sha256)=64 AND binding_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(envelope_file_sha256)=64 AND envelope_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(envelope_semantic_sha256)=64 AND envelope_semantic_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(normalized_sha256)=64 AND normalized_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(assessment_payload_hash)=64 AND assessment_payload_hash NOT GLOB '*[^0-9a-f]*'),CHECK(event_id>0),CHECK(length(receipt_self_hash)=64 AND receipt_self_hash NOT GLOB '*[^0-9a-f]*'),CHECK(length(receipt_file_sha256)=64 AND receipt_file_sha256 NOT GLOB '*[^0-9a-f]*'),CHECK(length(receipt_bytes) BETWEEN 3 AND 4194304),CHECK(length(created_at) BETWEEN 20 AND 64)) STRICT

The checksum under the current Migration.checksum algorithm is exactly:

    19c0307b99175dbbfbd69ef64807a9b172c5e6abf3fa6bb117b5f43b21ce163f

The ledger row is exactly version 1, name "fit001_processing_receipts_v1", and that checksum.

Any existing version/name/checksum/DDL/sqlite_master mismatch refuses atomic_mode_unavailable before domain DML. Tests cover absent-ledger bootstrap, exact compatible replay, outer rollback removing both ledger and receipt table, and every schema/checksum mismatch.

## 15. Attached-database transaction

After complete semantic admission:

1. Open the existing assessments database as main with URI mode=rw.
2. ATTACH the exact existing distinct vacancy database as alias vacancy.
3. Verify retained identities and PRAGMA database_list.
4. Safely checkpoint any WAL.
5. Set PRAGMA main.journal_mode=DELETE and vacancy.journal_mode=DELETE. Require both returned and read-back values to be "delete".
6. Set main.synchronous=FULL and vacancy.synchronous=FULL. Read back and require both FULL.
7. Require foreign_keys=ON and a bounded busy_timeout.
8. No constructor or schema script may switch either database back to WAL.
9. BEGIN IMMEDIATE.
10. Recheck durable recovery truth and any existing receipt.
11. Re-read the exact raw posting and every target projection.
12. Revalidate the configuration closure and both database path/inode identities.
13. Revalidate retained envelope/profile/evidence descriptors, name entries, and hashes.
14. Generate the one accepted_at timestamp.
15. Determine the prospective event ID and construct the prospective complete receipt as specified below.
16. Apply the migration ledger and processing_receipts DDL.
17. CAS the normalized projection.
18. CAS the assessment projection.
19. Insert the single event and require its ID to match the prospective ID.
20. Insert processing_receipts last.
21. Re-read every inserted or reused identity and exact receipt bytes.
22. Perform final descriptor/name/hash checks.
23. COMMIT.

Existing assessments, assessment_events, and vacancy.normalised_jobs schemas must be inspected through sqlite_master, PRAGMA table_info, indexes, and foreign-key facts and match the exact expected canonical contract. FIT-001 never recreates or mutates incompatible schemas.

## 16. Prospective event ID and receipt-size admission

The processing_receipts DDL permits receipt_bytes through 4,194,304 bytes. An accepted envelope is not sufficient by itself; the exact prospective receipt must fit before any DDL or DML.

Inside BEGIN IMMEDIATE, after all transaction rechecks and accepted_at generation but before any DDL or DML:

1. Read sqlite_sequence.seq for assessment_events when present and MAX(assessment_events.id).
2. Treat absent values as zero.
3. Compute prospective_event_id = max(sqlite_sequence.seq, MAX(id)) + 1.
4. Require prospective_event_id &lt;= 9,223,372,036,854,775,807. Overflow refuses without DDL/DML.
5. Build the complete prospective event payload, idempotency key, projections, receipt, self_hash, and exact stored receipt bytes using accepted_at and this prospective event ID.
6. Require len(stored_receipt_bytes) &lt;= 4,194,304.
7. If oversized, roll back the write-free transaction and emit invalid_processing_envelope_bytes.
8. Only then may migration DDL and domain DML begin.
9. The later event INSERT lastrowid must equal prospective_event_id exactly. Any mismatch rolls back and fails closed.

Tests cover event-ID decimal digit boundaries, sqlite_sequence greater than MAX(id), MAX(id) greater than sqlite_sequence, maximum signed SQLite row ID, overflow, the largest accepted exact receipt, and one-byte-larger refusal. The earlier claim that size rejection always occurs before a transaction is deleted; it occurs inside BEGIN IMMEDIATE but before any DDL or DML.

## 17. Atomic rollback and crash recovery

Injected failures after migration-ledger DDL, receipt-table DDL, normalized CAS, assessment CAS, event insert, receipt insert, final recheck, and before COMMIT must roll back every logical write across both databases. A normalized, assessment, or event projection without its processing receipt is never coherent success.

Subprocess crash tests cover every application-visible and filesystem-observable attached rollback-journal state:

- after BEGIN or first journal appearance
- after each logical DML boundary
- when both per-database journals are present
- when a super-journal or master association is observable
- during COMMIT
- immediately after COMMIT returns and before stdout

The child is terminated without cleanup. The next process reopens through SQLite's legitimate recovery path before interpretation. After recovery, require quick_check success, foreign_key_check empty, and exactly one of:

- no FIT logical projection/event/receipt exists
- the exact normalized + assessment + single event + receipt set exists

Do not require journal or super-journal files to be absent before SQLite recovery. Require coherent databases and clean legitimate journal disposition after the defined recovery step.

Where a platform cannot deterministically expose a particular internal SQLite journal state, only that internal boundary receives an explicit environment-qualified skip; the kill-during-COMMIT stress campaign still runs. Absence of observation cannot silently count as PASS.

## 18. Error mapping and durable-truth classification

Stable SQLite outcomes are:

- atomic_busy for SQLITE_BUSY and SQLITE_LOCKED
- storage_full for SQLITE_FULL
- storage_io_error for SQLITE_IOERR and extended IOERR codes
- interrupted for SQLITE_INTERRUPT, KeyboardInterrupt, and installed catchable SIGINT/SIGTERM handling
- recovery_incoherent for partial, ambiguous, malformed, or otherwise unclassifiable durable state

On a caught mapped error, exception, KeyboardInterrupt, or handled catchable signal:

1. Roll back if active and close/release SQLite connections, descriptors, flocks, and the cooperating umask lock in finally where execution permits.
2. Reopen through the defined SQLite recovery verifier.
3. Classify durable truth:
   - if one exact self-validating processing receipt exists and normalized, assessment, and single event projections all exactly match, emit the stored success receipt bytes and exit success regardless of the caught error
   - if no receipt and no process-owned normalized, assessment, or event projection exists, emit the mapped stable refusal, release resources, and permit a clean retry
   - if any partial projection, multiple event, malformed receipt, migration ambiguity, or unknown state exists, emit non-success recovery_incoherent, preserve evidence, and never auto-retry or claim success

An error observed after a successful COMMIT must never be reported as failure when recovery proves the exact committed state.

Finally/cleanup guarantees apply only to normal exceptions, KeyboardInterrupt, and explicitly installed catchable SIGINT/SIGTERM handlers. SIGKILL, SIGSTOP, abrupt power loss, or equivalent uncatchable termination cannot run finally and emits no receipt or refusal. The next invocation performs the same recovery classification before ordinary replay/admission. Tests cover SIGINT, SIGTERM, KeyboardInterrupt, and a killed child.

## 19. Replay semantics and stdout identity

Exact replay is considered only after operation, envelope, CLI, and live configuration/database identity admission.

binding_config_database re-snapshots the current configuration closure and both database identities before receipt lookup. Live configuration or database drift blocks replay.

binding_existing_receipt compares the staged candidate binding derived from the validated envelope, CLI, and current configuration/database identities with the stored receipt and stored binding only. If exact, historical replay deliberately does not revalidate current raw posting, profile.yaml, evidence.jsonl, profile context, extraction/alignment inputs, or current projections against mutable live inputs. It returns the sealed stored success bytes.

Tests mutate raw/profile after completion: the same operation/envelope/configuration/databases replays unchanged. A new operation evaluates current authorities and then conflicts or refuses as applicable.

Creation stdout bytes and replay stdout bytes are exactly equal to the stored canonical receipt BLOB, including its single trailing newline. No created/replayed flag, variable message, extra whitespace, timestamp update, additional event, or durable mutation may distinguish them. Internal metadata may record which branch occurred but cannot change stdout, receipt bytes, row counts, or timestamps.

Refusals emit one canonical structured refusal line and create no domain state. A valid operation_id is retained in refusal output. No false created or in_flight disposition may be reported before a claim exists.
## 20. Stable refusal precedence

Exactly one stable reason is selected in this order:

1. invalid_operation_id
2. unsafe_processing_envelope_path
3. invalid_processing_envelope_bytes
4. binding_cli_identity
5. binding_config_database
6. binding_existing_receipt
7. binding_raw_snapshot
8. binding_profile_evidence_context
9. binding_extraction
10. binding_alignment
11. binding_scoring_parameters
12. binding_opportunity_policy
13. binding_score_result
14. projection_conflict
15. atomic_mode_unavailable
16. atomic_busy
17. storage_full
18. storage_io_error
19. interrupted
20. recovery_incoherent

Transaction-time rechecks retain the same domain reason where applicable. Journal-mode, synchronous, foreign-key, schema compatibility, or attached-database setup failures use atomic_mode_unavailable. No test may accept either of two reasons.

## 21. Required positive, negative, race, and recovery gates

The implementation is accepted only with all of these objective gates:

### Positive and replay

- A real JobDatabase + existing AssessmentStore + ProfileStore fixture creates the exact normalized row, assessment, single event, and processing receipt; sibling rows are untouched.
- Creation stdout bytes equal replay stdout bytes equal stored receipt BLOB.
- Replay preserves exact row counts, event counts, receipt bytes, and timestamps.
- Post-COMMIT/pre-stdout failure recovers as exact success.
- A different profile may reuse only an exact normalized row and creates its own exact assessment/event/receipt.
- The owning operation with exact receipt bindings replays; every different operation for the same profile/job conflicts.
- After success, individually removing, renaming, or corrupting the profiles root, the selected profile directory, generation.json, profile.yaml, or evidence.jsonl still yields exact stored-byte replay with no profile path opened; each damaged object blocks only a new or replay-unprovable operation, which terminates with binding_profile_evidence_context at reason 8.

### No-write and constructor boundaries

- Complete-tree exact snapshots prove zero mutation for malformed operation, envelope path/bytes/schema, CLI identity, configuration-plan, data-home, and staged/derived database pathname/identity failures before the first database open; a missing configured database terminates binding_config_database at reason 5 without ever being created.
- After database open, refusal tests prove zero domain DDL/DML/rows/receipt/events/timestamps/user-file changes while excluding only enumerated SQLite-managed recovery/shared-memory/journal artifacts.
- Failed SQLite open, ATTACH, SELECT, or read-only PRAGMA inspection permits only legitimate SQLite-managed artifacts, maps stably per section 18, runs none of the later semantics, and performs durable-truth recovery whenever a handle existed.
- On the definitive-absence or replay-unprovable new-operation path, committed-generation profile validation occurs after exact receipt classification and before any journal-mode change, BEGIN IMMEDIATE, or domain write; subsequent raw/profile/evidence refusals prove zero domain mutation and zero user-file mutation outside the enumerated SQLite artifacts.
- No forbidden constructor runs in preflight.
- Exact replay performs no domain mutation and no journal-mode transition before its live config/database checks.

### Envelope and filesystem substitution

- Reject root, state, inbox, or leaf symlink.
- Reject hardlink, wrong owner, 0755 directory, 0644/0660 file, nlink drift, unlink, rename, inode replacement, ancestor replacement, nested descendant, alternate path spelling, and post-preflight/pre-BEGIN/pre-COMMIT substitution.
- Reject duplicate/unknown/missing JSON keys, bool-as-number, NaN, Infinity, invalid UTF-8, noncanonical JSON, extra newlines/bytes, oversize envelope, filename/hash mismatch, wrong control characters, and every field-specific bound violation.
- Prove exact retained-descriptor and name-entry revalidation.

### Profile/evidence coherence

The ProfileStore save/publication/recovery tests in this subsection remain universal owner tests. Every FIT admission/snapshot requirement, refusal, retained-leaf validation, selected-track check, drift check, and profile/evidence substitution negative in this subsection applies only to the definitive-absence or replay-unprovable new-operation path. A proven exact replay never opens or validates the profile root, selected profile directory, generation.json, profile.yaml, or evidence.jsonl; the explicit profile-removal replay positive controls that exemption.

- On the definitive-absence or replay-unprovable new-operation path, FIT uses the public no-write ProfileStore.open_existing seam; constructor/ensure writes and __new__ test bypasses are forbidden.
- Same-process and cross-process save-vs-snapshot exclusion uses the shared/exclusive profile-directory flock. Same-process release/join and cross-process poll/terminate/kill/wait/pipe cleanup are bounded and run in finally.
- On the definitive-absence or replay-unprovable new-operation path, a manifest-absent pair is legacy_unsealed only and always refuses FIT. One successful save seals it; FIT requires a strictly verified committed v1 manifest.
- Save publishes and directory-fsyncs in_progress before either leaf, fsyncs both content temps before rename, directory-fsyncs and verifies both renamed leaves before committed rename, then directory-fsyncs and verifies committed before returning success.
- Inject handled exception and process death after every temp fsync, each rename, the content-leaf directory barrier, committed-manifest rename before final directory fsync, and the final directory fsync. No mixed profile/evidence generation is ever admitted.
- Inject final committed-name directory-fsync failure plus rollback-temp creation/write/fsync, rollback rename, rollback directory-fsync, and rollback-revalidation failures. Proven rollback leaves exact durable in_progress and refuses FIT; unproved rollback returns exactly profile_generation_outcome_unknown; fresh locked disk classification is the sole recovery authority.
- Recovered exact committed manifest plus exact leaves may pass; in_progress refuses; absent, malformed, unsafe, mismatched, or drifting state refuses. Readers and recovery never repair, infer, upgrade, or write.
- Before mutation, absent or fully valid private v1 in_progress/committed manifest may be superseded; every unsafe, malformed, unrelated, substituted, wrong-owner/mode/link, or oversize existing manifest refuses byte-for-byte no-write.
- On the definitive-absence or replay-unprovable new-operation path, reject profile directory, generation manifest, or content-leaf replacement, symlink, hardlink, mode/owner/nlink drift, duplicate evidence IDs, selected-track citation escape, and pre-COMMIT content drift.
- On the definitive-absence or replay-unprovable new-operation path, enforce fstat plus bounded pread limits for all three leaves. Exact maxima reach parsing; maximum plus one refuses before full allocation. Fifty-iteration unsafe/oversize/malformed/replacement campaigns prove file-descriptor stability.
- On the definitive-absence or replay-unprovable new-operation path, split evidence JSONL only on exact literal LF and strict-parse each nonblank row with duplicate-key/nonfinite rejection while preserving existing noncompact ProfileStore serialization and compatible historical whitespace. EvidenceItem.claim alone may contain decoded HT/LF/CR from valid JSON escapes; every other EvidenceItem string field rejects all C0/DEL. Reject literal raw HT, CR, VT, FF, NUL, every other C0 byte, DEL, and str.splitlines behavior. Escaped prose controls never delimit rows. Exactly 10,000 nonblank rows reaches parsing; 10,001 refuses.
- On the definitive-absence or replay-unprovable new-operation path, verify all five profile/evidence/context hashes from retained exact bytes and revalidate the committed generation binding before BEGIN and COMMIT.

### Configuration, databases, and raw identity

- Reject configuration source/closure/semantic hash substitution and current configuration drift before replay.
- Reject missing, temporary, in-memory, same-inode, different-device, path/inode-mismatched, aliased, symlinked, hardlinked, renamed, or ancestor-replaced databases.
- Reject PRAGMA database_list mismatch and injected replacement after preflight but before every write boundary.
- Reject wrong posting status, legacy raw TEXT hash mismatch, parsed semantic JSON mismatch, duplicate/nonfinite stored JSON, posted_at/fetched_at type/timezone drift, raw snapshot key/value/hash drift, and current raw drift for a new operation.
- Prove same-operation historical replay remains byte-exact despite later raw/profile mutation.

### Imported extraction/alignment and scoring

- Reject every extraction input, output, receipt task, model, prompt_version, receipt_id, created_at, contract_version, and hash substitution.
- Reject every alignment input, output, receipt, profile/version/job/track, whole-profile context, other-track evidence ID, confidence, unknown, missing-requirement, and hash substitution.
- Explicitly verify imported fields are bound but not authenticated.
- Reject ScoringParams hash, fixed-policy body/hash, deterministic axes, fit/opportunity subscores, FitStatus, and every ScoreResult substitution.
- Assert no eligibility, research, application, release, or submission authority is created.

### Projection CAS and concurrency

- normalised_jobs, assessments, and processing event are insert-absent/reuse-exact only; no UPDATE path exists.
- Different operation, track, extraction/alignment receipt, staged model/prompt, score, or existing advanced state deterministically refuses projection_conflict.
- Same-operation concurrent processes produce one internally created success and one byte-identical replay; stdout is identical and there is one provider-free deterministic processing cycle.
- Changed concurrent contender gets the exact precedence reason and no duplicate row/event/receipt.
- Unicode composed/decomposed job keys produce exact distinct UTF-8 hashes and fixed-width ASCII idempotency keys.

### Modes and cooperating umask scope

- Constructor mode tests cover exact 0700 parents and 0600 databases/files.
- Unsafe existing 0755/0644/0660/owner/symlink/hardlink objects refuse without silent chmod.
- owner_private_umask nested and cooperating-thread tests prove serialization and restoration.
- Tests state, rather than deny, the dedicated-process/process-global limitation.

### Migration and attached atomicity

- Absent migration ledger positive.
- Exact ledger and table compatibility replay.
- Ledger/table checksum, name, version, DDL, sqlite_master, index, and foreign-key mismatch negatives.
- Outer rollback removes both newly created migration ledger/table and all domain writes.
- Failure to set/read back DELETE journal mode, FULL synchronous, foreign_keys ON, or exact database_list refuses atomic_mode_unavailable.
- WAL contention and busy behavior map stably.

### Fault and recovery campaign

- Inject failure after migration ledger DDL, processing_receipts DDL, normalized CAS, assessment CAS, event insert, receipt insert, final recheck, and pre-COMMIT; prove all logical writes roll back and retry succeeds.
- Inject BUSY, LOCKED, FULL, IOERR extended codes, INTERRUPT, KeyboardInterrupt, catchable SIGINT, and catchable SIGTERM; prove exact stable classification, lock/fd/umask release, quick_check, foreign_key_check, and coherent retry.
- Inject errors both before and after COMMIT; a durable committed operation is always reported as stored success.
- Kill child at observable rollback/super-journal/COMMIT boundaries; reopen and classify all-or-nothing durable truth.
- Partial rows, malformed receipt, multiple event, migration ambiguity, or unknown state produces recovery_incoherent and never false success or automatic retry.
- Uncatchable termination emits nothing and the next invocation performs recovery classification.

### External side-effect exclusion and regression

- Patch every provider, adapter, network, subprocess, browser, JAA, research, release, application, and submission seam to explode; require zero calls and zero mutations.
- Preserve the warning-strict full suite and the full INGEST race/lock matrix.
- Run py_compile, compileall, and git diff --check.
- Any eventual commit must have author and committer exactly Artiom Gutu &lt;gutu.artiom444@gmail.com&gt; and a clean lane.

## 22. Exhaustive implementation allowlist

The separately reviewed source implementation may touch only:

- NEW docs/processing/FIT-001_PROCESS_ONE_CONTRACT.md
- NEW src/market_aligner/processing.py
- MOD src/market_aligner/config.py
- MOD src/market_aligner/state/vacancies.py
- MOD src/market_aligner/profiler/store.py
- MOD src/market_aligner/state/migrations.py
- MOD src/market_aligner/research/store.py
- MOD src/market_aligner/service/api.py
- MOD src/market_aligner/cli.py
- NEW tests/test_process_one.py
- NEW tests/test_config.py
- MOD tests/test_migrations.py
- MOD README.md

No llm/pipeline.py modification is authorized by default because processing.py can rebuild the exact imported input domains. Any need for another path requires stop and independent re-review before editing.

The contract-document-only turn is narrower still: it may create only docs/processing/FIT-001_PROCESS_ONE_CONTRACT.md and must stop for exact-byte review before any source, test, README, configuration, commit, integration, push, fetch, provider, model, browser, JAA, live-data, release, or submission action.

## 23. Acceptance sequence

1. Create this contract document only in the existing isolated Ox worktree.
2. Report exact path, byte count, SHA-256, git status, and complete one-file diff.
3. Stop Ox.
4. Independently review the exact document bytes against this terminal contract.
5. Only a terminal exact-byte PASS may authorize source implementation in the same dedicated Market session and allowlist.
6. Ox implementation self-report is never acceptance; Codex independently inspects diffs, runs adversarial gates, and integrates only terminally verified work as Artiom.
7. No provider, JAA, release, submission, canonical integration, or push action is implied by contract acceptance.

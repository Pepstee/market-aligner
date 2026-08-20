from __future__ import annotations

from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from market_aligner.assessment.scoring import AssessmentAxes, FitStatus
from market_aligner.applications.assessment_promotion import AssessmentPromotionError
from market_aligner.assessment.geography import (
    GeographicPreferencePolicy,
    classify_geographic_preference,
)
from market_aligner.assessment.viability import FirstJobScopePolicy
from market_aligner.cli import build_parser
from market_aligner.domain.contracts import JobUrl, RawPosting
from market_aligner.llm.contracts import (
    EvidenceAlignment,
    EvidenceMatch,
    LLMReceipt,
    SemanticVacancyExtraction,
)
from market_aligner.profiler.schema import (
    CandidateProfile,
    EvidenceItem,
    TrackProfile,
    new_profile_id,
)
from market_aligner.profiler.store import ProfileStore
from market_aligner.service.api import AssessmentRequest, MarketAlignerService
from market_aligner.service.processing import ProcessingService
from market_aligner.state.vacancies import JobDatabase


class FixtureSemanticWorker:
    def __init__(self, *, drift_extraction_input: bool = False) -> None:
        self.drift_extraction_input = drift_extraction_input
        self.extractions = 0
        self.alignments = 0

    def extract_vacancy(
        self, raw_context: Mapping[str, Any]
    ) -> tuple[SemanticVacancyExtraction, LLMReceipt]:
        self.extractions += 1
        shell = dict(raw_context["deterministic_shell"])
        extraction = SemanticVacancyExtraction(
            source_content_sha256=str(raw_context["content_sha256"]),
            title=str(shell["title"]),
            company=str(shell["company"]),
            location=str(shell["location"]),
            description=str(shell["description"]),
            responsibilities=("Build reliable automation",),
            required_skills=("Python",),
            preferred_skills=("SQLite",),
            required_qualifications=(),
            preferred_qualifications=(),
            work_authorisation=(),
            contract_type="permanent",
            seniority="junior",
            remote_policy="remote",
            extraction_confidence=0.91,
        )
        receipt = LLMReceipt.bind(
            receipt_id=f"extract-{self.extractions}",
            task="semantic_vacancy_extraction",
            model="fixture-semantic-v1",
            prompt_version="extract-v1",
            inputs=raw_context,
            output=extraction,
            created_at="2026-08-20T00:00:00Z",
        )
        if self.drift_extraction_input:
            receipt = replace(receipt, input_sha256="f" * 64)
        return extraction, receipt

    def align_evidence(
        self, context: Mapping[str, Any]
    ) -> tuple[EvidenceAlignment, LLMReceipt]:
        self.alignments += 1
        vacancy = dict(context["vacancy"])
        profile = dict(context["profile"])
        job_key = f"{vacancy['board']}:{vacancy['job_id']}"
        alignment = EvidenceAlignment(
            profile_id=str(profile["profile_id"]),
            profile_version=str(profile["profile_version"]),
            job_key=job_key,
            matches=(
                EvidenceMatch(
                    requirement="Python",
                    evidence_ids=("ev-python",),
                    strength=0.9,
                    rationale="The evidence explicitly demonstrates Python automation.",
                ),
            ),
            missing_requirements=(),
            technical_alignment=0.8,
            evidence_match=0.9,
            confidence=0.9,
        )
        receipt = LLMReceipt.bind(
            receipt_id=f"align-{self.alignments}",
            task="evidence_alignment",
            model="fixture-semantic-v1",
            prompt_version="align-v1",
            inputs=context,
            output=alignment,
            created_at="2026-08-20T00:00:00Z",
        )
        return alignment, receipt


def _processing_fixture(root: Path, *, jobs: int = 1) -> tuple[str, Path]:
    profile_id = new_profile_id()
    evidence = EvidenceItem(
        evidence_id="ev-python",
        kind="project",
        claim="Built a production-style Python automation system.",
        source_ref="fixture://project/python",
        status="verified",
        confidence=0.9,
        content_sha256="a" * 64,
    )
    profile = CandidateProfile(
        profile_id=profile_id,
        version="fixture-v1",
        tracks={
            "automation": TrackProfile(
                interest=9,
                demonstrated_skill=8,
                confidence=0.9,
                market_readiness=8,
                evidence_ids=(evidence.evidence_id,),
                rationale="Verified fixture track.",
            )
        },
    )
    ProfileStore(root).save(profile, [evidence])
    database = JobDatabase(root / "state" / "vacancies.sqlite3")
    for index in range(1, jobs + 1):
        job = JobUrl("fixture", str(index), f"https://jobs.example.test/{index}")
        database.upsert_discovered(job)
        database.store_raw(
            RawPosting(
                board=job.board,
                job_id=job.job_id,
                url=job.url,
                fetched_at="2026-08-20T00:00:00Z",
                raw_json={
                    "title": f"Automation Engineer {index}",
                    "company": "Example",
                    "location": "Remote UK",
                    "description": "Build reliable Python automation.",
                },
            )
        )
    config = root / "config.yaml"
    config.write_text(
        "processing:\n"
        "  shard_size: 1\n"
        "  lease_seconds: 60\n",
        encoding="utf-8",
    )
    return profile_id, config


class ServiceTests(unittest.TestCase):
    def test_process_one_cli_requires_exact_job_key(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "process-one",
                    "--config", "config.yaml",
                    "--profile-id", "prf_fixture",
                    "--track", "automation",
                    "--worker-id", "exact",
                    "--model", "fixture",
                ]
            )
        parsed = parser.parse_args(
            [
                "process-one",
                "--config", "config.yaml",
                "--profile-id", "prf_fixture",
                "--track", "automation",
                "--worker-id", "exact",
                "--job-key", "workable:cogna:847CFBC5F4",
                "--model", "gpt-5.6-sol",
            ]
        )
        self.assertEqual("workable:cogna:847CFBC5F4", parsed.job_key)

    def test_process_one_promotes_processes_and_reports_only_exact_job_key(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root, jobs=0)
            source_path = root / "scraper" / "data_overnight" / "jobs.sqlite3"
            source = JobDatabase(source_path)
            for index in (1, 2):
                job = JobUrl("fixture", str(index), f"https://jobs.example.test/{index}")
                source.upsert_discovered(job)
                source.store_raw(
                    RawPosting(
                        job.board,
                        job.job_id,
                        job.url,
                        "2026-08-20T00:00:00Z",
                        raw_json={
                            "title": f"Automation Engineer {index}",
                            "company": "Example",
                            "location": "Remote UK",
                            "description": "Build reliable Python automation.",
                        },
                    )
                )
            config.write_text(
                "io:\n"
                "  database: scraper/data_overnight/jobs.sqlite3\n"
                "processing:\n"
                "  shard_size: 10\n"
                "  lease_seconds: 60\n",
                encoding="utf-8",
            )
            worker = FixtureSemanticWorker()
            first = ProcessingService(root, worker).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="exact-one",
                job_key="fixture:2",
            )
            self.assertEqual(1, worker.extractions)
            self.assertEqual(1, worker.alignments)
            self.assertEqual(1, first["shard_claimed"])
            self.assertEqual("fixture:2", first["scope"]["job_key"])
            self.assertEqual("fixture:2", first["promotion"]["job_key"])
            self.assertEqual(1, first["promotion"]["eligible_fetched"])
            self.assertEqual(1, first["ranked_count"])
            canonical_keys = [
                f"{row['board']}:{row['job_id']}"
                for row in JobDatabase(root / "state" / "vacancies.sqlite3")
                .collection_state()["postings"]
            ]
            self.assertEqual(["fixture:2"], canonical_keys)

            replay_worker = FixtureSemanticWorker()
            replay = ProcessingService(root, replay_worker).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="exact-replay",
                job_key="fixture:2",
            )
            self.assertEqual(0, replay["shard_claimed"])
            self.assertEqual(1, replay["ranked_count"])
            self.assertEqual(0, replay_worker.extractions)
            self.assertEqual(0, replay_worker.alignments)

            with self.assertRaisesRegex(KeyError, "no exact vacancy"):
                ProcessingService(root, FixtureSemanticWorker()).process(
                    config,
                    profile_id=profile_id,
                    track="automation",
                    worker_id="missing-exact",
                    job_key="fixture:missing",
                )

    def test_concurrent_board_scopes_have_isolated_deterministic_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, _ = _processing_fixture(root, jobs=0)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            for board in ("workable", "workday"):
                job = JobUrl(board, "1", f"https://jobs.example.test/{board}/1")
                database.upsert_discovered(job)
                database.store_raw(
                    RawPosting(
                        board=job.board,
                        job_id=job.job_id,
                        url=job.url,
                        fetched_at="2026-08-20T00:00:00Z",
                        raw_json={
                            "title": f"Automation Engineer {board}",
                            "company": "Example",
                            "location": "Remote UK",
                            "description": "Build reliable Python automation.",
                        },
                    )
                )
            configs = {}
            for board in ("workable", "workday"):
                path = root / f"{board}.yaml"
                path.write_text(
                    "processing:\n"
                    "  shard_size: 10\n"
                    "  lease_seconds: 60\n"
                    f"  include_boards: [{board}]\n",
                    encoding="utf-8",
                )
                configs[board] = path

            def process(board: str, suffix: str):
                return ProcessingService(root, FixtureSemanticWorker()).process(
                    configs[board],
                    profile_id=profile_id,
                    track="automation",
                    worker_id=f"{board}-{suffix}",
                )

            with ThreadPoolExecutor(max_workers=2) as pool:
                futures = {
                    board: pool.submit(process, board, "concurrent")
                    for board in configs
                }
                first = {board: future.result() for board, future in futures.items()}

            workable_path = Path(first["workable"]["reports"]["ranked_json"])
            workday_path = Path(first["workday"]["reports"]["ranked_json"])
            self.assertNotEqual(workable_path.parent, workday_path.parent)
            self.assertRegex(workable_path.parent.name, r"^scope_[0-9a-f]{64}$")
            self.assertRegex(workday_path.parent.name, r"^scope_[0-9a-f]{64}$")
            self.assertEqual(
                {"workable:1"},
                {
                    row["job_key"]
                    for row in json.loads(workable_path.read_text())["jobs"]
                },
            )
            self.assertEqual(
                {"workday:1"},
                {
                    row["job_key"]
                    for row in json.loads(workday_path.read_text())["jobs"]
                },
            )

            replay = {
                board: process(board, "replay")
                for board in ("workable", "workday")
            }
            for board in replay:
                self.assertEqual(
                    first[board]["report_namespace_sha256"],
                    replay[board]["report_namespace_sha256"],
                )
                self.assertEqual(first[board]["reports"], replay[board]["reports"])
                self.assertEqual(
                    first[board]["report_hashes"], replay[board]["report_hashes"]
                )

    def test_current_processing_result_promotes_atomically_and_rejects_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            run = ProcessingService(root, FixtureSemanticWorker()).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="promotion-worker",
            )
            service = MarketAlignerService(root)
            legacy = json.loads(Path(run["receipt_path"]).read_bytes())
            legacy.pop("receipt_sha256")
            legacy["config_sha256"] = "0" * 64
            legacy_sha = hashlib.sha256(
                json.dumps(
                    legacy, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
            legacy["receipt_sha256"] = legacy_sha
            legacy_path = Path(run["receipt_path"]).parent / f"{legacy_sha}.json"
            legacy_path.write_text(
                json.dumps(legacy, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(AssessmentPromotionError, "legacy"):
                service.promote_processing(
                    profile_id=profile_id,
                    track="automation",
                    job_key="fixture:1",
                    processing_receipt_path=legacy_path,
                )
            first = service.promote_processing(
                profile_id=profile_id,
                track="automation",
                job_key="fixture:1",
                processing_receipt_path=Path(run["receipt_path"]),
            )
            replay = service.promote_processing(
                profile_id=profile_id,
                track="automation",
                job_key="fixture:1",
                processing_receipt_path=Path(run["receipt_path"]),
            )
            self.assertTrue(first.created)
            self.assertFalse(replay.created)
            self.assertEqual(first.receipt_sha256, replay.receipt_sha256)
            assessment = service.assessments.assessment(profile_id, "fixture:1")
            self.assertEqual("pass", assessment["opportunity_decision"])
            self.assertEqual(first.policy_sha256, assessment["policy_hash"])
            with service.assessments.connection() as connection:
                research = connection.execute(
                    """SELECT status,priority FROM employer_research_queue
                       WHERE profile_id=? AND job_key=?""",
                    (profile_id, "fixture:1"),
                ).fetchone()
            self.assertEqual("queued", research["status"])
            self.assertEqual(
                1_000_000 + round(float(assessment["opportunity"]) * 100_000),
                research["priority"],
            )
            self.assertEqual(first.receipt_path.read_bytes(), bytes(
                service.assessments.processing_promotion(
                    profile_id, "fixture:1"
                )["receipt_bytes"]
            ))

            with JobDatabase(root / "state" / "vacancies.sqlite3").connect() as connection:
                row = connection.execute(
                    "SELECT result_json FROM processing_jobs WHERE job_key='fixture:1'"
                ).fetchone()
                changed = json.loads(row[0])
                changed["included"] = False
                connection.execute(
                    "UPDATE processing_jobs SET result_json=? WHERE job_key='fixture:1'",
                    (json.dumps(changed, sort_keys=True, separators=(",", ":")),),
                )
                connection.commit()
            with self.assertRaisesRegex(AssessmentPromotionError, "stale"):
                service.promote_processing(
                    profile_id=profile_id,
                    track="automation",
                    job_key="fixture:1",
                    processing_receipt_path=Path(run["receipt_path"]),
                )

    def test_processing_schema_migrates_legacy_rows_as_non_current_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "vacancies.sqlite3"
            with sqlite3.connect(path) as connection:
                connection.executescript(
                    """CREATE TABLE processing_jobs (
                         profile_id TEXT NOT NULL, track TEXT NOT NULL,
                         job_key TEXT NOT NULL, authority_sha256 TEXT NOT NULL,
                         source_content_sha256 TEXT NOT NULL, status TEXT NOT NULL,
                         lease_owner TEXT, lease_until REAL, result_json TEXT,
                         error TEXT, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                         PRIMARY KEY(
                           profile_id,track,job_key,authority_sha256,source_content_sha256
                         )
                       );
                       CREATE INDEX processing_jobs_resume ON processing_jobs(
                         profile_id,track,authority_sha256,status,lease_until
                       );"""
                )
                connection.execute(
                    """INSERT INTO processing_jobs(
                         profile_id,track,job_key,authority_sha256,source_content_sha256,
                         status,result_json
                       ) VALUES(?,?,?,?,?,'completed',?)""",
                    ("profile", "track", "board:1", "a" * 64, "b" * 64, '{"included":true}'),
                )

            database = JobDatabase(path)
            with database.connect() as connection:
                columns = {
                    row[1] for row in connection.execute(
                        "PRAGMA table_info(processing_jobs)"
                    )
                }
                migrated = connection.execute(
                    """SELECT processing_config_sha256,status,result_json
                       FROM processing_jobs"""
                ).fetchone()
            self.assertIn("processing_config_sha256", columns)
            self.assertEqual(("0" * 64, "completed", '{"included":true}'), migrated)
            self.assertEqual(
                {"included": True},
                database.reusable_processing_result(
                    profile_id="profile",
                    track="track",
                    job_key="board:1",
                    authority_sha256="a" * 64,
                    source_content_sha256="b" * 64,
                    processing_config_sha256="c" * 64,
                ),
            )

    def test_same_service_code_runs_multiple_profiles_and_new_user(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = ProfileStore(temporary)
            profiles = []
            for index in range(3):
                candidate = CandidateProfile(
                    profile_id=new_profile_id(),
                    version=f"v{index}",
                    tracks={
                        "track": TrackProfile(
                            interest=9 - index,
                            demonstrated_skill=7 - index,
                            confidence=0.8,
                            market_readiness=6,
                            rationale="Evidence-free execution fixture.",
                        )
                    },
                )
                store.save(candidate, [])
                profiles.append(candidate)

            service = MarketAlignerService(temporary)
            results = []
            for candidate in profiles:
                results.append(
                    service.assess(
                        AssessmentRequest(
                            profile_id=candidate.profile_id,
                            job_key="board:1",
                            track="track",
                            url="https://jobs.example.test/1",
                            title="Engineer",
                            company="Example",
                            extraction_confidence=0.9,
                            axes=AssessmentAxes(8, 7, 8, 2, 8),
                        )
                    )
                )
            self.assertEqual({item.profile_id for item in profiles}, {item.profile_id for item in results})
            self.assertTrue(all(item.fit_status is FitStatus.UNCALIBRATED for item in results))
            self.assertEqual(3, sum(len(service.assessments.ranked(item.profile_id)) for item in profiles))

    def test_process_is_resumable_and_writes_current_receipt_bound_reports(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            worker = FixtureSemanticWorker()
            service = ProcessingService(root, worker)

            first = service.process(
                config, profile_id=profile_id, track="automation", worker_id="worker-a"
            )
            self.assertEqual(1, first["shard_claimed"])
            self.assertEqual(1, first["included"])
            self.assertEqual(0, first["errors"])
            self.assertFalse(first["application_authority"])
            self.assertTrue(first["job_specific_opportunity_axes"])
            self.assertEqual(64, len(str(first["opportunity_policy_sha256"])))
            self.assertEqual(64, len(str(first["geographic_preference_policy_sha256"])))
            self.assertEqual(64, len(str(first["scope_sha256"])))
            self.assertEqual(1, first["scope_counts"]["scope_eligible"])
            self.assertEqual(64, len(str(first["evidence_authority_sha256"])))
            self.assertEqual(64, len(str(first["state_sha256"])))
            completed_rows = service.jobs.completed_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=str(first["evidence_authority_sha256"]),
                processing_config_sha256=str(first["config_sha256"]),
            )
            self.assertEqual(64, len(str(completed_rows[0]["opportunity_axes"]["facts_sha256"])))
            self.assertEqual(
                first["opportunity_policy_sha256"],
                completed_rows[0]["opportunity_axes"]["policy_sha256"],
            )
            self.assertEqual(
                "uk_remote", completed_rows[0]["geographic_preference"]["category"]
            )
            self.assertEqual(
                first["geographic_preference_policy_sha256"],
                completed_rows[0]["geographic_preference"]["policy_sha256"],
            )
            reports = {name: Path(path) for name, path in dict(first["reports"]).items()}
            self.assertTrue(all(path.is_file() for path in reports.values()))
            self.assertEqual(
                hashlib.sha256(reports["scatter_png"].read_bytes()).hexdigest(),
                first["report_hashes"]["scatter_png"],
            )
            ranked = json.loads(reports["ranked_json"].read_text(encoding="utf-8"))
            self.assertEqual("market-aligner.fit-opportunity-ranked.v1", ranked["schema_version"])
            self.assertEqual(["fixture:1"], [row["job_key"] for row in ranked["jobs"]])

            second = service.process(
                config, profile_id=profile_id, track="automation", worker_id="worker-b"
            )
            self.assertEqual(0, second["shard_claimed"])
            self.assertEqual(1, second["ranked_count"])
            self.assertEqual((1, 1), (worker.extractions, worker.alignments))

    def test_process_rejects_drifted_receipt_without_partial_result_then_retries(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            bad = ProcessingService(root, FixtureSemanticWorker(drift_extraction_input=True))
            failed = bad.process(
                config, profile_id=profile_id, track="automation", worker_id="worker-bad"
            )
            self.assertEqual(1, failed["errors"])
            self.assertEqual(0, failed["ranked_count"])
            self.assertEqual(
                [],
                bad.jobs.completed_processing(
                    profile_id=profile_id,
                    track="automation",
                    authority_sha256=str(failed["evidence_authority_sha256"]),
                    processing_config_sha256=str(failed["config_sha256"]),
                ),
            )

            good_worker = FixtureSemanticWorker()
            recovered = ProcessingService(root, good_worker).process(
                config, profile_id=profile_id, track="automation", worker_id="worker-good"
            )
            self.assertEqual(1, recovered["shard_claimed"])
            self.assertEqual(0, recovered["errors"])
            self.assertEqual(1, recovered["ranked_count"])

    def test_processing_leases_are_shard_safe(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, _ = _processing_fixture(root, jobs=2)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            authority = "b" * 64
            first = database.claim_fetched_for_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=authority,
                worker_id="worker-a",
                limit=1,
                lease_seconds=60,
            )
            second = database.claim_fetched_for_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=authority,
                worker_id="worker-b",
                limit=2,
                lease_seconds=60,
            )
            self.assertEqual(1, len(first))
            self.assertEqual(1, len(second))
            self.assertTrue({row.key for row in first}.isdisjoint({row.key for row in second}))

    def test_processing_scope_filters_before_calls_and_preserves_excluded_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, _ = _processing_fixture(root, jobs=3)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            excluded = JobUrl("excluded", "1", "https://excluded.example.test/1")
            database.upsert_discovered(excluded)
            database.store_raw(
                RawPosting(
                    board=excluded.board,
                    job_id=excluded.job_id,
                    url=excluded.url,
                    fetched_at="2026-08-20T00:00:00Z",
                    raw_json={"title": "Other", "description": "Other", "location": "Remote"},
                )
            )
            authority = "c" * 64
            scope = {"include_boards": ("fixture",), "exclude_boards": (), "max_total": 2}
            first = database.claim_fetched_for_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=authority,
                worker_id="worker-a",
                limit=1,
                lease_seconds=60,
                **scope,
            )
            second = database.claim_fetched_for_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=authority,
                worker_id="worker-b",
                limit=2,
                lease_seconds=60,
                **scope,
            )
            third = database.claim_fetched_for_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=authority,
                worker_id="worker-c",
                limit=2,
                lease_seconds=60,
                **scope,
            )
            self.assertEqual(["fixture:1"], [row.key for row in first])
            self.assertEqual(["fixture:2"], [row.key for row in second])
            self.assertEqual([], third)
            counts = database.processing_scope_counts(
                profile_id=profile_id,
                track="automation",
                authority_sha256=authority,
                **scope,
            )
            self.assertEqual(
                {
                    "available": 0,
                    "board_eligible": 3,
                    "completed": 0,
                    "excluded_by_board": 1,
                    "excluded_by_limit": 1,
                    "failed": 0,
                    "fetched_total": 4,
                    "leased": 2,
                    "scope_eligible": 2,
                },
                counts,
            )
            with database.connect() as connection:
                queued_keys = {
                    row[0] for row in connection.execute("SELECT job_key FROM processing_jobs")
                }
            self.assertEqual({"fixture:1", "fixture:2"}, queued_keys)

            config = root / "scoped-config.yaml"
            config.write_text(
                "processing:\n"
                "  shard_size: 2\n"
                "  lease_seconds: 60\n"
                "  include_boards: [fixture]\n"
                "  max_total: 2\n",
                encoding="utf-8",
            )
            semantic_worker = FixtureSemanticWorker()
            receipt = ProcessingService(root, semantic_worker).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="worker-scoped",
            )
            self.assertEqual((2, 2), (receipt["shard_claimed"], semantic_worker.extractions))
            self.assertEqual(2, semantic_worker.alignments)
            self.assertEqual(2, receipt["scope_counts"]["scope_eligible"])
            self.assertEqual(1, receipt["scope_counts"]["excluded_by_board"])
            self.assertEqual(1, receipt["scope_counts"]["excluded_by_limit"])
            with database.connect() as connection:
                scoped_keys = {
                    row[0]
                    for row in connection.execute(
                        "SELECT job_key FROM processing_jobs WHERE authority_sha256=?",
                        (receipt["evidence_authority_sha256"],),
                    )
                }
            self.assertEqual({"fixture:1", "fixture:2"}, scoped_keys)

    def test_geographic_preference_is_deterministic_configurable_and_never_rejects_unknown(self) -> None:
        default = GeographicPreferencePolicy()
        examples = (
            ("Remote UK", "remote", "uk_remote", 0),
            ("London", "hybrid", "uk_hybrid", 1),
            ("Birmingham", "on-site", "uk_onsite", 2),
            ("Bucharest, Romania", "remote", "romania_remote", 3),
            ("Remote Europe", "remote", "eu_remote", 4),
            ("Seoul", None, "unknown_other", 5),
        )
        for location, remote_policy, category, rank in examples:
            result = classify_geographic_preference(
                location=location, remote_policy=remote_policy, policy=default
            )
            self.assertEqual((category, rank), (result.category, result.rank))
            self.assertEqual(default.policy_hash, result.policy_sha256)
            self.assertEqual(64, len(result.facts_sha256))

        configured = GeographicPreferencePolicy.from_mapping(
            {"order": ["eu_remote", "uk_remote", "uk_hybrid", "uk_onsite", "romania_remote"]}
        )
        reordered = classify_geographic_preference(
            location="Remote Europe", remote_policy="remote", policy=configured
        )
        self.assertEqual(("eu_remote", 0), (reordered.category, reordered.rank))
        self.assertNotEqual(default.policy_hash, configured.policy_hash)

    def test_collector_database_promotes_into_scoped_processing_and_replays_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root, jobs=0)
            source_path = root / "scraper" / "data_overnight" / "jobs.sqlite3"
            source = JobDatabase(source_path)
            fetched = JobUrl("fixture", "1", "https://jobs.example.test/1")
            discovered = JobUrl("fixture", "2", "https://jobs.example.test/2")
            failed = JobUrl("fixture", "3", "https://jobs.example.test/3")
            for row in (fetched, discovered, failed):
                source.upsert_discovered(row)
            source.store_raw(
                RawPosting(
                    fetched.board,
                    fetched.job_id,
                    fetched.url,
                    "2026-08-20T00:00:00Z",
                    raw_json={
                        "title": "Automation Engineer",
                        "company": "Example",
                        "location": "Remote UK",
                        "description": "Build reliable Python automation.",
                    },
                )
            )
            source.record_error(failed.key, "retry later")
            config.write_text(
                "io:\n"
                "  database: scraper/data_overnight/jobs.sqlite3\n"
                "processing:\n"
                "  shard_size: 10\n"
                "  lease_seconds: 60\n"
                "  include_boards: [fixture]\n"
                "  max_total: 2\n",
                encoding="utf-8",
            )
            source_before = hashlib.sha256(source_path.read_bytes()).hexdigest()
            worker = FixtureSemanticWorker()
            service = ProcessingService(root, worker)
            first = service.process(
                config, profile_id=profile_id, track="automation", worker_id="promote-a"
            )
            self.assertEqual((1, 1), (first["promotion"]["imported"], first["shard_claimed"]))
            self.assertEqual(1, first["promotion"]["excluded_discovered"])
            self.assertEqual(1, first["promotion"]["excluded_error"])
            self.assertFalse(first["promotion"]["application_authority"])
            self.assertTrue(Path(first["promotion_receipt_path"]).is_file())
            self.assertEqual(first["promotion"]["receipt_sha256"], first["promotion_sha256"])
            for name in (
                "source_content_sha256", "source_db_sha256", "source_path_sha256",
                "source_schema_sha256", "config_sha256",
            ):
                self.assertEqual(64, len(first["promotion"][name]))
            self.assertEqual(source_before, hashlib.sha256(source_path.read_bytes()).hexdigest())
            self.assertEqual((1, 1), (worker.extractions, worker.alignments))

            second = service.process(
                config, profile_id=profile_id, track="automation", worker_id="promote-b"
            )
            self.assertEqual((0, 0, 1), (
                second["promotion"]["imported"],
                second["promotion"]["updated"],
                second["promotion"]["unchanged"],
            ))
            self.assertEqual(0, second["shard_claimed"])
            self.assertEqual((1, 1), (worker.extractions, worker.alignments))

            source.store_raw(
                RawPosting(
                    fetched.board,
                    fetched.job_id,
                    fetched.url,
                    "2026-08-20T01:00:00Z",
                    raw_json={
                        "title": "Automation Engineer",
                        "company": "Example",
                        "location": "Remote UK",
                        "description": "Updated complete Python automation evidence.",
                    },
                )
            )
            third = service.process(
                config, profile_id=profile_id, track="automation", worker_id="promote-c"
            )
            self.assertEqual(1, third["promotion"]["updated"])
            self.assertEqual(1, third["shard_claimed"])
            self.assertEqual((2, 2), (worker.extractions, worker.alignments))

    def test_concurrent_promotion_is_atomic_and_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = JobDatabase(root / "collector.sqlite3")
            for index in range(2):
                row = JobUrl("fixture", str(index), f"https://jobs.example.test/{index}")
                source.upsert_discovered(row)
                source.store_raw(
                    RawPosting(
                        row.board,
                        row.job_id,
                        row.url,
                        "2026-08-20T00:00:00Z",
                        raw_text=f"posting {index}",
                    )
                )
            target = JobDatabase(root / "target.sqlite3")
            with ThreadPoolExecutor(max_workers=2) as pool:
                results = list(
                    pool.map(
                        lambda _: target.promote_fetched_from(
                            source.path, config_sha256="d" * 64
                        ),
                        range(2),
                    )
                )
            self.assertEqual(2, sum(int(result["imported"]) for result in results))
            self.assertEqual(2, sum(int(result["unchanged"]) for result in results))
            self.assertEqual(2, target.stats()["fetched"])

    def test_first_job_scope_rejects_explicit_barriers_before_alignment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root, jobs=0)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            titles = (
                "Senior Full Stack Developer",
                "Azure Principal Platform Engineer - UK Security Clearance eligibility required",
            )
            for index, title in enumerate(titles, 1):
                row = JobUrl("workable", str(index), f"https://jobs.example.test/{index}")
                database.upsert_discovered(row)
                database.store_raw(
                    RawPosting(
                        row.board,
                        row.job_id,
                        row.url,
                        "2026-08-20T00:00:00Z",
                        raw_json={
                            "title": title,
                            "company": "Example",
                            "location": "Remote UK",
                            "description": "Lead a task while building reliable automation.",
                        },
                    )
                )
            config.write_text(
                "processing:\n  shard_size: 10\n  lease_seconds: 60\n",
                encoding="utf-8",
            )
            worker = FixtureSemanticWorker()
            service = ProcessingService(root, worker)
            receipt = service.process(
                config, profile_id=profile_id, track="automation", worker_id="scope-gate"
            )
            self.assertEqual((2, 0), (worker.extractions, worker.alignments))
            self.assertEqual((2, 0, 0), (
                receipt["rejected"], receipt["parked"], receipt["ranked_count"],
            ))
            results = service.jobs.completed_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=str(receipt["evidence_authority_sha256"]),
                processing_config_sha256=str(receipt["config_sha256"]),
            )
            self.assertEqual(2, len(results))
            self.assertTrue(all(not result["included"] for result in results))
            self.assertEqual(
                {"explicit_senior_title", "explicit_clearance_barrier"},
                {result["first_job_scope"]["reason"] for result in results},
            )
            self.assertTrue(all(
                result["first_job_scope"]["policy_sha256"]
                == receipt["first_job_scope_policy_sha256"]
                for result in results
            ))
            with self.assertRaisesRegex(
                AssessmentPromotionError, "rejected, parked or malformed"
            ):
                MarketAlignerService(root).promote_processing(
                    profile_id=profile_id,
                    track="automation",
                    job_key="workable:1",
                    processing_receipt_path=Path(receipt["receipt_path"]),
                )

    def test_policy_change_reprocesses_stale_completed_row_from_semantic_cache(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root, jobs=0)
            database = JobDatabase(root / "state" / "vacancies.sqlite3")
            row = JobUrl("workable", "senior", "https://jobs.example.test/senior")
            database.upsert_discovered(row)
            database.store_raw(
                RawPosting(
                    row.board,
                    row.job_id,
                    row.url,
                    "2026-08-20T00:00:00Z",
                    raw_json={
                        "title": "Sr. Automation Engineer",
                        "company": "Example",
                        "location": "Remote UK",
                        "description": "Build reliable Python automation.",
                    },
                )
            )
            config.write_text(
                "processing:\n  shard_size: 10\n  lease_seconds: 60\n",
                encoding="utf-8",
            )
            worker = FixtureSemanticWorker()
            permissive = FirstJobScopePolicy(senior_title_patterns=(r"$^",))
            stale = ProcessingService(root, worker, first_job_policy=permissive).process(
                config, profile_id=profile_id, track="automation", worker_id="old-policy"
            )
            self.assertEqual((1, 1, 1), (
                stale["ranked_count"], worker.extractions, worker.alignments,
            ))

            current = ProcessingService(root, worker).process(
                config, profile_id=profile_id, track="automation", worker_id="new-policy"
            )
            self.assertNotEqual(stale["config_sha256"], current["config_sha256"])
            self.assertEqual((1, 1), (worker.extractions, worker.alignments))
            self.assertEqual((1, 0, 1, 0), (
                current["shard_claimed"], current["ranked_count"],
                current["semantic_extractions_reused"],
                current["evidence_alignments_reused"],
            ))
            current_rows = database.completed_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=str(current["evidence_authority_sha256"]),
                processing_config_sha256=str(current["config_sha256"]),
            )
            self.assertEqual(1, len(current_rows))
            self.assertFalse(current_rows[0]["included"])
            self.assertEqual(
                "explicit_senior_title",
                current_rows[0]["first_job_scope"]["reason"],
            )


if __name__ == "__main__":
    unittest.main()

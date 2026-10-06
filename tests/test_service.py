from __future__ import annotations

from dataclasses import asdict, replace
from concurrent.futures import ThreadPoolExecutor
from contextlib import redirect_stdout
import base64
import hashlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import traceback
import unittest
from unittest.mock import patch
from pathlib import Path
from typing import Any, Mapping

from market_aligner.applications.canonical import ContractValidationError
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
    LLMTransportReceipt,
    SemanticVacancyExtraction,
    VACANCY_ELIGIBILITY_FIELDS,
    VACANCY_ELIGIBILITY_FACTS_TASK,
    VacancyEligibilityEvidence,
    VacancyEligibilityFacts,
)
from market_aligner.llm.pipeline import (
    accept_vacancy_eligibility_facts,
    vacancy_eligibility_input,
)
from market_aligner.profiler.schema import (
    CandidateProfile,
    EvidenceItem,
    TrackProfile,
    new_profile_id,
)
from market_aligner.profiler.store import ProfileStore
from market_aligner.research.store import choose_processing_promotion_transition
from market_aligner.service.api import AssessmentRequest, MarketAlignerService
from market_aligner.service import processing as processing_module
from market_aligner.service.processing import ProcessingService
from market_aligner.state.vacancies import JobDatabase, raw_posting_content_sha256


class FixtureSemanticWorker:
    def __init__(
        self,
        *,
        drift_extraction_input: bool = False,
        eligibility_prompt_version: str | None = "eligibility-v1",
    ) -> None:
        self.drift_extraction_input = drift_extraction_input
        self.vacancy_eligibility_prompt_version = eligibility_prompt_version
        self.extractions = 0
        self.alignments = 0
        self.eligibility_extractions = 0

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

    def extract_vacancy_eligibility(
        self, raw_context: Mapping[str, Any]
    ) -> tuple[VacancyEligibilityFacts, LLMReceipt]:
        self.eligibility_extractions += 1
        facts = VacancyEligibilityFacts(
            source_content_sha256=str(raw_context["content_sha256"]),
            work_jurisdiction=None,
            required_residence=None,
            sponsorship_available=None,
            minimum_years_experience=None,
            contract_type=None,
            source_evidence=(),
            unknown_fields=tuple(sorted(VACANCY_ELIGIBILITY_FIELDS)),
        )
        receipt = LLMReceipt.bind(
            receipt_id=f"eligibility-{self.eligibility_extractions}",
            task=VACANCY_ELIGIBILITY_FACTS_TASK,
            model="fixture-semantic-v1",
            prompt_version=str(self.vacancy_eligibility_prompt_version),
            inputs=raw_context,
            output=facts,
            created_at="2026-08-20T00:00:00Z",
        )
        return facts, receipt

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


class LegacyFixtureSemanticWorker(FixtureSemanticWorker):
    def __init__(self) -> None:
        super().__init__()
        self.vacancy_eligibility_prompt_version = None
        self.extract_vacancy_eligibility = None


class UnsupportedQuoteFixtureSemanticWorker(FixtureSemanticWorker):
    def extract_vacancy_eligibility(
        self, raw_context: Mapping[str, Any]
    ) -> tuple[VacancyEligibilityFacts, LLMReceipt]:
        self.eligibility_extractions += 1
        facts = VacancyEligibilityFacts(
            source_content_sha256=str(raw_context["content_sha256"]),
            work_jurisdiction=None,
            required_residence=None,
            sponsorship_available=True,
            minimum_years_experience=None,
            contract_type=None,
            source_evidence=(
                VacancyEligibilityEvidence(
                    field="sponsorship_available",
                    quote="We sponsor visas.",
                ),
            ),
            unknown_fields=tuple(
                sorted(set(VACANCY_ELIGIBILITY_FIELDS) - {"sponsorship_available"})
            ),
        )
        receipt = LLMReceipt.bind(
            receipt_id=f"eligibility-rejected-{self.eligibility_extractions}",
            task=VACANCY_ELIGIBILITY_FACTS_TASK,
            model="fixture-semantic-v1",
            prompt_version="eligibility-v1",
            inputs=raw_context,
            output=facts,
            created_at="2026-08-20T00:00:00Z",
        )
        self.rejected_facts = facts
        self.rejected_receipt = receipt
        return facts, receipt


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
    def test_processing_promotion_transition_requires_changed_source_and_receipt(self) -> None:
        existing = {
            "profile_id": "profile-fixture",
            "job_key": "board:1",
            "track": "automation",
            "source_sha256": "a" * 64,
            "receipt_sha256": "b" * 64,
            "receipt_bytes": b"prior receipt",
        }
        proposed = {
            **existing,
            "source_sha256": "c" * 64,
            "receipt_sha256": "d" * 64,
            "receipt_bytes": b"replacement receipt",
        }
        self.assertEqual(
            "replay",
            choose_processing_promotion_transition(
                existing,
                existing,
                publication_exists=False,
                research_lease_active=False,
            ),
        )
        self.assertEqual(
            "supersede",
            choose_processing_promotion_transition(
                existing,
                proposed,
                publication_exists=False,
                research_lease_active=False,
            ),
        )
        for blocked_publication, blocked_lease in ((True, False), (False, True)):
            with self.subTest(
                publication_exists=blocked_publication,
                research_lease_active=blocked_lease,
            ):
                with self.assertRaisesRegex(ValueError, "promotion transition refused"):
                    choose_processing_promotion_transition(
                        existing,
                        proposed,
                        publication_exists=blocked_publication,
                        research_lease_active=blocked_lease,
                    )
        for unchanged in (
            {**proposed, "receipt_sha256": existing["receipt_sha256"]},
            {**proposed, "source_sha256": existing["source_sha256"]},
        ):
            with self.subTest(unchanged=unchanged):
                with self.assertRaisesRegex(ValueError, "promotion transition refused"):
                    choose_processing_promotion_transition(
                        existing,
                        unchanged,
                        publication_exists=False,
                        research_lease_active=False,
                    )

        class KeySubclass(str):
            pass

        malformed = {KeySubclass("profile_id"): "profile-fixture", **existing}
        with self.assertRaisesRegex(ValueError, "promotion transition refused"):
            choose_processing_promotion_transition(
                malformed,
                proposed,
                publication_exists=False,
                research_lease_active=False,
            )

    def test_processing_prompt_version_change_misses_old_semantic_cache(self) -> None:
        cached = {
            "receipt": {
                "task": VACANCY_ELIGIBILITY_FACTS_TASK,
                "prompt_version": "eligibility-v2",
            }
        }
        callbacks: list[str] = []
        self.assertIsNone(
            processing_module.reuse_current_semantic_cache(
                cached,
                expected_task=VACANCY_ELIGIBILITY_FACTS_TASK,
                expected_prompt_version="eligibility-v3",
                validate_current=lambda _record: callbacks.append("stale"),
            )
        )
        self.assertEqual([], callbacks)
        self.assertEqual(
            "validated",
            processing_module.reuse_current_semantic_cache(
                cached,
                expected_task=VACANCY_ELIGIBILITY_FACTS_TASK,
                expected_prompt_version="eligibility-v2",
                validate_current=lambda _record: "validated",
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            old_worker = FixtureSemanticWorker(
                eligibility_prompt_version="eligibility-v2"
            )
            old_run = ProcessingService(root, old_worker).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="prompt-v2-worker",
                job_key="fixture:1",
            )
            new_worker = FixtureSemanticWorker(
                eligibility_prompt_version="eligibility-v3"
            )
            new_run = ProcessingService(root, new_worker).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="prompt-v3-worker",
                job_key="fixture:1",
            )
        self.assertNotEqual(old_run["config_sha256"], new_run["config_sha256"])
        self.assertEqual(1, new_run["shard_claimed"])
        self.assertEqual((0, 0, 1), (
            new_worker.extractions,
            new_worker.alignments,
            new_worker.eligibility_extractions,
        ))

    def test_fresh_assessment_database_is_owner_private_under_common_umask(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "state" / "assessments.sqlite3"
            previous = os.umask(0o022)
            try:
                MarketAlignerService(temporary)
            finally:
                os.umask(previous)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_process_job_cli_requires_exact_job_key(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "process-job",
                    "--config", "config.yaml",
                    "--profile-id", "prf_fixture",
                    "--track", "automation",
                    "--worker-id", "exact",
                    "--model", "fixture",
                ]
            )
        parsed = parser.parse_args(
            [
                "process-job",
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

    def test_process_cli_semantic_worker_plugin_runs_full_pipeline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            plugin_root = root / "plugins"
            plugin_root.mkdir()
            (plugin_root / "semantic_plugin_under_test.py").write_text(
                "from test_service import FixtureSemanticWorker\n"
                "\n"
                "factory_calls = []\n"
                "workers = []\n"
                "\n"
                "\n"
                "def fixture_factory(*, config_path, data_home):\n"
                "    worker = FixtureSemanticWorker()\n"
                "    factory_calls.append((str(config_path), str(data_home)))\n"
                "    workers.append(worker)\n"
                "    return worker\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(plugin_root))
            try:
                args = build_parser().parse_args(
                    [
                        "process",
                        "--config", str(config),
                        "--profile-id", profile_id,
                        "--track", "automation",
                        "--worker-id", "plugin-worker",
                        "--data-home", str(root),
                        "--semantic-worker",
                        "semantic_plugin_under_test:fixture_factory",
                    ]
                )
                output = io.StringIO()
                with redirect_stdout(output):
                    result = args.handler(args)
                module = sys.modules["semantic_plugin_under_test"]
            finally:
                sys.path.remove(str(plugin_root))
                sys.modules.pop("semantic_plugin_under_test", None)
            self.assertEqual(0, result)
            self.assertEqual([(str(config), str(root))], module.factory_calls)
            self.assertEqual(1, module.workers[0].extractions)
            self.assertEqual(1, module.workers[0].alignments)
            receipt = json.loads(output.getvalue())
            self.assertEqual(1, receipt["shard_claimed"])
            self.assertEqual(1, receipt["included"])
            self.assertEqual(0, receipt["errors"])
            self.assertEqual(1, receipt["ranked_count"])
            reports = {
                name: Path(path) for name, path in receipt["reports"].items()
            }
            self.assertTrue(all(path.is_file() for path in reports.values()))
            self.assertEqual(
                hashlib.sha256(reports["ranked_json"].read_bytes()).hexdigest(),
                receipt["report_hashes"]["ranked_json"],
            )
            ranked = json.loads(reports["ranked_json"].read_text(encoding="utf-8"))
            self.assertEqual(["fixture:1"], [row["job_key"] for row in ranked["jobs"]])
            self.assertTrue(
                any((root / "state" / "promotion-receipts").glob("*.json"))
            )
            completed = ProcessingService(
                root, FixtureSemanticWorker()
            ).jobs.completed_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=str(receipt["evidence_authority_sha256"]),
                processing_config_sha256=str(receipt["config_sha256"]),
            )
            self.assertEqual(1, len(completed))

    def test_process_job_cli_semantic_worker_plugin_processes_exact_job(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root, jobs=2)
            plugin_root = root / "plugins"
            plugin_root.mkdir()
            (plugin_root / "semantic_plugin_exact_under_test.py").write_text(
                "from test_service import FixtureSemanticWorker\n"
                "\n"
                "factory_calls = []\n"
                "workers = []\n"
                "\n"
                "\n"
                "def fixture_factory(*, config_path, data_home):\n"
                "    worker = FixtureSemanticWorker()\n"
                "    factory_calls.append((str(config_path), str(data_home)))\n"
                "    workers.append(worker)\n"
                "    return worker\n",
                encoding="utf-8",
            )
            sys.path.insert(0, str(plugin_root))
            try:
                args = build_parser().parse_args(
                    [
                        "process-job",
                        "--config", str(config),
                        "--profile-id", profile_id,
                        "--track", "automation",
                        "--worker-id", "plugin-exact",
                        "--job-key", "fixture:2",
                        "--data-home", str(root),
                        "--semantic-worker",
                        "semantic_plugin_exact_under_test:fixture_factory",
                    ]
                )
                output = io.StringIO()
                with redirect_stdout(output):
                    result = args.handler(args)
                module = sys.modules["semantic_plugin_exact_under_test"]
            finally:
                sys.path.remove(str(plugin_root))
                sys.modules.pop("semantic_plugin_exact_under_test", None)
            self.assertEqual(0, result)
            self.assertEqual([(str(config), str(root))], module.factory_calls)
            self.assertEqual(1, module.workers[0].extractions)
            self.assertEqual(1, module.workers[0].alignments)
            receipt = json.loads(output.getvalue())
            self.assertEqual(1, receipt["shard_claimed"])
            self.assertEqual("fixture:2", receipt["scope"]["job_key"])
            self.assertEqual("fixture:2", receipt["promotion"]["job_key"])
            self.assertEqual(1, receipt["ranked_count"])
            ranked = json.loads(
                Path(receipt["reports"]["ranked_json"]).read_text(encoding="utf-8")
            )
            self.assertEqual(["fixture:2"], [row["job_key"] for row in ranked["jobs"]])

    def test_process_cli_rejects_invalid_semantic_worker_before_state_creation(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            plugin_root = root / "plugins"
            plugin_root.mkdir()
            (plugin_root / "semantic_plugin_broken.py").write_text(
                "not_callable = 123\n"
                "\n"
                "\n"
                "def incompatible_factory(*, config_path, data_home):\n"
                "    class Partial:\n"
                "        def extract_vacancy(self, raw_context):\n"
                "            raise AssertionError(\"must not be called\")\n"
                "\n"
                "    return Partial()\n",
                encoding="utf-8",
            )
            data_home = root / "external-data"
            common = [
                "process",
                "--config", "unused.yaml",
                "--profile-id", "prf_fixture",
                "--track", "automation",
                "--worker-id", "reject",
                "--data-home", str(data_home),
            ]
            cases = [
                ("malformed-spec", ValueError, "module:factory syntax"),
                ("semantic_plugin_missing:factory", ModuleNotFoundError, "semantic_plugin_missing"),
                ("semantic_plugin_broken:not_callable", ValueError, "not callable"),
                (
                    "semantic_plugin_broken:incompatible_factory",
                    ValueError,
                    "incompatible object",
                ),
            ]
            sys.path.insert(0, str(plugin_root))
            try:
                for specification, error_type, message in cases:
                    with self.subTest(specification=specification):
                        args = build_parser().parse_args(
                            common + ["--semantic-worker", specification]
                        )
                        with self.assertRaisesRegex(error_type, message):
                            args.handler(args)
                        self.assertFalse(data_home.exists())
            finally:
                sys.path.remove(str(plugin_root))
                sys.modules.pop("semantic_plugin_broken", None)

    def test_process_cli_requires_exactly_one_semantic_selection(self) -> None:
        parser = build_parser()
        base = [
            "process",
            "--config", "config.yaml",
            "--profile-id", "prf_fixture",
            "--track", "automation",
            "--worker-id", "exact",
        ]
        with self.assertRaises(SystemExit):
            parser.parse_args(
                base + ["--model", "gpt-5.6-sol", "--semantic-worker", "pkg:factory"]
            )
        with self.assertRaises(SystemExit):
            parser.parse_args(base)
        codex = parser.parse_args(base + ["--model", "gpt-5.6-sol"])
        self.assertEqual("gpt-5.6-sol", codex.model)
        self.assertIsNone(codex.semantic_worker)
        plugin = parser.parse_args(base + ["--semantic-worker", "pkg:factory"])
        self.assertEqual("pkg:factory", plugin.semantic_worker)
        self.assertIsNone(plugin.model)
        with self.assertRaises(SystemExit):
            parser.parse_args(
                [
                    "semantic-canary",
                    "--semantic-worker", "pkg:factory",
                    "--output", "out.json",
                ]
            )
        canary = parser.parse_args(
            ["semantic-canary", "--model", "gpt-5.6-sol", "--output", "out.json"]
        )
        self.assertEqual("gpt-5.6-sol", canary.model)
        self.assertFalse(hasattr(canary, "semantic_worker"))

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

    def test_processing_promotion_supersedes_completed_research_and_requeues_current_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            first_run = ProcessingService(root, FixtureSemanticWorker()).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="promotion-first-worker",
                job_key="fixture:1",
            )
            service = MarketAlignerService(root)
            prior = service.promote_processing(
                profile_id=profile_id,
                track="automation",
                job_key="fixture:1",
                processing_receipt_path=Path(first_run["receipt_path"]),
            )
            prior_promotion = service.assessments.processing_promotion(
                profile_id, "fixture:1"
            )
            prior_receipt_bytes = bytes(prior_promotion["receipt_bytes"])
            prior_source_sha256 = str(prior_promotion["source_content_sha256"])
            prior_dossier = json.dumps(
                {
                    "promotion_receipt_sha256": prior.receipt_sha256,
                    "source_content_sha256": prior_source_sha256,
                    "preserved_archive_marker": "prior-completed-research",
                },
                sort_keys=True,
                separators=(",", ":"),
            )
            prior_dossier_sha256 = hashlib.sha256(
                prior_dossier.encode("utf-8")
            ).hexdigest()
            prior_evidence = (
                prior_dossier_sha256,
                prior_source_sha256,
                "e" * 64,
                prior.receipt_sha256,
                "f" * 64,
                "1" * 64,
                "2" * 64,
                "fixture-archive",
                "4" * 64,
                f"receipts/{'3' * 64}.json",
                "market-aligner.research-store-binding.v2",
            )
            with service.assessments.transaction() as connection:
                connection.execute(
                    """UPDATE employer_research_queue SET status='completed',attempts=7
                       WHERE profile_id=? AND job_key=?""",
                    (profile_id, "fixture:1"),
                )
                connection.execute(
                    """INSERT INTO employer_dossiers(
                         profile_id,job_key,dossier_json,dossier_hash,worker_id
                       ) VALUES(?,?,?,?,?)""",
                    (
                        profile_id,
                        "fixture:1",
                        prior_dossier,
                        prior_dossier_sha256,
                        "prior-research-worker",
                    ),
                )
                connection.execute(
                    """INSERT INTO employer_research_evidence(
                         profile_id,job_key,dossier_hash,source_content_sha256,
                         vacancy_snapshot_sha256,promotion_receipt_sha256,
                         canonical_vacancy_object_sha256,semantic_receipt_sha256,
                         receipt_file_sha256,archive_root_identity,
                         archive_root_policy_sha256,receipt_relative_path,schema_version
                       ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (profile_id, "fixture:1", *prior_evidence),
                )
                dossier_before = tuple(
                    connection.execute(
                        "SELECT * FROM employer_dossiers WHERE profile_id=? AND job_key=?",
                        (profile_id, "fixture:1"),
                    ).fetchone()
                )
                evidence_before = tuple(
                    connection.execute(
                        "SELECT * FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                        (profile_id, "fixture:1"),
                    ).fetchone()
                )

            vacancies = JobDatabase(root / "state" / "vacancies.sqlite3")
            previous_raw = vacancies.load_current_raw_snapshot("fixture:1")
            revised_raw = replace(
                previous_raw,
                fetched_at="2026-10-06T16:00:00Z",
                raw_json={
                    **dict(previous_raw.raw_json or {}),
                    "description": "Build reliable Python automation; maintain tests.",
                },
                content_sha256=None,
            )
            vacancies.store_raw(revised_raw)
            current_source_sha256 = raw_posting_content_sha256(
                vacancies.load_current_raw_snapshot("fixture:1")
            )
            self.assertNotEqual(prior_source_sha256, current_source_sha256)

            replacement_run = ProcessingService(
                root, FixtureSemanticWorker()
            ).process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="promotion-replacement-worker",
                job_key="fixture:1",
            )
            self.assertEqual(1, replacement_run["included"])
            self.assertEqual(0, replacement_run["errors"])
            replacement = service.promote_processing(
                profile_id=profile_id,
                track="automation",
                job_key="fixture:1",
                processing_receipt_path=Path(replacement_run["receipt_path"]),
            )
            self.assertTrue(replacement.created)
            current_promotion = service.assessments.processing_promotion(
                profile_id, "fixture:1"
            )
            self.assertEqual(current_source_sha256, current_promotion["source_content_sha256"])
            self.assertNotEqual(prior.receipt_sha256, replacement.receipt_sha256)
            self.assertEqual(
                replacement.receipt_path.read_bytes(),
                bytes(current_promotion["receipt_bytes"]),
            )

            with service.assessments.connection() as connection:
                supersede_event = connection.execute(
                    """SELECT payload_json FROM assessment_events
                       WHERE profile_id=? AND job_key=?
                         AND event_type='processing_assessment_promotion_superseded'""",
                    (profile_id, "fixture:1"),
                ).fetchone()
                queue = connection.execute(
                    """SELECT status,attempts,lease_owner,lease_until,last_error,
                              refresh_event_id,refresh_bridge_sha256
                       FROM employer_research_queue WHERE profile_id=? AND job_key=?""",
                    (profile_id, "fixture:1"),
                ).fetchone()
                dossier_after = tuple(
                    connection.execute(
                        "SELECT * FROM employer_dossiers WHERE profile_id=? AND job_key=?",
                        (profile_id, "fixture:1"),
                    ).fetchone()
                )
                evidence_after = tuple(
                    connection.execute(
                        "SELECT * FROM employer_research_evidence WHERE profile_id=? AND job_key=?",
                        (profile_id, "fixture:1"),
                    ).fetchone()
                )
            self.assertIsNotNone(supersede_event)
            audit = json.loads(supersede_event["payload_json"])
            self.assertEqual(
                prior_receipt_bytes,
                base64.b64decode(audit["prior_promotion"]["receipt_bytes_base64"]),
            )
            self.assertEqual(
                "queued",
                queue["status"],
            )
            self.assertEqual(0, queue["attempts"])
            self.assertIsNone(queue["lease_owner"])
            self.assertIsNone(queue["lease_until"])
            self.assertIsNone(queue["last_error"])
            self.assertIsNone(queue["refresh_event_id"])
            self.assertIsNone(queue["refresh_bridge_sha256"])
            self.assertEqual(dossier_before, dossier_after)
            self.assertEqual(evidence_before, evidence_after)

            new_task = service.assessments.claim_research(
                "replacement-research-worker",
                profile_id=profile_id,
                job_key="fixture:1",
            )
            self.assertIsNotNone(new_task)
            self.assertEqual(current_source_sha256, new_task.source_content_sha256)
            self.assertEqual(replacement.receipt_sha256, new_task.promotion_receipt_sha256)

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
            eligibility_result = completed_rows[0]["vacancy_eligibility"]
            self.assertEqual("source_bound_extraction", eligibility_result["status"])
            self.assertEqual(
                tuple(sorted(VACANCY_ELIGIBILITY_FIELDS)),
                tuple(eligibility_result["facts"]["unknown_fields"]),
            )
            self.assertEqual(
                VACANCY_ELIGIBILITY_FACTS_TASK,
                eligibility_result["receipt"]["task"],
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
            self.assertEqual(1, worker.eligibility_extractions)

    def test_processing_upgrade_reuses_semantic_cache_and_extracts_facts_once(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            legacy_worker = LegacyFixtureSemanticWorker()
            legacy_service = ProcessingService(root, legacy_worker)
            legacy = legacy_service.process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="worker-legacy",
                job_key="fixture:1",
            )
            self.assertEqual(0, legacy["errors"])
            self.assertEqual(1, legacy_worker.extractions)
            self.assertEqual(1, legacy_worker.alignments)
            self.assertEqual(0, legacy_worker.eligibility_extractions)

            worker = FixtureSemanticWorker()
            changed_policy = FirstJobScopePolicy(
                senior_title_patterns=(r"\bnever-match-fixture\b",)
            )
            service = ProcessingService(root, worker, first_job_policy=changed_policy)
            upgraded = service.process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="worker-upgrade",
                job_key="fixture:1",
            )
            self.assertEqual(0, upgraded["errors"])
            self.assertEqual(1, upgraded["semantic_extractions_reused"])
            self.assertEqual(1, upgraded["evidence_alignments_reused"])
            self.assertEqual((0, 0, 1), (
                worker.extractions,
                worker.alignments,
                worker.eligibility_extractions,
            ))

            rows = service.jobs.completed_processing(
                profile_id=profile_id,
                track="automation",
                authority_sha256=str(upgraded["evidence_authority_sha256"]),
                processing_config_sha256=str(upgraded["config_sha256"]),
            )
            self.assertEqual("source_bound_extraction", rows[0]["vacancy_eligibility"]["status"])
            repeated = service.process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="worker-repeat",
                job_key="fixture:1",
            )
            self.assertEqual(0, repeated["shard_claimed"])
            self.assertEqual(1, worker.eligibility_extractions)

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

    def test_rejected_eligibility_payload_is_archived_and_replays_exact_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            worker = UnsupportedQuoteFixtureSemanticWorker()
            service = ProcessingService(root, worker)

            result = service.process(
                config,
                profile_id=profile_id,
                track="automation",
                worker_id="worker-rejected-eligibility",
                job_key="fixture:1",
            )

            self.assertEqual(1, result["errors"])
            self.assertEqual(0, result["included"])
            self.assertFalse(result["application_authority"])
            self.assertEqual((1, 1, 0), (
                worker.extractions,
                worker.eligibility_extractions,
                worker.alignments,
            ))
            with sqlite3.connect(service.jobs.path) as connection:
                row = connection.execute(
                    """SELECT status,error,result_json FROM processing_jobs
                       WHERE profile_id=? AND track=? AND job_key=?
                         AND processing_config_sha256=?""",
                    (
                        profile_id,
                        "automation",
                        "fixture:1",
                        result["config_sha256"],
                    ),
                ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual("failed", row[0])
            self.assertIsNone(row[2])
            self.assertIn("eligibility_rejection_archive=archived", row[1])
            self.assertIn("ContractValidationError", row[1])
            self.assertIn(";sha256=", row[1])
            digest = row[1].split(";sha256=", 1)[1].split(";", 1)[0]
            self.assertEqual(64, len(digest))
            self.assertTrue(all(character in "0123456789abcdef" for character in digest))

            archive_path = (
                service.paths.state / f"vacancy-eligibility-rejection-{digest}.json"
            )
            payload = archive_path.read_bytes()
            self.assertEqual(digest, hashlib.sha256(payload).hexdigest())
            self.assertEqual(0o600, stat.S_IMODE(archive_path.stat().st_mode))
            document = json.loads(payload)
            self.assertEqual(
                {
                    "schema_version",
                    "authority_scope",
                    "application_authority",
                    "source_content_sha256",
                    "facts",
                    "receipt",
                    "error_type",
                    "error_message",
                },
                set(document),
            )
            self.assertEqual(
                "market-aligner.vacancy-eligibility-rejection.v1",
                document["schema_version"],
            )
            self.assertEqual("diagnostic_only", document["authority_scope"])
            self.assertIs(document["application_authority"], False)
            self.assertEqual(
                json.loads(json.dumps(asdict(worker.rejected_facts))),
                document["facts"],
            )
            self.assertEqual(
                json.loads(json.dumps(asdict(worker.rejected_receipt))),
                document["receipt"],
            )
            self.assertNotIn("profile", document)
            self.assertNotIn("candidate_inputs", document)

            with sqlite3.connect(service.jobs.path) as connection:
                row = connection.execute(
                    """SELECT board,job_id,url,fetched_at,raw_text,raw_json,content_hash
                       FROM postings WHERE key=?""",
                    ("fixture:1",),
                ).fetchone()
            self.assertIsNotNone(row)
            raw = RawPosting(
                board=row[0],
                job_id=row[1],
                url=row[2],
                fetched_at=row[3] or "",
                raw_text=row[4],
                raw_json=json.loads(row[5]) if row[5] else None,
                content_sha256=row[6],
            )
            facts_document = dict(document["facts"])
            facts_document["source_evidence"] = tuple(
                VacancyEligibilityEvidence(**dict(item))
                for item in facts_document["source_evidence"]
            )
            facts_document["unknown_fields"] = tuple(facts_document["unknown_fields"])
            replayed_facts = VacancyEligibilityFacts(**facts_document)
            receipt_document = dict(document["receipt"])
            if isinstance(receipt_document.get("transport"), dict):
                receipt_document["transport"] = LLMTransportReceipt(
                    **receipt_document["transport"]
                )
            replayed_receipt = LLMReceipt(**receipt_document)
            with self.assertRaises(ContractValidationError) as replay_failure:
                accept_vacancy_eligibility_facts(
                    raw,
                    replayed_facts,
                    replayed_receipt,
                    inputs=vacancy_eligibility_input(raw),
                )
            self.assertEqual(document["error_type"], type(replay_failure.exception).__name__)
            self.assertEqual(document["error_message"], str(replay_failure.exception))
            self.assertEqual(1, worker.eligibility_extractions)

    def test_rejection_archive_failure_is_recorded_without_replacing_validation_error(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_id, config = _processing_fixture(root)
            worker = UnsupportedQuoteFixtureSemanticWorker()
            service = ProcessingService(root, worker)
            atomic_json = processing_module._atomic_json

            def fail_rejection_archive(path: Path, value: object) -> None:
                if path.name.startswith("vacancy-eligibility-rejection-"):
                    raise PermissionError("secondary private path sentinel")
                atomic_json(path, value)

            with patch.object(
                processing_module,
                "_atomic_json",
                side_effect=fail_rejection_archive,
            ):
                result = service.process(
                    config,
                    profile_id=profile_id,
                    track="automation",
                    worker_id="worker-rejected-archive-failure",
                    job_key="fixture:1",
                )

            self.assertEqual(1, result["errors"])
            self.assertEqual(0, result["included"])
            with sqlite3.connect(service.jobs.path) as connection:
                row = connection.execute(
                    """SELECT status,error,result_json FROM processing_jobs
                       WHERE profile_id=? AND track=? AND job_key=?
                         AND processing_config_sha256=?""",
                    (
                        profile_id,
                        "automation",
                        "fixture:1",
                        result["config_sha256"],
                    ),
                ).fetchone()
            self.assertEqual("failed", row[0])
            self.assertIsNone(row[2])
            self.assertIn("ContractValidationError", row[1])
            self.assertIn("eligibility_rejection_archive=failed", row[1])
            self.assertIn("failure_type=PermissionError", row[1])
            self.assertIn(";sha256=", row[1])
            self.assertNotIn("secondary private path sentinel", row[1])
            digest = row[1].split(";sha256=", 1)[1].split(";", 1)[0]
            self.assertFalse(
                (service.paths.state / f"vacancy-eligibility-rejection-{digest}.json").exists()
            )
            self.assertEqual(1, worker.eligibility_extractions)

    def test_rejection_capture_suppresses_secondary_exception_context(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _processing_fixture(root)
            worker = UnsupportedQuoteFixtureSemanticWorker()
            raw = JobDatabase(root / "state" / "vacancies.sqlite3").load_current_raw_snapshot(
                "fixture:1"
            )
            inputs = vacancy_eligibility_input(raw)
            facts, receipt = worker.extract_vacancy_eligibility(inputs)
            real_canonical_bytes = processing_module._canonical_bytes

            for secondary_stage, secondary_type in (
                ("serialization", PermissionError),
                ("archive", OSError),
            ):
                with self.subTest(secondary_stage=secondary_stage):
                    original = ContractValidationError("original validation failure")
                    archive_status: dict[str, str] = {}
                    validation_calls = 0
                    archive_calls = 0

                    def validate() -> VacancyEligibilityFacts:
                        nonlocal validation_calls
                        validation_calls += 1
                        raise original

                    def archive(digest: str, document: dict[str, object]) -> None:
                        nonlocal archive_calls
                        archive_calls += 1
                        raise secondary_type("secondary private path sentinel")

                    def fail_serialization(value: object) -> bytes:
                        if (
                            isinstance(value, dict)
                            and value.get("schema_version")
                            == "market-aligner.vacancy-eligibility-rejection.v1"
                        ):
                            raise secondary_type("secondary private path sentinel")
                        return real_canonical_bytes(value)

                    if secondary_stage == "serialization":
                        context = patch.object(
                            processing_module,
                            "_canonical_bytes",
                            side_effect=fail_serialization,
                        )
                    else:
                        context = patch.object(
                            processing_module,
                            "_canonical_bytes",
                            wraps=real_canonical_bytes,
                        )
                    with context:
                        with self.assertRaises(ContractValidationError) as caught:
                            processing_module._accept_or_archive_eligibility_rejection(
                                facts=facts,
                                receipt=receipt,
                                source_sha256=str(raw.content_sha256),
                                validate=validate,
                                archive=archive,
                                archive_status=archive_status,
                            )
                    self.assertIs(caught.exception, original)
                    self.assertTrue(original.__suppress_context__)
                    self.assertNotIn(
                        "secondary private path sentinel",
                        "".join(traceback.format_exception(original)),
                    )
                    self.assertEqual(1, validation_calls)
                    self.assertEqual(1 if secondary_stage == "archive" else 0, archive_calls)
                    self.assertEqual("archive_failed", archive_status["status"])
                    self.assertEqual(secondary_type.__name__, archive_status["failure_type"])
                    self.assertEqual(
                        secondary_stage == "archive",
                        "sha256" in archive_status,
                    )

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
            self.assertEqual(1, worker.eligibility_extractions)
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

from __future__ import annotations

from dataclasses import replace
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any, Mapping

from market_aligner.assessment.scoring import AssessmentAxes, FitStatus
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
        "  market_demand: 8\n"
        "  barrier_to_entry: 2\n"
        "  growth_potential: 8\n"
        "  shard_size: 1\n"
        "  lease_seconds: 60\n",
        encoding="utf-8",
    )
    return profile_id, config


class ServiceTests(unittest.TestCase):
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
            self.assertFalse(first["job_specific_opportunity_axes"])
            self.assertEqual(64, len(str(first["evidence_authority_sha256"])))
            self.assertEqual(64, len(str(first["state_sha256"])))
            reports = {name: Path(path) for name, path in dict(first["reports"]).items()}
            self.assertTrue(all(path.is_file() for path in reports.values()))
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


if __name__ == "__main__":
    unittest.main()

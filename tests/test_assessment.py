from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path

from market_aligner.assessment.calibration import readiness
from market_aligner.assessment.eligibility import (
    EligibilityInput,
    EligibilityPolicy,
    assess_eligibility,
)
from market_aligner.assessment.opportunity import apply_gate
from market_aligner.assessment.scoring import AssessmentAxes, FitStatus, score
from market_aligner.assessment.viability import assess_viability
from market_aligner.domain.contracts import Vacancy
from market_aligner.llm.contracts import EvidenceAlignment, EvidenceMatch
from market_aligner.normalisation.deduplication import deduplicate
from market_aligner.profiler.schema import CandidateProfile, TrackProfile, new_profile_id
from market_aligner.research.models import (
    ResearchClaim,
    ResearchDossier,
    SourceCitation,
)
from market_aligner.research.store import AssessmentStore


def profile() -> CandidateProfile:
    return CandidateProfile(
        profile_id=new_profile_id(),
        version="v1",
        tracks={
            "applied": TrackProfile(
                interest=9,
                demonstrated_skill=7,
                confidence=0.8,
                market_readiness=7,
                rationale="Fixture profile.",
            )
        },
    )


def vacancy(board: str = "greenhouse", job_id: str = "1", **updates) -> Vacancy:
    values = {
        "board": board,
        "job_id": job_id,
        "url": f"https://jobs.example.test/{job_id}",
        "title": "Applied Engineer",
        "company": "Example Limited",
        "location": "Remote",
        "description": "Build and operate production systems.",
        "posted_at": "2026-07-31",
        "expires_at": "2026-08-31",
    }
    values.update(updates)
    return Vacancy(**values)


class AssessmentTests(unittest.TestCase):
    def test_generic_viability_and_deduplication(self) -> None:
        first = vacancy()
        second = vacancy(
            "lever",
            "2",
            url="https://jobs.example.test/1/apply?tracking=x",
            company="Example Ltd",
            description="A more complete description of the same production role.",
        )
        self.assertEqual("include", assess_viability(first, today=date(2026, 8, 1)).decision)
        self.assertEqual(
            "exclude",
            assess_viability(
                vacancy(expires_at="2026-07-01"),
                today=date(2026, 8, 1),
            ).decision,
        )
        groups = deduplicate([first, second])
        self.assertEqual(1, len(groups))
        self.assertEqual("lever:2", groups[0].representative.key)
        self.assertEqual(("greenhouse:1",), groups[0].duplicate_keys)

    def test_hard_eligibility_rejects_only_explicit_mismatches(self) -> None:
        policy = EligibilityPolicy(
            authorised_jurisdictions=frozenset({"jurisdiction-a", "jurisdiction-b"}),
            current_residence="jurisdiction-a",
            requires_sponsorship=False,
            maximum_years_required=3,
        )
        unknown = assess_eligibility(EligibilityInput(), policy)
        self.assertEqual("review", unknown.decision)
        mismatch = assess_eligibility(
            EligibilityInput(work_jurisdiction="jurisdiction-c", minimum_years_experience=5),
            policy,
        )
        self.assertEqual("reject", mismatch.decision)
        self.assertIn("work_authorisation_mismatch", mismatch.reasons)
        self.assertIn("experience_requirement_exceeds_policy", mismatch.reasons)

    def test_fit_is_explicitly_uncalibrated_and_profile_specific(self) -> None:
        candidate = profile()
        result = score(
            candidate,
            "board:1",
            "applied",
            AssessmentAxes(8, 8, 9, 2, 8),
        )
        self.assertEqual(FitStatus.UNCALIBRATED, result.fit_status)
        self.assertEqual(candidate.profile_id, result.profile_id)
        self.assertGreater(result.final, 70)
        self.assertFalse(readiness(29, 9).ready)
        self.assertTrue(readiness(30, 10).ready)

    def test_llm_alignment_cannot_cite_invented_evidence(self) -> None:
        alignment = EvidenceAlignment(
            profile_id=new_profile_id(),
            profile_version="v1",
            job_key="board:1",
            matches=(EvidenceMatch("Build queues", ("invented",), 0.8, "Claimed match"),),
            missing_requirements=(),
            technical_alignment=0.8,
            evidence_match=0.8,
            confidence=0.7,
        )
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            alignment.validate_evidence_ids({"real"})

    def test_research_is_profile_aware_and_requires_opportunity_pass(self) -> None:
        first = profile()
        second = profile()
        axes = AssessmentAxes(8, 8, 9, 1, 9)
        with tempfile.TemporaryDirectory() as temporary:
            store = AssessmentStore(Path(temporary) / "assessment.sqlite3")
            for candidate in (first, second):
                result = score(candidate, "board:1", "applied", axes)
                store.upsert_score(
                    result,
                    url="https://jobs.example.test/1",
                    title="Applied Engineer",
                    company="Example",
                    extraction_confidence=0.95,
                )
            self.assertEqual(1, len(store.ranked(first.profile_id)))
            self.assertEqual(1, len(store.ranked(second.profile_id)))
            with self.assertRaisesRegex(sqlite3.IntegrityError, "passed opportunity"):
                store.enqueue_research(first.profile_id, "board:1", 1)

            decision = apply_gate(store, first.profile_id, "board:1")
            self.assertTrue(decision.passed)
            task = store.claim_research("worker-1")
            self.assertIsNotNone(task)
            assert task is not None
            self.assertEqual(first.profile_id, task.profile_id)

            citation = SourceCitation(
                "src-1",
                "https://example.test/about",
                "About",
                "2026-08-01T00:00:00Z",
                hashlib.sha256(b"about").hexdigest(),
            )
            dossier = ResearchDossier(
                profile_id=first.profile_id,
                job_key="board:1",
                company="Example",
                role="Applied Engineer",
                claims=(ResearchClaim("The company publishes product documentation.", ("src-1",), 0.9),),
                citations=(citation,),
            )
            digest = store.complete_research(dossier, "worker-1")
            self.assertEqual(64, len(digest))
            self.assertEqual("employer_researched", store.assessment(first.profile_id, "board:1")["state"])
            self.assertEqual("scored", store.assessment(second.profile_id, "board:1")["state"])


if __name__ == "__main__":
    unittest.main()

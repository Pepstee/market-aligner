from __future__ import annotations

import hashlib
import sqlite3
import tempfile
import unittest
from datetime import date
from pathlib import Path

from market_aligner.assessment.calibration import readiness
from market_aligner.assessment.eligibility import (
    EligibilityDecision,
    EligibilityInput,
    EligibilityPolicy,
    assess_eligibility,
)
from market_aligner.assessment.geography import (
    EU_REMOTE_COUNTRIES,
    LocationFacts,
    SelectionBlocked,
    SelectionPolicy,
    classify_geography,
    decide_selection,
    rank_selected,
)
from market_aligner.assessment.opportunity import (
    PreProfileOpportunityConfidence,
    PreProfileOpportunityInput,
    PreProfileOpportunityPolicy,
    apply_gate,
    decide_pre_profile_opportunity,
    derive_opportunity_axes,
    pre_profile_opportunity_score,
)
from market_aligner.assessment.scoring import AssessmentAxes, FitStatus, ScoreResult, score
from market_aligner.assessment.viability import (
    FirstJobScopePolicy,
    assess_first_job_scope,
    assess_viability,
)
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
    @staticmethod
    def _location(country: str, mode: str, basis: str = "explicit") -> LocationFacts:
        return LocationFacts(
            country,
            "",
            "",
            f"{country} {mode}",
            mode,
            basis,
            "json:/location",
        )

    @staticmethod
    def _selection_score(job_key: str, final: float, opportunity: float) -> ScoreResult:
        return ScoreResult(
            "prf_0123456789abcdef0123456789abcdef",
            job_key,
            "synthetic_track",
            final / 100.0,
            opportunity,
            final,
            FitStatus.UNCALIBRATED,
            "0" * 64,
            {"interest": final / 100.0},
            {"market_demand": opportunity},
        )

    def test_explicit_geography_selection_is_evidence_bound_and_fail_closed(self) -> None:
        expected = (
            ("GB", "remote", "UK_REMOTE", 1),
            ("GB", "hybrid", "UK_HYBRID", 2),
            ("GB", "onsite", "UK_ONSITE", 3),
            ("RO", "remote", "RO_REMOTE", 4),
        )
        for country, mode, bucket, rank in expected:
            match = classify_geography(self._location(country, mode))
            self.assertEqual((bucket, rank), (match.bucket, match.priority_rank))
        for country in EU_REMOTE_COUNTRIES:
            match = classify_geography(self._location(country, "remote"))
            self.assertEqual(("EU_REMOTE", 5), (match.bucket, match.priority_rank))

        for facts in (
            self._location("GB", "unknown"),
            self._location("RO", "hybrid"),
            self._location("NO", "remote"),
        ):
            with self.assertRaises(SelectionBlocked):
                classify_geography(facts)
        with self.assertRaises(SelectionBlocked):
            self._location("GB", "remote", "inferred")
        with self.assertRaises(SelectionBlocked):
            self._location("UK", "remote")

    def test_deterministic_selection_enforces_hard_gates_and_geography_first_ranking(self) -> None:
        policy = SelectionPolicy(0.6, 0.5, 0.4, True, 21_600, 86_400, 5)
        geography = classify_geography(self._location("GB", "remote"))
        score_result = self._selection_score("job_a", 80.0, 0.7)
        selected = decide_selection(
            eligibility=EligibilityDecision("pass", (), ()),
            score=score_result,
            geography=geography,
            policy=policy,
            employer_dossier_sha256="0" * 64,
        )
        self.assertTrue(selected.hard_gate_passed)
        self.assertEqual(("UK_REMOTE", 1), (
            selected.geography_bucket,
            selected.geography_priority_rank,
        ))

        for eligibility in (
            EligibilityDecision("review", (), ("unknown",)),
            EligibilityDecision("reject", ("mismatch",), ()),
        ):
            with self.assertRaisesRegex(SelectionBlocked, "eligibility"):
                decide_selection(
                    eligibility=eligibility,
                    score=score_result,
                    geography=geography,
                    policy=policy,
                    employer_dossier_sha256="0" * 64,
                )
        with self.assertRaisesRegex(SelectionBlocked, "dossier"):
            decide_selection(
                eligibility=EligibilityDecision("pass", (), ()),
                score=score_result,
                geography=geography,
                policy=policy,
                employer_dossier_sha256=None,
            )

        ranked = rank_selected(
            [
                (classify_geography(self._location("FR", "remote")), self._selection_score("job_eu", 99.0, 0.9)),
                (classify_geography(self._location("GB", "remote")), self._selection_score("job_uk", 61.0, 0.4)),
                (classify_geography(self._location("RO", "remote")), self._selection_score("job_ro", 95.0, 0.8)),
            ]
        )
        self.assertEqual(
            ["UK_REMOTE", "RO_REMOTE", "EU_REMOTE"],
            [match.bucket for match, _score in ranked],
        )

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

    def test_first_job_scope_uses_title_and_explicit_requirements_not_description_prose(self) -> None:
        positives = (
            ("Graduate Software Engineer", "explicit_entry_title"),
            ("Junior Automation Developer", "explicit_entry_title"),
            ("Implementation Consultant", "configured_adjacent_role"),
            ("Automation Engineer", "configured_adjacent_role"),
        )
        for index, (title, reason) in enumerate(positives, 1):
            decision = assess_first_job_scope(
                vacancy(job_id=f"positive-{index}", title=title)
            )
            self.assertEqual(("include", reason), (decision.decision, decision.reason))
            self.assertEqual(64, len(decision.facts_sha256))
            self.assertEqual(64, len(decision.policy_sha256))

        for title in (
            "Senior Full Stack Developer",
            "Sr. Full Stack Developer",
            "Sr Platform Engineer",
            "Principal Platform Engineer",
            "Staff Software Engineer",
            "Engineering Lead",
            "Director of Automation",
        ):
            decision = assess_first_job_scope(vacancy(title=title))
            self.assertEqual(("exclude", "explicit_senior_title"), (
                decision.decision, decision.reason,
            ))

        for title in (
            "SRE Engineer",
            "CSR Automation Analyst",
            "Research Engineer",
            "User Support Engineer",
        ):
            self.assertNotEqual(
                "explicit_senior_title",
                assess_first_job_scope(vacancy(title=title)).reason,
            )

        clearance = assess_first_job_scope(
            vacancy(title="Azure Platform Engineer - UK Security Clearance eligibility required")
        )
        self.assertEqual(("exclude", "explicit_clearance_barrier"), (
            clearance.decision, clearance.reason,
        ))
        already_cleared = assess_first_job_scope(
            vacancy(
                title="Systems Engineer",
                required_qualifications=(
                    "Candidate already holds high-level UK security clearance",
                ),
            )
        )
        self.assertEqual(("exclude", "explicit_clearance_barrier"), (
            already_cleared.decision, already_cleared.reason,
        ))
        citizenship = assess_first_job_scope(
            vacancy(
                title="Systems Engineer",
                work_authorisation=("Must be a UK citizen",),
            )
        )
        residence = assess_first_job_scope(
            vacancy(
                title="Systems Engineer",
                required_qualifications=("10 years continuous UK residence",),
            )
        )
        for decision in (citizenship, residence):
            self.assertEqual(
                ("exclude", "explicit_citizenship_or_residence_barrier"),
                (decision.decision, decision.reason),
            )
        task_leadership = assess_first_job_scope(
            vacancy(
                title="Automation Engineer",
                description="Lead a task from discovery through delivery.",
            )
        )
        self.assertEqual("include", task_leadership.decision)
        unknown = assess_first_job_scope(vacancy(title="Technology Generalist"))
        self.assertEqual(("park", "first_job_scope_unknown"), (
            unknown.decision, unknown.reason,
        ))

        configured = FirstJobScopePolicy.from_mapping(
            {"adjacent_title_patterns": [r"\bproduct operator\b"]}
        )
        self.assertEqual(
            "include",
            assess_first_job_scope(vacancy(title="Product Operator"), configured).decision,
        )

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

    def test_opportunity_axes_are_job_specific_policy_hashed_fact_proxies(self) -> None:
        accessible = vacancy(
            contract_type="permanent",
            seniority="junior",
            required_skills=("Python", "Git"),
            responsibilities=("Build automation",),
            description="Permanent junior role with mentorship and a learning budget.",
        )
        demanding = vacancy(
            job_id="2",
            seniority="principal",
            required_skills=("Python", "Kubernetes", "AWS", "Terraform", "Go"),
            required_qualifications=("Masters degree", "Eight years experience"),
            work_authorisation=("Existing local work authorisation required",),
        )
        first = derive_opportunity_axes(accessible)
        repeat = derive_opportunity_axes(accessible)
        second = derive_opportunity_axes(demanding)
        self.assertEqual(first, repeat)
        self.assertNotEqual(first.facts_sha256, second.facts_sha256)
        self.assertEqual(first.policy_sha256, second.policy_sha256)
        self.assertLess(first.barrier_to_entry, second.barrier_to_entry)
        self.assertGreater(first.growth_potential, second.growth_potential)
        self.assertIn("explicit_growth:mentorship", first.signals)

    def test_pre_profile_opportunity_gate_is_candidate_independent_and_exact(self) -> None:
        value = PreProfileOpportunityInput.from_mapping(
            {
                "market_demand_bp": 8_000,
                "role_quality_bp": 7_000,
                "accessibility_bp": 9_000,
            }
        )
        confidence = PreProfileOpportunityConfidence(8_000, 8_000, 8_000, 8_000)
        decision = decide_pre_profile_opportunity(value, confidence)
        self.assertEqual(
            (decision.decision, decision.reason, decision.score_bp),
            ("pass", "viable", 7_850),
        )
        self.assertEqual(
            1,
            pre_profile_opportunity_score(
                PreProfileOpportunityInput(1, 0, 0),
                PreProfileOpportunityPolicy(weights=(50, 50, 0)),
            ),
        )
        policy = PreProfileOpportunityPolicy()
        self.assertEqual(policy, PreProfileOpportunityPolicy.from_document(policy.document()))
        for forbidden_field in ("fit", "candidate_fit", "interest", "candidate_interest"):
            poisoned = {
                "market_demand_bp": 8_000,
                "role_quality_bp": 7_000,
                "accessibility_bp": 9_000,
                forbidden_field: 1,
            }
            with self.subTest(forbidden_field=forbidden_field):
                with self.assertRaises(ValueError):
                    PreProfileOpportunityInput.from_mapping(poisoned)
        with self.assertRaises(ValueError):
            PreProfileOpportunityInput.from_mapping(
                {
                    "market_demand_bp": 8_000,
                    "role_quality_bp": 7_000,
                    "accessibility_bp": True,
                }
            )
        for poisoned in (
            {"market_demand_bp": 8_000, "role_quality_bp": 7_000},
            {"market_demand_bp": 8_000, "role_quality_bp": 7_000, "accessibility_bp": 9_000, "extra": 1},
        ):
            with self.assertRaises(ValueError):
                PreProfileOpportunityInput.from_mapping(poisoned)
        self.assertEqual(
            "abstain",
            decide_pre_profile_opportunity(
                value,
                PreProfileOpportunityConfidence(7_499, 8_000, 8_000, 8_000),
            ).decision,
        )
        rejected = decide_pre_profile_opportunity(value, confidence, viability_reason="expired")
        self.assertEqual((rejected.decision, rejected.reason, rejected.score_bp), ("reject", "expired", None))

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


def _pol(**kw):
    return EligibilityPolicy(**kw)




# ==========================================================================
# ELIGIBILITY-001 pure decision-owner contract (accepted document, section 11)
# Canonical values only: uppercase ISO members / lowercase contract enum.
# ==========================================================================



class EligibilityContractMatrixTests(unittest.TestCase):
    def _run(self, policy, **facts):
        d = assess_eligibility(EligibilityInput(**facts), policy)
        return d.decision, list(d.reasons), list(d.unknowns)

    def test_j1_unknown_jurisdiction_reviews_only(self):
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=frozenset({"DE"})),
                      work_jurisdiction=None),
            ("review", [], ["work_jurisdiction_unknown"]))

    def test_j2_exact_match_satisfies_and_sponsorship_irrelevant(self):
        for rs in (True, False, None):
            d = assess_eligibility(
                EligibilityInput(work_jurisdiction="DE"),
                _pol(authorised_jurisdictions=frozenset({"DE"}),
                     requires_sponsorship=rs))
            self.assertEqual((d.decision, list(d.reasons), list(d.unknowns)),
                             ("pass", [], []), rs)

    def test_known_without_member_routes(self):
        pol = _pol(authorised_jurisdictions=frozenset({"DE"}),
                   requires_sponsorship=True)
        self.assertEqual(
            self._run(pol, work_jurisdiction="NL", sponsorship_available=True),
            ("pass", [], []))
        self.assertEqual(
            self._run(pol, work_jurisdiction="NL",
                      sponsorship_available=False),
            ("reject", ["sponsorship_unavailable"], []))
        self.assertEqual(
            self._run(pol, work_jurisdiction="NL",
                      sponsorship_available=None),
            ("review", [], ["sponsorship_availability_unknown"]))
        pol_no_need = _pol(authorised_jurisdictions=frozenset({"DE"}),
                           requires_sponsorship=False)
        self.assertEqual(
            self._run(pol_no_need, work_jurisdiction="NL"),
            ("reject", ["work_authorisation_mismatch"], []))
        pol_unknown_need = _pol(authorised_jurisdictions=frozenset({"DE"}),
                                requires_sponsorship=None)
        self.assertEqual(
            self._run(pol_unknown_need, work_jurisdiction="NL"),
            ("review", [], ["sponsorship_requirement_unknown"]))

    def test_known_empty_set_never_passes_silently(self):
        pol = _pol(authorised_jurisdictions=frozenset(),
                   requires_sponsorship=True)
        self.assertEqual(
            self._run(pol, work_jurisdiction="DE", sponsorship_available=False),
            ("reject", ["sponsorship_unavailable"], []))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=frozenset(),
                           requires_sponsorship=False),
                      work_jurisdiction="DE"),
            ("reject", ["work_authorisation_mismatch"], []))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=frozenset(),
                           requires_sponsorship=None),
                      work_jurisdiction="DE"),
            ("review", [], ["sponsorship_requirement_unknown"]))

    def test_unknown_auth_set_routes(self):
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=None,
                           requires_sponsorship=True),
                      work_jurisdiction="DE", sponsorship_available=True),
            ("pass", [], []))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=None,
                           requires_sponsorship=True),
                      work_jurisdiction="DE", sponsorship_available=False),
            ("reject", ["sponsorship_unavailable"], []))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=None,
                           requires_sponsorship=True),
                      work_jurisdiction="DE", sponsorship_available=None),
            ("review", [], ["sponsorship_availability_unknown"]))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=None,
                           requires_sponsorship=False),
                      work_jurisdiction="DE"),
            ("review", [], ["authorised_jurisdictions_unknown"]))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=None,
                           requires_sponsorship=None),
                      work_jurisdiction="DE"),
            ("review", [],
             ["authorised_jurisdictions_unknown",
              "sponsorship_requirement_unknown"]))

    def test_residence_rows(self):
        base = dict(authorised_jurisdictions=frozenset({"DE"}),
                    current_residence="DE")
        self.assertEqual(self._run(_pol(**base), work_jurisdiction="DE",
                                   required_residence="DE"),
                         ("pass", [], []))
        self.assertEqual(
            self._run(_pol(current_residence="FR",
                           authorised_jurisdictions=frozenset({"DE"})),
                      work_jurisdiction="DE", required_residence="DE"),
            ("reject", ["residence_requirement_mismatch"], []))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=frozenset({"DE"})),
                      work_jurisdiction="DE", required_residence="DE"),
            ("review", [], ["candidate_residence_unknown"]))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=frozenset({"DE"})),
                      work_jurisdiction="DE"),
            ("pass", [], []))

    def test_experience_ceiling_direction(self):
        pol = _pol(authorised_jurisdictions=frozenset({"DE"}),
                   maximum_years_required=2.0)
        self.assertEqual(
            self._run(pol, work_jurisdiction="DE",
                      minimum_years_experience=3.0),
            ("reject", ["experience_requirement_exceeds_policy"], []))
        self.assertEqual(
            self._run(pol, work_jurisdiction="DE",
                      minimum_years_experience=2.0),
            ("pass", [], []))
        self.assertEqual(
            self._run(pol, work_jurisdiction="DE",
                      minimum_years_experience=1.0),
            ("pass", [], []))
        self.assertEqual(
            self._run(_pol(authorised_jurisdictions=frozenset({"DE"})),
                      work_jurisdiction="DE",
                      minimum_years_experience=1.0),
            ("review", [], ["maximum_experience_ceiling_unknown"]))

    def test_contract_dimension_rows(self):
        pol = _pol(authorised_jurisdictions=frozenset({"DE"}),
                   excluded_contract_types=frozenset({"contract"}))
        self.assertEqual(
            self._run(pol, work_jurisdiction="DE",
                      contract_type="contract"),
            ("reject", ["excluded_contract_type"], []))
        self.assertEqual(
            self._run(pol, work_jurisdiction="DE",
                      contract_type="permanent"),
            ("pass", [], []))
        known_empty = _pol(authorised_jurisdictions=frozenset({"DE"}),
                           excluded_contract_types=frozenset())
        self.assertEqual(
            self._run(known_empty, work_jurisdiction="DE",
                      contract_type="contract"),
            ("pass", [], []))
        unknown_excl = _pol(authorised_jurisdictions=frozenset({"DE"}),
                            excluded_contract_types=None)
        self.assertEqual(
            self._run(unknown_excl, work_jurisdiction="DE",
                      contract_type="contract"),
            ("review", [], ["excluded_contract_types_unknown"]))
        absent_contract = _pol(authorised_jurisdictions=frozenset({"DE"}),
                               excluded_contract_types=None)
        self.assertEqual(
            self._run(absent_contract, work_jurisdiction="DE"),
            ("pass", [], []))

    def test_reject_dominates_and_order_is_ascii_sorted(self):
        d = assess_eligibility(
            EligibilityInput(work_jurisdiction="NL",
                             required_residence="NL",
                             minimum_years_experience=5.0),
            _pol(authorised_jurisdictions=frozenset({"DE"}),
                 current_residence="DE",
                 requires_sponsorship=False,
                 maximum_years_required=2.0,
                 excluded_contract_types=frozenset()))
        self.assertEqual(d.decision, "reject")
        self.assertEqual(list(d.reasons),
                         ["experience_requirement_exceeds_policy",
                          "residence_requirement_mismatch",
                          "work_authorisation_mismatch"])
        self.assertEqual(list(d.unknowns), [])

    def test_policy_types_preserve_unknown_vs_known_empty(self):
        p = EligibilityPolicy()
        self.assertIsNone(p.authorised_jurisdictions)
        self.assertIsNone(p.excluded_contract_types)
        self.assertIsInstance(
            EligibilityPolicy(
                authorised_jurisdictions=frozenset()).authorised_jurisdictions,
            frozenset)

    def test_worked_example_a_normative(self):
        d = assess_eligibility(
            EligibilityInput(work_jurisdiction="NL",
                             required_residence="NL",
                             sponsorship_available=False,
                             minimum_years_experience=3.0,
                             contract_type="permanent"),
            _pol(authorised_jurisdictions=frozenset({"DE"}),
                 current_residence="DE",
                 requires_sponsorship=True,
                 maximum_years_required=2.0,
                 excluded_contract_types=frozenset()))
        self.assertEqual(d.decision, "reject")
        self.assertEqual(list(d.reasons),
                         ["experience_requirement_exceeds_policy",
                          "residence_requirement_mismatch",
                          "sponsorship_unavailable"])
        self.assertEqual(list(d.unknowns), [])


if __name__ == "__main__":
    unittest.main()

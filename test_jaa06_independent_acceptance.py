"""Independent acceptance tests for the bounded offline JAA-06 contract."""

from __future__ import annotations

import hashlib
from datetime import date

from career_automation.application_strategy import (
    ELEMENT_KINDS,
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
)
from career_automation.evidence_matching import MatchResult, MatchingPolicy, Requirement


AS_OF = date(2030, 1, 2)
DIGEST = hashlib.sha256(b"jaa06-acceptance").hexdigest()
POLICY = MatchingPolicy()


def _requirement(
    requirement_id: str,
    *,
    essential: bool = True,
    gap_kind: str = "evidence",
) -> Requirement:
    bridge = "fatal" if gap_kind == "structural" else "build_evidence"
    proofs = ("verified_claim",) if gap_kind == "structural" else ("portfolio_artifact",)
    return Requirement(
        requirement_id,
        f"claim-{requirement_id}",
        f"Atomic requirement {requirement_id}.",
        essential,
        gap_kind,
        bridge,
        proofs,
        8000,
        "vacancy:locked",
        (0, 10),
    )


def _matched(requirement: Requirement) -> MatchResult:
    return MatchResult(
        requirement.requirement_id,
        "matched",
        (f"evidence-{requirement.requirement_id}",),
        9000,
        "approved evidence",
        POLICY.policy_hash,
        None,
    )


def _support(requirement: Requirement) -> CandidateSupport:
    return CandidateSupport(
        requirement.requirement_id,
        requirement.criterion,
        1,
        f"evidence-{requirement.requirement_id}",
        1,
        requirement.accepted_proof_classes[0],
        "approved",
        "evidence",
        "approved",
        "evidence",
        "approved",
        date(2035, 1, 1),
    )


def _fact(
    claim_id: str = "research-role",
    source_ids: tuple[str, ...] = (
        "source:official-vacancy",
        "source:official-role",
    ),
) -> EmployerResearchFact:
    return EmployerResearchFact(
        claim_id,
        "role",
        "fact",
        source_ids,
        DIGEST,
        "current",
    )


def test_apply_now_strategy_is_complete_linked_and_reproducible() -> None:
    requirements = (_requirement("python"), _requirement("delivery"))
    results = tuple(_matched(row) for row in requirements)
    supports = tuple(_support(row) for row in requirements)
    arguments = {
        "fit_run_id": DIGEST,
        "dossier_hash": hashlib.sha256(b"dossier").hexdigest(),
        "candidate_profile_hash": hashlib.sha256(b"profile").hexdigest(),
        "requirements": requirements,
        "match_results": results,
        "candidate_support": supports,
        "employer_facts": (_fact(),),
        "as_of": AS_OF,
    }
    strategy = compile_application_strategy(**arguments)
    assert strategy == compile_application_strategy(**{
        **arguments,
        "requirements": tuple(reversed(requirements)),
        "match_results": tuple(reversed(results)),
        "candidate_support": tuple(reversed(supports)),
        "employer_facts": (_fact(
            source_ids=(
                "source:official-role",
                "source:official-vacancy",
            ),
        ),),
    })
    assert strategy.decision == "apply_now"
    assert strategy.certifies_slice is False
    assert strategy.dependency_gate == "JAA-05"
    assert len(strategy.coverage) == 2
    assert len(strategy.elements) == 2 * len(ELEMENT_KINDS)
    assert {row.kind for row in strategy.elements} == set(ELEMENT_KINDS)
    for element in strategy.elements:
        assert element.requirement_id
        assert element.candidate_claim_id
        assert element.candidate_evidence_id
        assert element.employer_research_claim_id == "research-role"
        assert element.employer_fact_sha256 == DIGEST
    document = strategy.document()
    assert document["schema_version"] == "jaa06.application-strategy.v1"
    assert document["strategy_id"] == strategy.strategy_id
    assert document["document_sha256"] == strategy.document_sha256


def test_bridgeable_gap_selects_close_gap_without_document_directives() -> None:
    mandatory = _requirement("mandatory")
    optional = _requirement("optional", essential=False)
    results = (
        _matched(mandatory),
        MatchResult(
            optional.requirement_id,
            "no_match",
            (),
            9000,
            "not demonstrated",
            POLICY.policy_hash,
            None,
        ),
    )
    strategy = compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(mandatory, optional),
        match_results=results,
        candidate_support=(_support(mandatory),),
        employer_facts=(),
        as_of=AS_OF,
    )
    assert strategy.decision == "close_gap_first"
    assert [row.state for row in strategy.coverage] == ["covered", "absent"]
    assert strategy.elements == ()


def test_uncovered_structural_requirement_rejects_candidacy() -> None:
    structural = _requirement("work-right", gap_kind="structural")
    strategy = compile_application_strategy(
        fit_run_id=DIGEST,
        dossier_hash=hashlib.sha256(b"dossier").hexdigest(),
        candidate_profile_hash=hashlib.sha256(b"profile").hexdigest(),
        requirements=(structural,),
        match_results=(MatchResult(
            structural.requirement_id,
            "no_match",
            (),
            9900,
            "mandatory right absent",
            POLICY.policy_hash,
            None,
        ),),
        candidate_support=(),
        employer_facts=(),
        as_of=AS_OF,
    )
    assert strategy.decision == "reject_candidacy"
    assert strategy.coverage[0].state == "release_blocking"
    assert strategy.elements == ()

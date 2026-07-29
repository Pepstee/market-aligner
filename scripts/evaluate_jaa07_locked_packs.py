#!/usr/bin/env python3
"""Evaluate the checked synthetic JAA-07 packs without certifying the slice."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from datetime import date
from pathlib import Path
from typing import Mapping

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from career_automation.application_compiler import (  # noqa: E402
    ApplicationSource,
    CandidateContact,
    DocumentSection,
    FactAuthority,
    FactualSentence,
    StructuredAnswer,
    StyleSlot,
    compile_application_source,
)
from career_automation.application_strategy import (  # noqa: E402
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
)
from career_automation.evidence_matching import (  # noqa: E402
    MatchResult,
    MatchingPolicy,
    Requirement,
    canonical_json,
    content_hash,
)
from career_automation.rendering import render_pdf_artifacts  # noqa: E402


DEFAULT_FIXTURE = (
    ROOT / "career_automation/fixtures/jaa07_locked_application_packs.json"
)
LIMITATIONS = (
    "Synthetic packs do not establish production document quality.",
    "Synthetic employers, vacancies, contacts and claims are not applicant data.",
    "This cohort cannot certify JAA-07 or unblock upstream authority.",
    "No artifact is released, submitted or published outside the temporary evaluator directory.",
)
METRIC_NAMES = (
    "page_contract",
    "parse_success",
    "section_contract",
    "requirement_coverage",
    "provenance_completeness",
    "factual_preservation",
    "deterministic_replay",
)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _slot(case_id: str, document_kind: str, purpose: str, text: str) -> StyleSlot:
    return StyleSlot(
        content_hash(
            {
                "contract": "jaa07.locked-style.v1",
                "case_id": case_id,
                "document_kind": document_kind,
                "purpose": purpose,
                "text": text,
            }
        ),
        document_kind,
        text,
    )


def _pack(case: Mapping[str, object]) -> ApplicationSource:
    case_id = str(case["id"])
    company = str(case["company"])
    role = str(case["role"])
    metric = str(case["metric"])
    year = str(case["year"])
    requirement_id = f"requirement:{case_id}"
    claim_id = f"claim:{case_id}"
    evidence_id = f"evidence:{case_id}"
    research_id = f"research:{case_id}"
    candidate_text = (
        f"Delivered the {case_id} service at {metric} availability in {year}."
    )
    employer_text = (
        f"{company} publishes an official service reliability objective."
    )
    employer_document = {
        "id": research_id,
        "kind": "company",
        "classification": "fact",
        "text": employer_text,
        "observed_at": "2030-01-02T00:00:00+00:00",
        "source_ids": [f"source:official:{case_id}"],
    }
    requirement = Requirement(
        requirement_id,
        claim_id,
        f"Deliver reliable service for {role}.",
        True,
        "evidence",
        "build_evidence",
        ("portfolio_artifact",),
        9000,
        f"vacancy:{case_id}",
        (0, 24),
    )
    policy = MatchingPolicy()
    match = MatchResult(
        requirement_id,
        "matched",
        (evidence_id,),
        9500,
        "checked synthetic direct evidence",
        policy.policy_hash,
        None,
    )
    strategy = compile_application_strategy(
        fit_run_id=_digest(f"fit:{case_id}"),
        dossier_hash=_digest(f"dossier:{case_id}"),
        candidate_profile_hash=_digest(f"profile:{case_id}"),
        requirements=(requirement,),
        match_results=(match,),
        candidate_support=(
            CandidateSupport(
                requirement_id,
                claim_id,
                1,
                evidence_id,
                1,
                "portfolio_artifact",
                "approved",
                "evidence",
                "approved",
                "evidence",
                "approved",
                date(2035, 1, 1),
            ),
        ),
        employer_facts=(
            EmployerResearchFact(
                research_id,
                "company",
                "fact",
                (f"source:official:{case_id}",),
                content_hash(employer_document),
                "current",
            ),
        ),
        as_of=date(2030, 1, 2),
    )
    elements = {row.kind: row for row in strategy.elements}

    def sentence(
        kind: str,
        *,
        text: str,
        fact_kind: str,
        document_kind: str,
        employer_json: str | None = None,
    ) -> FactualSentence:
        element = elements[kind]
        return FactualSentence(
            content_hash(
                {
                    "case_id": case_id,
                    "element_id": element.element_id,
                    "text": text,
                }
            ),
            text,
            text,
            fact_kind,
            document_kind,
            FactAuthority.from_element(element),
            employer_json,
        )

    cv = sentence(
        "cv_emphasis",
        text=candidate_text,
        fact_kind="candidate",
        document_kind="cv",
    )
    letter_candidate = sentence(
        "cover_letter_argument",
        text=candidate_text,
        fact_kind="candidate",
        document_kind="cover_letter",
    )
    letter_employer = sentence(
        "employer_hook",
        text=employer_text,
        fact_kind="employer",
        document_kind="cover_letter",
        employer_json=canonical_json(employer_document),
    )
    answer = sentence(
        "structured_answer",
        text=candidate_text,
        fact_kind="candidate",
        document_kind="answer",
    )
    cv_slot = _slot(case_id, "cv", "summary", "Relevant evidence")
    opening = _slot(
        case_id,
        "cover_letter",
        "salutation",
        "Dear Hiring Manager",
    )
    closing = _slot(
        case_id,
        "cover_letter",
        "signoff",
        "Kind regards",
    )
    answer_slot = _slot(
        case_id,
        "answer",
        "lead",
        "A relevant example follows.",
    )
    return compile_application_source(
        strategy=strategy,
        job_key=f"locked:{case_id}",
        role_title=role,
        company_name=company,
        vacancy_source_identity=f"vacancy:locked:{case_id}",
        vacancy_sha256=_digest(f"vacancy:{case_id}"),
        contact=CandidateContact(
            "Synthetic Candidate",
            str(case["email"]),
            str(case["phone"]),
            "London",
            f"contact:{case_id}",
            1,
            _digest(f"contact:{case_id}"),
        ),
        facts=(cv, letter_candidate, letter_employer, answer),
        style_slots=(cv_slot, opening, closing, answer_slot),
        cv_sections=(
            DocumentSection(
                "Professional Summary",
                (),
                (cv_slot.slot_id,),
            ),
            DocumentSection("Experience", (cv.sentence_id,)),
        ),
        letter_sections=(
            DocumentSection("Opening", (), (opening.slot_id,)),
            DocumentSection(
                "Evidence Match",
                (letter_candidate.sentence_id,),
            ),
            DocumentSection(
                "Company Fit",
                (letter_employer.sentence_id,),
            ),
            DocumentSection("Close", (), (closing.slot_id,)),
        ),
        answers=(
            StructuredAnswer(
                f"question:{case_id}",
                "Describe a relevant delivery example.",
                (answer.sentence_id,),
                (answer_slot.slot_id,),
            ),
        ),
    )


def evaluate(fixture: Mapping[str, object]) -> dict[str, object]:
    if (
        fixture.get("schema_version") != "jaa07.locked-application-packs.v1"
        or fixture.get("certifies_slice") is not False
        or tuple(fixture.get("dependency_gates", ()))
        != ("JAA-06", "JAA-05", "JAA-04")
        or tuple(fixture.get("limitations", ())) != LIMITATIONS
    ):
        raise ValueError("locked JAA-07 fixture truth boundary is invalid")
    cases = fixture.get("cases")
    if not isinstance(cases, list) or len(cases) != 20:
        raise ValueError("locked JAA-07 fixture requires exactly 20 packs")
    ids = [str(row.get("id")) for row in cases if isinstance(row, Mapping)]
    if len(ids) != 20 or len(set(ids)) != 20 or ids != sorted(ids):
        raise ValueError("locked JAA-07 case identities must be unique and ordered")
    passed = {name: 0 for name in METRIC_NAMES}
    results: list[dict[str, object]] = []
    for case in cases:
        if not isinstance(case, Mapping):
            raise ValueError("locked JAA-07 case must be an object")
        source = _pack(case)
        artifacts = render_pdf_artifacts(source)
        replay = render_pdf_artifacts(_pack(case))
        page_ok = (
            artifacts.cv_pdf.page_count == 2
            and artifacts.cover_letter_pdf.page_count == 1
        )
        parse_ok = bool(
            artifacts.cv_pdf.extracted_text.strip()
            and artifacts.cover_letter_pdf.extracted_text.strip()
        )
        headings = tuple(row.heading for row in source.cv_sections)
        section_ok = (
            headings == ("Professional Summary", "Experience")
            and tuple(row.heading for row in source.letter_sections)
            == ("Opening", "Evidence Match", "Company Fit", "Close")
        )
        requirements = {row.authority.requirement_id for row in source.facts}
        coverage_ok = (
            len(requirements) == 1
            and all(
                requirements
                == {
                    row.authority.requirement_id
                    for row in source.facts
                    if row.document_kind == document_kind
                }
                for document_kind in ("cv", "cover_letter", "answer")
            )
        )
        provenance_ok = all(
            row.text == row.approved_source_text
            and row.authority.strategy_element_id
            for row in source.facts
        )
        combined = (
            artifacts.cv_pdf.extracted_text
            + artifacts.cover_letter_pdf.extracted_text
            + artifacts.editable.answers_text
        )
        preservation_ok = all(
            value in combined
            for value in (
                str(case["metric"]),
                str(case["year"]),
                str(case["email"]),
                str(case["phone"]),
                str(case["company"]),
                str(case["role"]),
            )
        )
        replay_ok = replay == artifacts
        if (
            case.get("expected_artifact_set_sha256")
            != artifacts.artifact_set_sha256
        ):
            replay_ok = False
        checks = {
            "page_contract": page_ok,
            "parse_success": parse_ok,
            "section_contract": section_ok,
            "requirement_coverage": coverage_ok,
            "provenance_completeness": provenance_ok,
            "factual_preservation": preservation_ok,
            "deterministic_replay": replay_ok,
        }
        for name, accepted in checks.items():
            passed[name] += int(accepted)
        results.append(
            {
                "id": str(case["id"]),
                "checks": checks,
                "source_id": source.source_id,
                "artifact_set_sha256": artifacts.artifact_set_sha256,
            }
        )
    metrics = {
        name: passed[name] * 10_000 // len(cases)
        for name in METRIC_NAMES
    }
    if fixture.get("expected_metrics_bp") != metrics:
        raise ValueError("locked JAA-07 metrics differ from checked expectations")
    return {
        "schema_version": "jaa07.locked-evaluation-report.v1",
        "status": (
            "SOFTWARE_CONTRACT_PASS"
            if all(value == 10_000 for value in metrics.values())
            else "SOFTWARE_CONTRACT_FAIL"
        ),
        "fixture_sha256": hashlib.sha256(
            canonical_json(fixture).encode()
        ).hexdigest(),
        "packs": len(cases),
        "metrics_bp": metrics,
        "results": results,
        "certifies_slice": False,
        "dependency_gates": ["JAA-06", "JAA-05", "JAA-04"],
        "limitations": list(LIMITATIONS),
        "live_requests": 0,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    arguments = parser.parse_args()
    try:
        fixture = json.loads(arguments.fixture.read_text(encoding="utf-8"))
        if not isinstance(fixture, dict):
            raise ValueError("fixture root must be an object")
        report = evaluate(fixture)
    except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as exc:
        print(f"JAA-07 locked evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(canonical_json(report))
    return 0 if report["status"] == "SOFTWARE_CONTRACT_PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

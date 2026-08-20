"""Deterministic employer-facing package from approved candidate authority."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Mapping, Protocol

from .application_compiler import (
    ApplicationSource,
    CandidateContact,
    DocumentSection,
    FactAuthority,
    FactualSentence,
    ProfileFactAuthority,
    StyleSlot,
    VacancyFactAuthority,
    compile_application_source,
)
from .application_strategy import (
    CandidateSupport,
    EmployerResearchFact,
    compile_application_strategy,
)
from .candidate_authority import (
    APPROVED_CANDIDATE_SOURCE_HASHES,
    APPROVED_EVIDENCE_PATH,
)
from .evidence_matching import (
    PROOF_CLASSES,
    MatchResult,
    Requirement,
    canonical_json,
    content_hash,
)
from .external_document_assurance import (
    ExternalDocumentAssuranceError,
    assert_employer_facing_text,
)
from .rendering import ApplicationArtifacts, render_pdf_artifacts
from cv_generation.constraints import validate_generated_cv


PROFILE_CV_SECTIONS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("Professional Summary", ("E-013",)),
    ("Core Capabilities", ("E-012",)),
    (
        "Projects",
        (
            "E-011",
            "E-014",
            "E-015",
            "E-016",
            "E-017",
        ),
    ),
    ("Education", ("E-001", "E-002")),
)
PROFILE_LETTER_EVIDENCE_PRIORITY = (
    "E-011",
    "E-002",
)
MINIMUM_CV_FACTS = 8
MINIMUM_CV_WORDS = 110
MINIMUM_LETTER_CANDIDATE_FACTS = 2
MINIMUM_LETTER_WORDS = 90
OUTWARD_PROFILE_REWRITES: Mapping[str, str] = {
    "E-001": (
        "First-Class BSc (Hons) Computer Science, Birmingham Newman "
        "University, July 2026."
    ),
    "E-002": (
        "Dissertation: SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
        "Anomaly-Detection Pipeline for Serverless Workloads."
    ),
    "E-011": (
        "I led the end-to-end development of Market Aligner, covering its "
        "collectors, validation, caching, SQLite persistence, retries and resumability."
    ),
    "E-013": (
        "My GitHub portfolio is available under the username Pepstee, with work "
        "covering orchestration, SCAFAD and delivered software projects."
    ),
    "E-012": (
        "I architect and operate a multi-agent orchestration platform, owning "
        "requirements, system architecture, evaluation gates and acceptance decisions."
    ),
    "E-014": (
        "I provided product direction and validated the working Dubbing Studio MVP."
    ),
    "E-015": (
        "Dubbing Studio has 709 passing automated tests and a real command-line "
        "synthesis check that produced a timeline-correct WAV."
    ),
    "E-016": (
        "Built Learning Accelerator, a tested system for LLM-assisted question "
        "generation, spaced repetition, review sessions, persistence and analytics."
    ),
    "E-017": (
        "The public scafad-delta repository contains the SCAFAD implementation."
    ),
    "E-018": (
        "An earlier public orchestrator repository documents the development of "
        "my orchestration architecture."
    ),
}
OUTWARD_LETTER_REWRITES: Mapping[str, str] = {
    "E-011": (
        "In Market Aligner, I led work on collectors, validation, caching, "
        "SQLite persistence, retries and resumability."
    ),
}
OUTWARD_REWRITE_POLICY_SHA256 = content_hash(
    {
        "schema_version": "jaa.candidate-outward-rewrite-policy.v1",
        "mode": "exact_allowlist",
        "rewrites": dict(OUTWARD_PROFILE_REWRITES),
        "letter_rewrites": dict(OUTWARD_LETTER_REWRITES),
    }
)


@dataclass(frozen=True)
class CandidateApplicationPackage:
    source: ApplicationSource
    artifacts: ApplicationArtifacts
    vacancy_requirements: tuple[str, ...]


class GenerationRevisionWriter(Protocol):
    """Durable sink called synchronously as each production value is created."""

    def __call__(
        self,
        *,
        role: str,
        value: bytes,
        media_type: str,
        prior_sha256: str | None = None,
        approved: bool = True,
        rejection_codes: tuple[str, ...] = (),
    ) -> object: ...


def _approved_statements(path: Path) -> dict[str, dict[str, object]]:
    value = path.read_bytes()
    if _sha256(value) != APPROVED_CANDIDATE_SOURCE_HASHES["approved_evidence"]:
        raise ValueError("application factory candidate evidence hash differs")
    document = json.loads(value)
    rows = document.get("statements")
    if not isinstance(rows, list):
        raise ValueError("application factory candidate evidence is malformed")
    result = {str(row["id"]): dict(row) for row in rows if isinstance(row, Mapping)}
    if len(result) != len(rows):
        raise ValueError("application factory candidate evidence is ambiguous")
    return result


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _candidate_statement_is_outward_safe(value: str) -> bool:
    folded = value.casefold()
    internal_markers = (
        "ai-assisted",
        "ai agents",
        "approved evidence",
        "audit",
        "evidence",
        "governance",
        "model provenance",
        "prompt",
        "software factory",
    )
    return not any(marker in folded for marker in internal_markers)


def _outward_profile_text(
    evidence: Mapping[str, object],
    *,
    document_kind: str | None = None,
) -> str:
    evidence_id = str(evidence["id"])
    if document_kind == "cover_letter" and evidence_id in OUTWARD_LETTER_REWRITES:
        return OUTWARD_LETTER_REWRITES[evidence_id]
    return OUTWARD_PROFILE_REWRITES.get(evidence_id, str(evidence["statement"]))


def _employer_document(
    claim_id: str,
    text: str,
    *,
    source_identity: str,
) -> dict[str, object]:
    return {
        "id": claim_id,
        "kind": "role",
        "classification": "fact",
        "text": text,
        "source_ids": [source_identity],
    }


def _employer_requirement_statement(
    *,
    company_name: str,
    role_title: str,
    requirement_text: str,
) -> str:
    """Render an exact captured requirement as normal employer-facing prose."""
    requirement = requirement_text.strip().rstrip(".")
    words = requirement.split(maxsplit=1)
    if words and words[0].casefold() in {
        "be",
        "build",
        "demonstrate",
        "develop",
        "have",
        "know",
        "possess",
        "understand",
        "use",
        "work",
    }:
        predicate = words[0].casefold()
        if len(words) == 2:
            predicate = f"{predicate} {words[1]}"
        return (
            f"For the {role_title} position, {company_name} specifically asks "
            f"candidates to {predicate}."
        )
    if words and words[0].casefold().endswith("ing"):
        return (
            f"For the {role_title} position, {company_name} describes the work "
            f"as {requirement[0].casefold() + requirement[1:]}."
        )
    if requirement.casefold().startswith("experience with "):
        return (
            f"The {role_title} position at {company_name} calls for "
            f"{requirement[0].casefold() + requirement[1:]}."
        )
    return (
        f"The {role_title} position at {company_name} lists this requirement: "
        f"{requirement}."
    )


def _sentence(
    element,
    *,
    text: str,
    fact_kind: str,
    document_kind: str,
    employer_fact_json: str | None = None,
) -> FactualSentence:
    return FactualSentence(
        content_hash(
            {
                "contract": "jaa07.factual-sentence.v1",
                "element_id": element.element_id,
                "text": text,
                "fact_kind": fact_kind,
                "document_kind": document_kind,
            }
        ),
        text,
        text,
        fact_kind,
        document_kind,
        FactAuthority.from_element(element),
        employer_fact_json,
    )


def _profile_sentence(
    *,
    evidence: Mapping[str, object],
    candidate_profile_hash: str,
    statement_sha256: str,
    document_kind: str,
) -> FactualSentence:
    evidence_id = str(evidence["id"])
    approved_source_text = str(evidence["statement"])
    text = _outward_profile_text(evidence, document_kind=document_kind)
    rewritten = text != approved_source_text
    authority = ProfileFactAuthority(
        candidate_profile_hash=candidate_profile_hash,
        candidate_claim_id=f"approved-claim:{evidence_id}",
        candidate_claim_version=1,
        candidate_evidence_id=evidence_id,
        candidate_evidence_version=1,
        candidate_evidence_sha256=statement_sha256,
        proof_class=str(evidence["proof_class"]),
        outward_text_sha256=_sha256(text.encode()) if rewritten else None,
        rewrite_policy_sha256=(
            OUTWARD_REWRITE_POLICY_SHA256 if rewritten else None
        ),
    )
    return FactualSentence(
        content_hash(
            {
                "contract": "jaa07.profile-factual-sentence.v1",
                "candidate_profile_hash": candidate_profile_hash,
                "candidate_evidence_id": evidence_id,
                "candidate_evidence_sha256": statement_sha256,
                "text": text,
                "document_kind": document_kind,
            }
        ),
        text,
        approved_source_text,
        "candidate",
        document_kind,
        authority,
    )


def _slot(document_kind: str, purpose: str, text: str) -> StyleSlot:
    return StyleSlot(
        content_hash(
            {
                "contract": "jaa07.deterministic-style-slot.v1",
                "document_kind": document_kind,
                "purpose": purpose,
                "text": text,
            }
        ),
        document_kind,
        text,
    )


def _assert_package_quality(source: ApplicationSource) -> None:
    facts = {row.sentence_id: row for row in source.facts}
    cv_rows = [
        facts[sentence_id]
        for section in source.cv_sections
        for sentence_id in section.sentence_ids
    ]
    letter_rows = [
        facts[sentence_id]
        for section in source.letter_sections
        for sentence_id in section.sentence_ids
    ]
    cv_texts = [row.text.casefold().strip() for row in cv_rows]
    letter_texts = [row.text.casefold().strip() for row in letter_rows]
    slots = {row.slot_id: row for row in source.style_slots}
    letter_slot_texts = [
        slots[slot_id].text.casefold().strip()
        for section in source.letter_sections
        for slot_id in section.style_slot_ids
    ]
    if (
        len(cv_rows) < MINIMUM_CV_FACTS
        or len(" ".join(cv_texts).split()) < MINIMUM_CV_WORDS
    ):
        raise ValueError("candidate CV is too sparse for employer submission")
    if len(cv_texts) != len(set(cv_texts)):
        raise ValueError("candidate CV repeats factual content")
    if tuple(section.heading for section in source.cv_sections) != tuple(
        heading for heading, _ in PROFILE_CV_SECTIONS
    ):
        raise ValueError("candidate CV lacks the complete graduate profile structure")
    candidate_letter = [row for row in letter_rows if row.fact_kind == "candidate"]
    employer_letter = [row for row in letter_rows if row.fact_kind == "employer"]
    if (
        len(candidate_letter) < MINIMUM_LETTER_CANDIDATE_FACTS
        or not employer_letter
        or len(" ".join((*letter_slot_texts, *letter_texts)).split())
        < MINIMUM_LETTER_WORDS
    ):
        raise ValueError("candidate cover letter is too sparse for employer submission")
    if len(letter_texts) != len(set(letter_texts)):
        raise ValueError("candidate cover letter repeats factual content")
    if any(
        source.company_name.casefold() not in row.text.casefold()
        for row in employer_letter
    ):
        raise ValueError("candidate cover letter lacks company-bound vacancy context")


def build_candidate_application_package(
    *,
    decision_receipt: Mapping[str, object],
    candidate_projection: Mapping[str, object],
    job_key: str,
    vacancy_sha256: str,
    source_url: str,
    role_title: str,
    company_name: str,
    contact: CandidateContact,
    approved_evidence_path: Path = APPROVED_EVIDENCE_PATH,
    revision_writer: GenerationRevisionWriter | None = None,
) -> CandidateApplicationPackage:
    """Build a plain UK CV and letter using verbatim approved factual atoms."""
    if revision_writer is not None:
        revision_writer(
            role="generation.inputs",
            value=(
                canonical_json(
                    {
                        "schema_version": "jaa.candidate-generation-inputs.v1",
                        "decision_receipt": dict(decision_receipt),
                        "candidate_projection": dict(candidate_projection),
                        "job_key": job_key,
                        "vacancy_sha256": vacancy_sha256,
                        "source_url": source_url,
                        "role_title": role_title,
                        "company_name": company_name,
                    }
                )
                + "\n"
            ).encode(),
            media_type="application/json",
        )
    if (
        decision_receipt.get("decision") != "eligible"
        or decision_receipt.get("job_key") != job_key
        or decision_receipt.get("role_title") != role_title
        or decision_receipt.get("company_name") != company_name
        or decision_receipt.get("vacancy_sha256") != vacancy_sha256
        or decision_receipt.get("source_url") != source_url
        or decision_receipt.get("candidate_projection_sha256")
        != candidate_projection.get("projection_sha256")
    ):
        raise ValueError("application factory decision authority differs")
    matrix = decision_receipt.get("evidence_matrix")
    if not isinstance(matrix, list) or not matrix:
        raise ValueError("application factory requires an evidence matrix")
    all_requirements: list[str] = []
    matched_rows: list[Mapping[str, object]] = []
    for row in matrix:
        if (
            not isinstance(row, Mapping)
            or not isinstance(row.get("requirement_id"), str)
            or not isinstance(row.get("requirement_text"), str)
            or not row["requirement_text"].strip()
            or _sha256(str(row["requirement_text"]).encode())
            != row.get("requirement_text_sha256")
        ):
            raise ValueError("application factory requirement authority is malformed")
        all_requirements.append(f"{row['requirement_id']}: {row['requirement_text']}")
        if row.get("status") == "matched":
            matched_rows.append(row)
    statements = _approved_statements(approved_evidence_path)
    projection_rows = candidate_projection.get("approved_evidence")
    if not isinstance(projection_rows, list):
        raise ValueError("candidate projection evidence is malformed")
    projection_by_id = {
        str(row["id"]): dict(row)
        for row in projection_rows
        if isinstance(row, Mapping) and isinstance(row.get("id"), str)
    }
    if len(projection_by_id) != len(projection_rows):
        raise ValueError("candidate projection evidence is ambiguous")
    requirements: list[Requirement] = []
    matches: list[MatchResult] = []
    supports: list[CandidateSupport] = []
    selected_rows: list[Mapping[str, object]] = []
    source_identity = f"vacancy:{job_key}:{vacancy_sha256}"
    for row in matched_rows:
        evidence_ids = row.get("evidence_ids")
        if not isinstance(evidence_ids, list) or not evidence_ids:
            raise ValueError("matched requirement lacks approved evidence")
        evidence_id = ""
        for candidate_id in sorted(str(value) for value in evidence_ids):
            candidate = statements.get(candidate_id)
            if candidate is None or candidate_id in OUTWARD_PROFILE_REWRITES:
                continue
            outward_text = _outward_profile_text(candidate)
            if not _candidate_statement_is_outward_safe(outward_text):
                continue
            try:
                for document_kind in ("cv", "cover_letter"):
                    assert_employer_facing_text(
                        outward_text,
                        document_kind=document_kind,
                    )
            except ExternalDocumentAssuranceError:
                continue
            evidence_id = candidate_id
            break
        if not evidence_id:
            continue
        evidence = statements.get(evidence_id)
        projected = projection_by_id.get(evidence_id)
        if (
            evidence is None
            or projected is None
            or evidence.get("proof_class") != evidence.get("kind")
            or _sha256(str(evidence["statement"]).encode())
            != projected.get("statement_sha256")
        ):
            raise ValueError("matched evidence differs from candidate projection")
        requirement_id = str(row["requirement_id"])
        claim_id = f"approved-claim:{evidence_id}"
        requirement_text = str(row["requirement_text"])
        requirement = Requirement(
            requirement_id,
            claim_id,
            requirement_text,
            row.get("classification") == "essential",
            "evidence",
            "build_evidence",
            (str(evidence["proof_class"]),),
            10_000,
            source_identity,
            (0, len(requirement_text)),
        )
        requirements.append(requirement)
        matches.append(
            MatchResult(
                requirement_id,
                "matched",
                (evidence_id,),
                10_000,
                "Exact operator-approved evidence matched by candidate authority.",
                str(candidate_projection["policy_sha256"]),
                None,
            )
        )
        supports.append(
            CandidateSupport(
                requirement_id,
                claim_id,
                1,
                evidence_id,
                1,
                str(evidence["proof_class"]),
                "approved",
                "evidence",
                "approved",
                "evidence",
                "approved",
                None,
            )
        )
        selected_rows.append(row)
    selected_requirement_ids = {
        str(row["requirement_id"]) for row in selected_rows
    }
    for row in matrix:
        requirement_id = str(row["requirement_id"])
        if requirement_id in selected_requirement_ids:
            continue
        requirement_text = str(row["requirement_text"])
        requirements.append(
            Requirement(
                requirement_id,
                f"uncovered:{requirement_id}",
                requirement_text,
                row.get("classification") == "essential",
                "evidence",
                "build_evidence",
                tuple(sorted(PROOF_CLASSES)),
                10_000,
                source_identity,
                (0, len(requirement_text)),
            )
        )
        matches.append(
            MatchResult(
                requirement_id,
                "no_match",
                (),
                10_000,
                "No exact employer-safe approved evidence matched this requirement.",
                str(candidate_projection["policy_sha256"]),
                None,
            )
        )
    employer_context_rows = selected_rows or [matrix[0]]
    employer_documents = [
        _employer_document(
            f"vacancy-requirement:{row['requirement_id']}",
            _employer_requirement_statement(
                company_name=company_name,
                role_title=role_title,
                requirement_text=str(row["requirement_text"]),
            ),
            source_identity=source_identity,
        )
        for row in employer_context_rows
    ]
    vacancy_context_document = employer_documents[0]
    employer_facts = tuple(
        EmployerResearchFact(
            str(document["id"]),
            "role",
            "fact",
            tuple(str(value) for value in document["source_ids"]),
            content_hash(document),
            "current",
        )
        for document in employer_documents
    )
    try:
        as_of = datetime.fromisoformat(
            str(decision_receipt["observed_at"]).replace("Z", "+00:00")
        ).date()
    except (KeyError, ValueError) as exc:
        raise ValueError("application factory observation time is invalid") from exc
    if not isinstance(as_of, date):
        raise ValueError("application factory observation date is invalid")
    strategy = compile_application_strategy(
        fit_run_id=_sha256((canonical_json(dict(decision_receipt)) + "\n").encode()),
        dossier_hash=str(decision_receipt["vacancy_description_sha256"]),
        candidate_profile_hash=str(candidate_projection["projection_sha256"]),
        requirements=requirements,
        match_results=matches,
        candidate_support=supports,
        employer_facts=employer_facts,
        as_of=as_of,
        permit_eligible_gap_application=True,
    )
    employer_by_id = {str(document["id"]): document for document in employer_documents}
    strategy_cv: list[FactualSentence] = []
    strategy_letter: list[FactualSentence] = []
    letter_employer: list[FactualSentence] = []
    for element in strategy.elements:
        if element.kind in {"cv_emphasis", "cover_letter_argument"}:
            document_kind = "cv" if element.kind == "cv_emphasis" else "cover_letter"
            evidence = statements[element.candidate_evidence_id]
            sentence = _sentence(
                element,
                text=str(evidence["statement"]),
                fact_kind="candidate",
                document_kind=document_kind,
            )
            (strategy_cv if document_kind == "cv" else strategy_letter).append(sentence)
        elif element.kind == "employer_hook":
            document = employer_by_id[element.employer_research_claim_id]
            letter_employer.append(
                _sentence(
                    element,
                    text=str(document["text"]),
                    fact_kind="employer",
                    document_kind="cover_letter",
                    employer_fact_json=canonical_json(document),
                )
            )
    if not letter_employer:
        vacancy_fact_sha256 = content_hash(vacancy_context_document)
        vacancy_authority = VacancyFactAuthority(
            vacancy_source_identity=source_identity,
            vacancy_sha256=vacancy_sha256,
            employer_research_claim_id=str(vacancy_context_document["id"]),
            employer_fact_sha256=vacancy_fact_sha256,
        )
        vacancy_text = str(vacancy_context_document["text"])
        letter_employer.append(
            FactualSentence(
                content_hash(
                    {
                        "contract": "jaa07.vacancy-factual-sentence.v1",
                        "vacancy_source_identity": source_identity,
                        "vacancy_sha256": vacancy_sha256,
                        "employer_fact_sha256": vacancy_fact_sha256,
                        "text": vacancy_text,
                    }
                ),
                vacancy_text,
                vacancy_text,
                "employer",
                "cover_letter",
                vacancy_authority,
                canonical_json(vacancy_context_document),
            )
        )

    def profile_fact(evidence_id: str, document_kind: str) -> FactualSentence:
        evidence = statements.get(evidence_id)
        projected = projection_by_id.get(evidence_id)
        outward_text = (
            _outward_profile_text(evidence, document_kind=document_kind)
            if evidence is not None
            else ""
        )
        if (
            evidence is None
            or projected is None
            or evidence.get("proof_class") != evidence.get("kind")
            or not _candidate_statement_is_outward_safe(outward_text)
            or _sha256(str(evidence.get("statement", "")).encode())
            != projected.get("statement_sha256")
        ):
            raise ValueError("profile evidence differs from candidate authority")
        assert_employer_facing_text(
            outward_text,
            document_kind=document_kind,
        )
        return _profile_sentence(
            evidence=evidence,
            candidate_profile_hash=str(candidate_projection["projection_sha256"]),
            statement_sha256=str(projected["statement_sha256"]),
            document_kind=document_kind,
        )

    strategy_cv_by_evidence: dict[str, list[FactualSentence]] = {}
    for fact in strategy_cv:
        strategy_cv_by_evidence.setdefault(
            fact.authority.candidate_evidence_id, []
        ).append(fact)
    cv_sections_by_heading: dict[str, list[FactualSentence]] = {
        heading: [] for heading, _ in PROFILE_CV_SECTIONS
    }
    used_strategy_ids: set[str] = set()
    for heading, evidence_ids in PROFILE_CV_SECTIONS:
        for evidence_id in evidence_ids:
            matched = strategy_cv_by_evidence.get(evidence_id, [])
            if matched:
                cv_sections_by_heading[heading].extend(matched)
                used_strategy_ids.update(row.sentence_id for row in matched)
                # Strategy atoms must remain verbatim to preserve requirement
                # coverage.  Candidate-ratified education presentation is an
                # additional exact-authority projection, never a mutation of
                # that strategy atom.
                if evidence_id in {"E-001", "E-002"}:
                    projected_fact = profile_fact(evidence_id, "cv")
                    if all(row.text != projected_fact.text for row in matched):
                        cv_sections_by_heading[heading].append(projected_fact)
            else:
                cv_sections_by_heading[heading].append(profile_fact(evidence_id, "cv"))
    for fact in strategy_cv:
        if fact.sentence_id in used_strategy_ids:
            continue
        evidence = statements[fact.authority.candidate_evidence_id]
        if evidence["kind"] == "credential":
            heading = "Education"
        elif evidence["kind"] == "employment_record":
            heading = "Experience"
        else:
            heading = "Projects"
        cv_sections_by_heading[heading].append(fact)

    letter_candidate = list(strategy_letter)
    letter_evidence_ids = {
        row.authority.candidate_evidence_id for row in letter_candidate
    }
    for evidence_id in PROFILE_LETTER_EVIDENCE_PRIORITY:
        if evidence_id in letter_evidence_ids:
            continue
        letter_candidate.append(profile_fact(evidence_id, "cover_letter"))
        letter_evidence_ids.add(evidence_id)
        if len(letter_candidate) >= 2:
            break

    letter_open = _slot("cover_letter", "salutation", "Dear Hiring Manager,")
    letter_intent = _slot(
        "cover_letter",
        "opening-intent",
        (
            f"I am applying for the {role_title} position at {company_name}. "
            "I want to build and operate dependable software systems, and this "
            "opportunity is closely aligned with that direction."
        ),
    )
    letter_evidence_lead = _slot(
        "cover_letter",
        "evidence-lead",
        "My strongest relevant work comes from systems I have built and evaluated.",
    )
    letter_company_lead = _slot(
        "cover_letter",
        "company-lead",
        (
            "The closest direct overlap with the role is the requirement below."
            if selected_rows
            else "The role description gives clear context for my application."
        ),
    )
    letter_close = _slot(
        "cover_letter",
        "close",
        "I would welcome the opportunity to discuss this work in more detail and "
        "how I could contribute to the team.",
    )
    letter_signoff = _slot("cover_letter", "signoff", "Kind regards")
    letter_signature = _slot(
        "cover_letter",
        "signature",
        contact.full_name,
    )
    cv_sections = tuple(
        DocumentSection(
            heading,
            tuple(row.sentence_id for row in cv_sections_by_heading[heading]),
        )
        for heading, _ in PROFILE_CV_SECTIONS
    )
    facts = [
        *(row for section in cv_sections_by_heading.values() for row in section),
        *letter_candidate,
        *letter_employer,
    ]
    source = compile_application_source(
        strategy=strategy,
        job_key=job_key,
        role_title=role_title,
        company_name=company_name,
        vacancy_source_identity=source_identity,
        vacancy_sha256=vacancy_sha256,
        contact=contact,
        facts=facts,
        style_slots=(
            letter_open,
            letter_intent,
            letter_evidence_lead,
            letter_company_lead,
            letter_close,
            letter_signoff,
            letter_signature,
        ),
        cv_sections=cv_sections,
        letter_sections=(
            DocumentSection(
                "Opening",
                (),
                (letter_open.slot_id, letter_intent.slot_id),
            ),
            DocumentSection(
                "Evidence Match",
                tuple(row.sentence_id for row in letter_candidate),
                (letter_evidence_lead.slot_id,),
            ),
            DocumentSection(
                "Company Fit",
                tuple(row.sentence_id for row in letter_employer),
                (letter_company_lead.slot_id,),
            ),
            DocumentSection(
                "Close",
                (),
                (
                    letter_close.slot_id,
                    letter_signoff.slot_id,
                    letter_signature.slot_id,
                ),
            ),
        ),
        answers=(),
    )
    _assert_package_quality(source)
    if revision_writer is not None:
        revision_writer(
            role="document.source_inputs",
            value=(canonical_json(source.document()) + "\n").encode(),
            media_type="application/json",
        )
    artifacts = render_pdf_artifacts(source)
    cv_facts = {row.sentence_id: row.text for row in source.facts}
    constraint_receipt = validate_generated_cv(
        source_id=source.source_id,
        candidate_name=source.contact.full_name,
        candidate_city=source.contact.city,
        cv_text=artifacts.editable.cv_text,
        cv_sha256=artifacts.editable.cv_sha256,
        sections={
            section.heading: tuple(cv_facts[value] for value in section.sentence_ids)
            for section in source.cv_sections
        },
        rendered_pages=artifacts.cv_pdf.rendered_lines,
    )
    if revision_writer is not None:
        revision_writer(
            role="document.cv.constraints",
            value=(canonical_json(constraint_receipt.document()) + "\n").encode(),
            media_type="application/json",
        )
        for role, value, media_type in (
            ("document.cv.source", artifacts.editable.cv_text.encode(), "text/plain"),
            ("document.cv.final_pdf", artifacts.cv_pdf.pdf_bytes, "application/pdf"),
            (
                "document.cover_letter.source",
                artifacts.editable.cover_letter_text.encode(),
                "text/plain",
            ),
            (
                "document.cover_letter.final_pdf",
                artifacts.cover_letter_pdf.pdf_bytes,
                "application/pdf",
            ),
            ("form.answers", artifacts.editable.answers_text.encode(), "text/plain"),
        ):
            revision_writer(role=role, value=value, media_type=media_type)
    return CandidateApplicationPackage(
        source=source,
        artifacts=artifacts,
        vacancy_requirements=tuple(all_requirements),
    )


__all__ = ["CandidateApplicationPackage", "build_candidate_application_package"]

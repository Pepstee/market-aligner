"""Structural producer/consumer contract tests for current editorial requests.

The writer capture tests drive the real producer entrypoint
``run_editorial_composition_runtime`` with synthetic capture adapters that
raise a sentinel inside ``invoke`` before any provider call, then inspect the
exact emitted writer request bytes.  The validator tests check current-mode
selection, paraphrase and employer-atom exactness.  These tests are structural
checks only and grant no release or submission authority.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from cv_generation.editorial_composition import (  # noqa: E402
    ApprovedCoverLetterClaim,
    ApprovedCVClaim,
    CVSection,
    CV_CLAIM_ASSIGNMENT_INSTRUCTIONS,
    CandidateEditorialAuthority,
    CoverLetterSection,
    EditorialAtom,
    EditorialCompositionError,
    EditorialCompositionRuntime,
    build_cover_letter_editorial_draft,
    build_cover_letter_editorial_request,
    build_editorial_draft,
    build_editorial_request,
    run_editorial_composition_runtime,
    validate_cover_letter_editorial_draft,
    validate_editorial_draft,
)

_CAPTURES: dict[str, bytes] = {}


class WriterCaptureSentinel(Exception):
    pass


class _CaptureSession:
    def __init__(self, invocation_id: str, label: str) -> None:
        self.invocation_id = invocation_id
        self._label = label

    def invoke(self, *, request_bytes: bytes):
        _CAPTURES[self._label] = request_bytes
        raise WriterCaptureSentinel("synthetic capture stopped before any provider call")


class _CaptureWriterAdapter:
    provider = "synthetic-capture-writer"
    model = "capture-writer-1"
    transport_identity = "synthetic-capture-writer-transport"
    environment = "synthetic"
    stage = None

    def available(self) -> bool:
        return True

    def open_fresh_session(self, *, invocation_id: str) -> _CaptureSession:
        return _CaptureSession(invocation_id, "writer_request")


class _CaptureHumanizerAdapter(_CaptureWriterAdapter):
    provider = "synthetic-capture-humanizer"
    model = "capture-humanizer-1"
    transport_identity = "synthetic-capture-humanizer-transport"

    def open_fresh_session(self, *, invocation_id: str) -> _CaptureSession:
        return _CaptureSession(invocation_id, "humanizer_request")


@pytest.fixture(autouse=True)
def _clear_captures():
    _CAPTURES.clear()
    yield
    _CAPTURES.clear()


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _cv_claim(claim_id: str, text: str, category: str) -> ApprovedCVClaim:
    return ApprovedCVClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=_sha256(text),
        evidence_ids=(f"{claim_id}-evidence",),
        category=category,
    )


def _current_cv_request():
    authority = CandidateEditorialAuthority(
        candidate_name="Alex Example",
        candidate_city=None,
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256=_sha256("current authority source"),
        allow_missing_city=True,
        current_runtime=True,
    )
    return build_editorial_request(
        authority=authority,
        role_title="Software Engineer",
        company_name="Example Company",
        vacancy_sha256=_sha256("current vacancy"),
        approved_claims=(
            _cv_claim(
                "cur-hl-1",
                "Built a prototype issue classifier for the support queue, covering 3 product areas.",
                "highlight",
            ),
            _cv_claim(
                "cur-skill-1",
                "Alex Example maintained Python data pipelines with intermittent reviewer support.",
                "skill",
            ),
        ),
    )


def _legacy_cv_request():
    authority = CandidateEditorialAuthority(
        candidate_name="Alex Example",
        candidate_city="London",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256=_sha256("legacy authority source"),
    )
    return build_editorial_request(
        authority=authority,
        role_title="Software Engineer",
        company_name="Example Company",
        vacancy_sha256=_sha256("legacy vacancy"),
        approved_claims=(
            _cv_claim(
                "leg-sum-1",
                "Alex Example delivered evidence-checked engineering support work.",
                "summary",
            ),
            _cv_claim(
                "leg-cap-1",
                "Maintains reviewed Python automation for repetitive checks.",
                "capability_domain",
            ),
            _cv_claim(
                "leg-proj-1",
                "Built a prototype issue classifier for the support queue.",
                "project",
            ),
        ),
    )


def _capture_runtime() -> EditorialCompositionRuntime:
    return EditorialCompositionRuntime(
        environment="synthetic",
        writer=_CaptureWriterAdapter(),
        humanizer=_CaptureHumanizerAdapter(),
        document_kind="cv",
    )


def _run_writer_capture(request) -> dict:
    with pytest.raises(WriterCaptureSentinel):
        run_editorial_composition_runtime(request, runtime=_capture_runtime())
    return json.loads(_CAPTURES["writer_request"])


def test_current_writer_request_contract_and_immutability():
    request = _current_cv_request()
    frozen = (
        request.request_sha256,
        request.authority.source_sha256,
        tuple(claim.text_sha256 for claim in request.approved_claims),
    )
    payload = _run_writer_capture(request)
    assert "available_claim_ids" in payload
    assert "required_claim_ids" not in payload
    assert set(payload["available_claim_ids"]) == {"cur-hl-1", "cur-skill-1"}
    assert payload["claim_section_policy"] == {
        "cur-hl-1": ["Highlights"],
        "cur-skill-1": ["Skills"],
    }
    instructions = payload["instructions"]
    for exact_legacy in CV_CLAIM_ASSIGNMENT_INSTRUCTIONS:
        assert exact_legacy not in instructions
    joined = "\n".join(instructions)
    assert "verbatim" not in joined
    assert (
        "Select relevant, useful, supported approved claims as whole claims and retain each selected claim ID."
        in instructions
    )
    assert (
        "Rephrase a selected candidate claim professionally, preserving its supported meaning, quantities, dates, qualifiers and negation; never strengthen a limited statement."
        in instructions
    )
    assert (
        "Omit an unsuitable claim as a whole rather than removing its material caveat."
        in instructions
    )
    assert "humanizer_request" not in _CAPTURES
    request.__post_init__()
    assert frozen == (
        request.request_sha256,
        request.authority.source_sha256,
        tuple(claim.text_sha256 for claim in request.approved_claims),
    )


def test_legacy_writer_request_keeps_exact_verbatim_contract():
    payload = _run_writer_capture(_legacy_cv_request())
    assert "available_claim_ids" not in payload
    assert "required_claim_ids" not in payload
    assert payload["instructions"] == [
        "Return only one canonical JSON object matching the supplied response schema.",
        "Use approved_claim atoms verbatim; never paraphrase, split, or invent facts.",
        "Place every approved_claim atom only in a section listed for its claim ID in claim_section_policy.",
        "Omit connective atoms or select them only from the supplied finite rhetorical catalog.",
        "Do not add Curriculum Vitae/CV labels, work-rights text, or unsupported capabilities.",
        "Do not add AI-authorship disclosure or em/en dashes, including inside approved facts.",
        "Keep formats and datastores out of Core Capabilities.",
    ]
    assert payload["claim_section_policy"]["leg-sum-1"] == ["Professional Summary"]
    assert payload["claim_section_policy"]["leg-proj-1"] == [
        "Professional Summary",
        "Projects",
    ]


def test_current_connective_only_section_is_refused():
    request = _current_cv_request()
    draft = build_editorial_draft(
        candidate_name="Alex Example",
        candidate_city=None,
        sections=(
            CVSection(
                "Highlights",
                (EditorialAtom("connective", "For this:", None),),
            ),
        ),
        allow_missing_city=True,
        current_runtime=True,
    )
    with pytest.raises(EditorialCompositionError):
        validate_editorial_draft(request, draft)


def test_current_selected_subset_and_paraphrase_are_structurally_allowed():
    request = _current_cv_request()
    draft = build_editorial_draft(
        candidate_name="Alex Example",
        candidate_city=None,
        sections=(
            CVSection(
                "Highlights",
                (
                    EditorialAtom(
                        "approved_claim",
                        "Delivered a prototype issue classifier for the support queue spanning 3 product areas.",
                        "cur-hl-1",
                    ),
                ),
            ),
        ),
        allow_missing_city=True,
        current_runtime=True,
    )
    validate_editorial_draft(request, draft)


def test_current_unknown_claim_id_is_refused():
    request = _current_cv_request()
    draft = build_editorial_draft(
        candidate_name="Alex Example",
        candidate_city=None,
        sections=(
            CVSection(
                "Highlights",
                (
                    EditorialAtom(
                        "approved_claim",
                        "Built a prototype issue classifier.",
                        "cur-unknown-1",
                    ),
                ),
            ),
        ),
        allow_missing_city=True,
        current_runtime=True,
    )
    with pytest.raises(EditorialCompositionError):
        validate_editorial_draft(request, draft)


def test_legacy_changed_claim_text_is_still_refused():
    request = _legacy_cv_request()
    sections = (
        CVSection(
            "Professional Summary",
            (
                EditorialAtom(
                    "approved_claim",
                    "Alex Example delivered evidence-checked engineering support work.",
                    "leg-sum-1",
                ),
            ),
        ),
        CVSection(
            "Core Capabilities",
            (
                EditorialAtom(
                    "approved_claim",
                    "Maintains reviewed Python automation for repetitive checks.",
                    "leg-cap-1",
                ),
            ),
        ),
    )
    draft = build_editorial_draft(
        candidate_name="Alex Example",
        candidate_city="London",
        sections=sections,
    )
    validate_editorial_draft(request, draft)
    changed = build_editorial_draft(
        candidate_name="Alex Example",
        candidate_city="London",
        sections=(
            CVSection(
                "Professional Summary",
                (
                    EditorialAtom(
                        "approved_claim",
                        "Alex Example delivered evidence-checked engineering support work at scale.",
                        "leg-sum-1",
                    ),
                ),
            ),
            sections[1],
        ),
    )
    with pytest.raises(EditorialCompositionError):
        validate_editorial_draft(request, changed)


def _current_cover_request():
    authority = CandidateEditorialAuthority(
        candidate_name="Alex Example",
        candidate_city=None,
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256=_sha256("current cover authority source"),
        allow_missing_city=True,
        current_runtime=True,
    )
    employer = ApprovedCoverLetterClaim(
        claim_id="cov-emp-1",
        text="Example Company runs a support platform for software teams.",
        text_sha256=_sha256(
            "Example Company runs a support platform for software teams."
        ),
        evidence_ids=("cov-emp-1-evidence",),
        fact_kind="employer",
        section_heading="Opening",
    )
    candidate = ApprovedCoverLetterClaim(
        claim_id="cov-cand-1",
        text="Alex Example built a prototype issue classifier covering 3 product areas.",
        text_sha256=_sha256(
            "Alex Example built a prototype issue classifier covering 3 product areas."
        ),
        evidence_ids=("cov-cand-1-evidence",),
        fact_kind="candidate",
        section_heading="Evidence Match",
    )
    return build_cover_letter_editorial_request(
        authority=authority,
        role_title="Software Engineer",
        company_name="Example Company",
        vacancy_sha256=_sha256("current cover vacancy"),
        approved_claims=(employer, candidate),
    )


def _current_cover_sections(employer_text, candidate_text):
    return (
        CoverLetterSection(
            "Opening",
            (
                EditorialAtom("connective", "Dear Hiring Manager,", None),
                EditorialAtom(
                    "connective",
                    "I am applying for the Software Engineer role at Example Company.",
                    None,
                ),
                EditorialAtom("approved_claim", employer_text, "cov-emp-1"),
            ),
            current_runtime=True,
        ),
        CoverLetterSection(
            "Evidence Match",
            (EditorialAtom("approved_claim", candidate_text, "cov-cand-1"),),
            current_runtime=True,
        ),
        CoverLetterSection("Company Fit", (), current_runtime=True),
        CoverLetterSection(
            "Close",
            (
                EditorialAtom(
                    "connective", "Thank you for considering my application.", None
                ),
                EditorialAtom("connective", "Kind regards", None),
                EditorialAtom("connective", "Alex Example", None),
            ),
            current_runtime=True,
        ),
    )


def test_current_cover_candidate_paraphrase_allowed_and_employer_change_refused():
    request = _current_cover_request()
    candidate_text = (
        "Alex Example delivered a prototype issue classifier spanning 3 product areas."
    )
    draft = build_cover_letter_editorial_draft(
        candidate_name="Alex Example",
        sections=_current_cover_sections(
            "Example Company runs a support platform for software teams.",
            candidate_text,
        ),
        current_runtime=True,
    )
    validate_cover_letter_editorial_draft(request, draft)
    changed = build_cover_letter_editorial_draft(
        candidate_name="Alex Example",
        sections=_current_cover_sections(
            "Example Company operates a support platform serving software teams.",
            candidate_text,
        ),
        current_runtime=True,
    )
    with pytest.raises(EditorialCompositionError):
        validate_cover_letter_editorial_draft(request, changed)

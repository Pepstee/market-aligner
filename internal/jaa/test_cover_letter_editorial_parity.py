from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
    assess_application_as_recruiter,
)
from career_automation.candidate_application_factory import (
    CandidateApplicationMaterializationReceipt,
)
from career_automation.evidence_matching import canonical_json
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.rendering import _build_text_pdf
from career_automation.testing_adversarial_recruiter import (
    fixture_recruiter_result,
)
from cv_generation.adversarial_rebuild import (
    AdversarialRebuildError,
    bind_cover_letter_recruiter_improvement,
    rebuild_cover_letter_from_recruiter_assessment,
)
from cv_generation.editorial_composition import (
    ApprovedCoverLetterClaim,
    CandidateEditorialAuthority,
    CoverLetterSection,
    DetachedCodexEditorialAdapter,
    EditorialAtom,
    EditorialBackendResult,
    EditorialCompositionError,
    EditorialCompositionRuntime,
    EditorialStageEvidence,
    admit_cover_letter_editorial_composition,
    build_cover_letter_editorial_draft,
    build_cover_letter_editorial_request,
    cover_letter_humanizer_request_sha256,
    run_cover_letter_composition_runtime,
    run_editorial_composition_runtime,
    validate_cover_letter_editorial_draft,
)
from llm.client import Backend, LLMClient, LLMResponse


def _claim(
    claim_id: str,
    text: str,
    fact_kind: str,
    section_heading: str,
) -> ApprovedCoverLetterClaim:
    return ApprovedCoverLetterClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        evidence_ids=(f"evidence:{claim_id}",),
        fact_kind=fact_kind,
        section_heading=section_heading,
    )


def _fixture():
    listing = "Example Systems needs an engineer to build reliable AI automation."
    authority = CandidateEditorialAuthority(
        candidate_name="Artiom Gutu",
        candidate_city="Birmingham, United Kingdom",
        graduation_month_year="July 2026",
        dissertation_title="Verified Systems Dissertation",
        source_sha256="a" * 64,
    )
    claims = (
        _claim(
            "candidate-primary",
            "Built an evidence-bound multi-agent orchestration system.",
            "candidate",
            "Evidence Match",
        ),
        _claim(
            "candidate-secondary",
            "Designed deterministic workflow automation with bounded authority.",
            "candidate",
            "Evidence Match",
        ),
        _claim(
            "employer-opening",
            "Example Systems is hiring an AI Automation Engineer to build reliable AI automation.",
            "employer",
            "Opening",
        ),
        _claim(
            "employer-primary",
            "Example Systems is hiring for reliable AI automation.",
            "employer",
            "Company Fit",
        ),
        _claim(
            "employer-secondary",
            "Example Systems requires evidence-led engineering decisions.",
            "employer",
            "Company Fit",
        ),
    )
    request = build_cover_letter_editorial_request(
        authority=authority,
        role_title="AI Automation Engineer",
        company_name="Example Systems",
        vacancy_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        approved_claims=claims,
    )
    opening_rhetoric = (
        "The AI Automation Engineer role at Example Systems caught my attention "
        "because of the work described in the vacancy."
    )
    humanized_opening_rhetoric = (
        "I was drawn to the AI Automation Engineer role at Example Systems by "
        "the work described in the vacancy."
    )
    evidence_rhetoric = (
        "The strongest relevant evidence is set out below."
    )
    humanized_evidence_rhetoric = (
        "My strongest relevant evidence is set out below."
    )
    company_rhetoric = (
        "My interest in Example Systems comes from the work described in the vacancy."
    )
    close_cta = (
        "I would welcome the opportunity to discuss how this evidence could support "
        "Example Systems in this AI Automation Engineer position."
    )
    sections = (
        CoverLetterSection(
            "Opening",
            (
                EditorialAtom("connective", "Dear Hiring Manager,", None),
                EditorialAtom("connective", opening_rhetoric, None),
                EditorialAtom(
                    "approved_claim", claims[2].text, claims[2].claim_id
                ),
            ),
        ),
        CoverLetterSection(
            "Evidence Match",
            (
                EditorialAtom("connective", evidence_rhetoric, None),
                EditorialAtom("approved_claim", claims[0].text, claims[0].claim_id),
                EditorialAtom("approved_claim", claims[1].text, claims[1].claim_id),
            ),
        ),
        CoverLetterSection(
            "Company Fit",
            (
                EditorialAtom("connective", company_rhetoric, None),
                EditorialAtom("approved_claim", claims[3].text, claims[3].claim_id),
                EditorialAtom("approved_claim", claims[4].text, claims[4].claim_id),
            ),
        ),
        CoverLetterSection(
            "Close",
            (
                EditorialAtom("connective", close_cta, None),
                EditorialAtom("connective", "Kind regards", None),
                EditorialAtom("connective", authority.candidate_name, None),
            ),
        ),
    )
    writer = build_cover_letter_editorial_draft(
        candidate_name=authority.candidate_name,
        sections=sections,
    )
    final = build_cover_letter_editorial_draft(
        candidate_name=authority.candidate_name,
        sections=(
            replace(
                sections[0],
                atoms=(
                    sections[0].atoms[0],
                    EditorialAtom("connective", humanized_opening_rhetoric, None),
                    *sections[0].atoms[2:],
                ),
            ),
            replace(
                sections[1],
                atoms=(
                    EditorialAtom("connective", humanized_evidence_rhetoric, None),
                    *sections[1].atoms[1:],
                ),
            ),
            *sections[2:],
        ),
    )
    return listing, request, claims, writer, final


def _current_cover_fixture():
    authority = CandidateEditorialAuthority(
        candidate_name="Casey Test",
        candidate_city="Leeds, United Kingdom",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
        current_runtime=True,
    )
    claims = (
        _claim(
            "candidate-evidence",
            "Built a reproducible evidence review process.",
            "candidate",
            "Evidence Match",
        ),
        _claim(
            "employer-opening",
            "Example Systems runs a support platform for software teams.",
            "employer",
            "Opening",
        ),
    )
    request = build_cover_letter_editorial_request(
        authority=authority,
        role_title="Data Engineer",
        company_name="Example Systems",
        vacancy_sha256="b" * 64,
        approved_claims=claims,
    )
    sections = (
        CoverLetterSection(
            "Opening",
            (
                EditorialAtom("connective", "Dear Hiring Manager,", None),
                EditorialAtom(
                    "connective",
                    "I am applying for the Data Engineer role at Example Systems.",
                    None,
                ),
                EditorialAtom("approved_claim", claims[1].text, claims[1].claim_id),
            ),
            current_runtime=True,
        ),
        CoverLetterSection(
            "Evidence Match",
            (EditorialAtom("approved_claim", claims[0].text, claims[0].claim_id),),
            current_runtime=True,
        ),
        CoverLetterSection("Company Fit", (), current_runtime=True),
        CoverLetterSection(
            "Close",
            (
                EditorialAtom(
                    "connective",
                    "Thank you for considering my application.",
                    None,
                ),
                EditorialAtom("connective", "Kind regards", None),
                EditorialAtom("connective", authority.candidate_name, None),
            ),
            current_runtime=True,
        ),
    )
    draft = build_cover_letter_editorial_draft(
        candidate_name=authority.candidate_name,
        sections=sections,
        current_runtime=True,
    )
    return authority, claims, request, draft


def _current_cover_wire_document(draft):
    document = draft.document(include_identity=False)
    document.pop("current_runtime", None)
    for section in document["sections"]:
        section.pop("current_runtime", None)
    return document


def _evidence(request, writer, final):
    return (
        EditorialStageEvidence(
            stage="cover_letter_writer",
            environment="synthetic",
            provider="fixture-writer",
            model="fixture-v1",
            invocation_id="cover-writer-session",
            request_sha256=request.request_sha256,
            response_sha256=writer.draft_sha256,
        ),
        EditorialStageEvidence(
            stage="cover_letter_humanizer",
            environment="synthetic",
            provider="fixture-humanizer",
            model="fixture-v1",
            invocation_id="cover-humanizer-session",
            request_sha256=cover_letter_humanizer_request_sha256(request, writer),
            response_sha256=final.draft_sha256,
        ),
    )


class _Session:
    def __init__(self, adapter, invocation_id):
        self.adapter = adapter
        self.invocation_id = invocation_id

    def invoke(self, *, request_bytes):
        self.adapter.calls.append((request_bytes, self.invocation_id))
        response = self.adapter.response_bytes
        if response is None:
            document = (
                _current_cover_wire_document(self.adapter.draft)
                if self.adapter.draft.current_runtime
                else self.adapter.draft.document()
            )
            response = canonical_json(document).encode()
        return EditorialBackendResult(
            response_bytes=response,
            invocation_id=self.invocation_id,
            environment=self.adapter.environment,
            provider=self.adapter.provider,
            model=self.adapter.model,
            transport_identity=self.adapter.transport_identity,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            response_sha256=hashlib.sha256(response).hexdigest(),
            executable_sha256="e" * 64,
        )


class _Adapter:
    def __init__(self, stage, provider, draft):
        self.stage = stage
        self.provider = provider
        self.model = "fixture-v1"
        self.draft = draft
        self.environment = "synthetic"
        self.transport_identity = f"transport:{provider}"
        self.calls = []
        self.response_bytes = None

    def available(self):
        return True

    def open_fresh_session(self, *, invocation_id):
        return _Session(self, invocation_id)


def test_cv_runtime_rejects_cover_request_before_provider_availability() -> None:
    _, request, _, writer, final = _fixture()

    class _ProbeAdapter(_Adapter):
        availability_calls = 0

        def available(self):
            self.availability_calls += 1
            return True

    writer_adapter = _ProbeAdapter("cover_letter_writer", "writer", writer)
    humanizer_adapter = _ProbeAdapter(
        "cover_letter_humanizer", "humanizer", final
    )
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
        document_kind="cover_letter",
    )

    with pytest.raises(EditorialCompositionError, match="exact CV request"):
        run_editorial_composition_runtime(request, runtime=runtime)

    assert writer_adapter.availability_calls == 0
    assert humanizer_adapter.availability_calls == 0
    assert not writer_adapter.calls
    assert not humanizer_adapter.calls


def test_cover_runtime_rejects_forged_receipt_before_provider_availability() -> None:
    _, request, _, writer, final = _fixture()

    class _ProbeAdapter(_Adapter):
        availability_calls = 0

        def available(self):
            self.availability_calls += 1
            return True

    class _ForgedReceipt(CandidateApplicationMaterializationReceipt):
        def __post_init__(self):
            return None

        def authorize_editorial_request(self, candidate_request):
            del candidate_request
            return None

    writer_adapter = _ProbeAdapter("cover_letter_writer", "writer", writer)
    humanizer_adapter = _ProbeAdapter(
        "cover_letter_humanizer", "humanizer", final
    )
    writer_adapter.environment = "production"
    humanizer_adapter.environment = "production"
    runtime = EditorialCompositionRuntime(
        environment="production",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
        document_kind="cover_letter",
    )

    with pytest.raises(EditorialCompositionError, match="source materialization"):
        run_cover_letter_composition_runtime(
            request,
            runtime=runtime,
            materialization_receipt=object.__new__(_ForgedReceipt),
        )

    assert writer_adapter.availability_calls == 0
    assert humanizer_adapter.availability_calls == 0
    assert not writer_adapter.calls
    assert not humanizer_adapter.calls


def test_cover_letter_runtime_uses_distinct_one_shot_writer_and_humanizer() -> None:
    _, request, _, writer, final = _fixture()
    writer_adapter = _Adapter("cover_letter_writer", "writer", writer)
    humanizer_adapter = _Adapter("cover_letter_humanizer", "humanizer", final)
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
        document_kind="cover_letter",
    )
    result = run_cover_letter_composition_runtime(request, runtime=runtime)
    assert result[:2] == (writer, final)
    assert len(writer_adapter.calls) == len(humanizer_adapter.calls) == 1
    assert writer_adapter.calls[0][1] != humanizer_adapter.calls[0][1]
    writer_request = json.loads(writer_adapter.calls[0][0])
    humanizer_request = json.loads(humanizer_adapter.calls[0][0])
    assert writer_request["stage"] == "cover_letter_writer"
    assert humanizer_request["stage"] == "cover_letter_humanizer"
    assert "approved_claim" in " ".join(writer_request["instructions"])
    assert "em dash" in " ".join(humanizer_request["instructions"])
    assert writer_request["instructions"] == [
        "Return only one canonical JSON object matching the response schema.",
        "Write a specific UK cover letter under one page using the four supplied sections.",
        "Use approved_claim atoms verbatim and never invent or paraphrase facts.",
        "Use the exact Dear Hiring Manager, salutation and exact Kind regards plus candidate signature.",
        "After the salutation, Opening must contain an approved employer claim naming the company and role.",
        "Use the strongest supported candidate evidence and only the supplied typed rhetorical atoms.",
        "Add no work-rights text, AI disclosure, caveat, weakness, or unsupported tool claim.",
        "Use at most 500 words and 3500 characters; add no em or en dash.",
    ]
    assert humanizer_request["instructions"] == [
        "Return only one canonical JSON object matching the response schema.",
        "Preserve every approved_claim atom and all four sections exactly.",
        "Edit connective atoms only by selecting another supplied typed rhetorical atom for that section.",
        "Preserve the exact salutation, sign-off, signature and opening employer hook.",
        "Use no em dash, en dash, rule-of-three sales cadence, disclosure, or new fact.",
    ]
    assert not {"claim_section_policy", "required_claim_ids", "section_min_facts"} & set(
        writer_request
    )
    assert not {"claim_section_policy", "required_claim_ids"} & set(humanizer_request)
    assert writer_adapter.calls[0][0] == canonical_json(
        {
            "editorial_request": request.document(),
            "instructions": writer_request["instructions"],
            "rhetorical_catalog": writer_request["rhetorical_catalog"],
            "schema_version": "jaa.cover-letter-writer-runtime-request.v3",
            "stage": "cover_letter_writer",
        }
    ).encode()
    assert humanizer_adapter.calls[0][0] == canonical_json(
        {
            "editorial_request": request.document(),
            "humanizer_request_sha256": cover_letter_humanizer_request_sha256(
                request, writer
            ),
            "instructions": humanizer_request["instructions"],
            "schema_version": "jaa.cover-letter-humanizer-runtime-request.v3",
            "stage": "cover_letter_humanizer",
            "rhetorical_catalog": humanizer_request["rhetorical_catalog"],
            "writer_draft": writer.document(),
        }
    ).encode()


def test_current_cover_letter_runtime_binds_writer_and_humanizer_prompts() -> None:
    _, claims, request, draft = _current_cover_fixture()
    writer_adapter = _Adapter("cover_letter_writer", "writer", draft)
    humanizer_adapter = _Adapter("cover_letter_humanizer", "humanizer", draft)
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
        document_kind="cover_letter",
    )
    writer_draft, final_draft, *_ = run_cover_letter_composition_runtime(
        request, runtime=runtime
    )
    assert len(writer_adapter.calls) == 1
    assert len(humanizer_adapter.calls) == 1
    writer_request = json.loads(writer_adapter.calls[0][0])
    humanizer_request = json.loads(humanizer_adapter.calls[0][0])
    expected_section_policy = {
        claim.claim_id: [claim.section_heading] for claim in claims
    }
    expected_claim_ids = [claim.claim_id for claim in claims]

    assert writer_draft == final_draft == draft
    assert writer_request["claim_section_policy"] == expected_section_policy
    assert writer_request["available_claim_ids"] == expected_claim_ids
    assert "required_claim_ids" not in writer_request
    assert writer_request["section_min_facts"] == {
        "Opening": 0,
        "Evidence Match": 0,
        "Company Fit": 0,
    }
    writer_instructions = " ".join(writer_request["instructions"])
    assert (
        "do not require an employer claim in Opening or Company Fit"
        in writer_instructions
    )
    assert (
        "Opening must contain an approved employer claim naming the company and role"
        not in writer_instructions
    )
    assert (
        "Opening uses the exact salutation and supplied plain role/company sentence, followed only by its bound facts."
        in writer_instructions
    )
    assert (
        "Use only the supplied rhetorical catalog and add no claims or meta-signposts."
        in writer_instructions
    )
    assert (
        "Keep each approved claim ID and source meaning; paraphrase candidate claims only when every qualification and limitation remains explicit."
        in writer_instructions
    )
    assert (
        "Employer-kind claims must be copied exactly, character for character, from their bound approved source text; do not paraphrase, merge, or rewrite them."
        in writer_instructions
    )
    expected_employer_claims = {
        claim.claim_id: claim.text
        for claim in request.approved_claims
        if claim.fact_kind == "employer"
    }
    captured_employer_claims = {
        claim["claim_id"]: claim["text"]
        for claim in writer_request["editorial_request"]["approved_claims"]
        if claim["fact_kind"] == "employer"
    }
    assert expected_employer_claims
    assert captured_employer_claims == expected_employer_claims
    expected_candidate_claims = {
        claim.claim_id: claim.text
        for claim in request.approved_claims
        if claim.fact_kind == "candidate"
    }
    captured_candidate_claims = {
        claim["claim_id"]: claim["text"]
        for claim in writer_request["editorial_request"]["approved_claims"]
        if claim["fact_kind"] == "candidate"
    }
    assert captured_candidate_claims == expected_candidate_claims
    assert (
        "Add no work-rights text, AI disclosure, unsupported tool claim, or internal process commentary."
        in writer_instructions
    )
    assert writer_request["claim_section_policy"] == humanizer_request[
        "claim_section_policy"
    ]
    assert "required_claim_ids" not in humanizer_request
    assert writer_request["available_claim_ids"] == expected_claim_ids
    assert humanizer_request["available_claim_ids"] == expected_claim_ids
    humanizer_instructions = " ".join(humanizer_request["instructions"])
    assert (
        "Do not add generic signposts or an Opening employer hook; follow the supplied claim assignments."
        in humanizer_instructions
    )
    assert "Preserve the exact salutation, sign-off, signature, and required CTA." in humanizer_instructions
    assert "Use no em dash, en dash, disclosure, internal commentary, or new fact." in humanizer_instructions


def test_current_cover_runtime_passes_trusted_mode_to_both_response_parsers() -> None:
    _, _, request, writer = _current_cover_fixture()
    final = writer

    def pretty(draft):
        return json.dumps(
            _current_cover_wire_document(draft), ensure_ascii=False, indent=2
        ).encode("utf-8") + b"\n"

    writer_bytes = pretty(writer)
    humanizer_bytes = pretty(final)
    writer_adapter = _Adapter("cover_letter_writer", "writer", writer)
    writer_adapter.response_bytes = writer_bytes
    humanizer_adapter = _Adapter("cover_letter_humanizer", "humanizer", final)
    humanizer_adapter.response_bytes = humanizer_bytes
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
        document_kind="cover_letter",
    )

    writer_draft, final_draft, writer_evidence, humanizer_evidence = (
        run_cover_letter_composition_runtime(request, runtime=runtime)
    )

    assert writer_draft == writer
    assert final_draft == final
    assert writer_evidence.response_bytes_sha256 == hashlib.sha256(writer_bytes).hexdigest()
    assert humanizer_evidence.response_bytes_sha256 == hashlib.sha256(
        humanizer_bytes
    ).hexdigest()


def test_legacy_cover_runtime_still_requires_canonical_response_bytes() -> None:
    _, request, _, writer, final = _fixture()
    writer_adapter = _Adapter("cover_letter_writer", "writer", writer)
    writer_adapter.response_bytes = json.dumps(
        writer.document(), ensure_ascii=False, indent=2
    ).encode("utf-8") + b"\n"
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=_Adapter("cover_letter_humanizer", "humanizer", final),
        document_kind="cover_letter",
    )

    with pytest.raises(EditorialCompositionError, match="not canonical JSON"):
        run_cover_letter_composition_runtime(request, runtime=runtime)


def test_detached_cover_adapter_binds_format_mode_to_request_and_preserves_bytes(
    monkeypatch, tmp_path
) -> None:
    _, _, request, draft = _current_cover_fixture()
    response = _current_cover_wire_document(draft)
    response_bytes = json.dumps(
        response, ensure_ascii=False, indent=2
    ).encode("utf-8") + b"\n"
    binary = tmp_path / "synthetic-codex"
    binary.write_bytes(b"synthetic detached codex")
    binary.chmod(0o700)
    adapter = DetachedCodexEditorialAdapter(
        stage="cover_letter_writer",
        model="synthetic-model",
        codex_binary=str(binary),
        environment="synthetic",
        process_environment={"HOME": str(tmp_path), "PATH": str(tmp_path)},
    )
    request_bytes = canonical_json(
        {
            "editorial_request": request.document(),
            "instructions": [],
            "stage": "cover_letter_writer",
        }
    ).encode("utf-8")

    def fake_run(command, **kwargs):
        output = Path(command[command.index("--output-last-message") + 1])
        output.write_bytes(response_bytes)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"type": "item.completed", "item": {"type": "agent_message"}}
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "cv_generation.editorial_composition.subprocess.run", fake_run
    )
    result = adapter.open_fresh_session(invocation_id="current-cover").invoke(
        request_bytes=request_bytes
    )
    assert result.response_bytes == response_bytes
    assert result.response_sha256 == hashlib.sha256(response_bytes).hexdigest()


def test_detached_legacy_cover_adapter_requires_canonical_bytes_and_exact_mode(
    monkeypatch, tmp_path
) -> None:
    _, request, _, draft, _ = _fixture()
    response = draft.document()
    response.pop("draft_sha256")
    response_bytes = json.dumps(
        response, ensure_ascii=False, indent=2
    ).encode("utf-8") + b"\n"
    binary = tmp_path / "synthetic-legacy-codex"
    binary.write_bytes(b"synthetic detached codex")
    binary.chmod(0o700)
    adapter = DetachedCodexEditorialAdapter(
        stage="cover_letter_writer",
        model="synthetic-model",
        codex_binary=str(binary),
        environment="synthetic",
        process_environment={"HOME": str(tmp_path), "PATH": str(tmp_path)},
    )
    request_bytes = canonical_json(
        {
            "editorial_request": request.document(),
            "instructions": [],
            "stage": "cover_letter_writer",
        }
    ).encode("utf-8")
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--output-last-message") + 1])
        output.write_bytes(response_bytes)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"type": "item.completed", "item": {"type": "agent_message"}}
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "cv_generation.editorial_composition.subprocess.run", fake_run
    )
    with pytest.raises(EditorialCompositionError, match="not canonical JSON"):
        adapter.open_fresh_session(invocation_id="legacy-cover").invoke(
            request_bytes=request_bytes
        )
    malformed = json.loads(request_bytes)
    malformed["editorial_request"]["authority"]["current_runtime_pre_review"] = 1
    with pytest.raises(EditorialCompositionError, match="mode is invalid"):
        adapter.open_fresh_session(invocation_id="bad-mode-cover").invoke(
            request_bytes=canonical_json(malformed).encode("utf-8")
        )
    assert len(calls) == 1


@pytest.mark.parametrize("failure", ("duplicate", "unknown_fact"))
def test_detached_current_cover_adapter_keeps_duplicate_and_fact_guards(
    monkeypatch, tmp_path, failure
) -> None:
    _, _, request, draft = _current_cover_fixture()
    response = _current_cover_wire_document(draft)
    if failure == "unknown_fact":
        response["sections"][0]["atoms"][0]["source_kind"] = "unapproved_fact"
        response_bytes = json.dumps(response, ensure_ascii=False, indent=2).encode()
    else:
        valid = canonical_json(response).encode()
        response_bytes = b'{"candidate_name":"Other",' + valid[1:]
    binary = tmp_path / f"synthetic-codex-{failure}"
    binary.write_bytes(b"synthetic detached codex")
    binary.chmod(0o700)
    adapter = DetachedCodexEditorialAdapter(
        stage="cover_letter_writer",
        model="synthetic-model",
        codex_binary=str(binary),
        environment="synthetic",
        process_environment={"HOME": str(tmp_path), "PATH": str(tmp_path)},
    )
    request_bytes = canonical_json(
        {
            "editorial_request": request.document(),
            "instructions": [],
            "stage": "cover_letter_writer",
        }
    ).encode("utf-8")

    def fake_run(command, **kwargs):
        output = Path(command[command.index("--output-last-message") + 1])
        output.write_bytes(response_bytes)
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {"type": "item.completed", "item": {"type": "agent_message"}}
            ),
            stderr="",
        )

    monkeypatch.setattr(
        "cv_generation.editorial_composition.subprocess.run", fake_run
    )
    expected = "invalid JSON" if failure == "duplicate" else "source kind is unsupported"
    with pytest.raises(EditorialCompositionError, match=expected):
        adapter.open_fresh_session(invocation_id=f"current-cover-{failure}").invoke(
            request_bytes=request_bytes
        )

def test_cover_letter_admission_rejects_claim_mutation_and_kolhoz_text() -> None:
    _, request, _, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _evidence(request, writer, final)
    admit_cover_letter_editorial_composition(
        request=request,
        writer_draft=writer,
        final_draft=final,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )
    changed_claim = replace(
        final.sections[1].atoms[1], text="Invented five years of production ownership."
    )
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                final.sections[1],
                atoms=(
                    final.sections[1].atoms[0],
                    changed_claim,
                    final.sections[1].atoms[2],
                ),
            ),
            *final.sections[2:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="changed or invented"):
        validate_cover_letter_editorial_draft(request, changed)
    kolhoz = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            replace(final.sections[0], atoms=(EditorialAtom("connective", "I am applying — with great enthusiasm.", None),)),
            *final.sections[1:],
        ),
    )
    with pytest.raises(
        EditorialCompositionError,
        match="forbidden em or en dash",
    ):
        validate_cover_letter_editorial_draft(request, kolhoz)


def test_current_cover_letter_uses_bound_sections_and_exact_claims() -> None:
    _, claims, request, draft = _current_cover_fixture()
    validate_cover_letter_editorial_draft(request, draft)

    omitted_employer = build_cover_letter_editorial_draft(
        candidate_name=draft.candidate_name,
        sections=(
            replace(draft.sections[0], atoms=draft.sections[0].atoms[:2]),
            *draft.sections[1:],
        ),
        current_runtime=True,
    )
    validate_cover_letter_editorial_draft(request, omitted_employer)

    duplicated = build_cover_letter_editorial_draft(
        candidate_name=draft.candidate_name,
        sections=(
            replace(
                draft.sections[0],
                atoms=(*draft.sections[0].atoms, draft.sections[0].atoms[2]),
            ),
            *draft.sections[1:],
        ),
        current_runtime=True,
    )
    with pytest.raises(EditorialCompositionError, match="repeats an approved claim"):
        validate_cover_letter_editorial_draft(request, duplicated)

    misplaced_company_fit = replace(
        draft.sections[2],
        atoms=(*draft.sections[2].atoms, draft.sections[1].atoms[-1]),
    )
    misplaced = build_cover_letter_editorial_draft(
        candidate_name=draft.candidate_name,
        sections=(
            draft.sections[0],
            draft.sections[1],
            misplaced_company_fit,
            *draft.sections[3:],
        ),
        current_runtime=True,
    )
    with pytest.raises(EditorialCompositionError, match="wrong section"):
        validate_cover_letter_editorial_draft(request, misplaced)

    with pytest.raises(EditorialCompositionError, match="claim policy"):
        build_cover_letter_editorial_request(
            authority=request.authority,
            role_title=request.role_title,
            company_name=request.company_name,
            vacancy_sha256=request.vacancy_sha256,
            approved_claims=(claims[1],),
        )


def test_current_cover_letter_pairs_remain_invalid_in_legacy_mode() -> None:
    authority, _, _, _ = _current_cover_fixture()
    legacy_authority = replace(authority, current_runtime=False)
    legacy_incompatible_claims = (
        _claim(
            "candidate-opening",
            "Built a reproducible evidence review process.",
            "candidate",
            "Opening",
        ),
        _claim(
            "employer-evidence",
            "Example Systems runs a support platform for software teams.",
            "employer",
            "Evidence Match",
        ),
    )
    with pytest.raises(EditorialCompositionError, match="claim policy"):
        build_cover_letter_editorial_request(
            authority=legacy_authority,
            role_title="Data Engineer",
            company_name="Example Systems",
            vacancy_sha256="b" * 64,
            approved_claims=legacy_incompatible_claims,
        )


@pytest.mark.parametrize(
    "connective",
    (
        "As a leader, I built the function.",
        "Written with ChatGPT.",
        "Visa sponsorship is not required.",
        "They have it.",
        "This is it.",
    ),
)
def test_cover_letter_rejects_unsupported_content_smuggled_as_connective(
    connective: str,
) -> None:
    _, request, _, _, final = _fixture()
    evidence_match = final.sections[1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                evidence_match,
                atoms=(EditorialAtom("connective", connective, None), *evidence_match.atoms),
            ),
            *final.sections[2:],
        ),
    )
    with pytest.raises(
        EditorialCompositionError,
        match="typed rhetoric|work-rights|AI-authorship",
    ):
        validate_cover_letter_editorial_draft(request, changed)


def test_cover_letter_rejects_connective_after_exact_factual_span() -> None:
    _, request, _, _, final = _fixture()
    evidence_match = final.sections[1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                evidence_match,
                atoms=(
                    *evidence_match.atoms,
                    EditorialAtom("connective", "That is the practical match.", None),
                ),
            ),
            *final.sections[2:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="typed rhetoric"):
        validate_cover_letter_editorial_draft(request, changed)


def test_cover_letter_requires_exact_salutation_before_approved_hook() -> None:
    _, request, _, _, final = _fixture()
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            replace(final.sections[0], atoms=final.sections[0].atoms[1:]),
            *final.sections[1:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="exact salutation"):
        validate_cover_letter_editorial_draft(request, changed)


def test_cover_letter_rejects_616_word_authorised_fact() -> None:
    _, request, claims, _, final = _fixture()
    oversized = _claim(
        claims[0].claim_id,
        " ".join("automation" for _ in range(616)),
        "candidate",
        "Evidence Match",
    )
    changed_request = build_cover_letter_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(oversized, *claims[1:]),
    )
    evidence_match = final.sections[1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                evidence_match,
                atoms=(
                    evidence_match.atoms[0],
                    EditorialAtom(
                        "approved_claim", oversized.text, oversized.claim_id
                    ),
                    evidence_match.atoms[2],
                ),
            ),
            *final.sections[2:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="one-page proxy"):
        validate_cover_letter_editorial_draft(changed_request, changed)


@pytest.mark.parametrize(
    "forbidden_text",
    (
        "Built an evidence-bound system — with deterministic checks.",
        "Visa sponsorship is not required.",
        "This cover letter was written with ChatGPT.",
        "My CV was prepared with AI assistance.",
        "An LLM generated this application.",
        "Built this cover letter with ChatGPT.",
        "This CV was AI-assisted.",
        "This cover letter had AI assistance.",
        "I used ChatGPT to write this CV.",
        "ChatGPT helped me write this cover letter.",
        "This letter was prepared using ChatGPT.",
        "AI prepared this letter.",
        "ChatGPT prepared this letter.",
    ),
)
def test_global_bans_apply_to_approved_cover_letter_facts(
    forbidden_text: str,
) -> None:
    _, request, claims, _, final = _fixture()
    forbidden = _claim(
        claims[0].claim_id,
        forbidden_text,
        "candidate",
        "Evidence Match",
    )
    changed_request = build_cover_letter_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(forbidden, *claims[1:]),
    )
    evidence_match = final.sections[1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                evidence_match,
                atoms=(
                    evidence_match.atoms[0],
                    EditorialAtom(
                        "approved_claim", forbidden.text, forbidden.claim_id
                    ),
                    evidence_match.atoms[2],
                ),
            ),
            *final.sections[2:],
        ),
    )
    with pytest.raises(
        EditorialCompositionError,
        match="forbidden em or en dash|work-rights|AI-authorship",
    ):
        validate_cover_letter_editorial_draft(changed_request, changed)


def test_opening_hook_must_name_exact_company_and_role_from_approved_fact() -> None:
    _, request, claims, _, final = _fixture()
    generic_hook = _claim(
        claims[2].claim_id,
        "Example Systems is hiring for reliable automation.",
        "employer",
        "Opening",
    )
    changed_claims = (*claims[:2], generic_hook, *claims[3:])
    changed_request = build_cover_letter_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=changed_claims,
    )
    opening = final.sections[0]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            replace(
                opening,
                atoms=(
                    opening.atoms[0],
                    opening.atoms[1],
                    EditorialAtom(
                        "approved_claim", generic_hook.text, generic_hook.claim_id
                    ),
                ),
            ),
            *final.sections[1:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="company and role hook"):
        validate_cover_letter_editorial_draft(changed_request, changed)


@pytest.mark.parametrize(
    "disclosure",
    (
        "this letter was prepared using ChatGPT",
        "AI prepared this letter",
        "ChatGPT prepared this letter",
    ),
)
def test_opening_company_role_hook_rejects_standalone_letter_authorship(
    disclosure: str,
) -> None:
    _, request, claims, _, final = _fixture()
    forbidden = _claim(
        claims[2].claim_id,
        (
            "Example Systems is hiring an AI Automation Engineer and states that "
            f"{disclosure}."
        ),
        "employer",
        "Opening",
    )
    changed_request = build_cover_letter_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(*claims[:2], forbidden, *claims[3:]),
    )
    opening = final.sections[0]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            replace(
                opening,
                atoms=(
                    opening.atoms[0],
                    opening.atoms[1],
                    EditorialAtom(
                        "approved_claim", forbidden.text, forbidden.claim_id
                    ),
                ),
            ),
            *final.sections[1:],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="AI-authorship"):
        validate_cover_letter_editorial_draft(changed_request, changed)


@pytest.mark.parametrize(
    "disclosure",
    (
        "this letter was prepared using ChatGPT",
        "AI prepared this letter",
        "ChatGPT prepared this letter",
    ),
)
def test_company_fit_rejects_standalone_letter_authorship(
    disclosure: str,
) -> None:
    _, request, claims, _, final = _fixture()
    forbidden = _claim(
        claims[3].claim_id,
        f"Example Systems states that {disclosure}.",
        "employer",
        "Company Fit",
    )
    changed_request = build_cover_letter_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(*claims[:3], forbidden, *claims[4:]),
    )
    company_fit = final.sections[2]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            *final.sections[:2],
            replace(
                company_fit,
                atoms=(
                    company_fit.atoms[0],
                    EditorialAtom(
                        "approved_claim", forbidden.text, forbidden.claim_id
                    ),
                    company_fit.atoms[2],
                ),
            ),
            final.sections[3],
        ),
    )
    with pytest.raises(EditorialCompositionError, match="AI-authorship"):
        validate_cover_letter_editorial_draft(changed_request, changed)


@pytest.mark.parametrize(
    "legitimate_text",
    (
        "Built an AI-generated application document pipeline.",
        "Built a ChatGPT application that generated CV drafts.",
        "Built an AI tool that drafted the CV output.",
    ),
)
def test_authorship_control_allows_authority_bound_project_facts(
    legitimate_text: str,
) -> None:
    _, request, claims, _, final = _fixture()
    legitimate = _claim(
        claims[0].claim_id,
        legitimate_text,
        "candidate",
        "Evidence Match",
    )
    changed_request = build_cover_letter_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(legitimate, *claims[1:]),
    )
    evidence_match = final.sections[1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            final.sections[0],
            replace(
                evidence_match,
                atoms=(
                    evidence_match.atoms[0],
                    EditorialAtom(
                        "approved_claim", legitimate.text, legitimate.claim_id
                    ),
                    evidence_match.atoms[2],
                ),
            ),
            *final.sections[2:],
        ),
    )

    validate_cover_letter_editorial_draft(changed_request, changed)


def test_cover_letter_requires_substantive_typed_cta_before_signoff() -> None:
    _, request, _, _, final = _fixture()
    close = final.sections[-1]
    changed = build_cover_letter_editorial_draft(
        candidate_name=final.candidate_name,
        sections=(
            *final.sections[:-1],
            replace(close, atoms=close.atoms[1:]),
        ),
    )
    with pytest.raises(EditorialCompositionError, match="substantive CTA"):
        validate_cover_letter_editorial_draft(request, changed)


def test_natural_full_letter_uses_only_typed_rhetoric_and_exact_evidence() -> None:
    _, request, _, _, final = _fixture()

    validate_cover_letter_editorial_draft(request, final)
    paragraphs = tuple(
        " ".join(atom.text for atom in section.atoms)
        for section in final.sections
    )

    assert len(paragraphs) == 4
    assert paragraphs[0].startswith("Dear Hiring Manager,")
    assert "AI Automation Engineer role at Example Systems" in paragraphs[0]
    assert "evidence-bound multi-agent orchestration system" in paragraphs[1]
    assert "Example Systems requires evidence-led" in paragraphs[2]
    assert paragraphs[3].startswith("I would welcome the opportunity")
    assert paragraphs[3].endswith("Kind regards Artiom Gutu")


def _result() -> dict[str, object]:
    value = fixture_recruiter_result(
        fit_percent=62,
        fit_low=50,
        fit_high=72,
        overall_verdict="strong_fit",
    )
    value.update({
        "strengths": [{"location": "cover_letter", "assessment": "Specific evidence.", "outward_evidence_refs": ["cover_letter:char:0:1"]}],
        "risks": [{"category": "relevance", "severity": "low", "location": "cover_letter", "assessment": "Employer proof could appear sooner.", "outward_evidence_refs": ["cover_letter:char:0:1"]}],
        "application_improvements": [
            {"rank": 1, "target": "cover_letter", "recommendation": "Lead with the evidence-led employer fact.", "expected_effect": "Makes the company match visible sooner.", "support_required": False, "outward_evidence_refs": ["cover_letter:char:0:1"]},
            {"rank": 2, "target": "cover_letter", "recommendation": "Add five years of unsupported ownership.", "expected_effect": "Would inflate seniority.", "support_required": True, "outward_evidence_refs": ["cover_letter:char:0:1"]},
            {"rank": 3, "target": "cv", "recommendation": "Change the CV order.", "expected_effect": "Moves project evidence.", "support_required": False, "outward_evidence_refs": ["cv:char:0:1"]},
        ],
        "profile_improvements": [{"category": "experience", "recommendation": "Build larger-scale evidence.", "time_horizon": "months", "expected_effect": "Strengthens future applications."}],
    })
    return value


class _Recruiter(Backend):
    name = "cover-letter-recruiter-fixture"

    def available(self):
        return True

    def complete(self, system, user, temperature):
        del system, user, temperature
        return LLMResponse(text=json.dumps(_result()), model="fixture-v1")


def test_recruiter_applies_only_bound_cover_advice_and_routes_unsupported(tmp_path) -> None:
    listing, request, _, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _evidence(request, writer, final)
    _, _, editorial = admit_cover_letter_editorial_composition(
        request=request, writer_draft=writer, final_draft=final,
        writer_evidence=writer_evidence, humanizer_evidence=humanizer_evidence,
    )
    package = RecruiterAssessmentPackage(
        listing_text=listing,
        listing_text_sha256=request.vacancy_sha256,
        cv_pdf_bytes=_build_text_pdf((("Synthetic CV",),)),
        cover_letter_pdf_bytes=_build_text_pdf((tuple(atom.text for section in final.sections for atom in section.atoms),)),
        form_fields=(),
        intended_vacancy=IntendedVacancy("example:role", "b" * 64, request.role_title, request.company_name),
    )
    receipt = assess_application_as_recruiter(
        package,
        client=LLMClient(
            backend=_Recruiter(), model="fixture-v1", temperature=0, max_retries=1,
            cache_enabled=False, cache_dir=tmp_path / "cache", usage_log=tmp_path / "usage.jsonl",
        ),
    )
    binding = bind_cover_letter_recruiter_improvement(
        improvement_index=0,
        target_heading="Company Fit",
        claim_ids=("employer-secondary",),
        authority_source_sha256=request.authority.source_sha256,
        vacancy_sha256=request.vacancy_sha256,
        model_result_sha256=receipt.model_result_sha256,
        binding_source_sha256="c" * 64,
    )
    rebuilt = rebuild_cover_letter_from_recruiter_assessment(
        request=request,
        admitted_draft=final,
        editorial_receipt=editorial,
        recruiter_receipt=receipt,
        recruiter_package=package,
        bindings=(binding,),
        assessed_cover_letter_text_sha256=receipt.package_hashes["cover_letter_text_sha256"],
    )
    company = next(section for section in rebuilt.rebuilt_draft.sections if section.heading == "Company Fit")
    assert [atom.claim_id for atom in company.atoms if atom.claim_id] == [
        "employer-secondary", "employer-primary"
    ]
    assert [item.improvement_index for item in rebuilt.applied] == [0]
    assert [(item.source_index, item.reason_code) for item in rebuilt.roadmap] == [
        (1, "unsupported_by_candidate_or_vacancy_authority")
    ]
    substituted = bind_cover_letter_recruiter_improvement(
        improvement_index=0,
        target_heading="Company Fit",
        claim_ids=("employer-secondary",),
        authority_source_sha256=request.authority.source_sha256,
        vacancy_sha256="f" * 64,
        model_result_sha256=receipt.model_result_sha256,
        binding_source_sha256="c" * 64,
    )
    with pytest.raises(AdversarialRebuildError, match="different authority"):
        rebuild_cover_letter_from_recruiter_assessment(
            request=request, admitted_draft=final, editorial_receipt=editorial,
            recruiter_receipt=receipt, recruiter_package=package, bindings=(substituted,),
            assessed_cover_letter_text_sha256=receipt.package_hashes["cover_letter_text_sha256"],
        )

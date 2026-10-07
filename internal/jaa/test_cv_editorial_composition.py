from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

import cv_generation.editorial_composition as editorial_module
from career_automation.candidate_application_factory import (
    CandidateApplicationMaterializationReceipt,
)
from cv_generation.editorial_composition import (
    ApprovedCVClaim,
    CVSection,
    CandidateEditorialAuthority,
    EditorialAtom,
    EditorialCompositionError,
    EditorialBackendResult,
    EditorialCompositionRuntime,
    DetachedCodexEditorialAdapter,
    EditorialStageEvidence,
    admit_editorial_composition,
    build_editorial_draft,
    build_editorial_request,
    humanizer_request_sha256,
    run_editorial_composition_runtime,
    probe_detached_codex_editorial_cli,
    validate_editorial_draft,
)
from career_automation.evidence_matching import canonical_json


TITLE = (
    "SCAFAD: A Seven-Layer, Privacy-Preserving, Explainable "
    "Anomaly-Detection Pipeline for Serverless Workloads"
)


def test_detached_response_schema_types_every_property() -> None:
    def require_property_types(schema: object) -> None:
        assert isinstance(schema, dict)
        properties = schema.get("properties", {})
        assert isinstance(properties, dict)
        for property_schema in properties.values():
            assert isinstance(property_schema, dict)
            assert "type" in property_schema
            require_property_types(property_schema)
        if isinstance(schema.get("items"), dict):
            require_property_types(schema["items"])

    require_property_types(editorial_module._DRAFT_RESPONSE_SCHEMA)
    require_property_types(editorial_module._COVER_LETTER_RESPONSE_SCHEMA)


def _synthetic_cover_response() -> dict[str, object]:
    return {
        "candidate_name": "Casey Synthetic",
        "schema_version": editorial_module.COVER_LETTER_DRAFT_SCHEMA,
        "sections": [
            {
                "heading": heading,
                "atoms": [
                    {
                        "claim_id": None,
                        "source_kind": "connective",
                        "text": "Synthetic text.",
                    }
                ],
            }
            for heading in ("Opening", "Evidence Match", "Company Fit", "Close")
        ],
    }


def _cover_response_bytes(document: dict[str, object]) -> bytes:
    return canonical_json(document).encode("utf-8")


def test_cover_response_parser_keeps_canonical_mode_and_allows_current_formatting() -> None:
    document = _synthetic_cover_response()
    canonical = _cover_response_bytes(document)
    pretty = json.dumps(document, ensure_ascii=False, indent=2).encode("utf-8") + b"\n"

    for current_runtime in (False, True):
        parsed = editorial_module._cover_letter_draft_from_response(
            canonical, current_runtime=current_runtime
        )
        assert parsed.document(include_identity=False) == document

    parsed = editorial_module._cover_letter_draft_from_response(
        pretty, current_runtime=True
    )
    assert parsed.document(include_identity=False) == document
    with pytest.raises(EditorialCompositionError, match="not canonical JSON"):
        editorial_module._cover_letter_draft_from_response(
            pretty, current_runtime=False
        )


@pytest.mark.parametrize(
    "raw",
    (
        b'{"candidate_name":"Casey","candidate_name":"Other"}',
        b'{"candidate_name":"Casey","nested":{"key":1,"key":2}}',
        b'{"candidate_name":"Casey","nested":{"x":1,"\\u0078":2}}',
    ),
)
def test_cover_response_parser_rejects_duplicate_keys_in_current_mode(raw: bytes) -> None:
    with pytest.raises(EditorialCompositionError, match="invalid JSON"):
        editorial_module._cover_letter_draft_from_response(
            raw, current_runtime=True
        )


@pytest.mark.parametrize(
    "number",
    (b"NaN", b"Infinity", b"-Infinity", b"1e400", b"-1e400"),
)
def test_cover_response_parser_rejects_nonfinite_numbers_in_current_mode(
    number: bytes,
) -> None:
    raw = b'{"candidate_name":"Casey","value":' + number + b"}"
    with pytest.raises(EditorialCompositionError, match="invalid JSON"):
        editorial_module._cover_letter_draft_from_response(
            raw, current_runtime=True
        )


@pytest.mark.parametrize(
    "raw",
    (
        b"\xef\xbb\xbf{}",
        b'{"candidate_name":"Casey"} trailing',
        b"[1,2]",
        b"\xff",
    ),
)
def test_cover_response_parser_rejects_malformed_json_in_current_mode(raw: bytes) -> None:
    with pytest.raises(EditorialCompositionError):
        editorial_module._cover_letter_draft_from_response(
            raw, current_runtime=True
        )


@pytest.mark.parametrize("current_runtime", (1, 0, "true", None))
def test_cover_response_parser_rejects_non_exact_mode_types(current_runtime) -> None:
    with pytest.raises(EditorialCompositionError, match="invalid JSON"):
        editorial_module._cover_letter_draft_from_response(
            _cover_response_bytes(_synthetic_cover_response()),
            current_runtime=current_runtime,
        )


def test_cover_response_parser_rejects_non_bytes_and_unpaired_surrogates() -> None:
    class BytesSubclass(bytes):
        pass

    with pytest.raises(EditorialCompositionError, match="invalid JSON"):
        editorial_module._cover_letter_draft_from_response(
            BytesSubclass(b"{}"), current_runtime=True
        )
    with pytest.raises(EditorialCompositionError, match="invalid JSON"):
        editorial_module._cover_letter_draft_from_response(
            bytearray(b"{}"), current_runtime=True
        )
    for raw in (
        b'{"candidate_name":"\\ud800"}',
        b'{"candidate_name":"Casey","sections":[{"text":"\\ude00"}]}',
    ):
        with pytest.raises(EditorialCompositionError, match="invalid JSON"):
            editorial_module._cover_letter_draft_from_response(
                raw, current_runtime=True
            )

    document = _synthetic_cover_response()
    document["candidate_name"] = "Casey 😀"
    paired = json.dumps(document, ensure_ascii=True).encode("utf-8")
    parsed = editorial_module._cover_letter_draft_from_response(
        paired, current_runtime=True
    )
    assert parsed.candidate_name == "Casey 😀"


def test_editorial_section_policy_keeps_legacy_and_maps_current_headings() -> None:
    legacy = editorial_module.editorial_section_policy()
    current = editorial_module.editorial_section_policy(current_runtime=True)

    assert legacy == editorial_module._CATEGORY_BY_HEADING
    assert all(type(categories) is frozenset for categories in current.values())
    assert current["Highlights"] == frozenset({"highlight"})
    assert current["Skills"] == frozenset({"skill"})
    assert editorial_module.category_for_source_heading(
        "Highlights", current_runtime=True
    ) == "highlight"
    assert editorial_module.category_for_source_heading(
        "Skills", current_runtime=True
    ) == "skill"
    with pytest.raises(ValueError, match="invalid editorial section policy"):
        editorial_module.category_for_source_heading("highlight", current_runtime=True)
    with pytest.raises(ValueError, match="invalid editorial section policy"):
        editorial_module.category_for_source_heading("Highlights")

    schema = editorial_module._DRAFT_RESPONSE_SCHEMA
    legacy_schema = editorial_module.editorial_layout_response_schema(dict(schema))
    current_schema = editorial_module.editorial_layout_response_schema(
        dict(schema), current_runtime=True
    )
    assert legacy_schema == schema
    assert legacy_schema is not schema
    assert current_schema["properties"]["sections"]["minItems"] == 1
    assert current_schema["properties"]["sections"]["items"]["properties"][
        "heading"
    ]["enum"] == sorted(current)
    assert schema["properties"]["sections"]["minItems"] == 2
    assert editorial_module.validate_editorial_layout(("Highlights",), current_runtime=True) is None
    with pytest.raises(ValueError, match="invalid editorial section policy"):
        editorial_module.validate_editorial_layout(("Highlights",))


def test_current_highlight_draft_round_trips_without_legacy_required_sections() -> None:
    authority = CandidateEditorialAuthority(
        candidate_name="Synthetic Candidate",
        candidate_city="London, United Kingdom",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
        current_runtime=True,
    )
    claim = _claim(
        "highlight-1",
        "Delivered a workflow improvement.",
        editorial_module.category_for_source_heading(
            "Highlights", current_runtime=True
        ),
    )
    request = build_editorial_request(
        authority=authority,
        role_title="Synthetic Analyst",
        company_name="Example Employer",
        vacancy_sha256="b" * 64,
        approved_claims=(claim,),
    )
    assert request.approved_claims == (claim,)

    legacy_authority = CandidateEditorialAuthority(
        candidate_name="Synthetic Candidate",
        candidate_city="London, United Kingdom",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="a" * 64,
    )
    with pytest.raises(
        EditorialCompositionError,
        match="category is unsupported for editorial runtime",
    ):
        build_editorial_request(
            authority=legacy_authority,
            role_title="Synthetic Analyst",
            company_name="Example Employer",
            vacancy_sha256="b" * 64,
            approved_claims=(claim,),
        )
    draft = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=(
            CVSection(
                "Highlights",
                (EditorialAtom("approved_claim", claim.text, claim.claim_id),),
            ),
        ),
        current_runtime=True,
    )

    response = editorial_module._draft_from_response(
        canonical_json(draft.document()).encode(), current_runtime=True
    )
    validate_editorial_draft(request, response, current_runtime=True)
    assert response.document() == draft.document()
    assert response.current_runtime is True
    with pytest.raises(EditorialCompositionError, match="layout is invalid"):
        build_editorial_draft(
            candidate_name=authority.candidate_name,
            candidate_city=authority.candidate_city,
            sections=draft.sections,
        )
    with pytest.raises(EditorialCompositionError, match="mode differs from authority"):
        validate_editorial_draft(request, response, current_runtime=False)


def test_current_claim_assignment_uses_unique_primary_headings() -> None:
    categories_by_heading = editorial_module.editorial_section_policy(
        current_runtime=True
    )
    primary_category_by_heading = {
        heading: editorial_module.category_for_source_heading(
            heading, current_runtime=True
        )
        for heading in categories_by_heading
    }
    claims = [
        {"claim_id": "project-claim", "category": "project"},
        {"claim_id": "summary-claim", "category": "summary"},
    ]

    assignment = editorial_module.build_cv_claim_assignment_contract(
        claims, categories_by_heading, primary_category_by_heading
    )

    assert assignment == {
        "claim_section_policy": {
            "project-claim": ["Projects"],
            "summary-claim": ["Professional Summary"],
        },
        "required_claim_ids": ["project-claim", "summary-claim"],
    }
    assert "project" in categories_by_heading["Professional Summary"]

    class _HeadingKey(str):
        pass

    subclass_heading_map = {
        _HeadingKey(heading): category
        for heading, category in primary_category_by_heading.items()
    }
    with pytest.raises(ValueError, match="invalid CV claim assignment"):
        editorial_module.build_cv_claim_assignment_contract(
            claims, categories_by_heading, subclass_heading_map
        )


def test_current_cv_draft_requires_each_bound_claim_once_in_its_primary_section() -> None:
    request, draft = _current_fixture()
    validate_editorial_draft(request, draft, current_runtime=True)
    highlight_claim, project_claim = request.approved_claims

    omitted = build_editorial_draft(
        candidate_name=request.authority.candidate_name,
        candidate_city=request.authority.candidate_city,
        sections=(
            CVSection(
                "Highlights",
                (
                    EditorialAtom(
                        "approved_claim", highlight_claim.text, highlight_claim.claim_id
                    ),
                ),
            ),
        ),
        current_runtime=True,
    )
    with pytest.raises(
        EditorialCompositionError, match="must use every approved claim exactly once"
    ):
        validate_editorial_draft(request, omitted, current_runtime=True)

    repeated = build_editorial_draft(
        candidate_name=request.authority.candidate_name,
        candidate_city=request.authority.candidate_city,
        sections=(
            CVSection(
                "Highlights",
                (
                    EditorialAtom(
                        "approved_claim", highlight_claim.text, highlight_claim.claim_id
                    ),
                ),
            ),
            CVSection(
                "Projects",
                (
                    EditorialAtom(
                        "approved_claim", project_claim.text, project_claim.claim_id
                    ),
                    EditorialAtom(
                        "approved_claim", project_claim.text, project_claim.claim_id
                    ),
                ),
            ),
        ),
        current_runtime=True,
    )
    with pytest.raises(EditorialCompositionError, match="repeats an approved claim"):
        validate_editorial_draft(request, repeated, current_runtime=True)

    wrong_primary_section = build_editorial_draft(
        candidate_name=request.authority.candidate_name,
        candidate_city=request.authority.candidate_city,
        sections=(
            CVSection(
                "Professional Summary",
                (
                    EditorialAtom(
                        "approved_claim", project_claim.text, project_claim.claim_id
                    ),
                ),
            ),
        ),
        current_runtime=True,
    )
    with pytest.raises(
        EditorialCompositionError, match="outside its assigned CV section"
    ):
        validate_editorial_draft(request, wrong_primary_section, current_runtime=True)


def _claim(claim_id: str, text: str, category: str) -> ApprovedCVClaim:
    return ApprovedCVClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        evidence_ids=(f"evidence:{claim_id}",),
        category=category,
    )


def _adapter_request_bytes() -> bytes:
    return canonical_json(
        {"editorial_request": {"authority": {"candidate_city": "London"}}}
    ).encode()


def _fixture():
    authority = CandidateEditorialAuthority(
        candidate_name="Artiom Gutu",
        candidate_city="Birmingham, United Kingdom",
        graduation_month_year="July 2026",
        dissertation_title=TITLE,
        source_sha256="a" * 64,
        require_dissertation=True,
    )
    claims = (
        _claim(
            "summary",
            "AI systems engineer focused on reliable automation.",
            "summary",
        ),
        _claim(
            "capability",
            "AI orchestration, systems design, workflow automation and assurance.",
            "capability_domain",
        ),
        _claim(
            "project",
            "Built an evidence-bound multi-agent orchestration system.",
            "project",
        ),
        _claim(
            "education",
            f"First-Class BSc (Hons) Computer Science, July 2026. Dissertation: {TITLE}.",
            "education",
        ),
    )
    request = build_editorial_request(
        authority=authority,
        role_title="AI Automation Engineer",
        company_name="Example Systems",
        vacancy_sha256="b" * 64,
        approved_claims=claims,
    )
    sections = (
        CVSection(
            "Professional Summary",
            (EditorialAtom("approved_claim", claims[0].text, "summary"),),
        ),
        CVSection(
            "Core Capabilities",
            (EditorialAtom("approved_claim", claims[1].text, "capability"),),
        ),
        CVSection(
            "Projects",
            (EditorialAtom("approved_claim", claims[2].text, "project"),),
        ),
        CVSection(
            "Education",
            (EditorialAtom("approved_claim", claims[3].text, "education"),),
        ),
    )
    writer = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=sections,
    )
    final = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=sections,
    )
    return request, writer, final


def _current_fixture():
    authority = CandidateEditorialAuthority(
        candidate_name="Synthetic Candidate",
        candidate_city="Example City, United Kingdom",
        graduation_month_year=None,
        dissertation_title=None,
        source_sha256="c" * 64,
        current_runtime=True,
    )
    claims = (
        _claim("highlight", "Delivered a structured workflow improvement.", "highlight"),
        _claim("project", "Built a synthetic planning workflow.", "project"),
    )
    request = build_editorial_request(
        authority=authority,
        role_title="Synthetic Engineer",
        company_name="Example Employer",
        vacancy_sha256="d" * 64,
        approved_claims=claims,
    )
    draft = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=(
            CVSection(
                "Highlights",
                (EditorialAtom("approved_claim", claims[0].text, claims[0].claim_id),),
            ),
            CVSection(
                "Projects",
                (EditorialAtom("approved_claim", claims[1].text, claims[1].claim_id),),
            ),
        ),
        current_runtime=True,
    )
    return request, draft


def _stage_evidence(request, writer, final):
    return (
        EditorialStageEvidence(
            stage="resume_writer",
            environment="synthetic",
            provider="fixture-writer",
            model="fixture-v1",
            invocation_id="writer-session-1",
            request_sha256=request.request_sha256,
            response_sha256=writer.draft_sha256,
        ),
        EditorialStageEvidence(
            stage="humanizer",
            environment="synthetic",
            provider="fixture-humanizer",
            model="fixture-v1",
            invocation_id="humanizer-session-1",
            request_sha256=humanizer_request_sha256(request, writer),
            response_sha256=final.draft_sha256,
        ),
    )


class _ScriptedStageSession:
    def __init__(self, adapter, invocation_id):
        self.adapter = adapter
        self.invocation_id = invocation_id

    def invoke(self, *, request_bytes):
        return self.adapter._invoke(
            request_bytes=request_bytes, invocation_id=self.invocation_id
        )


class _ScriptedStageAdapter:
    def __init__(self, provider, model, draft, *, environment="synthetic"):
        self.provider = provider
        self.model = model
        self.transport_identity = f"fixture.transport.{provider}"
        self.environment = environment
        self.draft = draft
        self.calls = []

    def open_fresh_session(self, *, invocation_id):
        return _ScriptedStageSession(self, invocation_id)

    def available(self):
        return True

    def _invoke(self, *, request_bytes, invocation_id):
        self.calls.append((request_bytes, invocation_id))
        return EditorialBackendResult(
            response_bytes=(response := canonical_json(self.draft.document()).encode()),
            invocation_id=invocation_id,
            environment=self.environment,
            provider=self.provider,
            model=self.model,
            transport_identity=self.transport_identity,
            request_sha256=hashlib.sha256(request_bytes).hexdigest(),
            response_sha256=hashlib.sha256(response).hexdigest(),
            executable_sha256="e" * 64,
        )


def test_runtime_invokes_explicit_writer_and_humanizer_then_admits_outputs() -> None:
    request, writer, final = _fixture()
    writer_adapter = _ScriptedStageAdapter("fixture-writer", "writer-v2", writer)
    humanizer_adapter = _ScriptedStageAdapter(
        "fixture-humanizer", "humanizer-v2", final
    )
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
    )

    result = run_editorial_composition_runtime(request, runtime=runtime)

    assert result[:2] == (writer, final)
    assert result[2].provider == "fixture-writer"
    assert result[3].provider == "fixture-humanizer"
    assert len(writer_adapter.calls) == len(humanizer_adapter.calls) == 1
    assert writer_adapter.calls[0][1] != humanizer_adapter.calls[0][1]
    writer_request = json.loads(writer_adapter.calls[0][0])
    assert writer_request["claim_section_policy"] == {
        "capability": ["Core Capabilities"],
        "education": ["Education"],
        "project": ["Professional Summary", "Projects"],
        "summary": ["Professional Summary"],
    }
    assert "required_claim_ids" not in writer_request
    assert not any(
        "exactly once globally" in instruction
        for instruction in writer_request["instructions"]
    )


def test_current_runtime_writer_request_assigns_all_claims_once() -> None:
    request, draft = _current_fixture()
    writer_adapter = _ScriptedStageAdapter(
        "fixture-current-writer", "writer-v2", draft
    )
    humanizer_adapter = _ScriptedStageAdapter(
        "fixture-current-humanizer", "humanizer-v2", draft
    )
    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
    )

    run_editorial_composition_runtime(request, runtime=runtime)

    writer_request = json.loads(writer_adapter.calls[0][0])
    assert writer_request["claim_section_policy"] == {
        "highlight": ["Highlights"],
        "project": ["Projects"],
    }
    assert writer_request["required_claim_ids"] == ["highlight", "project"]
    assert any(
        "exactly once globally" in instruction
        for instruction in writer_request["instructions"]
    )
    assert any(
        "second copy" in instruction
        for instruction in writer_request["instructions"]
    )


def test_production_runtime_requires_exact_source_materialization() -> None:
    request, writer, final = _fixture()
    runtime = EditorialCompositionRuntime(
        environment="production",
        writer=_ScriptedStageAdapter(
            "production-writer", "writer-v2", writer, environment="production"
        ),
        humanizer=_ScriptedStageAdapter(
            "production-humanizer", "humanizer-v2", final, environment="production"
        ),
    )
    with pytest.raises(EditorialCompositionError, match="requires source materialization"):
        run_editorial_composition_runtime(request, runtime=runtime)

    class _DuckTypedReceipt:
        def authorize_editorial_request(self, candidate_request):
            raise AssertionError("duck-typed authority must never be called")

    with pytest.raises(EditorialCompositionError, match="requires source materialization"):
        run_editorial_composition_runtime(
            request,
            runtime=runtime,
            materialization_receipt=_DuckTypedReceipt(),
        )
    assert not runtime.writer.calls


@pytest.mark.parametrize("receipt_kind", ("subclass", "invalid_exact"))
def test_production_revalidates_exact_receipt_before_provider_availability(
    receipt_kind: str,
) -> None:
    request, writer, final = _fixture()

    class _AvailabilityProbe(_ScriptedStageAdapter):
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

    receipt = object.__new__(
        _ForgedReceipt
        if receipt_kind == "subclass"
        else CandidateApplicationMaterializationReceipt
    )
    writer_adapter = _AvailabilityProbe(
        "production-writer", "writer-v2", writer, environment="production"
    )
    humanizer_adapter = _AvailabilityProbe(
        "production-humanizer", "humanizer-v2", final, environment="production"
    )
    runtime = EditorialCompositionRuntime(
        environment="production",
        writer=writer_adapter,
        humanizer=humanizer_adapter,
    )

    with pytest.raises(
        EditorialCompositionError,
        match="requires source materialization|differs from source materialization",
    ):
        run_editorial_composition_runtime(
            request,
            runtime=runtime,
            materialization_receipt=receipt,
        )

    assert writer_adapter.availability_calls == 0
    assert humanizer_adapter.availability_calls == 0
    assert not writer_adapter.calls
    assert not humanizer_adapter.calls


def test_runtime_rejects_provider_identity_substitution() -> None:
    request, writer, final = _fixture()

    class _SubstitutingAdapter(_ScriptedStageAdapter):
        def _invoke(self, *, request_bytes, invocation_id):
            result = super()._invoke(
                request_bytes=request_bytes, invocation_id=invocation_id
            )
            return replace(result, provider="different-provider")

    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=_SubstitutingAdapter("fixture-writer", "writer-v2", writer),
        humanizer=_ScriptedStageAdapter("fixture-humanizer", "humanizer-v2", final),
    )
    with pytest.raises(EditorialCompositionError, match="configured adapter"):
        run_editorial_composition_runtime(request, runtime=runtime)


def test_runtime_rejects_transport_request_hash_substitution() -> None:
    request, writer, final = _fixture()

    class _SubstitutingAdapter(_ScriptedStageAdapter):
        def _invoke(self, *, request_bytes, invocation_id):
            result = super()._invoke(
                request_bytes=request_bytes, invocation_id=invocation_id
            )
            return replace(result, request_sha256="0" * 64)

    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=_SubstitutingAdapter("fixture-writer", "writer-v2", writer),
        humanizer=_ScriptedStageAdapter("fixture-humanizer", "humanizer-v2", final),
    )
    with pytest.raises(EditorialCompositionError, match="configured adapter"):
        run_editorial_composition_runtime(request, runtime=runtime)


def test_runtime_rejects_reused_cross_stage_session() -> None:
    request, writer, final = _fixture()
    shared_session = _ScriptedStageSession(
        _ScriptedStageAdapter("fixture-shared", "shared-v1", writer),
        "unused",
    )

    class _ReusingAdapter(_ScriptedStageAdapter):
        def open_fresh_session(self, *, invocation_id):
            shared_session.invocation_id = invocation_id
            shared_session.adapter = self
            return shared_session

    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=_ReusingAdapter("fixture-writer", "writer-v2", writer),
        humanizer=_ReusingAdapter("fixture-humanizer", "humanizer-v2", final),
    )
    with pytest.raises(EditorialCompositionError, match="distinct requested session"):
        run_editorial_composition_runtime(request, runtime=runtime)


def test_production_runtime_rejects_synthetic_stage_adapter() -> None:
    request, writer, final = _fixture()
    with pytest.raises(EditorialCompositionError, match="environment differs"):
        EditorialCompositionRuntime(
            environment="production",
            writer=_ScriptedStageAdapter("fixture-writer", "writer-v2", writer),
            humanizer=_ScriptedStageAdapter(
                "production-humanizer",
                "humanizer-v2",
                final,
                environment="production",
            ),
        )


def test_runtime_rejects_backend_with_history_access() -> None:
    request, writer, final = _fixture()

    class _HistoryAdapter(_ScriptedStageAdapter):
        def _invoke(self, *, request_bytes, invocation_id):
            return replace(
                super()._invoke(
                    request_bytes=request_bytes,
                    invocation_id=invocation_id,
                ),
                history_access=True,
            )

    runtime = EditorialCompositionRuntime(
        environment="synthetic",
        writer=_HistoryAdapter("fixture-writer", "writer-v2", writer),
        humanizer=_ScriptedStageAdapter("fixture-humanizer", "humanizer-v2", final),
    )
    with pytest.raises(EditorialCompositionError, match="isolation is not fail-closed"):
        run_editorial_composition_runtime(request, runtime=runtime)


def _detached_adapter(
    tmp_path, draft, *, stage="resume_writer", allow_missing_city=False
):
    tmp_path.mkdir(parents=True, exist_ok=True)
    binary = tmp_path / f"codex-{stage}"
    binary.write_bytes(f"synthetic {stage} codex binary".encode())
    binary.chmod(0o700)
    return DetachedCodexEditorialAdapter(
        stage=stage,
        model="gpt-5.6-sol",
        codex_binary=str(binary),
        environment="synthetic",
        process_environment={
            "HOME": str(tmp_path),
            "PATH": str(tmp_path),
            "OPENAI_API_KEY": "must-not-cross",
            "CANDIDATE_SECRET": "must-not-cross",
        },
        allow_missing_city=allow_missing_city,
    ), binary, draft


def test_detached_codex_adapter_is_one_shot_hash_bound_and_scrubbed(
    monkeypatch, tmp_path
) -> None:
    _, draft, _ = _fixture()
    adapter, binary, draft = _detached_adapter(tmp_path, draft)
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        request_root = Path(kwargs["cwd"])
        assert sorted(path.name for path in request_root.iterdir()) == [
            "request.prompt.json",
            "response.schema.json",
        ]
        schema = json.loads((request_root / "response.schema.json").read_text())
        assert "draft_sha256" not in schema["properties"]
        headings = schema["properties"]["sections"]["items"]["properties"][
            "heading"
        ]["enum"]
        assert headings == sorted(headings)
        output = Path(command[command.index("--output-last-message") + 1])
        response_document = draft.document()
        response_document.pop("draft_sha256")
        output.write_bytes(canonical_json(response_document).encode())
        event = {"type": "item.completed", "item": {"type": "agent_message"}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(event), stderr="")

    monkeypatch.setattr("cv_generation.editorial_composition.subprocess.run", fake_run)
    request_bytes = _adapter_request_bytes()
    session = adapter.open_fresh_session(invocation_id="writer-invocation")
    result = session.invoke(request_bytes=request_bytes)

    assert len(calls) == 1
    command, invocation = calls[0]
    assert "--ephemeral" in command
    assert "--ignore-user-config" in command
    assert "--ignore-rules" in command
    assert command[command.index("-s") + 1] == "read-only"
    assert invocation["input"].encode() == request_bytes
    assert invocation["env"]["CODEX_HOME"] == str(tmp_path / ".codex")
    assert "OPENAI_API_KEY" not in invocation["env"]
    assert "CANDIDATE_SECRET" not in invocation["env"]
    assert result.request_sha256 == hashlib.sha256(request_bytes).hexdigest()
    assert result.response_sha256 == hashlib.sha256(result.response_bytes).hexdigest()
    assert result.executable_sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert result.call_count == 1
    assert result.history_access is result.cache_access is result.tool_access is False
    assert result.retrieval_access is result.filesystem_access is False
    assert result.environment_access is False
    assert result.network_access is result.project_document_access is False
    with pytest.raises(EditorialCompositionError, match="single-use"):
        session.invoke(request_bytes=request_bytes)


@pytest.mark.parametrize(
    ("event", "message"),
    (
        ("not-json", "malformed event"),
        (json.dumps({"type": "unknown.event"}), "forbidden event"),
        (
            json.dumps(
                {"type": "item.started", "item": {"type": "command_execution"}}
            ),
            "forbidden item",
        ),
    ),
)
def test_detached_codex_adapter_rejects_invalid_jsonl_event(
    monkeypatch, tmp_path, event, message
) -> None:
    _, draft, _ = _fixture()
    adapter, _, draft = _detached_adapter(tmp_path, draft)
    calls = []

    def fake_run(command, **kwargs):
        calls.append(command)
        output = Path(command[command.index("--output-last-message") + 1])
        response_document = draft.document()
        response_document.pop("draft_sha256")
        output.write_bytes(canonical_json(response_document).encode())
        return SimpleNamespace(returncode=0, stdout=event, stderr="")

    monkeypatch.setattr("cv_generation.editorial_composition.subprocess.run", fake_run)
    with pytest.raises(EditorialCompositionError, match=message):
        adapter.open_fresh_session(invocation_id="writer").invoke(
            request_bytes=_adapter_request_bytes()
        )
    assert len(calls) == 1


def test_detached_codex_adapter_rejects_executable_substitution(tmp_path) -> None:
    _, draft, _ = _fixture()
    adapter, binary, _ = _detached_adapter(tmp_path, draft)
    binary.write_bytes(b"substituted executable")

    with pytest.raises(EditorialCompositionError, match="executable changed"):
        adapter.open_fresh_session(invocation_id="writer").invoke(request_bytes=b"{}")


def test_detached_codex_adapter_rejects_model_supplied_draft_identity(
    monkeypatch, tmp_path
) -> None:
    _, draft, _ = _fixture()
    adapter, _, _ = _detached_adapter(tmp_path, draft)

    def fake_run(command, **kwargs):
        output = Path(command[command.index("--output-last-message") + 1])
        output.write_bytes(canonical_json(draft.document()).encode())
        event = {"type": "item.completed", "item": {"type": "agent_message"}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(event), stderr="")

    monkeypatch.setattr("cv_generation.editorial_composition.subprocess.run", fake_run)
    with pytest.raises(EditorialCompositionError, match="draft schema differs"):
        adapter.open_fresh_session(invocation_id="writer").invoke(
            request_bytes=_adapter_request_bytes()
        )


def test_runtime_rejects_swapped_detached_stage_adapters(tmp_path) -> None:
    _, writer, _ = _fixture()
    humanizer, _, _ = _detached_adapter(tmp_path, writer, stage="humanizer")
    writer_adapter, _, _ = _detached_adapter(
        tmp_path / "second", writer, stage="resume_writer"
    )

    with pytest.raises(EditorialCompositionError, match="another stage"):
        EditorialCompositionRuntime(
            environment="synthetic",
            writer=humanizer,
            humanizer=writer_adapter,
        )


def test_installed_codex_cli_passes_no_provider_contract_probe() -> None:
    binary = Path("/usr/bin/codex")
    if not binary.is_file():
        pytest.skip("Gigabyte Codex binary is not installed at /usr/bin/codex")

    contract = probe_detached_codex_editorial_cli(str(binary))

    assert contract.version.startswith("codex-cli ")
    assert contract.executable_sha256 == hashlib.sha256(binary.read_bytes()).hexdigest()
    assert len(contract.contract_sha256) == 64
    writer = DetachedCodexEditorialAdapter(
        stage="resume_writer",
        model="gpt-5.6-sol",
        codex_binary=str(binary),
        environment="production",
    )
    humanizer = DetachedCodexEditorialAdapter(
        stage="humanizer",
        model="gpt-5.6-sol",
        codex_binary=str(binary),
        environment="production",
    )
    runtime = EditorialCompositionRuntime("production", writer, humanizer)
    assert runtime.writer is not runtime.humanizer
    assert writer.transport_identity != humanizer.transport_identity


def test_admits_evidence_bound_writer_and_distinct_humanizer_sessions() -> None:
    request, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _stage_evidence(request, writer, final)

    writer_receipt, humanizer_receipt, composition = admit_editorial_composition(
        request=request,
        writer_draft=writer,
        final_draft=final,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )

    assert writer_receipt.stage == "resume_writer"
    assert humanizer_receipt.stage == "humanizer"
    assert writer_receipt.invocation_id_sha256 != humanizer_receipt.invocation_id_sha256
    assert composition.request_sha256 == request.request_sha256
    assert composition.final_draft_sha256 == final.draft_sha256
    assert composition.release_authority is False


def test_good_unchanged_humanizer_output_is_not_rejected() -> None:
    request, writer, _ = _fixture()
    writer_evidence, humanizer_evidence = _stage_evidence(request, writer, writer)
    humanizer_evidence = replace(
        humanizer_evidence,
        response_sha256=writer.draft_sha256,
    )

    _, _, receipt = admit_editorial_composition(
        request=request,
        writer_draft=writer,
        final_draft=writer,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )

    assert receipt.final_draft_sha256 == writer.draft_sha256


def test_unknown_or_rewritten_claim_is_rejected() -> None:
    request, writer, _ = _fixture()
    summary = writer.sections[0]
    unknown = replace(
        summary,
        atoms=(
            summary.atoms[0],
            EditorialAtom("approved_claim", "Invented a result.", "not-approved"),
        ),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(unknown, *writer.sections[1:]),
    )
    with pytest.raises(EditorialCompositionError, match="unknown claim"):
        validate_editorial_draft(request, draft)

    rewritten = replace(
        summary,
        atoms=(
            summary.atoms[0],
            EditorialAtom("approved_claim", "Improved the approved claim.", "summary"),
        ),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(rewritten, *writer.sections[1:]),
    )
    with pytest.raises(EditorialCompositionError, match="changed an approved claim"):
        validate_editorial_draft(request, draft)


@pytest.mark.parametrize(
    ("text", "message"),
    (
        ("Right to work in the UK.", "work-rights"),
        ("Curriculum Vitae", "document labels"),
    ),
)
def test_candidate_prohibited_content_is_rejected(text: str, message: str) -> None:
    request, writer, _ = _fixture()
    malicious = _claim("malicious", text, "project")
    request = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(*request.approved_claims, malicious),
    )
    projects = writer.sections[2]
    projects = replace(
        projects,
        atoms=(*projects.atoms, EditorialAtom("approved_claim", text, "malicious")),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(*writer.sections[:2], projects, *writer.sections[3:]),
    )
    with pytest.raises(EditorialCompositionError, match=message):
        validate_editorial_draft(request, draft)


def test_location_is_bound_to_candidate_authority() -> None:
    request, writer, _ = _fixture()
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city="Wolverhampton, United Kingdom",
        sections=writer.sections,
    )
    with pytest.raises(EditorialCompositionError, match="location differs"):
        validate_editorial_draft(request, draft)


def test_current_runtime_allows_only_authority_bound_absent_city() -> None:
    request, writer, _ = _fixture()
    authority = replace(
        request.authority,
        candidate_city=None,
        allow_missing_city=True,
        current_runtime=True,
    )
    current_request = build_editorial_request(
        authority=authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=request.approved_claims,
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=None,
        sections=writer.sections,
        allow_missing_city=True,
        current_runtime=True,
    )
    validate_editorial_draft(current_request, draft)
    schema = editorial_module.editorial_city_response_schema(
        dict(editorial_module._DRAFT_RESPONSE_SCHEMA),
        authority_city=None,
        allow_missing_city=True,
    )
    assert schema["properties"]["candidate_city"] == {"type": "null"}
    assert editorial_module._DRAFT_RESPONSE_SCHEMA["properties"]["candidate_city"] == {
        "type": "string",
        "minLength": 1,
    }
    with pytest.raises(EditorialCompositionError):
        CandidateEditorialAuthority(
            candidate_name=request.authority.candidate_name,
            candidate_city=None,
            graduation_month_year=None,
            dissertation_title=None,
            source_sha256="a" * 64,
        )
    with pytest.raises(EditorialCompositionError):
        validate_editorial_draft(
            current_request,
            build_editorial_draft(
                candidate_name=writer.candidate_name,
                candidate_city="Invented City",
                sections=writer.sections,
                allow_missing_city=True,
            ),
        )


def test_detached_adapter_city_mode_is_stage_scoped_and_preserves_legacy_identity(
    tmp_path,
) -> None:
    _, draft, _ = _fixture()
    for stage in (
        "resume_writer",
        "humanizer",
        "cover_letter_writer",
        "cover_letter_humanizer",
    ):
        for requested_mode in (False, True):
            adapter, binary, _ = _detached_adapter(
                tmp_path / stage / str(requested_mode),
                draft,
                stage=stage,
                allow_missing_city=requested_mode,
            )
            expected_mode = requested_mode and stage in {
                "resume_writer",
                "humanizer",
            }
            assert adapter.allow_missing_city is expected_mode

            expected_identity = {
                "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                "cli_contract_sha256": editorial_module.content_hash(
                    {
                        "environment": "synthetic",
                        "executable_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
                    }
                ),
                "cwd_policy": "fresh-request-material-only",
                "disabled_features": list(editorial_module._DISABLED_CODEX_FEATURES),
                "environment_names": sorted(
                    editorial_module._scrubbed_codex_environment(
                        adapter.process_environment
                    )
                ),
                "ignore_project_rules": True,
                "model": "gpt-5.6-sol",
                "network_tools_enabled": False,
                "project_doc_max_bytes": 0,
                "provider": editorial_module.EDITORIAL_PROVIDER_IDENTITY,
                "response_schema_sha256": editorial_module.content_hash(
                    adapter._response_schema
                ),
                "sandbox": "read-only",
                "single_attempt": True,
                "stage": stage,
                "timeout_seconds": 120.0,
                "output_path_policy": "fresh-response-directory-only",
            }
            if expected_mode:
                null_city_schema = editorial_module.editorial_city_response_schema(
                    dict(adapter._response_schema),
                    authority_city=None,
                    allow_missing_city=True,
                )
                expected_identity.update(
                    {
                        "allow_missing_city": True,
                        "null_city_response_schema_sha256": editorial_module.content_hash(
                            null_city_schema
                        ),
                    }
                )
            assert adapter.transport_identity == editorial_module.content_hash(
                expected_identity
            )


def test_editorial_city_mode_rejects_non_exact_stage_and_flag_types() -> None:
    class StageSubclass(str):
        pass

    for stage, flag in (
        (StageSubclass("resume_writer"), True),
        ("resume_writer", 1),
    ):
        with pytest.raises(EditorialCompositionError, match="invalid editorial city mode"):
            editorial_module.effective_editorial_city_mode(stage, flag)


def test_graduation_day_and_wrong_dissertation_are_rejected() -> None:
    request, writer, _ = _fixture()
    wrong = _claim(
        "wrong-education",
        "BSc Computer Science, 2 July 2026. Dissertation: SCAFAD.",
        "education",
    )
    request = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(*request.approved_claims, wrong),
    )
    education = replace(
        writer.sections[-1],
        atoms=(EditorialAtom("approved_claim", wrong.text, wrong.claim_id),),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(*writer.sections[:-1], education),
    )
    with pytest.raises(EditorialCompositionError, match="month and year"):
        validate_editorial_draft(request, draft)


def test_dissertation_cannot_appear_without_candidate_authority() -> None:
    request, writer, _ = _fixture()
    authority = replace(
        request.authority,
        dissertation_title=None,
        require_dissertation=False,
    )
    request = build_editorial_request(
        authority=authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=request.approved_claims,
    )
    with pytest.raises(EditorialCompositionError, match="lacks candidate authority"):
        validate_editorial_draft(request, writer)


def test_formats_and_datastores_are_not_capability_domains() -> None:
    request, writer, _ = _fixture()
    bad = _claim("bad-capability", "Python, JSON and SQLite.", "capability_domain")
    request = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(*request.approved_claims, bad),
    )
    capabilities = replace(
        writer.sections[1],
        atoms=(EditorialAtom("approved_claim", bad.text, bad.claim_id),),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(writer.sections[0], capabilities, *writer.sections[2:]),
    )
    with pytest.raises(EditorialCompositionError, match="masquerade"):
        validate_editorial_draft(request, draft)


@pytest.mark.parametrize(
    "connective",
    (
        "I built 12 production systems.",
        "A pivotal contribution — with measurable value.",
        "As a leader, I owned the delivery.",
        "Written with ChatGPT.",
        "Visa sponsorship is not required.",
        "They have it.",
        "This is it.",
    ),
)
def test_connectives_cannot_smuggle_claims_or_ai_prose(connective: str) -> None:
    request, writer, _ = _fixture()
    summary = replace(
        writer.sections[0],
        atoms=(EditorialAtom("connective", connective), writer.sections[0].atoms[0]),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(summary, *writer.sections[1:]),
    )
    with pytest.raises(EditorialCompositionError, match="connective"):
        validate_editorial_draft(request, draft)


@pytest.mark.parametrize(
    "forbidden_text",
    (
        "AI systems engineer — focused on reliable automation.",
        "Visa sponsorship is not required.",
        "This CV was written with ChatGPT.",
        "My CV was prepared with AI assistance.",
        "An LLM generated this application.",
        "Built this CV with ChatGPT.",
        "This CV was AI-assisted.",
        "This cover letter had AI assistance.",
        "I used ChatGPT to write this CV.",
        "ChatGPT helped me write this cover letter.",
    ),
)
def test_global_bans_apply_to_approved_cv_claims(forbidden_text: str) -> None:
    request, writer, _ = _fixture()
    forbidden = _claim("summary", forbidden_text, "summary")
    changed_request = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(forbidden, *request.approved_claims[1:]),
    )
    summary = replace(
        writer.sections[0],
        atoms=(EditorialAtom("approved_claim", forbidden.text, forbidden.claim_id),),
    )
    changed = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(summary, *writer.sections[1:]),
    )
    with pytest.raises(
        EditorialCompositionError,
        match="forbidden em or en dash|work-rights|AI-authorship",
    ):
        validate_editorial_draft(changed_request, changed)


@pytest.mark.parametrize(
    "legitimate_text",
    (
        "Built AI application automation for employer workflows.",
        "Built an AI-generated application document pipeline.",
        "Built a ChatGPT application that generated CV drafts.",
        "Built an AI tool that drafted the CV output.",
    ),
)
def test_global_authorship_ban_does_not_reject_legitimate_ai_application_work(
    legitimate_text: str,
) -> None:
    request, writer, _ = _fixture()
    legitimate = _claim(
        "summary",
        legitimate_text,
        "project",
    )
    changed_request = build_editorial_request(
        authority=request.authority,
        role_title=request.role_title,
        company_name=request.company_name,
        vacancy_sha256=request.vacancy_sha256,
        approved_claims=(legitimate, *request.approved_claims[1:]),
    )
    summary = replace(
        writer.sections[0],
        atoms=(
            EditorialAtom("approved_claim", legitimate.text, legitimate.claim_id),
        ),
    )
    changed = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(summary, *writer.sections[1:]),
    )

    validate_editorial_draft(changed_request, changed)


def test_humanizer_cannot_change_claims_or_share_writer_session() -> None:
    request, writer, final = _fixture()
    summary = final.sections[0]
    altered = replace(
        summary,
        atoms=(EditorialAtom("approved_claim", "Humanizer invented this.", "summary"),),
    )
    final = build_editorial_draft(
        candidate_name=final.candidate_name,
        candidate_city=final.candidate_city,
        sections=(altered, *final.sections[1:]),
    )
    writer_evidence, humanizer_evidence = _stage_evidence(request, writer, final)
    with pytest.raises(EditorialCompositionError, match="changed an approved claim"):
        admit_editorial_composition(
            request=request,
            writer_draft=writer,
            final_draft=final,
            writer_evidence=writer_evidence,
            humanizer_evidence=humanizer_evidence,
        )

    request, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _stage_evidence(request, writer, final)
    humanizer_evidence = replace(
        humanizer_evidence,
        invocation_id=writer_evidence.invocation_id,
    )
    with pytest.raises(EditorialCompositionError, match="distinct sessions"):
        admit_editorial_composition(
            request=request,
            writer_draft=writer,
            final_draft=final,
            writer_evidence=writer_evidence,
            humanizer_evidence=humanizer_evidence,
        )


def test_stage_hash_mismatch_fails_closed() -> None:
    request, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _stage_evidence(request, writer, final)
    with pytest.raises(EditorialCompositionError, match="not bound"):
        admit_editorial_composition(
            request=request,
            writer_draft=writer,
            final_draft=final,
            writer_evidence=replace(writer_evidence, response_sha256="f" * 64),
            humanizer_evidence=humanizer_evidence,
        )


def test_connective_only_section_is_not_admitted() -> None:
    request, writer, _ = _fixture()
    summary = replace(
        writer.sections[0],
        atoms=(EditorialAtom("connective", "For this:"),),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(summary, *writer.sections[1:]),
    )
    with pytest.raises(EditorialCompositionError, match="approved factual claims"):
        validate_editorial_draft(request, draft)


def test_receipts_are_self_validating_and_never_release_authority() -> None:
    request, writer, final = _fixture()
    writer_evidence, humanizer_evidence = _stage_evidence(request, writer, final)
    writer_receipt, _, composition = admit_editorial_composition(
        request=request,
        writer_draft=writer,
        final_draft=final,
        writer_evidence=writer_evidence,
        humanizer_evidence=humanizer_evidence,
    )
    with pytest.raises(EditorialCompositionError, match="cannot grant"):
        replace(writer_receipt, release_authority=True)
    with pytest.raises(EditorialCompositionError, match="identity is invalid"):
        replace(composition, final_draft_sha256="f" * 64)

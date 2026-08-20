from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

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


def _claim(claim_id: str, text: str, category: str) -> ApprovedCVClaim:
    return ApprovedCVClaim(
        claim_id=claim_id,
        text=text,
        text_sha256=hashlib.sha256(text.encode()).hexdigest(),
        evidence_ids=(f"evidence:{claim_id}",),
        category=category,
    )


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
            (
                EditorialAtom("connective", "Relevant background:", None),
                EditorialAtom("approved_claim", claims[0].text, "summary"),
            ),
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
    final_sections = (
        replace(
            sections[0],
            atoms=(
                EditorialAtom("connective", "Background relevant to the role:", None),
                sections[0].atoms[1],
            ),
        ),
        *sections[1:],
    )
    final = build_editorial_draft(
        candidate_name=authority.candidate_name,
        candidate_city=authority.candidate_city,
        sections=final_sections,
    )
    return request, writer, final


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


def _detached_adapter(tmp_path, draft, *, stage="resume_writer"):
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
    request_bytes = canonical_json({"synthetic": "request"}).encode()
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
            request_bytes=b"{}"
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
        adapter.open_fresh_session(invocation_id="writer").invoke(request_bytes=b"{}")


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
    ),
)
def test_connectives_cannot_smuggle_claims_or_ai_prose(connective: str) -> None:
    request, writer, _ = _fixture()
    summary = replace(
        writer.sections[0],
        atoms=(EditorialAtom("connective", connective), writer.sections[0].atoms[1]),
    )
    draft = build_editorial_draft(
        candidate_name=writer.candidate_name,
        candidate_city=writer.candidate_city,
        sections=(summary, *writer.sections[1:]),
    )
    with pytest.raises(EditorialCompositionError, match="connective"):
        validate_editorial_draft(request, draft)


def test_humanizer_cannot_change_claims_or_share_writer_session() -> None:
    request, writer, final = _fixture()
    summary = final.sections[0]
    altered = replace(
        summary,
        atoms=(
            summary.atoms[0],
            EditorialAtom("approved_claim", "Humanizer invented this.", "summary"),
        ),
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
        atoms=(EditorialAtom("connective", "Relevant background:"),),
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

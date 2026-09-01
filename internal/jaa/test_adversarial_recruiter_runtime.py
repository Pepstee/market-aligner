from __future__ import annotations

import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from career_automation.adversarial_recruiter import (
    RecruiterAssessmentPackage,
)
from career_automation.adversarial_recruiter_runtime import (
    DetachedCodexRecruiterBackend,
    run_synthetic_recruiter_canary,
)
from career_automation.external_document_assurance import IntendedVacancy
from career_automation.rendering import _build_text_pdf
from career_automation.testing_adversarial_recruiter import (
    fixture_recruiter_result,
)
from llm.client import LLMClient, LLMError


def _result() -> dict[str, object]:
    return fixture_recruiter_result()


def _pdf(text: str) -> bytes:
    return _build_text_pdf((tuple(text.splitlines()),))


def _package() -> RecruiterAssessmentPackage:
    listing = "[SYNTHETIC NON-CANDIDATE CANARY]\nOperate a fictional Python service."
    return RecruiterAssessmentPackage(
        listing_text=listing,
        listing_text_sha256=hashlib.sha256(listing.encode()).hexdigest(),
        cv_pdf_bytes=_pdf("Synthetic Candidate\nBuilt a fictional service."),
        cover_letter_pdf_bytes=_pdf("This is a synthetic application canary."),
        form_fields=(("synthetic", "Is this synthetic?", "Yes"),),
        intended_vacancy=IntendedVacancy(
            "synthetic-canary:001",
            hashlib.sha256(b"synthetic body").hexdigest(),
            "Synthetic Engineer",
            "Synthetic Employer",
        ),
    )


def _client(backend, tmp_path) -> LLMClient:
    return LLMClient(
        backend=backend,
        model=backend.model,
        temperature=0,
        max_retries=1,
        cache_enabled=False,
        cache_dir=tmp_path / "cache",
        usage_log=tmp_path / "usage.jsonl",
    )


def test_isolated_transport_invokes_once_and_exposes_only_request_fields(
    monkeypatch, tmp_path
) -> None:
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex binary")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        request_root = Path(kwargs["cwd"])
        assert sorted(path.name for path in request_root.iterdir()) == [
            "request.prompt.txt",
            "response.schema.json",
        ]
        output = Path(cmd[cmd.index("--output-last-message") + 1])
        output.write_text(json.dumps(_result()), encoding="utf-8")
        event = {"type": "item.completed", "item": {"type": "agent_message"}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(event), stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    backend = DetachedCodexRecruiterBackend(
        model="gpt-5.6-sol",
        codex_binary=str(binary),
        environment={
            "PATH": str(tmp_path),
            "HOME": str(tmp_path),
            "OPENAI_API_KEY": "must-not-cross",
            "CANDIDATE_SECRET": "must-not-cross",
        },
    )
    from career_automation.adversarial_recruiter import assess_application_as_recruiter

    receipt = assess_application_as_recruiter(_package(), client=_client(backend, tmp_path))
    assert receipt.model_result["fit_percent"] == 52
    assert backend.invocation_count == 1
    assert len(calls) == 1
    cmd, invocation = calls[0]
    assert "--ephemeral" in cmd
    assert "--ignore-user-config" in cmd
    assert "--ignore-rules" in cmd
    assert cmd[cmd.index("-s") + 1] == "read-only"
    assert invocation["env"]["CODEX_HOME"] == str(tmp_path / ".codex")
    assert "OPENAI_API_KEY" not in invocation["env"]
    assert "CANDIDATE_SECRET" not in invocation["env"]
    provider_visible = invocation["input"].casefold()
    for forbidden in (
        "approved_evidence",
        "candidate_projection",
        "application_source_identity",
        "upstream_fit",
        "generation_history",
        "conversation_history",
    ):
        assert forbidden not in provider_visible
    assert backend.transport_receipt is not None
    assert backend.transport_receipt.invocation_count == 1
    assert backend.transport_receipt.provider_sha256
    assert backend.transport_receipt.model_sha256
    assert backend.transport_receipt.transport_sha256
    assert backend.transport_receipt.request_sha256
    assert backend.transport_receipt.response_sha256


def test_tool_event_fails_closed_without_second_invocation(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex binary")
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        event = {"type": "item.started", "item": {"type": "command_execution"}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(event), stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)
    backend = DetachedCodexRecruiterBackend(
        model="gpt-5.6-sol", codex_binary=str(binary), environment={"HOME": str(tmp_path)}
    )
    with pytest.raises(LLMError, match="forbidden tool item"):
        backend.complete("system", "user", 0)
    assert len(calls) == 1
    assert backend.invocation_count == 1


def test_cli_failure_reports_stdout_when_stderr_is_also_present(monkeypatch, tmp_path) -> None:
    binary = tmp_path / "codex"
    binary.write_bytes(b"synthetic codex binary")

    def fake_run(cmd, **kwargs):
        return SimpleNamespace(
            returncode=1,
            stderr="non-fatal startup diagnostic",
            stdout=json.dumps(
                {
                    "type": "error",
                    "message": "invalid_json_schema: schema must have a type key",
                }
            ),
        )

    monkeypatch.setattr("subprocess.run", fake_run)
    backend = DetachedCodexRecruiterBackend(
        model="gpt-5.6-sol", codex_binary=str(binary), environment={"HOME": str(tmp_path)}
    )
    with pytest.raises(LLMError) as error:
        backend.complete("system", "user", 0)
    message = str(error.value)
    assert "non-fatal startup diagnostic" in message
    assert "invalid_json_schema" in message
    assert "must have a type key" in message


def test_synthetic_canary_refuses_unmarked_package() -> None:
    package = _package()
    mutated = RecruiterAssessmentPackage(
        listing_text="ordinary listing",
        listing_text_sha256=hashlib.sha256(b"ordinary listing").hexdigest(),
        cv_pdf_bytes=package.cv_pdf_bytes,
        cover_letter_pdf_bytes=package.cover_letter_pdf_bytes,
        form_fields=package.form_fields,
        intended_vacancy=package.intended_vacancy,
    )
    with pytest.raises(ValueError, match="synthetic non-candidate marker"):
        run_synthetic_recruiter_canary(mutated, model="gpt-5.6-sol")

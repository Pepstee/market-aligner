"""
llm/test_llm.py — offline self-test for the LLM module. NO API key required.

Run:  python llm/test_llm.py     (from repo root)

Proves the contract the rest of the project relies on:
  1. extract_job on a fixture raw posting returns a schema-VALID dict.
  2. rate_axes returns all five 0-10 axes, schema-valid.
  3. assess_portfolio returns schema-valid per-field evidence.
  4. A second IDENTICAL extract_job call is a CACHE HIT — the backend is NOT
     called again (asserted via MockBackend.call_count).
  5. normalise_skill maps a Korean alias ('블렌더' -> 'blender') by RULE, with
     no backend call; an unknown term falls back to the LLM and is LOGGED.
  6. ClaudeCliBackend, run against a FAKE `claude` shim on PATH, parses the
     Claude Code JSON envelope's `result` field; and the not-logged-in shim
     raises the clear, actionable error. (No real auth or network.)

Checks 1-5 run on MockBackend in a throwaway temp cache/log dir, so they are
hermetic and deterministic — no dependence on ambient cache state. Check 6 uses
a shim, so it too needs neither an API key nor a logged-in CLI.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from llm.client import (  # noqa: E402
    BackendProcessFailure,
    ClaudeCliBackend,
    CodexCliBackend,
    LLMClient,
    LLMError,
    MockBackend,
    validate_json,
)
from llm import capabilities as caps  # noqa: E402
from llm.schema_loader import load_schema  # noqa: E402


def _write_claude_shim(dir_path: Path, stdout: str, exit_code: int = 0) -> Path:
    """Drop an executable fake `claude` into `dir_path` that ignores stdin.

    It reads (and discards) any STDIN so the parent's `input=` write never blocks
    on a full pipe, then prints `stdout` and exits with `exit_code`. This lets us
    exercise ClaudeCliBackend's command construction + JSON parsing with NO real
    auth or network.
    """
    shim = dir_path / "claude"
    body = (
        "#!/usr/bin/env python3\n"
        "import sys\n"
        "sys.stdin.read()\n"  # drain stdin so the parent's input write completes
        f"sys.stdout.write({stdout!r})\n"
        f"sys.exit({exit_code})\n"
    )
    shim.write_text(body, encoding="utf-8")
    shim.chmod(shim.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return shim


# --------------------------------------------------------------------------- #
# Fixture: a raw Greenhouse-style UK graduate AI posting.
# --------------------------------------------------------------------------- #
FIXTURE_RAW = {
    "board": "greenhouse",
    "job_id": "example:10042",
    "url": "https://job-boards.greenhouse.io/example/jobs/10042",
    "fetched_at": "2026-07-18T09:00:00Z",
    "raw_json": {
        "title": "Graduate AI Automation Engineer",
        "company": "Example AI",
        "location_text": "Birmingham, UK",
        "content_text": (
            "Build agentic AI and workflow automation services using Python, "
            "AWS Lambda, LLM APIs, Docker and Git. Graduate applicants welcome."
        ),
    },
}


def _fresh_client(tmp: Path) -> tuple[LLMClient, MockBackend]:
    """A client with a throwaway cache + usage log, so tests don't collide."""
    backend = MockBackend()
    client = LLMClient(
        backend=backend,
        model="mock",
        temperature=0.0,
        max_retries=3,
        cache_enabled=True,
        cache_dir=tmp / "cache",
        usage_log=tmp / "usage.jsonl",
        _backoff_base=0.0,
    )
    return client, backend


def run() -> int:
    passed = 0

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)

        # --- 1. extract_job returns a schema-valid dict --------------------- #
        client, backend = _fresh_client(tmp)
        row = caps.extract_job(FIXTURE_RAW, client=client)
        validate_json(row, load_schema("job_extract"))
        assert row["mapped_career"] == "AI_Automation_Engineer", f"career={row['mapped_career']}"
        assert row["entry_level"] is True, f"entry_level={row['entry_level']}"
        assert "python" in row["required_software"], row["required_software"]
        assert "aws" in row["required_software"], row["required_software"]
        assert 0.0 <= row["extraction_confidence"] <= 1.0
        print("[1] extract_job -> schema-valid; "
              f"career={row['mapped_career']}, entry={row['entry_level']}, "
              f"sw={row['required_software']}, conf={row['extraction_confidence']}")
        passed += 1
        assert backend.call_count == 1, backend.call_count

        # --- 2. rate_axes: all five axes, schema-valid ---------------------- #
        axes = caps.rate_axes(row, client=client)
        validate_json(axes, load_schema("axis_ratings"))
        expected_axes = {
            "technical_alignment", "evidence_match", "growth_potential",
            "market_demand", "barrier_to_entry",
        }
        assert set(axes) == expected_axes, set(axes)
        assert all(0.0 <= v <= 10.0 for v in axes.values()), axes
        print(f"[2] rate_axes -> schema-valid; {json.dumps(axes, ensure_ascii=False)}")
        passed += 1

        # --- 3. assess_portfolio -------------------------------------------- #
        port = caps.assess_portfolio(
            [
                {"title": "Multi-agent orchestrator", "desc": "Python, AI agents, AWS and CI"},
                {"title": "Market aligner", "desc": "LLM extraction and workflow automation"},
            ],
            client=client,
        )
        validate_json(port, load_schema("portfolio_assess"))
        careers = {e["career"] for e in port["per_field"]}
        assert "Agentic_AI_Engineer" in careers or "AI_Automation_Engineer" in careers, careers
        print(f"[3] assess_portfolio -> schema-valid; fields={sorted(careers)}, "
              f"skills={port['detected_skills']}")
        passed += 1

        # --- 4. CACHE HIT: identical extract_job does NOT re-call backend --- #
        client2, backend2 = _fresh_client(tmp / "sub")
        first = caps.extract_job(FIXTURE_RAW, client=client2)
        calls_after_first = backend2.call_count
        second = caps.extract_job(FIXTURE_RAW, client=client2)
        calls_after_second = backend2.call_count
        assert first == second, "cached result differs from first"
        assert calls_after_first == 1, calls_after_first
        assert calls_after_second == 1, (
            f"CACHE MISS: backend called {calls_after_second} times, expected 1"
        )
        print(f"[4] cache HIT verified: backend.call_count stayed at "
              f"{calls_after_second} across two identical calls")
        passed += 1

        # --- 5. normalise_skill: Korean alias by RULE, unknown -> LLM+log --- #
        client3, backend3 = _fresh_client(tmp / "sk")
        aliases = {
            "blender": ["Blender", "블렌더"],
            "unreal": ["Unreal", "Unreal Engine", "UE5", "UE4", "언리얼"],
            "figma": ["Figma", "피그마"],
        }
        cid = caps.normalise_skill("블렌더", aliases=aliases, client=client3,
                                   log_merges=False)
        assert cid == "blender", f"블렌더 -> {cid!r}"
        assert backend3.call_count == 0, (
            f"rule match must NOT call the model (calls={backend3.call_count})"
        )
        # English + version-suffixed alias also by rule
        assert caps.normalise_skill("UE5", aliases=aliases, client=client3,
                                    log_merges=False) == "unreal"
        assert backend3.call_count == 0
        # Unknown term falls back to the LLM (mock) and gets logged for review
        merge_log = tmp / "sk_merges.jsonl"
        caps._MERGE_LOG = merge_log  # redirect the review log into the temp dir
        _ = caps.normalise_skill("zbrush", aliases=aliases, client=client3,
                                 log_merges=True)
        assert backend3.call_count == 1, (
            f"unknown term should hit the model once (calls={backend3.call_count})"
        )
        assert merge_log.exists(), "LLM-fallback merge was not logged for review"
        logged = [json.loads(l) for l in merge_log.read_text().splitlines() if l.strip()]
        assert logged and logged[-1]["term"] == "zbrush", logged
        print(f"[5] normalise_skill: '블렌더'->'{cid}' by RULE (0 model calls); "
              f"'UE5'->'unreal'; unknown 'zbrush' -> LLM fallback logged "
              f"(approved={logged[-1]['approved']})")
        passed += 1

        # --- 6. ClaudeCliBackend against a fake `claude` shim --------------- #
        # No real auth or network: a shim on PATH prints the Claude Code JSON
        # envelope; we prove command construction + `result` parsing, then prove
        # the not-logged-in path raises the clear, actionable error.
        shim_dir = tmp / "shim_ok"
        shim_dir.mkdir()
        canned = '{"type":"result","subtype":"success","result":"{\\"ok\\":true}"}'
        _write_claude_shim(shim_dir, canned)

        old_path = os.environ.get("PATH", "")
        try:
            os.environ["PATH"] = f"{shim_dir}{os.pathsep}{old_path}"
            backend = ClaudeCliBackend(model="sonnet", cli_timeout_seconds=30.0)
            assert backend.available(), "shim should be discoverable on PATH"
            resp = backend.complete("[[task:generic]] sys", '{"in":1}', 0.0)
            parsed = json.loads(resp.text)
            assert parsed == {"ok": True}, f"parsed result={parsed!r} (raw={resp.text!r})"
            assert resp.model == "sonnet", resp.model
            print(f"[6a] ClaudeCliBackend(shim) -> parsed `result` = {parsed} "
                  f"(model={resp.model})")

            # Not-logged-in shim: backend must raise the clear error.
            logout_dir = tmp / "shim_logout"
            logout_dir.mkdir()
            _write_claude_shim(logout_dir, "Not logged in. Please run /login\n", exit_code=1)
            os.environ["PATH"] = f"{logout_dir}{os.pathsep}{old_path}"
            raised = ""
            try:
                ClaudeCliBackend(model="sonnet").complete("sys", "user", 0.0)
            except LLMError as exc:
                raised = str(exc)
            assert "not logged in" in raised.lower(), f"unexpected error: {raised!r}"
            assert "claude login" in raised, f"error should name the fix: {raised!r}"
            print(f"[6b] not-logged-in shim -> clear LLMError raised: {raised!r}")
        finally:
            os.environ["PATH"] = old_path
        passed += 1

    print(f"\nllm/test_llm.py OK — {passed}/6 checks passed "
          "(offline MockBackend + ClaudeCliBackend shim).")
    return 0


if __name__ == "__main__":
    sys.exit(run())


def test_extract_job_preserves_positional_client_and_profile_calls(tmp_path):
    import pytest
    client, backend = _fresh_client(tmp_path)
    positional = caps.extract_job(FIXTURE_RAW, client)
    keyword = caps.extract_job(FIXTURE_RAW, client=client)
    with_profile = caps.extract_job(FIXTURE_RAW, {"tracks": {}}, client=client)
    assert positional == keyword == with_profile
    validate_json(positional, load_schema("job_extract"))
    with pytest.raises(TypeError, match="client twice"):
        caps.extract_job(FIXTURE_RAW, client, client=client)


def test_creative_extraction_and_ratings_use_separate_validated_contracts(tmp_path):
    client, backend = _fresh_client(tmp_path)
    raw = {"board": "fixture", "job_id": "creative", "url": "https://example.test/creative",
           "raw_json": {"title": "신입 UX 디자이너", "company": "Example"},
           "raw_text": "신입 UX UI 디자이너 Figma 피그마 Blender 원격 현장 설치"}
    row = caps.extract_job(raw, client=client, mode="creative")
    validate_json(row, load_schema("creative_job_extract"))
    assert row["mapped_career"] == "UX_UI"
    assert row["entry_level"] is True
    assert row["required_software"] == ["blender", "figma"]
    assert row["remote_flag"] is True
    assert row["site_intensity"] > 0
    axes = caps.rate_axes(row, {}, client=client, mode="creative")
    validate_json(axes, load_schema("creative_axis_ratings"))
    assert set(axes) == {"visualization", "spatial_relevance", "cs_usefulness", "english_usefulness",
                         "freelance_potential", "market_demand", "barrier_to_entry"}
    assert caps.extract_job(FIXTURE_RAW, client=client)["mapped_career"] == "AI_Automation_Engineer"


def test_creative_portfolio_assessment_preserves_advisory_fields(tmp_path):
    client, backend = _fresh_client(tmp_path)
    result = caps.assess_portfolio([{"title": "UX UI exhibition", "description": "Figma Blender prototype"}],
                                   client=client, mode="creative")
    validate_json(result, load_schema("creative_portfolio_assess"))
    assert {r["career"] for r in result["per_field"]} == {"UX_UI", "Exhibition"}
    assert result["detected_skills"] == ["blender", "figma"]
    assert caps.assess_portfolio([], client=client, mode="creative")["per_field"] == []
    import pytest
    with pytest.raises(ValueError, match="portfolio mode"):
        caps.assess_portfolio([], client=client, mode="unknown")


def test_codex_cli_backend_uses_ephemeral_session(monkeypatch):
    from types import SimpleNamespace

    from llm import client as client_module

    commands = []

    def fake_run(command, **kwargs):
        commands.append(command)
        output_path = Path(command[command.index("--output-last-message") + 1])
        output_path.write_text("synthetic sanity result", encoding="utf-8")
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(CodexCliBackend, "resolve_binary", staticmethod(lambda: "/test/codex"))
    monkeypatch.setattr(client_module.subprocess, "run", fake_run)

    response = CodexCliBackend(model="gpt-6-luna").complete("synthetic system", "synthetic user", 0.0)

    assert response.text == "synthetic sanity result"
    assert commands[0][:4] == ["/test/codex", "exec", "--json", "--ephemeral"]
    assert "-s" in commands[0]
    assert commands[0][commands[0].index("-s") + 1] == "read-only"


def test_codex_cli_backend_redacts_structured_stdout_failure(monkeypatch):
    import hashlib
    from types import SimpleNamespace

    from llm import client as client_module

    command = []
    diagnostic = json.dumps(
        {
            "type": "error",
            "error": {
                "reason": "sandbox_runtime_denied",
                "operation": "open",
                "errno": "EACCES",
                "path": "/tmp/synthetic private/profile.json",
                "api_key": "synthetic-secret-value",
                "details": "synthetic unknown payload",
            },
        }
    )

    def fake_run(args, **kwargs):
        command.extend(args)
        return SimpleNamespace(
            returncode=17,
            stdout=diagnostic,
            stderr="synthetic unstructured stderr",
        )

    monkeypatch.setattr(CodexCliBackend, "resolve_binary", staticmethod(lambda: "/test/codex"))
    monkeypatch.setattr(client_module.subprocess, "run", fake_run)

    try:
        CodexCliBackend(model="gpt-6-luna").complete(
            "synthetic system", "synthetic user", 0.0
        )
    except BackendProcessFailure as error:
        failure = error.backend_failure
    else:
        raise AssertionError("nonzero Codex CLI result should fail closed")

    assert "--json" in command
    assert failure == {
        "error_category": "sandbox_runtime_denied",
        "exit_code": 17,
        "operation": "open",
        "path_class": "tmp",
        "errno": "EACCES",
        "diagnostic_sha256": hashlib.sha256(
            (diagnostic + "\nsynthetic unstructured stderr").encode("utf-8")
        ).hexdigest(),
        "stderr_diagnosis": (
            "sandbox_runtime_denied operation=open errno=EACCES path=[PATH]"
        ),
        "private_capture_status": "not_requested",
        "private_capture_sha256": None,
        "private_capture_errno": None,
    }
    assert "synthetic-secret-value" not in str(failure)
    assert "/tmp/synthetic private/profile.json" not in str(failure)
    assert "synthetic unknown payload" not in str(failure)
    assert "synthetic unstructured stderr" not in str(failure)


def test_backend_failure_capture_is_bounded_and_classifies_read_only_path():
    import hashlib

    diagnostic = (
        "x" * 24000
        + ' fatal error: read-only file system errno=EROFS operation="write" '
        + 'path="/run/synthetic directory/state.sock" token=synthetic-secret'
    )
    failure = BackendProcessFailure(
        "Codex CLI", exit_code=1, stdout=diagnostic, stderr=""
    )

    assert failure.backend_failure["error_category"] == "filesystem_read_only"
    assert failure.backend_failure["operation"] == "write"
    assert failure.backend_failure["path_class"] == "run"
    assert failure.backend_failure["errno"] == "EROFS"
    assert failure.backend_failure["diagnostic_sha256"] == hashlib.sha256(
        (diagnostic + "\n").encode("utf-8")
    ).hexdigest()
    assert "x" * 100 not in str(failure)
    assert "synthetic-secret" not in str(failure)
    assert "/run/synthetic directory/state.sock" not in str(failure)


def test_backend_failure_does_not_promote_path_alias_warning():
    failure = BackendProcessFailure(
        "Codex CLI",
        exit_code=1,
        stderr="warning: failed to configure path aliases: read-only file system (os error 30)",
    )

    assert failure.backend_failure["error_category"] == "process_exit"
    assert failure.backend_failure["errno"] is None


def test_backend_failure_keeps_distinct_fatal_error_after_path_alias_warning():
    failure = BackendProcessFailure(
        "Codex CLI",
        exit_code=1,
        stderr=(
            "warning: failed to configure path aliases: read-only file system (os error 30)\n"
            'fatal: permission denied operation="open" '
            'path="/tmp/synthetic file" errno=EACCES'
        ),
    )

    assert failure.backend_failure["error_category"] == "permission_denied"
    assert failure.backend_failure["operation"] == "open"
    assert failure.backend_failure["path_class"] == "tmp"
    assert failure.backend_failure["errno"] == "EACCES"


def test_codex_cli_backend_writes_bounded_failure_output_privately(tmp_path, monkeypatch):
    import hashlib
    import json
    import pytest
    from types import SimpleNamespace

    import llm.client as client_module

    diagnostic_dir = tmp_path / "diagnostics"
    diagnostic_dir.mkdir(mode=0o700)
    diagnostic_dir.chmod(0o700)
    monkeypatch.setenv("JAA_LLM_DIAGNOSTIC_CAPTURE_DIR", str(diagnostic_dir))
    child_stdout = (
        'fatal: permission denied operation="open" '
        'path="/tmp/synthetic private file" errno=EACCES private-token'
    )
    child_stderr = "synthetic child stderr credential"

    monkeypatch.setattr(
        CodexCliBackend, "resolve_binary", staticmethod(lambda: "/test/codex")
    )
    monkeypatch.setattr(
        client_module.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(
            returncode=1, stdout=child_stdout, stderr=child_stderr
        ),
    )

    with pytest.raises(BackendProcessFailure) as caught:
        CodexCliBackend(model="synthetic-model").complete(
            "synthetic system", "synthetic user", 0.0
        )

    failure = caught.value.backend_failure
    artifact_path = diagnostic_dir / "child-process-output.json"
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))
    assert stat.S_IMODE(diagnostic_dir.stat().st_mode) == 0o700
    assert stat.S_IMODE(artifact_path.stat().st_mode) == 0o600
    assert artifact["stdout_excerpt"] == child_stdout
    assert artifact["stderr_excerpt"] == child_stderr
    assert failure["private_capture_status"] == "written"
    assert failure["private_capture_sha256"] == hashlib.sha256(
        artifact_path.read_bytes()
    ).hexdigest()
    assert failure["private_capture_errno"] is None
    assert "private-token" not in str(failure)
    assert "synthetic child stderr credential" not in str(failure)

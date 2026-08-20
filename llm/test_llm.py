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
    ClaudeCliBackend,
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

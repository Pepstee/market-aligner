"""Truth controls for slice status and external JAA-04 runtime state."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "ASSURANCE_MANIFEST.json"


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_unimplemented_slices_are_not_declared_complete() -> None:
    components = _manifest()["components"]
    jaa05 = components["JAA-05"]
    assert jaa05["increment"] == "implementation_in_progress_dependency_blocked"
    for relative in jaa05["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-05 materialised path missing: {relative}"
    for test in jaa05["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-05 declared test missing: {relative}"

    jaa06 = components["JAA-06"]
    assert jaa06["increment"] == "implementation_in_progress_dependency_blocked"
    for relative in jaa06["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-06 materialised path missing: {relative}"
    for test in jaa06["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-06 declared test missing: {relative}"

    jaa07 = components["JAA-07"]
    assert jaa07["increment"] == "implementation_in_progress_dependency_blocked"
    for relative in jaa07["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-07 materialised path missing: {relative}"
    for test in jaa07["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-07 declared test missing: {relative}"

    jaa08 = components["JAA-08"]
    assert jaa08["increment"] == "implementation_in_progress_dependency_blocked"
    for relative in jaa08["owns"]:
        assert (ROOT / relative).is_file(), f"JAA-08 materialised path missing: {relative}"
    for test in jaa08["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), f"JAA-08 declared test missing: {relative}"

    jaa09 = components["JAA-09"]
    assert jaa09["increment"] == "implementation_in_progress_dependency_blocked"
    assert (ROOT / "career_automation/ats_fixture.py").exists()
    assert not (ROOT / "career_automation/browser_executor.py").exists()

    for number in range(10, 17):
        slice_id = f"JAA-{number:02d}"
        component = components[slice_id]
        assert component["increment"] == "not_implemented"

        # A future declaration cannot become progress merely by changing this
        # status string. Every declared owned path and named slice test is
        # currently absent, matching the truthful starting state.
        for pattern in component["owns"]:
            if not any(token in pattern for token in ("*", "?", "[")):
                assert not (ROOT / pattern).exists(), f"{slice_id} status needs reassessment"
        for test in component["tests"]:
            for relative in test["files"]:
                if slice_id == "JAA-16" and relative == "test_acceptance_declaration_contract.py":
                    continue
                assert not (ROOT / relative).exists(), f"{slice_id} status needs reassessment"


def test_stale_and_incomplete_slice_states_are_explicit() -> None:
    components = _manifest()["components"]
    assert components["JAA-00"]["increment"] == "historical_baseline"
    assert components["JAA-01"]["increment"] == "complete"
    assert components["JAA-02"]["increment"] == "complete"
    assert components["JAA-03"]["increment"] == "complete"
    assert components["JAA-04"]["increment"] == "increment_b_incomplete"


def test_jaa04_inflight_databases_and_response_bytes_are_untracked() -> None:
    tracked = subprocess.run(
        ("git", "ls-files", "-z", "--", "runtime_evidence/jaa04/inflight"),
        cwd=ROOT,
        check=True,
        capture_output=True,
    ).stdout
    assert tracked == b""
    ignored = subprocess.run(
        (
            "git", "check-ignore", "--quiet", "--no-index",
            "runtime_evidence/jaa04/inflight/queue.sqlite3",
        ),
        cwd=ROOT,
        check=False,
    )
    assert ignored.returncode == 0

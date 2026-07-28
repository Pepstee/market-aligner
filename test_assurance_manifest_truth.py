"""Truth controls for slice status and external JAA-04 runtime state."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import yaml

from tracked_source_revision import source_git_revision


ROOT = Path(__file__).resolve().parent
MANIFEST = ROOT / "ASSURANCE_MANIFEST.json"
SLICES = ROOT / "IMPLEMENTATION_SLICES.yaml"


def _manifest() -> dict[str, object]:
    return json.loads(MANIFEST.read_text(encoding="utf-8"))


def test_unimplemented_slices_are_not_declared_complete() -> None:
    components = _manifest()["components"]
    executable_slices = {
        item["id"]: item
        for item in yaml.safe_load(SLICES.read_text(encoding="utf-8"))["slices"]
    }
    jaa05 = components["JAA-05"]
    assert jaa05["increment"] == "implementation_in_progress_human_evidence_blocked"
    assert jaa05["certification"]["status"] == "blocked"
    assert jaa05["certification"]["blocked_by"] == "HUMAN_EVIDENCE_AUTHORING"
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
    assert jaa09["evidence"] == []
    assert "one genuine JAA-08 token" in jaa09["claim"]
    for relative in jaa09["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-09 materialised path missing: {relative}"
        )
    for test in jaa09["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-09 declared test missing: {relative}"
            )

    jaa10 = components["JAA-10"]
    assert jaa10["increment"] == "implementation_in_progress_dependency_blocked"
    assert jaa10["evidence"] == []
    assert "production certification is withheld" in jaa10["claim"]
    assert "exact seven-control executable mutation cohort passes" in jaa10["claim"]
    mutation_tests = [
        test for test in jaa10["tests"]
        if test["id"] == "JAA-10-mutation-cohort"
    ]
    assert len(mutation_tests) == 1
    assert len(mutation_tests[0]["argv"][4:]) == 7
    for relative in jaa10["owns"]:
        assert (ROOT / relative).is_file(), (
            f"JAA-10 materialised path missing: {relative}"
        )
    for test in jaa10["tests"]:
        for relative in test["files"]:
            assert (ROOT / relative).is_file(), (
                f"JAA-10 declared test missing: {relative}"
            )

    for number in range(11, 17):
        slice_id = f"JAA-{number:02d}"
        component = components[slice_id]
        assert component["increment"] == "not_implemented"
        assert component["claim"] == executable_slices[slice_id]["objective"]
        assert component["depends_on"] == executable_slices[slice_id]["depends_on"]
        if slice_id == "JAA-11":
            assert component["evidence"] == [
                {
                    "kind": "live_canary",
                    "scope": "JAA-11-live-canary",
                    "required": True,
                    "status": "not_collected",
                    "external_action_gate": "explicit_operator_approval_required",
                    "max_age_seconds": 86400,
                }
            ]
        else:
            assert component["evidence"] == []

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
    jaa01 = components["JAA-01"]
    assert jaa01["increment"] == "implementation_complete_current_recertification_blocked"
    historical_receipt = ROOT / jaa01["certification"]["historical_receipt"]
    historical_document = json.loads(historical_receipt.read_text(encoding="utf-8"))
    assert jaa01["certification"] == {
        "status": "historical_receipt_stale",
        "historical_receipt": (
            "runtime_evidence/jaa01/"
            "sha256-a8454e3515c95d73e7dc502016dd1c54bc4e78395c47430bb9fb34f254ec4d84.json"
        ),
        "historical_source_content_revision": (
            "sha256:14eb7db0bc3575eee6854eef4ce0bd729e76d6eee8d20ac261db657f87b7854b"
        ),
        "historical_source_git_revision": "a9f94bcd75213fb0511edf55d7e67256df41f756",
        "current_recertification_blocked_by": "genuine_frozen_jaa00_runtime_unavailable",
        "required_current_scope": [
            "current-tracked-source-tree",
            "exact-source-commit",
        ],
    }
    assert (
        historical_document["source_content_revision"]
        == jaa01["certification"]["historical_source_content_revision"]
    )
    assert (
        historical_document["source_git_revision"]
        == jaa01["certification"]["historical_source_git_revision"]
    )
    assert historical_document["source_git_revision"] != source_git_revision(ROOT)
    current_receipt_tests = [
        test for test in jaa01["tests"]
        if test["id"] == "JAA-01-current-receipt"
    ]
    assert current_receipt_tests == [
        {
            "id": "JAA-01-current-receipt",
            "argv": [
                "{python}",
                "-m",
                "pytest",
                "-q",
                "test_jaa01_checked_receipt_current_revision.py",
            ],
            "files": ["test_jaa01_checked_receipt_current_revision.py"],
        }
    ]
    assert jaa01["evidence"] == [
        {
            "kind": "frozen_runtime",
            "scope": "JAA-01-current-runtime",
            "required": True,
            "tracked": False,
        }
    ]
    assert components["JAA-02"]["increment"] == "complete"
    assert components["JAA-03"]["increment"] == "complete"
    jaa04 = components["JAA-04"]
    assert jaa04["increment"] == "complete"
    assert jaa04["certification"] == {
        "status": "independently_certified",
        "certified_source_git_revision": "a4f44905323abd21f926341e35263a478d381cf4",
        "corpus_inventory_sha256": "f93733a741ffe9b0441fe4bf549d3bb34e167d28d90283f70003843805201258",
        "receipt": "sha256-69299c7d8bac80bcd2b73a85069e80ba433ef75d6092349384f2dd6cdaff418b.json",
        "independent_ruling": "/home/gutua/software-factory/.control/resumed-dual-lane-20260728/jaa/round-09-fable-jaa04-final-certification-ruling.json",
        "note": "This certification supersedes the stale increment_b_incomplete manifest state.",
    }


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
